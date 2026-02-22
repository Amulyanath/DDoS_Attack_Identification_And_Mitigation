import time
import collections


class TrafficAnalyzer:
    def __init__(self, threshold_pps=500, history_window=10):
        self.threshold_pps = threshold_pps
        self.stats = collections.defaultdict(lambda: {'total': 0, 'ips': collections.defaultdict(int)})
        self.last_check = time.time()

        self.last_analysis = {
            "attack_detected": False,
            "attack_type": "None",
            "severity": "Normal",
            "confidence_score": 0,
            "entropy": 1.0,
            "protocols": {},
            "total_pps": 0,
        }

    def add_packet(self, src_ip, protocol):
        self.stats[protocol]['total'] += 1
        self.stats[protocol]['ips'][src_ip] += 1

    def calculate_entropy(self, total_packets, total_unique_ips):
        if total_packets == 0:
            return 1.0
        return min(1.0, total_unique_ips / total_packets)

    def get_geo(self, ip):
        countries = ["USA", "Germany", "China", "Russia", "Brazil", "India", "UK", "Canada"]
        if ip.startswith("10."):
            seed = sum(int(x) for x in ip.split('.') if x.isdigit())
            return countries[seed % len(countries)]
        if ip.startswith("192.168."):
            return "USA"
        return "Unknown"

    def calculate_risk_score(self, percentage, entropy, pps):
        base_score = percentage * 0.7 + (1.0 - entropy) * 20
        pps_factor = min(10, pps / 100)
        return min(100, int(base_score + pps_factor))

    def infer_bot_probability(self, risk_score, entropy):
        bot_probability = int(min(99, max(1, risk_score * 0.7 + entropy * 30)))
        human_probability = 100 - bot_probability
        return bot_probability, human_probability

    def classify_attack(self, dominant_protocol, total_pps, entropy, unique_ip_count):
        if total_pps > self.threshold_pps * 3 and (entropy > 0.55 or unique_ip_count > 12):
            return "Botnet-like Behavior"
        if dominant_protocol == 'TCP':
            return "SYN Flood"
        if dominant_protocol == 'UDP':
            return "UDP Flood"
        if dominant_protocol == 'HTTP':
            return "HTTP Flood"
        return f"{dominant_protocol} Flood"

    def analyze(self):
        current_time = time.time()
        time_diff = current_time - self.last_check

        if time_diff < 1.0:
            return None

        active_protocols = list(self.stats.keys())
        total_global_packets = sum(p['total'] for p in self.stats.values())
        all_unique_ips = set()
        for p in self.stats.values():
            all_unique_ips.update(p['ips'].keys())

        entropy = self.calculate_entropy(total_global_packets, len(all_unique_ips))

        protocol_pps = {}
        max_pps = 0
        dominant_protocol = "None"
        attack_detected = False

        for proto in active_protocols:
            count = self.stats[proto]['total']
            pps = count / time_diff
            protocol_pps[proto] = pps

            if pps > self.threshold_pps:
                attack_detected = True

            if pps > max_pps:
                max_pps = pps
                dominant_protocol = proto

        attack_type = "None"
        confidence = 0
        severity = "Normal"
        total_pps = (total_global_packets / time_diff) if time_diff > 0 else 0

        if attack_detected:
            attack_type = self.classify_attack(dominant_protocol, total_pps, entropy, len(all_unique_ips))
            proto_dominance = (max_pps / total_pps) if total_pps > 0 else 0
            entropy_factor = entropy if attack_type == "Botnet-like Behavior" else (1.0 - entropy)
            confidence = int((proto_dominance * 0.4 + entropy_factor * 0.6) * 100)
            confidence = max(45, min(99, confidence))

            if total_pps > self.threshold_pps * 10:
                severity = "Critical"
            elif total_pps > self.threshold_pps * 5:
                severity = "High"
            elif total_pps > self.threshold_pps * 2:
                severity = "Moderate"
            else:
                severity = "Low"

        protocol_data = {}
        for proto in active_protocols:
            total_proto = self.stats[proto]['total']
            sorted_ips = sorted(self.stats[proto]['ips'].items(), key=lambda x: x[1], reverse=True)
            sources = []
            for ip, count in sorted_ips:
                percentage = (count / total_proto * 100) if total_proto > 0 else 0
                if percentage > 3:
                    risk_score = self.calculate_risk_score(percentage, entropy, protocol_pps[proto])
                    bot_probability, human_probability = self.infer_bot_probability(risk_score, entropy)
                    threat_confidence = int(min(99, max(1, (risk_score * 0.65) + (percentage * 0.35))))
                    sources.append({
                        "ip": ip,
                        "percentage": round(percentage, 1),
                        "count": count,
                        "geo": self.get_geo(ip),
                        "country": self.get_geo(ip),
                        "risk_score": risk_score,
                        "threat_confidence": threat_confidence,
                        "bot_probability": bot_probability,
                        "human_probability": human_probability,
                        "is_bot": "True" if bot_probability >= 60 else "False"
                    })

            protocol_data[proto] = {
                "pps": round(protocol_pps[proto], 2),
                "attack": protocol_pps[proto] > self.threshold_pps,
                "sources": sources
            }

            self.stats[proto]['total'] = 0
            self.stats[proto]['ips'].clear()

        self.last_analysis = {
            "attack_detected": attack_detected,
            "attack_type": attack_type,
            "severity": severity,
            "confidence_score": confidence,
            "entropy": round(entropy, 3),
            "protocols": protocol_data,
            "total_pps": round(total_pps, 2)
        }

        self.last_check = current_time
        return self.last_analysis

    def check_rpf(self, ip):
        try:
            last_octet = int(ip.split('.')[-1])
            if last_octet % 2 != 0:
                return False
        except Exception:
            pass
        return True
