import collections
import time


class Mitigator:
    def __init__(self):
        self.blocked_ips = set()
        self.blocked_ips_per_protocol = collections.defaultdict(set)
        self.rate_limits = collections.defaultdict(int)
        self.source_rate_limits = {}
        self.source_counters = {}
        self.rate_limited_sources = set()

        self.blackhole_active = False
        self.scrubbing_active = False

        self.current_stage = 0
        self.recommended_action = "Monitor Traffic"
        self.mitigation_status = "Monitoring"

        self.actions_taken = []
        self.firewall_active = False
        self.dropped_count = 0

    def update_mitigation_stage(self, severity):
        if severity == "Critical":
            self.current_stage = 4
            self.recommended_action = "Activate Blackhole Routing"
            self.blackhole_active = True
        elif severity == "High":
            self.current_stage = 3
            self.recommended_action = "Block Malicious Sources"
            self.blackhole_active = False
            self.scrubbing_active = True
        elif severity == "Moderate":
            self.current_stage = 2
            self.recommended_action = "Enable Traffic Scrubbing"
            self.blackhole_active = False
            self.scrubbing_active = True
        elif severity == "Low":
            self.current_stage = 1
            self.recommended_action = "Apply Rate Limiting"
            self.blackhole_active = False
            self.scrubbing_active = False
        else:
            self.current_stage = 0
            self.recommended_action = "Monitor Traffic"
            self.blackhole_active = False
            self.scrubbing_active = False

        self.firewall_active = self.current_stage > 0
        self.mitigation_status = "Active" if self.firewall_active else "Monitoring"

    def add_action(self, action_type, detail):
        self.actions_taken.append({
            "timestamp": time.strftime("%H:%M:%S"),
            "action": action_type,
            "detail": detail
        })
        if len(self.actions_taken) > 30:
            self.actions_taken.pop(0)

    def block_ip(self, ip, protocol=None, auto=False):
        if protocol:
            if ip not in self.blocked_ips_per_protocol[protocol]:
                self.blocked_ips_per_protocol[protocol].add(ip)
                self.add_action("Blocked", f"{ip} ({protocol}){' [AUTO]' if auto else ''}")
        else:
            if ip not in self.blocked_ips:
                self.blocked_ips.add(ip)
                self.add_action("Blocked", f"{ip}{' [AUTO]' if auto else ''}")

    def unblock_ip(self, ip, protocol=None):
        if protocol:
            if ip in self.blocked_ips_per_protocol[protocol]:
                self.blocked_ips_per_protocol[protocol].remove(ip)
                self.add_action("Unblocked", f"{ip} ({protocol})")
        else:
            if ip in self.blocked_ips:
                self.blocked_ips.remove(ip)
                self.add_action("Unblocked", ip)

    def set_rate_limit(self, protocol, limit):
        current = self.rate_limits.get(protocol)
        if current != limit:
            self.rate_limits[protocol] = limit
            self.add_action("Rate Limited", f"{protocol} -> {limit} pps")

    def set_source_rate_limit(self, ip, protocol, limit):
        key = f"{ip}|{protocol}"
        previous = self.source_rate_limits.get(key)
        if previous != limit:
            self.source_rate_limits[key] = limit
            self.rate_limited_sources.add(key)
            self.add_action("Rate Limited", f"{ip} ({protocol}) -> {limit} pps")

    def _source_over_limit(self, ip, protocol):
        key = f"{ip}|{protocol}"
        if key not in self.source_rate_limits:
            return False

        now = time.time()
        window = self.source_counters.get(key)
        if not window or now - window['ts'] >= 1:
            self.source_counters[key] = {'ts': now, 'count': 1}
            return False

        window['count'] += 1
        return window['count'] > self.source_rate_limits[key]

    def should_drop(self, ip, protocol, pps, rpf_valid):
        if self.blackhole_active:
            return True

        if ip in self.blocked_ips:
            return True

        if self.current_stage >= 3 and ip in self.blocked_ips_per_protocol.get(protocol, set()):
            return True

        if self.scrubbing_active and not rpf_valid:
            return True

        if self.current_stage >= 1 and protocol in self.rate_limits and self.rate_limits[protocol] > 0:
            if pps > self.rate_limits[protocol]:
                return True

        if self._source_over_limit(ip, protocol):
            return True

        return False

    def auto_mitigate(self, analysis):
        if not analysis or not analysis.get('attack_detected'):
            return

        for proto, data in analysis['protocols'].items():
            if not data.get('attack'):
                continue

            dynamic_limit = max(20, int(data['pps'] * 0.6))
            self.set_rate_limit(proto, dynamic_limit)

            for src in data.get('sources', []):
                risk = src.get('risk_score', 0)
                contribution = src.get('percentage', 0)

                if self.current_stage >= 3 and (risk >= 80 or contribution >= 25):
                    self.block_ip(src['ip'], proto, auto=True)
                elif risk >= 55 or contribution >= 12:
                    per_source_limit = max(8, int(dynamic_limit * 0.25))
                    self.set_source_rate_limit(src['ip'], proto, per_source_limit)

    def get_all_blocked_ips(self):
        blocked = set(self.blocked_ips)
        for ips in self.blocked_ips_per_protocol.values():
            blocked.update(ips)
        return sorted(blocked)

    def get_rate_limited_sources(self):
        return sorted(self.rate_limited_sources)
