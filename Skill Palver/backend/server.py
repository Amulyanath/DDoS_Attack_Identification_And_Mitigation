from flask import Flask, jsonify, request, send_from_directory
import time
import random
from detector import TrafficAnalyzer
from mitigator import Mitigator

app = Flask(__name__, static_folder='../frontend/static', template_folder='../frontend')

COMMON_PROTOCOLS = ['UDP', 'TCP', 'HTTP', 'ICMP', 'DNS']

traffic_data = []
attack_mode = False
attack_type = "None"
dropped_packets = 0




timeline = ["System initialized. Monitoring traffic..."]
THRESHOLD = 40

traffic_history = {
    "normal": [],
    "during_attack": [],
    "after_mitigation": []
}

mitigator = Mitigator()
analyzer = TrafficAnalyzer(threshold_pps=THRESHOLD)


def add_log(msg):
    timestamp = time.strftime("%H:%M:%S")
    timeline.append(f"{timestamp} - {msg}")
    if len(timeline) > 60:
        timeline.pop(1)


def generate_traffic_packet():
    global attack_mode, attack_type

    if attack_mode:
        if attack_type == "Mixed":
            proto = random.choice(COMMON_PROTOCOLS)
            ip = f"10.0.0.{random.randint(1, 8)}"
        elif attack_type == "SYN Flood":
            proto = 'TCP'
            ip = f"10.0.0.{random.randint(1, 4)}"
        elif attack_type == "UDP Flood":
            proto = 'UDP'
            ip = f"10.0.0.{random.randint(1, 5)}"
        elif attack_type == "HTTP Flood":
            proto = 'HTTP'
            ip = f"10.0.0.{random.randint(1, 6)}"
        elif attack_type == "Botnet":
            proto = random.choice(['TCP', 'UDP', 'HTTP'])
            ip = f"10.0.{random.randint(0, 3)}.{random.randint(1, 40)}"
        else:
            proto = random.choice(COMMON_PROTOCOLS)
            ip = f"10.0.0.{random.randint(1, 10)}"
    else:
        proto = random.choice(COMMON_PROTOCOLS)
        ip = f"192.168.0.{random.randint(1, 50)}"

    return {"ip": ip, "protocol": proto, "timestamp": time.time()}


@app.route('/')
def index():
    return send_from_directory('../frontend', 'index.html')


@app.route('/start_attack')
def start_attack():
    global attack_mode, attack_type
    attack_mode = True
    attack_type = request.args.get('type', 'Mixed')
    add_log(f"ALERT: Simulation started for {attack_type}")
    return jsonify({"attack_mode": True, "type": attack_type})


@app.route('/stop_attack')
def stop_attack():
    global attack_mode, attack_type
    attack_mode = False
    attack_type = "None"
    add_log("INFO: Simulation stopped. System returning to normal.")
    return jsonify({"attack_mode": False})


@app.route('/simulate')
def simulate():
    global traffic_data, dropped_packets, attack_mode

    requests_this_cycle = random.randint(100, 200) if attack_mode else random.randint(10, 30)

    dropped_before = dropped_packets
    accepted_count = 0

    for _ in range(requests_this_cycle):
        packet = generate_traffic_packet()
        ip = packet['ip']
        proto = packet['protocol']

        stats = analyzer.last_analysis['protocols'].get(proto, {})
        current_pps = stats.get('pps', 0)
        rpf_valid = analyzer.check_rpf(ip)

        if mitigator.should_drop(ip, proto, current_pps, rpf_valid):
            dropped_packets += 1
            mitigator.dropped_count = dropped_packets
            continue

        accepted_count += 1
        traffic_data.append(packet)
        analyzer.add_packet(ip, proto)

    if attack_mode:
        traffic_history["during_attack"].append(requests_this_cycle)
        traffic_history["after_mitigation"].append(accepted_count)
    else:
        traffic_history["normal"].append(accepted_count)

    for key in traffic_history:
        if len(traffic_history[key]) > 60:
            traffic_history[key].pop(0)

    dropped_this_cycle = dropped_packets - dropped_before
    return jsonify({
        "message": "traffic simulated",
        "count": requests_this_cycle,
        "accepted": accepted_count,
        "dropped": dropped_this_cycle
    })


@app.route('/status')
def status():
    global dropped_packets, timeline

    analysis = analyzer.analyze()
    if analysis:
        old_stage = mitigator.current_stage
        mitigator.update_mitigation_stage(analysis['severity'])

        if mitigator.current_stage != old_stage:
            add_log(f"ACTION: Escalated to Mitigation Stage {mitigator.current_stage} ({mitigator.recommended_action})")

        if analysis['attack_detected']:
            add_log(f"DETECTED: {analysis['attack_type']} (Severity: {analysis['severity']})")
            mitigator.auto_mitigate(analysis)

    avg_normal = (sum(traffic_history["normal"]) / len(traffic_history["normal"])) if traffic_history["normal"] else 20.0
    avg_attack = (sum(traffic_history["during_attack"]) / len(traffic_history["during_attack"])) if traffic_history["during_attack"] else 0.0
    avg_stabilized = (sum(traffic_history["after_mitigation"]) / len(traffic_history["after_mitigation"])) if traffic_history["after_mitigation"] else 0.0

    all_blocked = mitigator.get_all_blocked_ips()
    rate_limited_sources = mitigator.get_rate_limited_sources()
    latest_action = mitigator.actions_taken[-1]['action'] if mitigator.actions_taken else "None"

    return jsonify({
        "intelligence": analyzer.last_analysis,
        "mitigation": {
            "stage": mitigator.current_stage,
            "status": mitigator.mitigation_status,
            "recommended": mitigator.recommended_action,
            "action_taken": latest_action,
            "scrubbing": mitigator.scrubbing_active,
            "blackhole": mitigator.blackhole_active,
            "global_blocked": list(mitigator.blocked_ips),
            "proto_blocked": {p: list(ips) for p, ips in mitigator.blocked_ips_per_protocol.items()},
            "blocked_ips": all_blocked,
            "blocked_count": len(all_blocked),
            "rate_limits": dict(mitigator.rate_limits),
            "rate_limited_sources": rate_limited_sources,
            "rate_limited_count": len(rate_limited_sources),
            "actions": mitigator.actions_taken,
            "firewall_status": "Triggered" if mitigator.firewall_active else "Idle",
            "effectiveness": {
                "normal": round(avg_normal, 1),
                "during_attack": round(avg_attack, 1),
                "stabilized": round(avg_stabilized, 1) if mitigator.current_stage > 0 else "N/A"
            }
        },
        "dropped_packets": dropped_packets,
        "traffic_history": traffic_history,
        "timeline": list(reversed(timeline))
    })


@app.route('/api/mitigate/block', methods=['POST'])
def block_ip_route():
    data = request.json
    ip = data.get('ip')
    protocol = data.get('protocol')
    mitigator.block_ip(ip, protocol)
    add_log(f"MITIGATION: Manually blocked IP {ip}" + (f" for {protocol}" if protocol else ""))
    return jsonify({"status": "IP blocked"})


@app.route('/api/mitigate/unblock', methods=['POST'])
def unblock_ip_route():
    data = request.json
    ip = data.get('ip')
    protocol = data.get('protocol')
    mitigator.unblock_ip(ip, protocol)
    add_log(f"MITIGATION: Manually unblocked IP {ip}")
    return jsonify({"status": "IP unblocked"})


if __name__ == '__main__':
    app.run(debug=True, port=5000)
