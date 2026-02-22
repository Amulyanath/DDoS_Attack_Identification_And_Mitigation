import requests
import time
import json

BASE_URL = "http://127.0.0.1:5000"

def test_system():
    print("--- Starting DDoS System Verification ---")
    
    # 1. Check Initial Status
    try:
        resp = requests.get(f"{BASE_URL}/status")
        data = resp.json()
        print(f"[INIT] Severity: {data['intelligence']['severity']}")
        print(f"[INIT] Action List Count: {len(data['mitigation']['actions'])}")
    except Exception as e:
        print(f"[ERROR] Could not connect to server: {e}")
        return

    # 2. Start Botnet Attack
    print("\n[ATTACK] Triggering Distributed Botnet Attack...")
    requests.get(f"{BASE_URL}/start_attack?type=Botnet")
    
    # Wait for simulation to run and analysis to catch up
    for i in range(5):
        requests.get(f"{BASE_URL}/simulate")
        time.sleep(0.5)
        
    # 3. Verify Classification and Mitigation
    resp = requests.get(f"{BASE_URL}/status")
    data = resp.json()
    intelligence = data['intelligence']
    mitigation = data['mitigation']
    
    print(f"\n[DETECTED] Attack Type: {intelligence['attack_type']}")
    print(f"[DETECTED] Confidence: {intelligence['confidence_score']}%")
    print(f"[DETECTED] Severity: {intelligence['severity']}")
    
    # Verify Source Intelligence
    proto_data = list(intelligence['protocols'].values())[0]
    if proto_data['sources']:
        src = proto_data['sources'][0]
        print(f"[SOURCE] IP: {src['ip']}, Geo: {src['geo']}, Risk: {src['risk_score']}, Bot: {src['is_bot']}")
    
    # Verify Mitigation Action
    if mitigation['stage'] >= 3:
        print(f"[MITIGATION] Stage {mitigation['stage']} Active: {mitigation['recommended']}")
        if mitigation['actions']:
            print(f"[ACTION] Last Action: {mitigation['actions'][-1]['action']} - {mitigation['actions'][-1]['detail']}")
        if mitigation['global_blocked'] or mitigation['proto_blocked']:
            print(f"[SUCCESS] Malicious IPs successfully blocked automatically.")
            
    # 4. Check Effectiveness
    print(f"\n[EFFECTIVENESS] Baseline: {mitigation['effectiveness']['baseline']}")
    print(f"[EFFECTIVENESS] Stabilized: {mitigation['effectiveness']['stabilized']}")
    
    # 5. Stop Attack
    print("\n[CLEANUP] Stopping attack simulation...")
    requests.get(f"{BASE_URL}/stop_attack")
    print("--- Verification Complete ---")

if __name__ == "__main__":
    test_system()
