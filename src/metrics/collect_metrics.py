import os
import json
from datetime import datetime

LOG_DIR = "logs"

def load_log(path):
    entries = []
    if not os.path.exists(path):
        return entries
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            try:
                entries.append(json.loads(line))
            except:
                pass
    return entries


# -------------------------------------------------------------
# Helper: Convert timestamp ISO → datetime
# -------------------------------------------------------------
def parse_ts(ts):
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except:
        return None


# -------------------------------------------------------------
# Parse insecure system logs
# -------------------------------------------------------------
def parse_insecure(attacker, actuator):
    attack_attempts = 0
    attack_successes = 0
    latency = []

    # Detect attack attempts
    for log in attacker:
        msg = log.get("message", "")
        if "Launching replay attack" in msg or "Replaying captured message" in msg:
            attack_attempts += 1

    # Detect attack success (plaintext actuator always accepts)
    for log in actuator:
        msg = log.get("message", "")
        if "ACTUATOR ACTION" in msg:
            attack_successes += 1

    # Detect latency from attacker-captured payloads
    for log in attacker:
        if log.get("message") == "📥 Captured message":
            payload_raw = log.get("extra", {}).get("payload")
            if not payload_raw:
                continue
            try:
                payload = json.loads(payload_raw)
                t_sensor = parse_ts(payload["timestamp"])
                t_attacker = parse_ts(log["timestamp"])
                if t_sensor and t_attacker:
                    latency.append((t_attacker - t_sensor).total_seconds() * 1000)
            except:
                pass

    return {
        "attack_attempts": attack_attempts,
        "attack_successes": attack_successes,
        "latency_ms": latency
    }


# -------------------------------------------------------------
# Parse secure system logs
# -------------------------------------------------------------
def parse_secure(attacker, actuator):
    attack_attempts = 0
    blocked_attacks = 0
    accepted = 0
    latency = []

    # Count attempts from secure attacker
    for log in attacker:
        msg = log.get("message", "")
        if "Launching replay attack" in msg or "Replaying" in msg:
            attack_attempts += 1

    # Secure actuator behavior:
    #   - accepted message (normal sensor message)
    #   - rejected message (attacker or invalid)
    for log in actuator:
        msg = log.get("message", "")
        extra = log.get("extra", {})

        if "Message accepted" in msg:
            accepted += 1

        # Failed security checks
        if (
            "Message verification failed" in msg
            or "Message rejected" in msg
            or "Replay attack detected" in msg
            or extra.get("sender") is None
        ):
            blocked_attacks += 1

    # Extract secure latency:
    # Received secure message → Message accepted
    last_received = None
    for log in actuator:
        msg = log.get("message", "")
        ts = parse_ts(log.get("timestamp"))

        if "Received secure message" in msg:
            last_received = ts

        if "Message accepted" in msg and last_received:
            latency.append((ts - last_received).total_seconds() * 1000)
            last_received = None

    return {
        "attack_attempts": attack_attempts,
        "attacks_blocked": blocked_attacks,
        "legitimate_messages": accepted,
        "latency_ms": latency
    }


# -------------------------------------------------------------
# MAIN
# -------------------------------------------------------------
def main():
    print("\n============================================================")
    print("CEN455 MQTT SECURITY METRICS COLLECTION")
    print("============================================================\n")

    # Load insecure logs
    insecure_attacker = load_log(os.path.join(LOG_DIR, "attacker_insecure.log"))
    insecure_actuator = load_log(os.path.join(LOG_DIR, "actuator_insecure.log"))

    # Load secure logs
    secure_attacker = load_log(os.path.join(LOG_DIR, "attacker_secure.log"))
    secure_actuator = load_log(os.path.join(LOG_DIR, "actuator_secure.log"))

    print("Parsing INSECURE logs...")
    insecure_metrics = parse_insecure(insecure_attacker, insecure_actuator)

    print("Parsing SECURE logs...")
    secure_metrics = parse_secure(secure_attacker, secure_actuator)

    # Save results
    results = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "insecure": insecure_metrics,
        "secure": secure_metrics
    }

    output_path = os.path.join(LOG_DIR, "metrics_results.json")
    with open(output_path, "w") as f:
        json.dump(results, f, indent=2)

    print("\n============================================================")
    print("METRICS COLLECTION COMPLETE")
    print("============================================================")
    print(f"Results saved to: {output_path}")


if __name__ == "__main__":
    main()
