# Secure Smart Home Communication Using MQTT and Cryptography

A Comparative Implementation of Insecure vs Secure IoT Messaging Pipelines



 Abstract

This project implements and evaluates two IoT messaging pipelines using the MQTT protocol: an insecure plaintext system and a secured cryptographic system. The insecure pipeline demonstrates how eavesdropping, tampering, spoofing, and replay attacks can easily compromise unprotected IoT communication. The secure system integrates RSA-2048 key exchange, AES-256-GCM authenticated encryption, DSA-2048 signatures, replay protection, constant-time comparison, and MQTT broker authentication. Quantitative metrics confirm that the secure system blocks 100% of attacks while maintaining practical IoT latency within acceptable limits.



1. Project Overview

MQTT is widely used in IoT environments due to its lightweight publish–subscribe architecture. However, the default MQTT workflow includes no encryption, no authentication, and no message integrity verification. This project demonstrates:

* How plaintext MQTT communication is vulnerable to real-world cyberattacks.
* How layered cryptography transforms MQTT into a secure, attack-resistant system.
* How both insecure and secure pipelines behave under identical attack conditions.

The repository includes complete implementations of insecure and secure systems, attack scripts, Docker environments, and tools for metric collection and visualization.



2. Objectives

* Demonstrate vulnerabilities of plaintext MQTT communication.
* Implement security mechanisms using RSA, AES-GCM, and DSA.
* Add replay protection and constant-time comparison for side-channel defense.
* Quantitatively compare attack success rates and latency overhead.
* Build reproducible Docker setups for both insecure and secure systems.



3. System Architecture

Phase I — Insecure MQTT System

* Plaintext communication between sensor, broker, and actuator.
* No authentication or encryption.
* Vulnerable to:

  * Eavesdropping
  * Tampering
  * Forged message injection
  * Replay attacks
* Result: All attacks succeed without detection.

Phase II — Secure MQTT System

Cryptographic Features

* RSA-2048 for session-key exchange.
* AES-256-GCM for confidentiality and integrity.
* DSA-2048 for digital signatures.
* Constant-time comparison to prevent timing attacks.
* Replay counters to prevent message reuse.
* MQTT broker authentication (ACLs, usernames, passwords).

Secure Message Flow

1. Sensor generates AES session key.
2. Payload encrypted using AES-256-GCM.
3. AES key encrypted with RSA.
4. DSA signatures created for authenticity.
5. Encrypted message published to secure broker topic.

Outcome

* All malicious packets are rejected.
* No replay, no tampering, and no forgery are accepted.
* Attacker is unable to read ciphertext.

Phase III — Metrics and Performance Evaluation

Metrics collected using:

```
collect_metrics.py
plot_results.py
```

Summary of results:

| Metric              | Insecure System | Secure System |
| ------------------- | --------------- | ------------- |
| Attack success rate | 100/100         | 0/100         |
| Latency             | 1–3 ms          | 10–25 ms      |
| Integrity           | None            | AES-GCM       |
| Authentication      | None            | DSA-2048      |

The secure system introduces only minor computational overhead.



 4. Repository Structure

```
src/
│
├── insecure/
│   ├── sensor.py
│   ├── actuator.py
│   ├── attacker.py
│   ├── timing_attack_demo.py
│ 
│
├── secure/
│   ├── sensor_secure.py
│   ├── actuator_secure.py
│   └── attacker_secure.py
│
├── common/
│   ├── crypto_utils.py
│   ├── mq_helpers.py
│   └── logger.py
│
└── utils/
    └── generate_keys.py

docker-compose.insecure.yml  
docker-compose.secure.yml  
logs/  
metrics/  
```



5. Setup Instructions

Prerequisites

* Docker
* Docker Compose
* Python 3.10 or above

Verify installation:

```
docker --version
docker compose version
python --version
```



6. Generate Cryptographic Keys

Before running the secure pipeline:

```
python utils/generate_keys.py
```

This creates RSA, DSA, and AES key materials inside the `keys/` directory.

 7. Running the Insecure System

Start the insecure MQTT pipeline:

```
docker compose -f docker-compose.insecure.yml up --build
```

Expected behavior:

* Plaintext MQTT traffic visible in logs.
* Attacker successfully performs:

  * Eavesdropping
  * Tampering
  * Injection
  * Replay
* No detection or rejection.



 8. Running the Secure System

Start the secure pipeline:

```
docker compose -f docker-compose.secure.yml up --build
```

9. Logs

Check for Logs

```
ls logs
```

Expected behavior:

* gives .log files for insecure system
* gives .log files for secure systems

---

10. Metrics Collection and Visualization

Collect metrics:

```
python collect_metrics.py
```

Generate plots:

```
python plot_results.py
```

Plots include:

* Attack success rate comparison
* Latency comparison



11. Attack Demonstration Summary

| Attack Type   | Insecure Result | Secure Result                |
| ------------- | --------------- | ---------------------------- |
| Eavesdropping | Fully visible   | Ciphertext only              |
| Injection     | Accepted        | Rejected (invalid signature) |
| Replay        | Accepted        | Rejected (counter mismatch)  |
| Tampering     | Accepted        | Rejected (GCM tag failure)   |



 12. Timing Attack Demonstration (Insecure System)

The insecure folder includes a timing-attack demonstration showing how early-exit comparison logic leaks timing information. This demo is executed outside Docker so that timing measurements remain accurate.

Step 1 — Navigate to the insecure directory

```
cd src/insecure
```

 Step 2 — Run the vulnerable comparison server

```
python timing_attack_demo.py
```

Leave this terminal running.


 13. Conclusion

The insecure MQTT pipeline is vulnerable to all major IoT attack vectors, including eavesdropping, tampering, forgery, and replay. The secure system, which integrates AES-GCM, RSA-2048, DSA-2048, replay counters, and broker authentication, prevents all observed attacks. Quantitative evaluations confirm that the secure pipeline blocks 100% of attacks while maintaining a small and acceptable performance overhead. This project demonstrates how layered cryptography significantly strengthens the security of smart home communication systems.


