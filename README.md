  **Secure Smart Home Communication Using MQTT & Cryptography**

*A Comparative Implementation of Insecure vs Secure IoT Messaging Pipelines*


 Abstract

This project develops and evaluates two MQTT-based smart home communication systems—one deliberately insecure and one fully secured using modern cryptography. The insecure design demonstrates how eavesdropping, spoofing, tampering, and replay attacks completely compromise plaintext IoT pipelines. The secure system integrates RSA-2048 key exchange, AES-256-GCM encryption, DSA-2048 digital signatures, replay protection, constant-time comparison, and broker-level hardening. Metrics collected from both systems confirm that cryptographic protection blocks 100% of attacks while maintaining practical IoT latency ranges.


 1. Project Overview

MQTT is widely used in IoT environments due to its lightweight publish–subscribe model—but its default configuration provides **no encryption, no authentication, and no integrity checks**. This project shows:

* How an **unsecured MQTT workflow** is vulnerable to real-world IoT attacks
* How layered cryptography transforms it into a **strong, attack-resistant communication system**

The implementation includes complete Python modules for both insecure and secure systems, along with attack scripts, Docker environments, and quantitative evaluation tools.



2. Objectives

Demonstrate the vulnerabilities of plaintext MQTT systems
Implement a secure, cryptography-based communication pipeline
Integrate RSA, AES-GCM, and DSA for confidentiality, integrity & authenticity
Apply replay protection and constant-time comparison
Quantitatively measure security overhead and attack success rates



 3. System Architecture

 **Phase I — Insecure MQTT System**

* Plaintext sensor → broker → actuator messages
* No authentication, no encryption, no integrity protection
* Attacker can:

  *  Eavesdrop
  * Inject forged packets
  * Replay captured messages
  * Tamper with payload fields
  * Outcome: 100% of attacks successful


 **Phase II — Secure MQTT System**

Security features include:

 Cryptography

* RSA-2048 → secure session-key exchange
* AES-256-GCM → encryption + integrity (AEAD)
* DSA-2048 → digital signatures for authentication

  Protections

* Monotonic counters → replay attack prevention
* Constant-time comparison → timing attack resistance
* Broker ACLs + credentials → client authentication
* Secure message protocol:

  1. Generate AES session key
  2. Encrypt payload with AES-GCM
  3. Encrypt session key with RSA
  4. Sign fields with DSA
  5. Publish to secure topic

 Outcome

100% malicious packets blocked
All ciphertext unreadable to attacker
 No replay, tampering, or forgery accepted

  **Phase III — Metrics & Performance Evaluation**

Metrics collected via `collect_metrics.py` and visualized using `plot_results.py`.

 Key Findings

| Metric              | Insecure System | Secure System |
| ------------------- | --------------- | ------------- |
| Attack success rate | **100/100**     | **0/100**     |
| Latency             | 1–3 ms          | 10–25 ms      |
| Message integrity   |   None          |  AES-GCM     |
| Authentication      |    None          |  DSA-2048    |
| (Page 13–15)        |                 |               |

The secure system adds a small computational cost but remains well within acceptable IoT timing thresholds.

---

 4. Repository Structure

```
src/
│
├── insecure/        # Plaintext MQTT system (Phase I)
│   ├── sensor.py
│   ├── actuator.py
│   └── attacker.py
│
├── secure/          # Cryptographically secure system (Phase II)
│   ├── sensor_secure.py
│   ├── actuator_secure.py
│   └── attacker_secure.py
│
├── common/          # Shared modules
│   ├── mq_helpers.py
│   ├── crypto_utils.py
│   └── logger.py
│
└── utils/
    └── generate_keys.py
```

Plus:

* `docker-compose.insecure.yml`
* `docker-compose.secure.yml`
* `/logs`
* `/metrics`



  5. Running the Systems (Docker)

  Run Insecure System

```
docker compose -f docker-compose.insecure.yml up --build
```

Expect:

* Plaintext logs
* Successful replay, injection & tampering attacks
* Attacker reading traffic freely



  Run Secure System

```
docker compose -f docker-compose.secure.yml up --build
```

Expect:

* AES-GCM encrypted payloads
* RSA-encrypted session keys
* Valid/invalid signature logs
* Replay detection rejections

6. Attack Demonstration Summary

| Attack Type   | Insecure Result | Secure Result                |
| ------------- | --------------- | ---------------------------- |
| Eavesdropping | Full visibility | Ciphertext only              |
| Injection     | Accepted        | Rejected (invalid signature) |
| Replay        | Accepted        | Rejected (counter check)     |
| Tampering     | Accepted        | Rejected (GCM tag mismatch)  |


 7. Quantitative Analysis (Key Plots)

Attack Success Rate Plot

* Insecure → **0** attacks blocked
* Secure → **270+** attacks blocked
   

Security Overhead Plot

* Mean insecure latency → **4.23 ms**
* Mean secure latency → **21.14 ms**

Even with cryptographic operations, secure latency remains IoT-safe.

8. Timing Attack Analysis

Evaluates:

* Early-exit comparison (leaks timing patterns)
*  Constant-time comparison (uniform timing)

Example vulnerable timings (µs):

* All wrong → 0.767
* 15/16 bytes correct → 1.260

Constant-time timings: 2.14–3.99 µs with no correlation.

**Conclusion:** constant-time comparison is essential for preventing side-channel leakage.


 9. Conclusion

* The insecure MQTT system is completely exposed to all major IoT attack vectors.
* Integrating AES-GCM, RSA, DSA, replay protection, and broker authentication results in **full attack mitigation**.
* Cryptographic overhead remains minimal and practical for real-world IoT.


