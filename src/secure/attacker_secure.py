"""
Advanced Secure Attacker
CEN455 Secure MQTT Home Automation System

This attacker performs:
1. Fake message injection
2. Replay attack (old timestamp)
3. Timestamp freshness violation
4. Tampering attack (modifies encrypted payload)
5. Invalid RSA-encrypted session key injection
6. Signature forgery attempt
7. Garbage ciphertext payload
"""

import json
import time
import os
import base64
import random

from src.common.crypto_utils import (
    generate_session_key,
    rsa_encrypt_for_public,
    dsa_sign,
    aesgcm_encrypt
)
from src.common.mq_helpers import connect_client, publish_message
from src.common.logger import get_logger


logger = get_logger("attacker_secure")

BROKER_TOPIC = "home/secure/door"
BROKER_HOST = "mqtt-broker"
BROKER_PORT = 1883


# -------------------------------------------------------------------
# 1. FAKE PAYLOAD ATTACK
# -------------------------------------------------------------------
def fake_payload():
    logger.warning("ATTACK: Fake message with forged signature")
    return json.dumps({
        "type": "door_status",
        "timestamp": int(time.time()),
        "value": "OPEN",
        "nonce": "bad_nonce",
        "signature": "INVALID_SIGNATURE_123"
    })


# -------------------------------------------------------------------
# 2. REPLAY ATTACK
# -------------------------------------------------------------------
def replay_attack():
    logger.warning("ATTACK: Replay attack with OLD timestamp")
    return json.dumps({
        "type": "door_status",
        "timestamp": int(time.time()) - 600,  # 10 minutes old
        "value": "CLOSED",
        "nonce": "nonce123",
        "signature": "FAKE_SIG"
    })


# -------------------------------------------------------------------
# 3. TIMESTAMP FRESHNESS VIOLATION
# -------------------------------------------------------------------
def future_timestamp_attack():
    logger.warning("ATTACK: Future timestamp attack (clock tampering)")
    return json.dumps({
        "type": "door_status",
        "timestamp": int(time.time()) + 5000,  # 1 hr 20 min in the future
        "value": "CLOSED",
        "nonce": "future123",
        "signature": "FAKE_SIG"
    })


# -------------------------------------------------------------------
# 4. AES-GCM TAMPERING ATTACK
# -------------------------------------------------------------------
def tamper_ciphertext():
    logger.warning("ATTACK: AES-GCM tampering attack")

    # Produce an AES-GCM encrypted sample
    aes_key = generate_session_key(32)
    encrypted = aesgcm_encrypt(aes_key, b"VALID_DATA", b"test")

    tampered_ct = base64.b64encode(os.urandom(32)).decode()

    forged_payload = {
        "encrypted_key": base64.b64encode(os.urandom(16)).decode(),
        "nonce": encrypted["nonce"],
        "ciphertext": tampered_ct,
        "signature": "INVALID_SIG"
    }

    return json.dumps(forged_payload)


# -------------------------------------------------------------------
# 5. INVALID RSA ENCRYPTED SESSION KEY
# -------------------------------------------------------------------
def bad_session_key():
    logger.warning("ATTACK: Invalid RSA-encrypted session key")

    random_ct = base64.b64encode(os.urandom(64)).decode()

    return json.dumps({
        "encrypted_key": random_ct,
        "nonce": "xyz",
        "ciphertext": "AAAA",
        "signature": "BAD_SIG"
    })


# -------------------------------------------------------------------
# 6. SIGNATURE FORGERY ATTEMPT
# -------------------------------------------------------------------
def forged_signature():
    logger.warning("ATTACK: Signature forgery attempt")

    return json.dumps({
        "type": "cmd",
        "timestamp": int(time.time()),
        "value": "UNLOCK",
        "nonce": "fake123",
        "signature": base64.b64encode(os.urandom(64)).decode()
    })


# -------------------------------------------------------------------
# 7. RANDOM GARBAGE PAYLOAD
# -------------------------------------------------------------------
def random_garbage():
    logger.warning("ATTACK: Sending random garbage bytes")

    garbage = base64.b64encode(os.urandom(128)).decode()

    return json.dumps({
        "ciphertext": garbage,
        "nonce": "garbage123",
        "encrypted_key": garbage,
        "signature": "NONE"
    })


# -------------------------------------------------------------------
# RUN ALL ATTACKS IN SEQUENCE
# -------------------------------------------------------------------
def run_attacker():
    logger.info("SECURE ATTACKER STARTED")

    client = connect_client(
        client_id="attacker_secure",
        host=BROKER_HOST,
        port=BROKER_PORT
    )

    time.sleep(1)

    attacks = [
        fake_payload,
        replay_attack,
        future_timestamp_attack,
        tamper_ciphertext,
        bad_session_key,
        forged_signature,
        random_garbage
    ]

    for attack_fn in attacks:
        msg = attack_fn()
        publish_message(client, BROKER_TOPIC, msg)
        time.sleep(2)

    logger.info("ATTACKER FINISHED")


if __name__ == "__main__":
    run_attacker()
