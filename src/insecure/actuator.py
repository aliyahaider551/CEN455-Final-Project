"""
INSECURE Actuator - Subscribes to plaintext MQTT messages and acts on them.
This version FIXES container exiting AND fixes broker connection errors.
"""

import sys
import os
import json
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from common.mq_helpers import connect_client, subscribe_topic
from common.logger import get_logger

logger = get_logger("actuator_insecure")

#  IMPORTANT: connect to Docker broker container
BROKER_HOST = "mqtt-broker"
BROKER_PORT = 1883

CLIENT_ID = "actuator_insecure"
TOPIC = "home/door"

def perform_action(event_data):
    event = event_data.get("event", "unknown")
    print(f"→ ACTUATOR ACTION: {event}")
    logger.info("Actuator performed action", extra={"extra_data": event_data})

def on_message(client, userdata, message):
    payload = message.payload.decode()

    logger.info("Received message", extra={"extra_data": {"payload": payload}})

    try:
        data = json.loads(payload)
        perform_action(data)
    except Exception as e:
        logger.error(f"Error parsing message: {e}")

def main():
    logger.info("Starting insecure actuator", extra={"extra_data": {"broker": BROKER_HOST}})

    # Connect to broker
    client = connect_client(
        CLIENT_ID,
        host=BROKER_HOST,
        port=BROKER_PORT,
        on_message=on_message
    )

    # Subscribe
    subscribe_topic(client, TOPIC)
    logger.info("Subscribed to insecure topic", extra={"extra_data": {"topic": TOPIC}})

    print("Insecure actuator running (plaintext, no verification)...")

    # KEEP CONTAINER ALIVE
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Actuator stopped")

if __name__ == "__main__":
    main()
