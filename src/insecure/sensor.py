# src/insecure/sensor_insecure.py
"""
INSECURE Sensor - Publishes plaintext messages to MQTT broker.
This demonstrates the vulnerabilities when no encryption or authentication is used.
"""
import sys
import os
import time
import json
import uuid
from datetime import datetime

# Add parent directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from common.mq_helpers import connect_client, publish_message, disconnect_client
from common.logger import get_logger

logger = get_logger("sensor_insecure")

# ============================================================
# FIX: Change default broker host FROM "localhost" TO "mqtt-broker"
# ============================================================
BROKER_HOST = os.getenv("MQTT_BROKER", "mqtt-broker")
BROKER_PORT = int(os.getenv("MQTT_PORT", "1883"))

CLIENT_ID = "sensor_insecure"
TOPIC = "home/door"
PUBLISH_INTERVAL = 2  # seconds


def generate_sensor_data(counter):
    """Generate sample sensor data"""
    return {
        "sensor_id": "sensor_001",
        "event": "door_open",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "counter": counter,
        "temperature": 22.5,  # dummy data
        "status": "active"
    }


def main():
    """Main sensor loop"""
    logger.info("Starting insecure sensor", extra={
        'extra_data': {
            'broker': BROKER_HOST,
            'port': BROKER_PORT,
            'topic': TOPIC,
            'mode': 'INSECURE'
        }
    })

    # Connect to broker
    try:
        client = connect_client(CLIENT_ID, host=BROKER_HOST, port=BROKER_PORT)
    except Exception as e:
        logger.error(f"Failed to connect to broker: {e}", extra={
            'extra_data': {'error': str(e)}
        })
        return

    counter = 0

    try:
        while True:
            counter += 1

            # Generate sensor data
            data = generate_sensor_data(counter)
            msg_id = str(uuid.uuid4())
            data['msg_id'] = msg_id

            # Convert to JSON (plaintext, no encryption)
            payload = json.dumps(data)

            # Publish to broker
            publish_message(client, TOPIC, payload, qos=0)

            logger.info("Published plaintext message", extra={
                'extra_data': {
                    'topic': TOPIC,
                    'counter': counter,
                    'msg_id': msg_id,
                    'payload_size': len(payload),
                    'event': data['event']
                }
            })

            # First message warning
            if counter == 1:
                logger.warning("INSECURE MODE: Messages are sent in plaintext!", extra={
                    'extra_data': {'security_level': 'NONE'}
                })

            time.sleep(PUBLISH_INTERVAL)

    except KeyboardInterrupt:
        logger.info("Sensor stopped by user", extra={
            'extra_data': {'total_messages': counter}
        })
    except Exception as e:
        logger.error(f"Sensor error: {e}", extra={
            'extra_data': {'error': str(e), 'counter': counter}
        })
    finally:
        disconnect_client(client)
        logger.info("Sensor shutdown complete")


if __name__ == "__main__":
    main()
