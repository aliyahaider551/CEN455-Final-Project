# src/secure/sensor_secure.py
"""
SECURE Sensor - Publishes encrypted and signed messages to MQTT broker.
Uses AES-GCM for encryption, RSA for key exchange, and DSA for signatures.
Includes replay protection with monotonic counters.
"""
import sys
import os
import json
import time
import uuid
from datetime import datetime
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from common.mq_helpers import connect_client, publish_message, disconnect_client
from common.logger import get_logger
from common.crypto_utils import (
    generate_session_key, aesgcm_encrypt, rsa_encrypt_for_public,
    dsa_sign, load_rsa_public, load_dsa_private
)

logger = get_logger("sensor_secure")

# Configuration
BROKER_HOST = os.getenv("MQTT_HOST", "mqtt-broker")
BROKER_PORT = int(os.getenv("MQTT_PORT", "1883"))
CLIENT_ID = "sensor_secure"
TOPIC = "home/secure/door"
PUBLISH_INTERVAL = 2  # seconds
SENSOR_ID = "sensor_001_secure"

# Key paths
KEYS_DIR = Path(__file__).parent.parent / "utils" / "keys"
ACTUATOR_RSA_PUB = KEYS_DIR / "actuator_rsa_pub.pem"
SENSOR_DSA_PRIV = KEYS_DIR / "sensor_dsa_priv.pem"

class SecureSensor:
    """Secure sensor with cryptographic protections"""
    
    def __init__(self):
        self.sensor_id = SENSOR_ID
        self.counter = 0
        self.actuator_rsa_pub = None
        self.sensor_dsa_priv = None
        self.client = None
        
    def load_keys(self):
        """Load cryptographic keys"""
        try:
            # Load actuator's RSA public key (for encrypting session keys)
            with open(ACTUATOR_RSA_PUB, "rb") as f:
                self.actuator_rsa_pub = load_rsa_public(f.read())
            
            # Load sensor's DSA private key (for signing messages)
            with open(SENSOR_DSA_PRIV, "rb") as f:
                self.sensor_dsa_priv = load_dsa_private(f.read())
            
            logger.info("Keys loaded successfully", extra={
                'extra_data': {
                    'actuator_rsa_pub': str(ACTUATOR_RSA_PUB),
                    'sensor_dsa_priv': str(SENSOR_DSA_PRIV)
                }
            })
            
        except FileNotFoundError as e:
            logger.error(f"Key file not found: {e}", extra={
                'extra_data': {'error': str(e)}
            })
            print(f"ERROR: Key files not found!")
            print(f"   Please run: python src/utils/generate_keys.py")
            print(f"   Expected keys in: {KEYS_DIR}\n")
            raise
    
    def generate_sensor_data(self):
        """Generate sample sensor data"""
        return {
            "sensor_id": self.sensor_id,
            "event": "door_open",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "temperature": 22.5,
            "status": "active"
        }
    
    def create_secure_message(self, data):
        """
        Create a secure message with encryption, authentication, and replay protection.
        
        Protocol:
        1. Generate fresh AES session key
        2. Encrypt payload with AES-GCM
        3. Encrypt session key with actuator's RSA public key
        4. Sign the entire message with sensor's DSA private key
        5. Include monotonic counter for replay protection
        """
        self.counter += 1
        msg_id = str(uuid.uuid4())
        
        # Step 1: Generate fresh session key for this message
        session_key = generate_session_key(32)  # AES-256
        
        # Step 2: Prepare payload
        payload_data = data.copy()
        payload_data['counter'] = self.counter
        payload_data['msg_id'] = msg_id
        payload_json = json.dumps(payload_data).encode('utf-8')
        
        # Step 3: Encrypt payload with AES-GCM
        # Use associated data to bind context (topic + sender)
        associated_data = f"{TOPIC}|{self.sensor_id}".encode('utf-8')
        encrypted = aesgcm_encrypt(session_key, payload_json, associated_data)
        
        # Step 4: Encrypt session key with actuator's RSA public key
        enc_session_key = rsa_encrypt_for_public(self.actuator_rsa_pub, session_key)
        
        # Step 5: Create message structure
        message = {
            "sender": self.sensor_id,
            "enc_session_key": enc_session_key,
            "nonce": encrypted['nonce'],
            "ciphertext": encrypted['ciphertext'],
            "counter": self.counter,
            "timestamp": time.time(),
            "msg_id": msg_id
        }
        
        # Step 6: Sign the message (sign nonce + ciphertext + counter)
        # This ensures integrity and authenticity
        sign_data = (
            message['nonce'] + 
            message['ciphertext'] + 
            str(message['counter']) + 
            self.sensor_id
        ).encode('utf-8')
        
        signature = dsa_sign(self.sensor_dsa_priv, sign_data)
        message['signature'] = signature
        
        return message, len(payload_json)
    
    def connect(self):
        """Connect to MQTT broker"""
        self.client = connect_client(CLIENT_ID, host=BROKER_HOST, port=BROKER_PORT)
    
    def run(self):
        """Main sensor loop"""
        logger.info("Starting secure sensor", extra={
            'extra_data': {
                'broker': BROKER_HOST,
                'port': BROKER_PORT,
                'topic': TOPIC,
                'mode': 'SECURE',
                'sensor_id': self.sensor_id
            }
        })
        
        try:
            while True:
                # Generate sensor data
                data = self.generate_sensor_data()
                
                # Create secure message
                start_time = time.time()
                secure_msg, plaintext_size = self.create_secure_message(data)
                crypto_time = (time.time() - start_time) * 1000  # ms
                
                # Publish secure message
                payload = json.dumps(secure_msg)
                publish_message(self.client, TOPIC, payload, qos=0)
                
                logger.info("Published secure message", extra={
                    'extra_data': {
                        'topic': TOPIC,
                        'counter': self.counter,
                        'msg_id': secure_msg['msg_id'],
                        'plaintext_size': plaintext_size,
                        'encrypted_size': len(payload),
                        'crypto_time_ms': round(crypto_time, 2),
                        'event': data['event']
                    }
                })
                
                if self.counter == 1:
                    print(f"SECURE MODE ACTIVE")
                    print(f"   Encryption: AES-256-GCM")
                    print(f"   Key Exchange: RSA-2048")
                    print(f"   Signatures: DSA-2048")
                    print(f"   Replay Protection: Monotonic Counter")
                    print(f"   Integrity: AEAD + Digital Signature\n")
                
                time.sleep(PUBLISH_INTERVAL)
                
        except KeyboardInterrupt:
            logger.info("Sensor stopped by user", extra={
                'extra_data': {'total_messages': self.counter}
            })

def main():
    """Main entry point"""
    sensor = SecureSensor()
    
    try:
        # Load cryptographic keys
        sensor.load_keys()
        
        # Connect to broker
        sensor.connect()
        
        # Run sensor loop
        sensor.run()
        
    except Exception as e:
        logger.error(f"Sensor error: {e}", extra={
            'extra_data': {'error': str(e)}
        })
        raise
    finally:
        if sensor.client:
            disconnect_client(sensor.client)
        logger.info("Sensor shutdown complete")

if __name__ == "__main__":
    main()
