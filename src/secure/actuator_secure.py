# src/secure/actuator_secure.py
"""
SECURE Actuator - Receives encrypted and signed MQTT messages.
Verifies signatures, decrypts content, and enforces replay protection.
"""
import sys
import os
import json
import time
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from common.mq_helpers import connect_client, subscribe_topic, disconnect_client, wait_for_messages
from common.logger import get_logger
from common.crypto_utils import (
    aesgcm_decrypt, rsa_decrypt_with_private, dsa_verify,
    load_rsa_private, load_dsa_public
)

logger = get_logger("actuator_secure")

# Configuration
BROKER_HOST = os.getenv("MQTT_HOST", "mqtt-broker")
BROKER_PORT = int(os.getenv("MQTT_PORT", "1883"))
CLIENT_ID = "actuator_secure"
TOPIC = "home/secure/door"


# Key paths
KEYS_DIR = Path(__file__).parent.parent / "utils" / "keys"
ACTUATOR_RSA_PRIV = KEYS_DIR / "actuator_rsa_priv.pem"
SENSOR_DSA_PUB = KEYS_DIR / "sensor_dsa_pub.pem"

# State file for replay protection
STATE_FILE = Path(__file__).parent.parent.parent / "logs" / "actuator_state.json"

class SecureActuator:
    """Secure actuator with cryptographic verification and replay protection"""
    
    def __init__(self):
        self.actuator_rsa_priv = None
        self.sensor_dsa_pub = None
        self.client = None
        self.last_counters = {}  # Track last counter per sender for replay protection
        self.messages_received = 0
        self.messages_accepted = 0
        self.messages_rejected = 0
        
    def load_keys(self):
        """Load cryptographic keys"""
        try:
            # Load actuator's RSA private key (for decrypting session keys)
            with open(ACTUATOR_RSA_PRIV, "rb") as f:
                self.actuator_rsa_priv = load_rsa_private(f.read())
            
            # Load sensor's DSA public key (for verifying signatures)
            with open(SENSOR_DSA_PUB, "rb") as f:
                self.sensor_dsa_pub = load_dsa_public(f.read())
            
            logger.info("Keys loaded successfully", extra={
                'extra_data': {
                    'actuator_rsa_priv': str(ACTUATOR_RSA_PRIV),
                    'sensor_dsa_pub': str(SENSOR_DSA_PUB)
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
    
    def load_state(self):
        """Load last counter values from disk for replay protection"""
        try:
            if STATE_FILE.exists():
                with open(STATE_FILE, 'r') as f:
                    self.last_counters = json.load(f)
                logger.info("Loaded replay protection state", extra={
                    'extra_data': {'counters': self.last_counters}
                })
        except Exception as e:
            logger.warning(f"Could not load state: {e}")
            self.last_counters = {}
    
    def save_state(self):
        """Save last counter values to disk"""
        try:
            STATE_FILE.parent.mkdir(exist_ok=True)
            with open(STATE_FILE, 'w') as f:
                json.dump(self.last_counters, f, indent=2)
        except Exception as e:
            logger.error(f"Could not save state: {e}")
    
    def check_replay(self, sender, counter):
        """
        Check if message is a replay attack.
        Returns True if message is valid (not a replay), False if replay detected.
        """
        last_counter = self.last_counters.get(sender, 0)
        
        if counter <= last_counter:
            logger.warning("REPLAY DETECTED", extra={
                'extra_data': {
                    'attack': 'replay',
                    'sender': sender,
                    'counter': counter,
                    'last_counter': last_counter,
                    'rejected': True
                }
            })
            return False
        
        # Update last counter
        self.last_counters[sender] = counter
        self.save_state()
        return True
    
    def verify_message(self, message):
        """
        Verify message authenticity and integrity.
        Returns decrypted payload if valid, None otherwise.
        """
        try:
            sender = message['sender']
            counter = message['counter']
            msg_id = message.get('msg_id', 'unknown')
            
            # Step 1: Verify signature FIRST (before any decryption)
            # This prevents chosen-ciphertext attacks
            sign_data = (
                message['nonce'] + 
                message['ciphertext'] + 
                str(counter) + 
                sender
            ).encode('utf-8')
            
            if not dsa_verify(self.sensor_dsa_pub, sign_data, message['signature']):
                logger.warning("SIGNATURE VERIFICATION FAILED", extra={
                    'extra_data': {
                        'attack': 'tamper',
                        'sender': sender,
                        'counter': counter,
                        'msg_id': msg_id,
                        'rejected': True
                    }
                })
                print(f"   Signature verification failed - message tampered!")
                return None
            
            # Step 2: Check replay protection
            if not self.check_replay(sender, counter):
                print(f"    Replay attack detected - counter: {counter} <= last: {self.last_counters[sender]-1}")
                return None
            
            # Step 3: Decrypt session key with RSA private key
            session_key = rsa_decrypt_with_private(
                self.actuator_rsa_priv, 
                message['enc_session_key']
            )
            
            # Step 4: Decrypt payload with AES-GCM
            associated_data = f"{TOPIC}|{sender}".encode('utf-8')
            plaintext = aesgcm_decrypt(
                session_key,
                message['nonce'],
                message['ciphertext'],
                associated_data
            )
            
            # Step 5: Parse decrypted payload
            payload = json.loads(plaintext.decode('utf-8'))
            
            logger.info("Message verified and decrypted", extra={
                'extra_data': {
                    'sender': sender,
                    'counter': counter,
                    'msg_id': msg_id,
                    'event': payload.get('event'),
                    'signature_valid': True,
                    'replay_check': 'passed'
                }
            })
            
            return payload
            
        except Exception as e:
            logger.error(f"Message verification failed: {e}", extra={
                'extra_data': {
                    'error': str(e),
                    'sender': message.get('sender'),
                    'counter': message.get('counter')
                }
            })
            print(f"    Verification error: {str(e)}")
            return None
    
    def perform_action(self, payload):
        """Execute action based on verified message"""
        event = payload.get('event', 'unknown')
        sensor_id = payload.get('sensor_id', 'unknown')
        counter = payload.get('counter')
        
        logger.info(f" PERFORMING SECURE ACTION: {event}", extra={
            'extra_data': {
                'action': 'execute',
                'event': event,
                'sensor_id': sensor_id,
                'counter': counter,
                'verified': True
            }
        })
        
        print(f"SECURE ACTION EXECUTED:")
        print(f"   Event: {event}")
        print(f"   Sensor: {sensor_id}")
        print(f"   Counter: {counter}")
        print(f"   Status: Verified & Authenticated")
        
        # Simulate action
        if event == "door_open":
            print(f"   → Door unlocked (verified from {sensor_id})")
        elif event == "door_close":
            print(f"   → Door locked (verified from {sensor_id})")
    
    def on_message(self, client, userdata, message):
        """Callback for incoming MQTT messages"""
        self.messages_received += 1
        start_time = time.time()
        
        try:
            # Parse message
            payload = message.payload.decode('utf-8')
            secure_msg = json.loads(payload)
            
            logger.info("Received secure message", extra={
                'extra_data': {
                    'topic': message.topic,
                    'sender': secure_msg.get('sender'),
                    'counter': secure_msg.get('counter'),
                    'msg_id': secure_msg.get('msg_id')
                }
            })
            
            # Verify and decrypt
            decrypted_payload = self.verify_message(secure_msg)
            
            verify_time = (time.time() - start_time) * 1000  # ms
            
            if decrypted_payload:
                # Message is valid - perform action
                self.perform_action(decrypted_payload)
                self.messages_accepted += 1
                
                logger.info("Message accepted", extra={
                    'extra_data': {
                        'verify_time_ms': round(verify_time, 2),
                        'accepted': True
                    }
                })
            else:
                # Message rejected (replay, tamper, or invalid signature)
                self.messages_rejected += 1
                print(f"MESSAGE REJECTED")
                print(f"   Sender: {secure_msg.get('sender')}")
                print(f"   Counter: {secure_msg.get('counter')}")
                print(f"   Reason: Failed security checks")
                
                logger.info("Message rejected", extra={
                    'extra_data': {
                        'verify_time_ms': round(verify_time, 2),
                        'rejected': True
                    }
                })
            
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON: {e}")
            self.messages_rejected += 1
        except Exception as e:
            logger.error(f"Error processing message: {e}", extra={
                'extra_data': {'error': str(e)}
            })
            self.messages_rejected += 1
    
    def connect(self):
        """Connect to MQTT broker"""
        self.client = connect_client(
            CLIENT_ID,
            host=BROKER_HOST,
            port=BROKER_PORT,
            on_message=self.on_message
        )
    
    def run(self):
        """Main actuator loop"""
        logger.info("Starting secure actuator", extra={
            'extra_data': {
                'broker': BROKER_HOST,
                'port': BROKER_PORT,
                'topic': TOPIC,
                'mode': 'SECURE'
            }
        })
        
        # Subscribe to topic
        subscribe_topic(self.client, TOPIC, qos=0)
        
        print(f"SECURE ACTUATOR ACTIVE")
        print(f"   Listening on: {TOPIC}")
        print(f"   Protections enabled:")
        print(f"      - Signature verification (DSA)")
        print(f"      - Encryption (AES-256-GCM)")
        print(f"      - Replay protection (counters)")
        print(f"      - Integrity protection (AEAD)")
        print(f"\n   Waiting for secure messages...\n")
        
        # Wait for messages
        try:
            wait_for_messages()
        except KeyboardInterrupt:
            print(f" ACTUATOR STATISTICS:")
            print(f"   Total received: {self.messages_received}")
            print(f"   Accepted: {self.messages_accepted}")
            print(f"   Rejected: {self.messages_rejected}")
            
            logger.info("Actuator stopped by user", extra={
                'extra_data': {
                    'total_received': self.messages_received,
                    'accepted': self.messages_accepted,
                    'rejected': self.messages_rejected
                }
            })

def main():
    """Main entry point"""
    actuator = SecureActuator()
    
    try:
        # Load keys
        actuator.load_keys()
        
        # Load replay protection state
        actuator.load_state()
        
        # Connect to broker
        actuator.connect()
        
        # Run actuator loop
        actuator.run()
        
    except Exception as e:
        logger.error(f"Actuator error: {e}", extra={
            'extra_data': {'error': str(e)}
        })
        raise
    finally:
        if actuator.client:
            disconnect_client(actuator.client)
        actuator.save_state()
        logger.info("Actuator shutdown complete")

if __name__ == "__main__":
    main()
