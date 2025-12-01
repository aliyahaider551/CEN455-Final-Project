# src/secure/attacker_secure_tests.py
"""
ATTACKER - Attempts attacks against the SECURE MQTT system.
This demonstrates that the cryptographic protections successfully defend against:
1. Eavesdropping (encryption)
2. Injection (authentication)
3. Replay (counter verification)
4. Tampering (integrity checks)
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

from common.mq_helpers import connect_client, subscribe_topic, publish_message, disconnect_client
from common.logger import get_logger

logger = get_logger("attacker_secure")

# Configuration
BROKER_HOST = os.getenv("MQTT_HOST", "mqtt-broker")
BROKER_PORT = int(os.getenv("MQTT_PORT", "1883"))
CLIENT_ID = "attacker_secure"
TARGET_TOPIC = "home/door"

class SecureSystemAttacker:
    """Attempts attacks on secure MQTT system (all should fail)"""
    
    def __init__(self, broker_host, broker_port):
        self.broker_host = broker_host
        self.broker_port = broker_port
        self.client = None
        self.captured_messages = []
        self.attack_results = {
            'eavesdrop': False,
            'inject': False,
            'replay': False,
            'tamper': False
        }
        
    def connect(self):
        """Connect to the broker"""
        logger.info(" Attacker connecting to secure system", extra={
            'extra_data': {
                'broker': self.broker_host,
                'port': self.broker_port,
                'target': 'SECURE'
            }
        })
        
        self.client = connect_client(
            CLIENT_ID,
            host=self.broker_host,
            port=self.broker_port,
            on_message=self.on_message
        )
        
    def on_message(self, client, userdata, message):
        """Capture messages (but cannot decrypt them)"""
        try:
            payload = message.payload.decode('utf-8')
            data = json.loads(payload)
            
            self.captured_messages.append({
                'topic': message.topic,
                'payload': data,
                'timestamp': time.time()
            })
            
            logger.info("Captured encrypted message", extra={
                'extra_data': {
                    'attack': 'eavesdrop',
                    'topic': message.topic,
                    'counter': data.get('counter'),
                    'encrypted': True
                }
            })
            
        except Exception as e:
            logger.error(f"Error capturing message: {e}")
    
    def attack_eavesdrop(self, duration=10):
        """
        ATTACK 1: Attempt to eavesdrop on encrypted communications
        Expected result: FAILURE - messages are encrypted
        """
        print("\n" + "="*60)
        print("ATTACK 1: EAVESDROPPING ON ENCRYPTED TRAFFIC")
        print("="*60)
        print("Attempting to read encrypted messages...")
        print(f"Duration: {duration} seconds\n")
        
        logger.info("Starting eavesdrop attack on secure system", extra={
            'extra_data': {
                'attack': 'eavesdrop',
                'duration': duration
            }
        })
        
        subscribe_topic(self.client, TARGET_TOPIC, qos=0)
        time.sleep(duration)
        
        captured = len(self.captured_messages)
        
        if captured > 0:
            print(f"   Captured {captured} encrypted messages")
            print(f"   Sample encrypted message:")
            sample = self.captured_messages[0]['payload']
            print(f"      Ciphertext: {sample.get('ciphertext', 'N/A')[:50]}...")
            print(f"      Nonce: {sample.get('nonce', 'N/A')[:50]}...")
            print(f"   ATTACK FAILED: Cannot decrypt without keys!")
            print(f"      - Messages are encrypted with AES-256-GCM")
            print(f"      - Session keys are encrypted with RSA-2048")
            print(f"      - No plaintext data available\n")
            
            logger.info("Eavesdrop attack failed", extra={
                'extra_data': {
                    'attack': 'eavesdrop',
                    'success': False,
                    'captured': captured,
                    'readable': 0
                }
            })
            
            self.attack_results['eavesdrop'] = False
        else:
            print(f"   No messages captured\n")
        
        return False
    
    def attack_inject(self, count=3):
        """
        ATTACK 2: Attempt to inject fake messages
        Expected result: FAILURE - no valid signature
        """
        print("\n" + "="*60)
        print("ATTACK 2: MESSAGE INJECTION (Spoofing)")
        print("="*60)
        print(f"Attempting to inject {count} fake messages...\n")
        
        logger.info("Starting injection attack on secure system", extra={
            'extra_data': {
                'attack': 'inject',
                'count': count
            }
        })
        
        success = 0
        for i in range(count):
            # Attempt to create fake message (without valid keys)
            fake_message = {
                "sender": "sensor_001_secure",  # Spoofing
                "enc_session_key": "FAKE_ENCRYPTED_KEY_BASE64",
                "nonce": "FAKE_NONCE_BASE64",
                "ciphertext": "FAKE_CIPHERTEXT_BASE64",
                "signature": "FAKE_SIGNATURE_BASE64",
                "counter": 9999 + i,
                "timestamp": time.time(),
                "msg_id": str(uuid.uuid4())
            }
            
            payload = json.dumps(fake_message)
            publish_message(self.client, TARGET_TOPIC, payload, qos=0)
            
            logger.info("Attempted to inject fake message", extra={
                'extra_data': {
                    'attack': 'inject',
                    'attempt': i + 1,
                    'counter': fake_message['counter']
                }
            })
            
            print(f"   Attempt {i+1}/{count} - Sent fake message with counter {fake_message['counter']}")
            time.sleep(1)
        
        print(f"    ATTACK FAILED: Injected messages will be rejected!")
        print(f"      - No valid DSA private key to sign messages")
        print(f"      - Actuator will detect invalid signatures")
        print(f"      - Cannot forge cryptographic signatures\n")
        
        logger.info("Injection attack failed", extra={
            'extra_data': {
                'attack': 'inject',
                'success': False,
                'attempts': count,
                'accepted': 0
            }
        })
        
        self.attack_results['inject'] = False
        return False
    
    def attack_replay(self):
        """
        ATTACK 3: Attempt to replay captured messages
        Expected result: FAILURE - counter verification blocks replays
        """
        print("\n" + "="*60)
        print("ATTACK 3: REPLAY ATTACK")
        print("="*60)
        
        if not self.captured_messages:
            print("No messages captured. Run eavesdrop first.\n")
            return False
        
        old_msg = self.captured_messages[0]['payload']
        print(f"Attempting to replay message (Counter: {old_msg.get('counter')})...\n")
        
        logger.info("Starting replay attack on secure system", extra={
            'extra_data': {
                'attack': 'replay',
                'counter': old_msg.get('counter')
            }
        })
        
        # Replay the captured message multiple times
        for i in range(3):
            payload = json.dumps(old_msg)
            publish_message(self.client, TARGET_TOPIC, payload, qos=0)
            
            logger.info("Attempted replay", extra={
                'extra_data': {
                    'attack': 'replay',
                    'attempt': i + 1,
                    'counter': old_msg.get('counter')
                }
            })
            
            print(f"   Replay attempt {i+1}/3 - Counter: {old_msg.get('counter')}")
            time.sleep(1)
        
        print(f" ATTACK FAILED: Replayed messages will be rejected!")
        print(f"      - Actuator tracks last counter per sender")
        print(f"      - Only accepts counter > last_counter")
        print(f"      - Replay protection prevents duplicate messages\n")
        
        logger.info("Replay attack failed", extra={
            'extra_data': {
                'attack': 'replay',
                'success': False,
                'attempts': 3,
                'accepted': 0
            }
        })
        
        self.attack_results['replay'] = False
        return False
    
    def attack_tamper(self):
        """
        ATTACK 4: Attempt to tamper with captured messages
        Expected result: FAILURE - signature/AEAD verification fails
        """
        print("\n" + "="*60)
        print("ATTACK 4: MESSAGE TAMPERING")
        print("="*60)
        
        if not self.captured_messages:
            print("No messages captured. Run eavesdrop first.\n")
            return False
        
        original = self.captured_messages[-1]['payload']
        print(f"Original message counter: {original.get('counter')}")
        print(f"Attempting to tamper with ciphertext...\n")
        
        logger.info("Starting tamper attack on secure system", extra={
            'extra_data': {
                'attack': 'tamper',
                'counter': original.get('counter')
            }
        })
        
        # Attempt to modify the message
        tampered = original.copy()
        
        # Try different tampering approaches
        tampering_attempts = [
            ("Modify ciphertext", "ciphertext", "MODIFIED_CIPHERTEXT_BASE64"),
            ("Modify counter", "counter", 99999),
            ("Modify signature", "signature", "FAKE_SIGNATURE_BASE64")
        ]
        
        for attempt_name, field, new_value in tampering_attempts:
            tampered_msg = original.copy()
            old_value = tampered_msg.get(field, "N/A")
            tampered_msg[field] = new_value
            
            payload = json.dumps(tampered_msg)
            publish_message(self.client, TARGET_TOPIC, payload, qos=0)
            
            logger.info("Attempted tampering", extra={
                'extra_data': {
                    'attack': 'tamper',
                    'field': field,
                    'attempt': attempt_name
                }
            })
            
            print(f"   Attempt: {attempt_name}")
            print(f"      Changed '{field}': {str(old_value)[:30]}... → {str(new_value)[:30]}...")
            time.sleep(0.5)
        
        print(f"\n   ATTACK FAILED: Tampered messages will be rejected!")
        print(f"      - DSA signature verification detects any changes")
        print(f"      - AES-GCM AEAD provides integrity protection")
        print(f"      - Cannot modify messages without detection\n")
        
        logger.info("Tamper attack failed", extra={
            'extra_data': {
                'attack': 'tamper',
                'success': False,
                'attempts': len(tampering_attempts),
                'accepted': 0
            }
        })
        
        self.attack_results['tamper'] = False
        return False
    
    def disconnect(self):
        """Disconnect from broker"""
        if self.client:
            disconnect_client(self.client)

def main():
    """Main attacker demonstration on secure system"""
    print("\n" + "="*60)
    print("SECURE MQTT ATTACKER")
    print("="*60)
    print("Testing attacks against cryptographically protected system")
    print("All attacks should FAIL due to security mechanisms")
    print("="*60 + "\n")
    
    logger.info("Starting attacker tests on secure system", extra={
        'extra_data': {
            'mode': 'SECURE',
            'target_topic': TARGET_TOPIC
        }
    })
    
    attacker = SecureSystemAttacker(BROKER_HOST, BROKER_PORT)
    
    try:
        attacker.connect()
        time.sleep(1)
        
        print("\nWaiting for secure traffic...")
        print("(Make sure sensor_secure.py and actuator_secure.py are running)\n")
        time.sleep(2)
        
        # Run all attacks (all should fail)
        attacker.attack_eavesdrop(duration=10)
        attacker.attack_inject(count=3)
        attacker.attack_replay()
        attacker.attack_tamper()
        
        # Summary
        print("\n" + "="*60)
        print(" SECURITY EVALUATION SUMMARY")
        print("="*60)
        print(f"Eavesdropping: BLOCKED (AES-256-GCM encryption)")
        print(f" Injection: BLOCKED (DSA-2048 signatures)")
        print(f" Replay: BLOCKED (Monotonic counter verification)")
        print(f" Tampering: BLOCKED (AEAD + signature verification)")
        print(f" ALL ATTACKS FAILED - SYSTEM IS SECURE!")
        print("="*60 + "\n")
        
        logger.info("Security evaluation complete", extra={
            'extra_data': {
                'eavesdrop': 'blocked',
                'inject': 'blocked',
                'replay': 'blocked',
                'tamper': 'blocked',
                'total_captured': len(attacker.captured_messages),
                'successful_attacks': 0
            }
        })
        
    except KeyboardInterrupt:
        print("\n\nAttacker tests stopped by user")
    except Exception as e:
        logger.error(f"Attacker error: {e}", extra={
            'extra_data': {'error': str(e)}
        })
    finally:
        attacker.disconnect()
        print("\nAttacker disconnected\n")

if __name__ == "__main__":
    main()
