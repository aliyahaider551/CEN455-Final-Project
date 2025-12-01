# src/utils/generate_keys.py
"""
Generate cryptographic keys for the secure MQTT system.
Creates RSA and DSA key pairs for both sensor and actuator.
"""
import os
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from common.crypto_utils import (
    generate_rsa_keypair, generate_dsa_keypair,
    save_keys_to_files
)

KEYS_DIR = Path(__file__).parent / "keys"

def main():
    """Generate all required keys"""
    print("\n" + "="*60)
    print("🔐 CRYPTOGRAPHIC KEY GENERATION")
    print("="*60)
    print(f"Generating keys in: {KEYS_DIR}\n")
    
    # Create keys directory
    KEYS_DIR.mkdir(exist_ok=True)
    
    # Generate sensor keys
    print("1. Generating sensor keys...")
    sensor_rsa_priv, sensor_rsa_pub = generate_rsa_keypair(2048)
    sensor_dsa_priv, sensor_dsa_pub = generate_dsa_keypair()
    save_keys_to_files("sensor", sensor_rsa_priv, sensor_rsa_pub, 
                       sensor_dsa_priv, sensor_dsa_pub, str(KEYS_DIR))
    print("   ✅ Sensor RSA keys (2048-bit)")
    print("   ✅ Sensor DSA keys (2048-bit)")
    
    # Generate actuator keys
    print("\n2. Generating actuator keys...")
    actuator_rsa_priv, actuator_rsa_pub = generate_rsa_keypair(2048)
    actuator_dsa_priv, actuator_dsa_pub = generate_dsa_keypair()
    save_keys_to_files("actuator", actuator_rsa_priv, actuator_rsa_pub,
                       actuator_dsa_priv, actuator_dsa_pub, str(KEYS_DIR))
    print("   ✅ Actuator RSA keys (2048-bit)")
    print("   ✅ Actuator DSA keys (2048-bit)")
    
    print("\n" + "="*60)
    print("✅ KEY GENERATION COMPLETE")
    print("="*60)
    print("\nGenerated files:")
    for key_file in sorted(KEYS_DIR.glob("*.pem")):
        size = key_file.stat().st_size
        print(f"   - {key_file.name} ({size} bytes)")
    
    print("\n⚠️  SECURITY NOTES:")
    print("   - Keep private keys (*_priv.pem) SECRET")
    print("   - Add keys/ to .gitignore")
    print("   - In production, use secure key management (HSM, vault)")
    print("   - These keys are for demonstration only")
    print("\n" + "="*60 + "\n")

if __name__ == "__main__":
    main()
