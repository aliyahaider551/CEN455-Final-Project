# src/insecure/timing_attack_demo.py
"""
Timing Attack Demonstration - Shows how timing differences can leak information.
This demonstrates why constant-time operations are necessary.
"""
import time
import random
import statistics
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from common.logger import get_logger

logger = get_logger("timing_attack_demo")


def vulnerable_compare(secret: bytes, guess: bytes) -> bool:
    """
    VULNERABLE: Early-exit comparison leaks timing information.
    This is the type of comparison that enables timing attacks.
    """
    if len(secret) != len(guess):
        return False
    
    for i in range(len(secret)):
        if secret[i] != guess[i]:
            return False  # Early exit - timing leak!
    return True


def secure_compare(secret: bytes, guess: bytes) -> bool:
    """
    SECURE: Constant-time comparison prevents timing attacks.
    Always checks all bytes regardless of differences.
    """
    if len(secret) != len(guess):
        return False
    
    result = 0
    for i in range(len(secret)):
        result |= secret[i] ^ guess[i]
    return result == 0


def measure_timing(compare_func, secret: bytes, guess: bytes, iterations: int = 1000) -> float:
    """Measure average execution time of comparison function"""
    times = []
    for _ in range(iterations):
        start = time.perf_counter()
        compare_func(secret, guess)
        end = time.perf_counter()
        times.append((end - start) * 1_000_000)  # Convert to microseconds
    return statistics.mean(times)


def demonstrate_timing_attack():
    """
    Demonstrate how timing attacks work on vulnerable implementations.
    Shows that incorrect guesses at different positions take different times.
    """
    print("\n" + "="*60)
    print("TIMING ATTACK DEMONSTRATION")
    print("="*60)
    print("\nThis demonstrates how timing differences can leak information")
    print("about secret values, allowing attackers to guess them byte-by-byte.\n")
    
    # Secret to attack
    secret = b"SECRET_KEY_12345"
    
    print(f"Secret: {secret}")
    print(f"Length: {len(secret)} bytes\n")
    
    # Test vulnerable comparison
    print("=" * 60)
    print("1. VULNERABLE COMPARISON (Early Exit)")
    print("=" * 60)
    
    # Test guesses with different number of correct bytes
    test_cases = [
        (b"AAAAAAAAAAAAAAAA", "All wrong"),
        (b"SECRET__________", "First 6 bytes correct"),
        (b"SECRET_KEY______", "First 10 bytes correct"),
        (b"SECRET_KEY_1234_", "First 15 bytes correct"),
        (b"SECRET_KEY_12345", "All correct"),
    ]
    
    vulnerable_times = []
    for guess, description in test_cases:
        avg_time = measure_timing(vulnerable_compare, secret, guess, iterations=10000)
        vulnerable_times.append(avg_time)
        logger.info("Timing measurement", extra={
            'extra_data': {
                'attack': 'timing',
                'comparison': 'vulnerable',
                'description': description,
                'time_us': round(avg_time, 3)
            }
        })
        print(f"   {description:30s} → {avg_time:8.3f} μs")
    
    print("\nTIMING LEAK DETECTED!")
    print(f"   Time difference: {max(vulnerable_times) - min(vulnerable_times):.3f} μs")
    print(f"   An attacker can use this to guess the secret byte-by-byte!\n")
    
    # Test secure comparison
    print("=" * 60)
    print("2. SECURE COMPARISON (Constant-Time)")
    print("=" * 60)
    
    secure_times = []
    for guess, description in test_cases:
        avg_time = measure_timing(secure_compare, secret, guess, iterations=10000)
        secure_times.append(avg_time)
        logger.info("Timing measurement", extra={
            'extra_data': {
                'attack': 'timing',
                'comparison': 'secure',
                'description': description,
                'time_us': round(avg_time, 3)
            }
        })
        print(f"   {description:30s} → {avg_time:8.3f} μs")
    
    print("\nTIMING LEAK MITIGATED!")
    print(f"   Time difference: {max(secure_times) - min(secure_times):.3f} μs")
    print(f"   All comparisons take approximately the same time.\n")
    
    # Summary
    print("=" * 60)
    print(" SUMMARY")
    print("=" * 60)
    print(f"\nVulnerable Implementation:")
    print(f"   Min time: {min(vulnerable_times):.3f} μs")
    print(f"   Max time: {max(vulnerable_times):.3f} μs")
    print(f"   Range:    {max(vulnerable_times) - min(vulnerable_times):.3f} μs")
    print(f"   Verdict:  VULNERABLE to timing attacks")
    
    print(f"\nSecure Implementation:")
    print(f"   Min time: {min(secure_times):.3f} μs")
    print(f"   Max time: {max(secure_times):.3f} μs")
    print(f"   Range:    {max(secure_times) - min(secure_times):.3f} μs")
    print(f"   Verdict:  RESISTANT to timing attacks")
    
    print("\n" + "="*60)
    print(" MITIGATION STRATEGIES")
    print("="*60)
    print("""
1. Use constant-time comparison functions (hmac.compare_digest)
2. Always check all bytes, never early-exit on mismatch
3. Use blinding for RSA operations
4. Add random delays (less reliable, not recommended alone)
5. Use AEAD ciphers (AES-GCM) that verify before decrypting
""")
    print("="*60 + "\n")
    
    logger.info("Timing attack demonstration complete", extra={
        'extra_data': {
            'vulnerable_range_us': round(max(vulnerable_times) - min(vulnerable_times), 3),
            'secure_range_us': round(max(secure_times) - min(secure_times), 3)
        }
    })


def main():
    """Main timing attack demonstration"""
    try:
        demonstrate_timing_attack()
    except KeyboardInterrupt:
        print("\n\nDemonstration stopped by user\n")
    except Exception as e:
        logger.error(f"Error: {e}", extra={'extra_data': {'error': str(e)}})
        raise


if __name__ == "__main__":
    main()
