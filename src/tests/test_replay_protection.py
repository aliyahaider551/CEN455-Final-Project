# src/tests/test_replay_protection.py
"""
Unit tests for replay protection mechanisms.
Tests counter-based replay detection.
"""
import pytest
import sys
import os
import json
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))


class ReplayProtector:
    """Simple replay protection implementation for testing"""
    
    def __init__(self):
        self.last_counters = {}
    
    def check_counter(self, sender_id, counter):
        """
        Check if counter is valid (not a replay).
        Returns True if valid, False if replay detected.
        """
        last_counter = self.last_counters.get(sender_id, 0)
        
        if counter <= last_counter:
            return False
        
        # Update last counter
        self.last_counters[sender_id] = counter
        return True
    
    def reset(self, sender_id=None):
        """Reset counters for testing"""
        if sender_id:
            self.last_counters[sender_id] = 0
        else:
            self.last_counters = {}


class TestReplayProtection:
    """Test replay protection mechanisms"""
    
    def test_first_message_accepted(self):
        """Test that first message from sender is accepted"""
        protector = ReplayProtector()
        
        # First message should be accepted
        assert protector.check_counter("sensor1", 1) is True
    
    def test_sequential_counters_accepted(self):
        """Test that sequential increasing counters are accepted"""
        protector = ReplayProtector()
        
        # Sequential messages should all be accepted
        assert protector.check_counter("sensor1", 1) is True
        assert protector.check_counter("sensor1", 2) is True
        assert protector.check_counter("sensor1", 3) is True
        assert protector.check_counter("sensor1", 4) is True
    
    def test_replay_detected(self):
        """Test that replayed messages are detected"""
        protector = ReplayProtector()
        
        # Send messages
        assert protector.check_counter("sensor1", 1) is True
        assert protector.check_counter("sensor1", 2) is True
        assert protector.check_counter("sensor1", 3) is True
        
        # Try to replay old messages
        assert protector.check_counter("sensor1", 1) is False
        assert protector.check_counter("sensor1", 2) is False
        assert protector.check_counter("sensor1", 3) is False
    
    def test_equal_counter_rejected(self):
        """Test that equal counter is rejected (replay)"""
        protector = ReplayProtector()
        
        assert protector.check_counter("sensor1", 5) is True
        
        # Same counter should be rejected
        assert protector.check_counter("sensor1", 5) is False
    
    def test_decreasing_counter_rejected(self):
        """Test that decreasing counters are rejected"""
        protector = ReplayProtector()
        
        assert protector.check_counter("sensor1", 10) is True
        
        # Lower counters should be rejected
        assert protector.check_counter("sensor1", 9) is False
        assert protector.check_counter("sensor1", 5) is False
        assert protector.check_counter("sensor1", 1) is False
    
    def test_large_gap_accepted(self):
        """Test that large gaps in counters are accepted"""
        protector = ReplayProtector()
        
        assert protector.check_counter("sensor1", 1) is True
        
        # Large jump should be accepted (might indicate message loss)
        assert protector.check_counter("sensor1", 100) is True
        assert protector.check_counter("sensor1", 1000) is True
    
    def test_multiple_senders(self):
        """Test replay protection with multiple senders"""
        protector = ReplayProtector()
        
        # Different senders have independent counters
        assert protector.check_counter("sensor1", 1) is True
        assert protector.check_counter("sensor2", 1) is True
        assert protector.check_counter("sensor3", 1) is True
        
        assert protector.check_counter("sensor1", 2) is True
        assert protector.check_counter("sensor2", 2) is True
        assert protector.check_counter("sensor3", 2) is True
        
        # Replay detection is per-sender
        assert protector.check_counter("sensor1", 1) is False
        assert protector.check_counter("sensor2", 1) is False
        assert protector.check_counter("sensor3", 1) is False
    
    def test_zero_counter_rejected(self):
        """Test that counter 0 is rejected if not first"""
        protector = ReplayProtector()
        
        # First counter can be any positive value
        assert protector.check_counter("sensor1", 5) is True
        
        # Counter 0 should be rejected as it's less than last
        assert protector.check_counter("sensor1", 0) is False
    
    def test_negative_counter_rejected(self):
        """Test that negative counters are rejected"""
        protector = ReplayProtector()
        
        assert protector.check_counter("sensor1", 10) is True
        
        # Negative counters should be rejected
        assert protector.check_counter("sensor1", -1) is False
        assert protector.check_counter("sensor1", -100) is False


class TestReplayProtectionPersistence:
    """Test replay protection state persistence"""
    
    def test_state_serialization(self):
        """Test that counter state can be saved and loaded"""
        protector = ReplayProtector()
        
        # Build up state
        protector.check_counter("sensor1", 10)
        protector.check_counter("sensor2", 20)
        protector.check_counter("sensor3", 30)
        
        # Serialize state
        state = json.dumps(protector.last_counters)
        
        # Create new protector and load state
        new_protector = ReplayProtector()
        new_protector.last_counters = json.loads(state)
        
        # Verify state was restored
        assert new_protector.last_counters == protector.last_counters
        
        # Verify replay protection still works
        assert new_protector.check_counter("sensor1", 11) is True
        assert new_protector.check_counter("sensor1", 10) is False


class TestReplayAttackScenarios:
    """Test realistic replay attack scenarios"""
    
    def test_captured_message_replay(self):
        """Simulate attacker capturing and replaying a message"""
        protector = ReplayProtector()
        
        # Legitimate messages
        assert protector.check_counter("sensor1", 1) is True
        assert protector.check_counter("sensor1", 2) is True
        captured_counter = 2  # Attacker captures this message
        assert protector.check_counter("sensor1", 3) is True
        
        # More legitimate messages
        assert protector.check_counter("sensor1", 4) is True
        assert protector.check_counter("sensor1", 5) is True
        
        # Attacker tries to replay captured message
        assert protector.check_counter("sensor1", captured_counter) is False
    
    def test_immediate_replay(self):
        """Test immediate replay of just-sent message"""
        protector = ReplayProtector()
        
        # Send message
        assert protector.check_counter("sensor1", 1) is True
        
        # Immediately replay it
        assert protector.check_counter("sensor1", 1) is False
    
    def test_delayed_replay(self):
        """Test replay after many subsequent messages"""
        protector = ReplayProtector()
        
        # Send messages 1-10
        for i in range(1, 11):
            assert protector.check_counter("sensor1", i) is True
        
        # Try to replay any old message
        for old_counter in [1, 3, 5, 7, 9]:
            assert protector.check_counter("sensor1", old_counter) is False
    
    def test_out_of_order_delivery(self):
        """Test handling of out-of-order message delivery"""
        protector = ReplayProtector()
        
        # Messages arrive out of order
        assert protector.check_counter("sensor1", 3) is True  # Message 3 arrives first
        assert protector.check_counter("sensor1", 1) is False  # Message 1 arrives late (rejected)
        assert protector.check_counter("sensor1", 2) is False  # Message 2 arrives late (rejected)
        assert protector.check_counter("sensor1", 4) is True   # Message 4 arrives (accepted)
        
        # Note: This shows limitation of counter-based approach with unreliable networks
        # Messages 1 and 2 are lost if message 3 arrives first


class TestEdgeCases:
    """Test edge cases and boundary conditions"""
    
    def test_very_large_counter(self):
        """Test handling of very large counter values"""
        protector = ReplayProtector()
        
        large_counter = 2**31 - 1  # Near max 32-bit int
        assert protector.check_counter("sensor1", large_counter) is True
        assert protector.check_counter("sensor1", large_counter + 1) is True
    
    def test_empty_sender_id(self):
        """Test handling of empty sender ID"""
        protector = ReplayProtector()
        
        # Empty string as sender ID should still work
        assert protector.check_counter("", 1) is True
        assert protector.check_counter("", 2) is True
        assert protector.check_counter("", 1) is False
    
    def test_special_characters_in_sender_id(self):
        """Test sender IDs with special characters"""
        protector = ReplayProtector()
        
        special_ids = [
            "sensor-1", "sensor_1", "sensor.1",
            "sensor@domain", "sensor#1", "sensor/1"
        ]
        
        for sender_id in special_ids:
            assert protector.check_counter(sender_id, 1) is True
            assert protector.check_counter(sender_id, 2) is True
            assert protector.check_counter(sender_id, 1) is False


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
