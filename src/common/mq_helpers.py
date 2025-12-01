# src/common/mq_helpers.py
"""
MQTT connection and helper utilities for the CEN455 Secure MQTT project.
Provides wrapper functions for consistent MQTT client setup.
"""
import paho.mqtt.client as mqtt
import time
from .logger import get_logger
import os

logger = get_logger("mq_helpers")


def connect_client(client_id,  host=os.getenv("MQTT_HOST", "mqtt-broker"), port=1883, username=None, password=None, 
                   on_message=None, on_connect=None, on_disconnect=None):
    """
    Create and connect an MQTT client with consistent configuration.
    
    Args:
        client_id: Unique client identifier
        host: Broker hostname (default: localhost)
        port: Broker port (default: 1883)
        username: Optional username for authentication
        password: Optional password for authentication
        on_message: Callback function for incoming messages
        on_connect: Callback function for connection events
        on_disconnect: Callback function for disconnection events
        
    Returns:
        Connected MQTT client instance
    """
    client = mqtt.Client(client_id=client_id)
    
    # Set authentication if provided
    if username:
        client.username_pw_set(username, password)
    
    # Set callbacks
    if on_message:
        client.on_message = on_message
    
    if on_connect:
        client.on_connect = on_connect
    else:
        # Default on_connect callback
        def default_on_connect(client, userdata, flags, rc):
            if rc == 0:
                logger.info("Connected successfully", extra={
                    'extra_data': {
                        'client_id': client_id,
                        'host': host,
                        'port': port,
                        'result_code': rc
                    }
                })
            else:
                logger.error(f"Connection failed with code {rc}", extra={
                    'extra_data': {
                        'client_id': client_id,
                        'host': host,
                        'port': port,
                        'result_code': rc
                    }
                })
        client.on_connect = default_on_connect
    
    if on_disconnect:
        client.on_disconnect = on_disconnect
    
    # Connect to broker
    try:
        client.connect(host, port, keepalive=60)
        client.loop_start()
        
        # Small sleep to ensure connection is established
        time.sleep(0.5)
        
        logger.info("MQTT client initialized", extra={
            'extra_data': {
                'client_id': client_id,
                'host': host,
                'port': port
            }
        })
        
        return client
        
    except Exception as e:
        logger.error(f"Failed to connect: {str(e)}", extra={
            'extra_data': {
                'client_id': client_id,
                'host': host,
                'port': port,
                'error': str(e)
            }
        })
        raise


def publish_message(client, topic, payload, qos=0):
    """
    Publish a message to a topic with logging.
    
    Args:
        client: MQTT client instance
        topic: Topic to publish to
        payload: Message payload (string or bytes)
        qos: Quality of Service level (0, 1, or 2)
        
    Returns:
        MQTTMessageInfo object
    """
    result = client.publish(topic, payload, qos=qos)
    
    logger.info("Message published", extra={
        'extra_data': {
            'topic': topic,
            'qos': qos,
            'payload_size': len(payload) if payload else 0,
            'mid': result.mid
        }
    })
    
    return result


def subscribe_topic(client, topic, qos=0):
    """
    Subscribe to a topic with logging.
    
    Args:
        client: MQTT client instance
        topic: Topic to subscribe to
        qos: Quality of Service level (0, 1, or 2)
        
    Returns:
        Tuple of (result_code, message_id)
    """
    result, mid = client.subscribe(topic, qos=qos)
    
    logger.info("Subscribed to topic", extra={
        'extra_data': {
            'topic': topic,
            'qos': qos,
            'result': result,
            'mid': mid
        }
    })
    
    return result, mid


def disconnect_client(client):
    """
    Cleanly disconnect an MQTT client.
    
    Args:
        client: MQTT client instance to disconnect
    """
    try:
        client.loop_stop()
        client.disconnect()
        logger.info("Client disconnected", extra={
            'extra_data': {'client_id': client._client_id.decode() if hasattr(client._client_id, 'decode') else str(client._client_id)}
        })
    except Exception as e:
        logger.error(f"Error during disconnect: {str(e)}", extra={
            'extra_data': {'error': str(e)}
        })


def wait_for_messages(duration=None):
    """
    Wait for messages to be processed. Used for long-running subscribers.
    
    Args:
        duration: How long to wait in seconds (None = wait indefinitely)
    """
    try:
        if duration:
            time.sleep(duration)
        else:
            # Wait indefinitely (until Ctrl+C)
            while True:
                time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Interrupted by user")


if __name__ == "__main__":
    # Test MQTT connectivity
    print("Testing MQTT connection...")
    
    def test_callback(client, userdata, message):
        print(f"Received: {message.topic} -> {message.payload.decode()}")
    
    try:
        client = connect_client("test_client", on_message=test_callback)
        subscribe_topic(client, "test/topic")
        publish_message(client, "test/topic", "Hello MQTT!")
        time.sleep(2)
        disconnect_client(client)
        print("MQTT connection test passed")
    except Exception as e:
        print(f"MQTT connection test failed: {e}")
