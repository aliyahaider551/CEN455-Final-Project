# MQTT Broker Setup

This directory contains the Mosquitto MQTT broker configuration for the CEN455 Secure MQTT project.

## Quick Start

1. **Start the broker**:
   ```bash
   docker-compose up -d
   ```

2. **View logs**:
   ```bash
   docker-compose logs -f
   ```

3. **Stop the broker**:
   ```bash
   docker-compose down
   ```

## Configuration Files

- **docker-compose.yml**: Docker container configuration
- **mosquitto.conf**: Main Mosquitto broker configuration
- **aclfile**: Access Control List for topic-level permissions
- **passwordfile.example**: Example password file template

## Enabling Authentication

By default, `allow_anonymous true` is set for easy demonstration. To enable authentication:

1. Create a password file:
   ```bash
   mosquitto_passwd -c passwordfile sensor1
   mosquitto_passwd -b passwordfile actuator1 password123
   mosquitto_passwd -b passwordfile attacker password123
   ```

2. Edit `mosquitto.conf`:
   - Set `allow_anonymous false`
   - Uncomment `password_file /mosquitto/config/passwordfile`
   - Uncomment `acl_file /mosquitto/config/aclfile`

3. Restart the broker:
   ```bash
   docker-compose restart
   ```

## Testing Connectivity

Test if the broker is running:
```bash
mosquitto_pub -h localhost -p 1883 -t test/topic -m "Hello MQTT"
mosquitto_sub -h localhost -p 1883 -t test/topic
```

## Ports

- **1883**: MQTT protocol
- **9001**: WebSocket protocol (optional)

## Troubleshooting

- Check logs: `docker-compose logs mosquitto`
- Verify container is running: `docker ps`
- Test connection: `telnet localhost 1883`
