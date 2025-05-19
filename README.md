# Adaptive VPN with Protocol Switching

This project implements an adaptive VPN solution with dynamic protocol switching between WireGuard and IPsec based on network metrics. It also features advanced cryptography with Curve25519 for key exchange and experimental support for the post-quantum Kyber algorithm.

## Features

- Dynamic switching between WireGuard and IPsec VPN protocols
- Protocol selection based on network metrics (ping, jitter, bandwidth)
- Curve25519 elliptic curve cryptography for secure key exchange
- Experimental support for post-quantum cryptography (Kyber)
- Automatic configuration management
- Client-server architecture with secure API communication

## Requirements

### Client Requirements
- Python 3.6 or higher
- Required Python packages (see client/requirements.txt):
  - requests
  - pynacl
  - cryptography
- WireGuard client (for Windows, macOS, or Linux)
- IPsec client (native or StrongSwan)

### Server Requirements
- Linux server (Ubuntu/Debian recommended)
- Python 3.6 or higher
- WireGuard
- StrongSwan (for IPsec)
- NGINX
- Required Python packages (see server/requirements.txt)

## Setup

### Server Setup

1. Upload the cloud-init script from `scripts/cloud-init.yml` to your server provider's user-data section, or run the script manually.

2. Alternatively, to set up the server manually:
   ```bash
   # Install required packages
   apt update && apt upgrade -y
   apt install -y python3 python3-pip python3-venv wireguard strongswan iptables-persistent openssl nginx
   
   # Clone this repository
   git clone https://github.com/yourusername/adaptive-vpn.git /opt/adaptive-vpn
   
   # Set up the VPN server
   cd /opt/adaptive-vpn
   python3 -m venv venv
   venv/bin/pip install -r server/requirements.txt
   
   # Copy the server files to the appropriate location
   cp server/vpn_server.py /opt/adaptive-vpn/
   
   # Enable IP forwarding
   echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/99-vpn.conf
   sysctl -p /etc/sysctl.d/99-vpn.conf
   
   # Create systemd service
   cp scripts/vpn-server.service /etc/systemd/system/
   systemctl enable vpn-server
   systemctl start vpn-server
   ```

### Client Setup

1. Install the required packages:
   ```bash
   pip install -r client/requirements.txt
   ```

2. Install WireGuard client for your platform:
   - Windows: [WireGuard for Windows](https://www.wireguard.com/install/)
   - macOS: `brew install wireguard-tools`
   - Linux: `apt install wireguard` or equivalent for your distribution

3. Install IPsec client for your platform:
   - Windows: Built-in VPN client or StrongSwan VPN Client
   - macOS: Built-in VPN client
   - Linux: `apt install strongswan` or equivalent

## Usage

### Running the Client

1. Start the VPN client:
   ```bash
   python client/vpn_client.py --action start
   ```

2. To stop the VPN:
   ```bash
   python client/vpn_client.py --action stop
   ```

3. To check status:
   ```bash
   python client/vpn_client.py --action status
   ```

### Monitoring

The client automatically monitors network conditions and switches between protocols as needed.

## Architecture

- The client measures network metrics (ping, jitter, bandwidth) to determine the optimal protocol
- The server provides configuration and key management via a secure API
- Both WireGuard and IPsec configurations are maintained and switched dynamically
- Curve25519 is used for the primary key exchange
- Kyber is used as an experimental post-quantum security layer

## Security Considerations

- This implementation includes simulated Kyber for demonstration purposes; in production, use a proper Kyber library
- SSL certificate validation should be properly configured in production
- Shared secret derivation and authentication should be strengthened in a production environment

## License

MIT License

## Author

Your Name 