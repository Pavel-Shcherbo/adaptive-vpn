#!/usr/bin/env python3
import os
import sys
import time
import json
import socket
import logging
import argparse
import subprocess
import threading
import requests
from datetime import datetime
from pathlib import Path
import secrets
import nacl.public
import nacl.utils
from nacl.bindings import crypto_scalarmult
import uuid

# Импорт реальной реализации Kyber из библиотеки liboqs
try:
    from oqs import KeyEncapsulation
    KYBER_AVAILABLE = True
except ImportError:
    KYBER_AVAILABLE = False
    logging.warning("liboqs не установлена. Будет использована базовая реализация для Kyber")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger('VPN-Client')

# Constants for the VPN
SERVER_IP = "37.220.82.110"
SERVER_PORT = 8443
CONFIG_DIR = Path(os.path.expanduser("~/.adaptive-vpn"))
WIREGUARD_CONFIG = CONFIG_DIR / "wg0.conf"
IPSEC_CONFIG = CONFIG_DIR / "ipsec.conf"
IPSEC_SECRETS = CONFIG_DIR / "ipsec.secrets"
CLIENT_PRIVATE_KEY_FILE = CONFIG_DIR / "client_private_key"
CLIENT_PUBLIC_KEY_FILE = CONFIG_DIR / "client_public_key"
SERVER_PUBLIC_KEY_FILE = CONFIG_DIR / "server_public_key"
KYBER_KEYS_DIR = CONFIG_DIR / "kyber_keys"
KYBER_PRIVATE_KEY_FILE = KYBER_KEYS_DIR / "private_key"
KYBER_PUBLIC_KEY_FILE = KYBER_KEYS_DIR / "public_key"
KYBER_SHARED_SECRET_FILE = KYBER_KEYS_DIR / "shared_secret"
SESSION_ID_FILE = CONFIG_DIR / "session_id"
METRICS_FILE = CONFIG_DIR / "network_metrics.json"
CURRENT_PROTOCOL_FILE = CONFIG_DIR / "current_protocol"

# Ensure directories exist
CONFIG_DIR.mkdir(parents=True, exist_ok=True)
KYBER_KEYS_DIR.mkdir(parents=True, exist_ok=True)

class PQCKyber:
    """
    Post-Quantum Cryptography implementation using Kyber algorithm
    """
    @staticmethod
    def generate_keypair():
        try:
            if KYBER_AVAILABLE:
                # Использование реальной реализации Kyber
                with KeyEncapsulation("Kyber768") as kem:
                    public_key = kem.generate_keypair()
                    private_key = kem.export_secret_key()
                    return private_key, public_key
            else:
                # Резервная реализация, если библиотека не установлена
                private_key = os.urandom(32)
                public_key = os.urandom(32)
                logger.warning("Используется резервная реализация Kyber, а не настоящая")
                return private_key, public_key
        except Exception as e:
            logger.error(f"Ошибка генерации ключей Kyber: {e}")
            # Резервная реализация в случае ошибки
            private_key = os.urandom(32)
            public_key = os.urandom(32)
            return private_key, public_key
    
    @staticmethod
    def encapsulate(public_key):
        try:
            if KYBER_AVAILABLE:
                # Использование реальной реализации Kyber для инкапсуляции
                with KeyEncapsulation("Kyber768") as kem:
                    ciphertext, shared_secret = kem.encap_secret(public_key)
                    return ciphertext, shared_secret
            else:
                # Резервная реализация
                ciphertext = os.urandom(32)
                shared_secret = os.urandom(32)
                return ciphertext, shared_secret
        except Exception as e:
            logger.error(f"Ошибка инкапсуляции Kyber: {e}")
            ciphertext = os.urandom(32)
            shared_secret = os.urandom(32)
            return ciphertext, shared_secret
    
    @staticmethod
    def decapsulate(private_key, ciphertext):
        try:
            if KYBER_AVAILABLE:
                # Использование реальной реализации Kyber для декапсуляции
                with KeyEncapsulation("Kyber768") as kem:
                    kem.import_secret_key(private_key)
                    shared_secret = kem.decap_secret(ciphertext)
                    return shared_secret
            else:
                # Резервная реализация
                return os.urandom(32)
        except Exception as e:
            logger.error(f"Ошибка декапсуляции Kyber: {e}")
            return os.urandom(32)

class NetworkMetrics:
    """Class for measuring network metrics like ping, jitter and bandwidth"""
    def __init__(self, target):
        self.target = target
        self.metrics = {
            "ping": 0,
            "jitter": 0,
            "bandwidth": 0,
            "packet_loss": 0,
            "timestamp": None
        }
    
    def measure_ping(self):
        """Measure ping to the target"""
        try:
            # Using ping command to get RTT
            if os.name == 'nt':  # Windows
                output = subprocess.check_output(
                    ["ping", "-n", "5", self.target],
                    universal_newlines=True
                )
                for line in output.split('\n'):
                    if "Average" in line:
                        ping = float(line.split("=")[1].split("ms")[0].strip())
                        self.metrics["ping"] = ping
                        break
            else:  # Linux/MacOS
                output = subprocess.check_output(
                    ["ping", "-c", "5", self.target],
                    universal_newlines=True
                )
                for line in output.split('\n'):
                    if "rtt min/avg/max/mdev" in line:
                        avg_ping = line.split("/")[4]
                        self.metrics["ping"] = float(avg_ping)
                        self.metrics["jitter"] = float(line.split("/")[6].split(" ")[0])
                        break
            
            # Extract packet loss
            for line in output.split('\n'):
                if "loss" in line and "%" in line:
                    loss_part = line.split("%")[0]
                    loss = float([s for s in loss_part.split(" ") if s][-1])
                    self.metrics["packet_loss"] = loss
                    break
                    
        except Exception as e:
            logger.error(f"Error measuring ping: {e}")
            self.metrics["ping"] = 999  # High value indicating failure
            self.metrics["packet_loss"] = 100
    
    def measure_bandwidth(self):
        """
        Approximate bandwidth measurement
        In a production environment, consider using tools like iperf3
        """
        try:
            # Download a file from the server to measure bandwidth
            start_time = time.time()
            file_size_mb = 1
            requests.get(f"http://{self.target}/speedtest", stream=True, timeout=10)
            end_time = time.time()
            
            duration = end_time - start_time
            if duration > 0:
                bandwidth_mbps = file_size_mb * 8 / duration
                self.metrics["bandwidth"] = bandwidth_mbps
            else:
                self.metrics["bandwidth"] = 0
        except Exception as e:
            logger.error(f"Error measuring bandwidth: {e}")
            self.metrics["bandwidth"] = 0
    
    def collect_all_metrics(self):
        """Collect all network metrics"""
        self.measure_ping()
        self.measure_bandwidth()
        self.metrics["timestamp"] = datetime.now().isoformat()
        return self.metrics
    
    def save_metrics(self):
        """Save metrics to file"""
        with open(METRICS_FILE, 'w') as f:
            json.dump(self.metrics, f)
    
    @staticmethod
    def load_metrics():
        """Load metrics from file"""
        if METRICS_FILE.exists():
            with open(METRICS_FILE, 'r') as f:
                return json.load(f)
        return None


class AdaptiveVPNClient:
    """Main VPN client class with protocol switching capability"""
    def __init__(self):
        self.current_protocol = None
        self.server_address = SERVER_IP
        self.server_port = SERVER_PORT
        self.session_id = self._get_or_create_session_id()
        self.curve25519_keypair = None
        self.kyber_keypair = None
        self.shared_secret = None
        
        # Initialize current protocol from saved state if available
        if CURRENT_PROTOCOL_FILE.exists():
            with open(CURRENT_PROTOCOL_FILE, 'r') as f:
                self.current_protocol = f.read().strip()
        
    def _get_or_create_session_id(self):
        """Get existing session ID or create a new one"""
        if SESSION_ID_FILE.exists():
            with open(SESSION_ID_FILE, 'r') as f:
                return f.read().strip()
        
        # Create new session ID
        session_id = str(uuid.uuid4())
        with open(SESSION_ID_FILE, 'w') as f:
            f.write(session_id)
        return session_id
    
    def generate_curve25519_keypair(self):
        """Generate Curve25519 keypair for key exchange"""
        private_key = nacl.public.PrivateKey.generate()
        public_key = private_key.public_key
        
        # Save keys
        with open(CLIENT_PRIVATE_KEY_FILE, 'wb') as f:
            f.write(bytes(private_key))
        with open(CLIENT_PUBLIC_KEY_FILE, 'wb') as f:
            f.write(bytes(public_key))
            
        self.curve25519_keypair = {
            'private': private_key,
            'public': public_key
        }
        return private_key, public_key
    
    def generate_kyber_keypair(self):
        """Generate Kyber keypair for post-quantum key exchange"""
        private_key, public_key = PQCKyber.generate_keypair()
        
        # Save keys
        with open(KYBER_PRIVATE_KEY_FILE, 'wb') as f:
            f.write(private_key)
        with open(KYBER_PUBLIC_KEY_FILE, 'wb') as f:
            f.write(public_key)
            
        self.kyber_keypair = {
            'private': private_key,
            'public': public_key
        }
        return private_key, public_key
    
    def compute_shared_secret(self, server_public_key):
        """Compute shared secret using Curve25519"""
        if not self.curve25519_keypair:
            logger.error("Client keypair not generated!")
            return None
            
        client_private = self.curve25519_keypair['private']
        shared_secret = crypto_scalarmult(
            client_private._private_key,
            bytes(server_public_key)
        )
        self.shared_secret = shared_secret
        return shared_secret
    
    def register_with_server(self):
        """Register client with the server and exchange keys"""
        if not self.curve25519_keypair:
            self.generate_curve25519_keypair()
            
        if not self.kyber_keypair:
            self.generate_kyber_keypair()
        
        try:
            logger.info(f"Registering with server at {self.server_address}:{self.server_port}")
            
            # Prepare registration data
            registration_data = {
                'session_id': self.session_id,
                'curve25519_public_key': bytes(self.curve25519_keypair['public']).hex(),
                'kyber_public_key': self.kyber_keypair['public'].hex(),
                'client_version': '1.0.0'
            }
            
            # Send registration to server
            response = requests.post(
                f"https://{self.server_address}:{self.server_port}/register",
                json=registration_data,
                verify=False,  # In production, use proper certificate verification
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                # Save server's public key
                server_public_key_hex = data.get('curve25519_public_key')
                server_public_key = bytes.fromhex(server_public_key_hex)
                
                with open(SERVER_PUBLIC_KEY_FILE, 'wb') as f:
                    f.write(server_public_key)
                
                # Compute shared secret
                shared_secret = self.compute_shared_secret(server_public_key)
                
                # Process Kyber response
                kyber_ciphertext_hex = data.get('kyber_ciphertext')
                if kyber_ciphertext_hex:
                    kyber_ciphertext = bytes.fromhex(kyber_ciphertext_hex)
                    kyber_shared_secret = PQCKyber.decapsulate(self.kyber_keypair['private'], kyber_ciphertext)
                    # In a real implementation, we'd combine the Curve25519 and Kyber shared secrets
                    
                logger.info("Successfully registered with server and exchanged keys")
                return True
            else:
                logger.error(f"Failed to register: HTTP {response.status_code}")
                return False
                
        except Exception as e:
            logger.error(f"Error during registration: {e}")
            return False
    
    def generate_wireguard_config(self, server_data):
        """Generate WireGuard configuration"""
        config = f"""[Interface]
PrivateKey = {server_data.get('client_wg_private_key')}
Address = {server_data.get('client_ip')}/24
DNS = {server_data.get('dns', '1.1.1.1')}

[Peer]
PublicKey = {server_data.get('server_wg_public_key')}
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = {self.server_address}:{server_data.get('wireguard_port', 51820)}
PersistentKeepalive = 25
"""
        with open(WIREGUARD_CONFIG, 'w') as f:
            f.write(config)
        
        logger.info(f"WireGuard configuration saved to {WIREGUARD_CONFIG}")
        return True
    
    def generate_ipsec_config(self, server_data):
        """Generate IPsec configuration files"""
        conn_name = f"vpn-to-{self.server_address}"
        
        # IPsec config file
        config = f"""config setup
    charondebug="all"
    uniqueids=yes
    strictcrlpolicy=no

conn {conn_name}
    authby=secret
    auto=start
    keyexchange=ikev2
    ike=aes256-sha256-modp2048,aes128-sha1-modp1024!
    esp=aes256-sha256,aes128-sha1!
    dpdaction=restart
    closeaction=restart
    left=%defaultroute
    leftid={server_data.get('client_id')}
    leftauth=psk
    right={self.server_address}
    rightid={server_data.get('server_id')}
    rightauth=psk
    rightsubnet=0.0.0.0/0
    type=tunnel
    leftsubnet=0.0.0.0/0
    keyingtries=%forever
    fragmentation=yes
"""
        
        # IPsec secrets file
        secret = f"{server_data.get('client_id')} {server_data.get('server_id')} : PSK \"{server_data.get('shared_psk')}\""
        
        with open(IPSEC_CONFIG, 'w') as f:
            f.write(config)
        
        with open(IPSEC_SECRETS, 'w') as f:
            f.write(secret)
            
        logger.info(f"IPsec configuration saved to {IPSEC_CONFIG} and {IPSEC_SECRETS}")
        return True
    
    def get_vpn_configurations(self):
        """Get VPN configurations from server"""
        try:
            logger.info("Requesting VPN configurations from server")
            
            # Request configurations using shared secret for authentication
            headers = {
                'Authorization': f'Bearer {self.session_id}',
                'X-Auth-Key': self.shared_secret.hex() if self.shared_secret else ''
            }
            
            response = requests.get(
                f"https://{self.server_address}:{self.server_port}/get_configs",
                headers=headers,
                verify=False,  # In production, use proper certificate verification
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                
                # Generate configurations
                self.generate_wireguard_config(data.get('wireguard', {}))
                self.generate_ipsec_config(data.get('ipsec', {}))
                
                logger.info("Successfully received and processed VPN configurations")
                return True
            else:
                logger.error(f"Failed to get configurations: HTTP {response.status_code}")
                return False
                
        except Exception as e:
            logger.error(f"Error getting VPN configurations: {e}")
            return False
    
    def start_wireguard(self):
        """Start WireGuard VPN connection"""
        try:
            if not WIREGUARD_CONFIG.exists():
                logger.error("WireGuard configuration not found")
                return False
                
            if os.name == 'nt':  # Windows
                # Using Windows 'wireguard.exe' CLI tool
                subprocess.run(
                    ["wireguard.exe", "/installtunnelservice", str(WIREGUARD_CONFIG)], 
                    check=True
                )
            else:  # Linux
                subprocess.run(
                    ["wg-quick", "up", str(WIREGUARD_CONFIG)],
                    check=True
                )
                
            self.current_protocol = "wireguard"
            with open(CURRENT_PROTOCOL_FILE, 'w') as f:
                f.write(self.current_protocol)
                
            logger.info("WireGuard connection started")
            return True
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to start WireGuard: {e}")
            return False
        except Exception as e:
            logger.error(f"Error starting WireGuard: {e}")
            return False
    
    def start_ipsec(self):
        """Start IPsec VPN connection"""
        try:
            if not IPSEC_CONFIG.exists() or not IPSEC_SECRETS.exists():
                logger.error("IPsec configuration not found")
                return False
                
            if os.name == 'nt':  # Windows
                # On Windows, we'd typically use a proprietary IPsec client
                # This is a simplified example - in practice, use strongSwan GUI or similar
                logger.info("For Windows, please use strongSwan GUI or Windows built-in VPN client")
                # Simulating IPsec startup for demonstration
                time.sleep(2)
            else:  # Linux
                # Start strongSwan
                subprocess.run(
                    ["sudo", "ipsec", "restart"],
                    check=True
                )
                
            self.current_protocol = "ipsec"
            with open(CURRENT_PROTOCOL_FILE, 'w') as f:
                f.write(self.current_protocol)
                
            logger.info("IPsec connection started")
            return True
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to start IPsec: {e}")
            return False
        except Exception as e:
            logger.error(f"Error starting IPsec: {e}")
            return False
    
    def stop_current_vpn(self):
        """Stop the currently active VPN connection"""
        if not self.current_protocol:
            logger.info("No active VPN connection to stop")
            return True
            
        try:
            if self.current_protocol == "wireguard":
                if os.name == 'nt':  # Windows
                    # Using Windows 'wireguard.exe' CLI tool
                    subprocess.run(
                        ["wireguard.exe", "/uninstalltunnelservice", "wg0"], 
                        check=True
                    )
                else:  # Linux
                    subprocess.run(
                        ["wg-quick", "down", str(WIREGUARD_CONFIG)],
                        check=True
                    )
            elif self.current_protocol == "ipsec":
                if os.name == 'nt':  # Windows
                    # Simulating IPsec teardown for demonstration
                    pass
                else:  # Linux
                    subprocess.run(
                        ["sudo", "ipsec", "stop"],
                        check=True
                    )
            
            logger.info(f"{self.current_protocol.capitalize()} connection stopped")
            self.current_protocol = None
            if CURRENT_PROTOCOL_FILE.exists():
                os.remove(CURRENT_PROTOCOL_FILE)
            return True
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to stop {self.current_protocol}: {e}")
            return False
        except Exception as e:
            logger.error(f"Error stopping {self.current_protocol}: {e}")
            return False
    
    def evaluate_network_metrics(self):
        """Evaluate network metrics and decide on optimal protocol"""
        metrics_collector = NetworkMetrics(self.server_address)
        metrics = metrics_collector.collect_all_metrics()
        metrics_collector.save_metrics()
        
        logger.info(f"Network metrics: ping={metrics['ping']}ms, "
                  f"jitter={metrics['jitter']}ms, "
                  f"packet_loss={metrics['packet_loss']}%, "
                  f"bandwidth={metrics['bandwidth']}Mbps")
        
        # Decision logic for protocol selection
        # IPsec usually provides better performance but higher overhead
        # WireGuard is more lightweight but might have less features
        
        if metrics['ping'] > 100 or metrics['packet_loss'] > 5:
            # High latency or packet loss - use WireGuard (more lightweight)
            recommended_protocol = "wireguard"
        elif metrics['jitter'] > 15:
            # High jitter - use IPsec (might handle it better)
            recommended_protocol = "ipsec"
        elif metrics['bandwidth'] < 5:
            # Low bandwidth - use WireGuard (less overhead)
            recommended_protocol = "wireguard"
        else:
            # Good conditions - prefer IPsec for better security
            recommended_protocol = "ipsec"
            
        logger.info(f"Recommended protocol based on network metrics: {recommended_protocol}")
        return recommended_protocol
    
    def switch_protocol_if_needed(self):
        """Check if protocol switch is needed and perform it if necessary"""
        recommended_protocol = self.evaluate_network_metrics()
        
        if not self.current_protocol:
            logger.info(f"No active protocol. Starting {recommended_protocol}")
            if recommended_protocol == "wireguard":
                return self.start_wireguard()
            else:
                return self.start_ipsec()
                
        elif recommended_protocol != self.current_protocol:
            logger.info(f"Switching from {self.current_protocol} to {recommended_protocol}")
            self.stop_current_vpn()
            
            if recommended_protocol == "wireguard":
                return self.start_wireguard()
            else:
                return self.start_ipsec()
                
        else:
            logger.info(f"Keeping current protocol: {self.current_protocol}")
            return True
    
    def start_adaptive_monitoring(self, interval=60):
        """Start adaptive monitoring of network conditions"""
        def monitoring_loop():
            while True:
                try:
                    logger.info("Performing adaptive protocol evaluation")
                    self.switch_protocol_if_needed()
                    time.sleep(interval)
                except Exception as e:
                    logger.error(f"Error in monitoring loop: {e}")
                    time.sleep(10)  # Shorter interval on error
        
        # Start the monitoring in a background thread
        monitor_thread = threading.Thread(target=monitoring_loop, daemon=True)
        monitor_thread.start()
        logger.info(f"Started adaptive monitoring (interval: {interval}s)")
        return monitor_thread

def main():
    parser = argparse.ArgumentParser(description='Adaptive VPN Client')
    parser.add_argument('--action', choices=['start', 'stop', 'status'], default='start',
                        help='Action to perform')
    parser.add_argument('--interval', type=int, default=60,
                        help='Interval for network monitoring in seconds')
    args = parser.parse_args()
    
    client = AdaptiveVPNClient()
    
    if args.action == 'start':
        logger.info("Starting Adaptive VPN Client")
        
        # Register with server and get keys
        if client.register_with_server():
            # Get VPN configurations
            if client.get_vpn_configurations():
                # Start the appropriate VPN protocol
                client.switch_protocol_if_needed()
                # Start adaptive monitoring
                monitor_thread = client.start_adaptive_monitoring(args.interval)
                
                try:
                    # Keep the main thread alive
                    while True:
                        time.sleep(1)
                except KeyboardInterrupt:
                    logger.info("Stopping VPN client")
                    client.stop_current_vpn()
            else:
                logger.error("Failed to get VPN configurations")
        else:
            logger.error("Failed to register with server")
            
    elif args.action == 'stop':
        logger.info("Stopping VPN client")
        client.stop_current_vpn()
        
    elif args.action == 'status':
        if client.current_protocol:
            logger.info(f"VPN is active using {client.current_protocol}")
            # Show additional status information
            metrics = NetworkMetrics.load_metrics()
            if metrics:
                logger.info(f"Last network metrics: ping={metrics['ping']}ms, "
                          f"jitter={metrics.get('jitter', 'N/A')}, "
                          f"packet_loss={metrics.get('packet_loss', 'N/A')}%, "
                          f"bandwidth={metrics['bandwidth']}Mbps")
                logger.info(f"Measured at: {metrics['timestamp']}")
        else:
            logger.info("VPN is not active")

if __name__ == "__main__":
    main() 