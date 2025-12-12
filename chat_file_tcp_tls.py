"""
TCP Server/Client with TLS + Connection Pooling
Optimized for multiple file transfers
"""
import socket
import ssl
import struct
import threading
import json
import os
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


def generate_self_signed_cert():
    """Generate self-signed TLS certificate"""
    if os.path.exists("server.crt") and os.path.exists("server.key"):
        print("✅ TLS certificate exists")
        return
    
    print("🔑 Generating TLS certificate...")
    
    try:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "VN"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Secure QR File"),
            x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
        ])
        
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=365)
        ).add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.DNSName("127.0.0.1"),
            ]),
            critical=False,
        ).sign(private_key, hashes.SHA256())
        
        with open("server.key", "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
        
        with open("server.crt", "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        
        print("✅ TLS certificate generated")
    
    except Exception as e:
        print(f"❌ Certificate error: {e}")
        raise


class TcpChatServer:
    """TLS Server with thread pool for handling multiple clients"""
    
    def __init__(self, host: str, port: int, on_text_received, on_file_received):
        self.host = host
        self.port = port
        self.on_text_received = on_text_received
        self.on_file_received = on_file_received
        self.running = False
        self.thread = None
        
        # ✅ Thread pool for concurrent client handling
        self.executor = ThreadPoolExecutor(max_workers=10)
        
        generate_self_signed_cert()
        
        self.ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ssl_context.load_cert_chain('server.crt', 'server.key')

    def start(self):
        """Start server in background"""
        if self.running:
            return
        self.running = True
        self.thread = threading.Thread(target=self._run_server, daemon=True)
        self.thread.start()

    def _run_server(self):
        """Main server loop"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            sock.bind((self.host, self.port))
            sock.listen(10)
            sock.settimeout(1.0)
            
            print(f"[TLS Server] Listening on {self.host}:{self.port}")
            
            while self.running:
                try:
                    client_sock, addr = sock.accept()
                    
                    # ✅ Submit to thread pool (no manual thread creation)
                    self.executor.submit(self._wrap_and_handle_client, client_sock, addr)
                
                except socket.timeout:
                    continue
                except OSError as e:
                    if self.running and e.errno not in [10053, 10054]:
                        print(f"[TLS Server] Accept error: {e}")
                except Exception as e:
                    if self.running:
                        print(f"[TLS Server] Accept error: {e}")
        
        finally:
            sock.close()
            self.executor.shutdown(wait=False)
            print("[TLS Server] Stopped")
    
    def _wrap_and_handle_client(self, client_sock, addr):
        """Wrap with TLS and handle client"""
        secure_sock = None
        try:
            client_sock.settimeout(5.0)
            secure_sock = self.ssl_context.wrap_socket(client_sock, server_side=True)
            self._handle_client(secure_sock, addr)
        
        except ssl.SSLError:
            pass  # Silent TLS errors
        except socket.timeout:
            pass
        except OSError as e:
            if e.errno not in [10053, 10054]:
                print(f"[TLS Server] Error from {addr[0]}: {e}")
        except Exception as e:
            print(f"[TLS Server] Error from {addr[0]}: {e}")
        finally:
            if secure_sock:
                try:
                    secure_sock.close()
                except:
                    pass
            elif client_sock:
                try:
                    client_sock.close()
                except:
                    pass

    def _handle_client(self, secure_sock, addr):
        """Process client message"""
        try:
            # Read message type (1 byte)
            msg_type_byte = self._recv_exact(secure_sock, 1)
            if not msg_type_byte:
                return
            msg_type = msg_type_byte[0]
            
            # Read payload length (4 bytes)
            len_bytes = self._recv_exact(secure_sock, 4)
            if not len_bytes:
                return
            payload_len = struct.unpack('!I', len_bytes)[0]
            
            # Validate size
            if payload_len > 50 * 1024 * 1024:
                return
            
            # Read payload
            payload = self._recv_exact(secure_sock, payload_len)
            if not payload:
                return
            
            # Process by type
            if msg_type == 0x01:  # Text
                try:
                    data = json.loads(payload.decode('utf-8'))
                    text = data.get('text', '')
                    if text:
                        self.on_text_received(text, addr)
                except:
                    pass
            
            elif msg_type == 0x02:  # File
                try:
                    # Parse filename
                    fname_len = struct.unpack('!I', payload[:4])[0]
                    filename = payload[4:4+fname_len].decode('utf-8')
                    file_data = payload[4+fname_len:]
                    
                    if filename and file_data:
                        self.on_file_received(file_data, filename, addr)
                        
                except Exception as e:
                    print(f"[TLS Server] File error: {e}")
        
        except:
            pass
    
    def _recv_exact(self, sock, n):
        """Receive exactly n bytes"""
        data = b''
        while len(data) < n:
            try:
                chunk = sock.recv(n - len(data))
                if not chunk:
                    return None
                data += chunk
            except:
                return None
        return data

    def stop(self):
        """Stop server"""
        self.running = False
        if self.thread:
            self.thread.join(timeout=2.0)


class TcpChatClient:
    """Simple TLS Client - No pooling, stable for large files"""
    
    def __init__(self):
        self.ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = ssl.CERT_NONE

    def send_text(self, text: str, server_ip: str, server_port: int):
        payload = json.dumps({'text': text}).encode('utf-8')
        self._send_message(0x01, payload, server_ip, server_port)

    def send_file(self, filepath: str, server_ip: str, server_port: int):
        filename = os.path.basename(filepath)
        with open(filepath, "rb") as f:
            file_data = f.read()
        fname_bytes = filename.encode('utf-8')
        payload = struct.pack('!I', len(fname_bytes)) + fname_bytes + file_data
        self._send_message(0x02, payload, server_ip, server_port)
    
    def _send_message(self, msg_type: int, payload: bytes, server_ip: str, server_port: int):
        sock = None
        secure_sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10.0)
            
            secure_sock = self.ssl_context.wrap_socket(sock, server_hostname=server_ip)
            secure_sock.connect((server_ip, server_port))
            
            message = bytes([msg_type]) + struct.pack('!I', len(payload)) + payload
            secure_sock.sendall(message)
            
        except Exception as e:
            raise Exception(f"Send failed: {e}")
        finally:
            if secure_sock:
                try:
                    secure_sock.close()
                except:
                    pass
            elif sock:
                try:
                    sock.close()
                except:
                    pass
                
    def send_text(self, text: str, server_ip: str, server_port: int):
        """Send text message"""
        payload = json.dumps({'text': text}).encode('utf-8')
        self._send_message(0x01, payload, server_ip, server_port)

    def send_file(self, filepath: str, server_ip: str, server_port: int):
        """Send file"""
        filename = os.path.basename(filepath)
        
        with open(filepath, "rb") as f:
            file_data = f.read()
        
        fname_bytes = filename.encode('utf-8')
        payload = struct.pack('!I', len(fname_bytes)) + fname_bytes + file_data
        
        self._send_message(0x02, payload, server_ip, server_port)
    
    def _send_message(self, msg_type: int, payload: bytes, server_ip: str, server_port: int):
        """Send message - reuse connections for speed"""
        secure_sock = None
        try:
            # Get or create connection
            secure_sock = self._get_connection(server_ip, server_port)
            
            # ✅ Send all at once (faster than 3 separate calls)
            message = bytes([msg_type]) + struct.pack('!I', len(payload)) + payload
            secure_sock.sendall(message)
            
            # ✅ Return to pool instead of closing
            self._return_connection(server_ip, server_port, secure_sock)
            
        except Exception as e:
            # Close failed connection
            if secure_sock:
                try:
                    secure_sock.close()
                except:
                    pass
            raise Exception(f"Send failed: {e}")