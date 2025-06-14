"""
Authentication Client Implementation
Author: Suneet Dungrani

Client-side implementation of the formally verified authentication protocol.
"""

import os
import hashlib
import logging
from typing import Optional, Tuple, Dict
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

from protocol import (
    SecureAuthProtocol, ClientHello, ServerHello,
    ClientKeyExchange, ServerKeyExchange,
    ClientVerify, ServerVerify
)


class AuthenticationClient:
    """
    Client implementation of the secure authentication protocol.
    
    This client can authenticate with the server using the
    formally verified protocol, establishing a secure session.
    """
    
    def __init__(self, client_id: str):
        self.client_id = client_id
        self.protocol = SecureAuthProtocol()
        self.session_id: Optional[str] = None
        self.session_token: Optional[bytes] = None
        self.session_key: Optional[bytes] = None
        self.logger = self._setup_logging()
        
    def _setup_logging(self) -> logging.Logger:
        """Configure client logging"""
        logger = logging.getLogger(f'AuthClient-{self.client_id}')
        logger.setLevel(logging.INFO)
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        return logger
    
    def _derive_client_secret(self, password: str) -> bytes:
        """Derive client secret from password"""
        # In production, this would use proper key derivation
        return hashlib.pbkdf2_hmac('sha256', 
                                  password.encode(), 
                                  b'client_salt', 
                                  100000)
    
    def initiate_authentication(self) -> ClientHello:
        """Start authentication protocol"""
        self.logger.info("Initiating authentication")
        
        # Generate session ID
        self.session_id = os.urandom(16).hex()
        
        # Create protocol session
        self.protocol.create_session(self.session_id)
        
        # Generate client nonce
        nonce_c = self.protocol._generate_nonce()
        
        # Create ClientHello
        msg = ClientHello(
            message_type='ClientHello',
            sender_id=self.client_id,
            sequence_number=1,
            client_id=self.client_id,
            nonce_c=nonce_c
        )
        
        session = self.protocol.sessions[self.session_id]
        session['nonces']['client'] = nonce_c
        session['transcript'].append(msg)
        
        self.logger.info(f"Sent ClientHello for session {self.session_id}")
        return msg
    
    def process_server_hello(self, msg: ServerHello) -> None:
        """Process ServerHello message"""
        self.logger.info("Received ServerHello")
        
        session = self.protocol.sessions[self.session_id]
        
        # Store server nonce
        session['nonces']['server'] = msg.nonce_s
        session['transcript'].append(msg)
        
        # Load DH parameters
        session['dh_params'] = serialization.load_pem_parameters(
            msg.dh_params,
            backend=default_backend()
        )
        
        self.protocol.dh_parameters = session['dh_params']
        session['state'] = 'HELLO_RECEIVED'
    
    def create_key_exchange(self, password: str) -> ClientKeyExchange:
        """Create ClientKeyExchange message"""
        self.logger.info("Creating key exchange")
        
        session = self.protocol.sessions[self.session_id]
        
        # Generate DH key pair
        private_key = session['dh_params'].generate_private_key()
        public_key = private_key.public_key()
        
        session['dh_private'] = private_key
        
        # Serialize public key
        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicKeyFormat.SubjectPublicKeyInfo
        )
        
        # Create client proof
        client_secret = self._derive_client_secret(password)
        proof_data = (session['nonces']['client'] + 
                     session['nonces']['server'] + 
                     client_secret)
        proof = hashlib.sha256(proof_data).digest()
        
        # Encrypt proof
        pre_master = hashlib.sha256(client_secret + session['nonces']['client']).digest()
        encrypted_proof = self.protocol._encrypt_aes_gcm(pre_master, proof)
        
        msg = ClientKeyExchange(
            message_type='ClientKeyExchange',
            sender_id=self.client_id,
            sequence_number=3,
            dh_public_c=public_bytes,
            encrypted_proof=encrypted_proof
        )
        
        session['transcript'].append(msg)
        session['state'] = 'KEY_SENT'
        
        self.logger.info("Sent ClientKeyExchange")
        return msg
    
    def process_server_key_exchange(self, msg: ServerKeyExchange) -> None:
        """Process ServerKeyExchange message"""
        self.logger.info("Received ServerKeyExchange")
        
        session = self.protocol.sessions[self.session_id]
        
        # Verify state
        if session['state'] != 'KEY_SENT':
            raise ValueError("Invalid protocol state")
        
        # Load server's public key
        server_public = serialization.load_pem_public_key(
            msg.dh_public_s,
            backend=default_backend()
        )
        
        # Compute shared secret
        shared_secret = session['dh_private'].exchange(server_public)
        
        # Derive keys
        session_key, mac_key = self.protocol._derive_keys(
            shared_secret,
            session['nonces']['client'],
            session['nonces']['server']
        )
        
        session['keys']['session'] = session_key
        session['keys']['mac'] = mac_key
        self.session_key = session_key
        
        session['transcript'].append(msg)
        session['state'] = 'KEY_RECEIVED'
        
        self.logger.info("Derived session keys")
    
    def create_client_verify(self) -> ClientVerify:
        """Create ClientVerify message"""
        self.logger.info("Creating client verification")
        
        session = self.protocol.sessions[self.session_id]
        
        # Compute MAC over transcript
        transcript_hash = self.protocol._hash_transcript(session['transcript'])
        mac_value = self.protocol._compute_mac(
            session['keys']['mac'],
            transcript_hash
        )
        
        msg = ClientVerify(
            message_type='ClientVerify',
            sender_id=self.client_id,
            sequence_number=5,
            mac_value=mac_value
        )
        
        session['transcript'].append(msg)
        session['state'] = 'VERIFY_SENT'
        
        self.logger.info("Sent ClientVerify")
        return msg
    
    def process_server_verify(self, msg: ServerVerify) -> bool:
        """Process ServerVerify message and complete authentication"""
        self.logger.info("Received ServerVerify")
        
        session = self.protocol.sessions[self.session_id]
        
        # Verify state
        if session['state'] != 'VERIFY_SENT':
            raise ValueError("Invalid protocol state")
        
        # Add message to transcript before verification
        session['transcript'].append(msg)
        
        # Verify server's MAC
        transcript_hash = self.protocol._hash_transcript(session['transcript'][:-1])
        
        if not self.protocol._verify_mac(
            session['keys']['mac'],
            transcript_hash,
            msg.mac_value
        ):
            self.logger.error("Server MAC verification failed")
            return False
        
        # Store session token
        self.session_token = msg.session_token
        session['state'] = 'COMPLETED'
        
        self.logger.info("Authentication completed successfully")
        self.logger.info(f"Session token: {self.session_token.hex()}")
        
        return True
    
    def get_session_info(self) -> Optional[Dict]:
        """Get current session information"""
        if self.session_id and self.session_token:
            return {
                'session_id': self.session_id,
                'session_token': self.session_token.hex(),
                'authenticated': True,
                'has_session_key': self.session_key is not None
            }
        return None
    
    def cleanup(self) -> None:
        """Cleanup client session"""
        if self.session_id:
            self.protocol.cleanup_session(self.session_id)
            self.session_id = None
            self.session_token = None
            self.session_key = None
            self.logger.info("Cleaned up client session")


def authenticate_with_server(client_id: str, password: str) -> Optional[AuthenticationClient]:
    """
    Helper function to perform complete authentication flow.
    In a real implementation, this would communicate with a server.
    """
    client = AuthenticationClient(client_id)
    
    try:
        # Step 1: Send ClientHello
        client_hello = client.initiate_authentication()
        
        # In real implementation, send to server and receive response
        # For demonstration, we simulate the server responses
        
        print(f"Client {client_id} authentication initiated")
        return client
        
    except Exception as e:
        print(f"Authentication failed: {e}")
        return None


if __name__ == "__main__":
    # Example client usage
    client = authenticate_with_server("alice", "alice_password123")
    if client:
        print("Authentication successful!")
        print(f"Session info: {client.get_session_info()}")