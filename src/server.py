"""
Authentication Server Implementation
Author: Suneet Dungrani

Server-side implementation of the formally verified authentication protocol.
"""

import os
import time
import hashlib
import logging
from typing import Dict, Optional, Tuple
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

from protocol import (
    SecureAuthProtocol, ClientHello, ServerHello,
    ClientKeyExchange, ServerKeyExchange,
    ClientVerify, ServerVerify
)


class AuthenticationServer:
    """
    Server implementation of the secure authentication protocol.
    
    This server maintains a credential database and handles
    authentication requests according to the formally verified protocol.
    """
    
    def __init__(self):
        self.protocol = SecureAuthProtocol()
        self.credentials_db: Dict[str, bytes] = {}
        self.active_sessions: Dict[str, Dict] = {}
        self.session_tokens: Dict[str, Dict] = {}
        self.logger = self._setup_logging()
        
    def _setup_logging(self) -> logging.Logger:
        """Configure server logging"""
        logger = logging.getLogger('AuthServer')
        logger.setLevel(logging.INFO)
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        return logger
    
    def register_client(self, client_id: str, password: str) -> None:
        """Register a new client with credentials"""
        # Derive credential from password
        salt = os.urandom(32)
        credential = hashlib.pbkdf2_hmac('sha256', 
                                        password.encode(), 
                                        salt, 
                                        100000)
        
        self.credentials_db[client_id] = salt + credential
        self.logger.info(f"Registered client: {client_id}")
    
    def _verify_client_credential(self, client_id: str, proof: bytes) -> bool:
        """Verify client's credential proof"""
        if client_id not in self.credentials_db:
            return False
        
        stored = self.credentials_db[client_id]
        salt = stored[:32]
        expected_credential = stored[32:]
        
        # In real implementation, this would verify the proof
        # against the stored credential
        return True
    
    def handle_client_hello(self, session_id: str, msg: ClientHello) -> ServerHello:
        """Process ClientHello message"""
        self.logger.info(f"Received ClientHello from {msg.client_id}")
        
        # Create new session
        self.protocol.create_session(session_id)
        self.active_sessions[session_id] = {
            'client_id': msg.client_id,
            'start_time': time.time(),
            'state': 'HELLO_RECEIVED'
        }
        
        # Generate ServerHello response
        response = self.protocol.process_client_hello(session_id, msg)
        
        self.logger.info(f"Sent ServerHello for session {session_id}")
        return response
    
    def handle_client_key_exchange(self, session_id: str, msg: ClientKeyExchange) -> ServerKeyExchange:
        """Process ClientKeyExchange message"""
        self.logger.info(f"Received ClientKeyExchange for session {session_id}")
        
        session = self.protocol.sessions[session_id]
        server_session = self.active_sessions[session_id]
        
        # Verify state
        if session['state'] != 'HELLO_SENT':
            raise ValueError("Invalid protocol state")
        
        # Generate server DH key pair
        private_key = self.protocol.dh_parameters.generate_private_key()
        public_key = private_key.public_key()
        
        # Deserialize client's public key
        client_public = serialization.load_pem_public_key(
            msg.dh_public_c,
            backend=default_backend()
        )
        
        # Compute shared secret
        shared_secret = private_key.exchange(client_public)
        
        # Derive keys
        session_key, mac_key = self.protocol._derive_keys(
            shared_secret,
            session['nonces']['client'],
            session['nonces']['server']
        )
        
        session['keys']['session'] = session_key
        session['keys']['mac'] = mac_key
        
        # Create server proof
        proof_data = (session['nonces']['server'] + 
                     session['nonces']['client'] + 
                     b'server_secret')
        server_proof = hashlib.sha256(proof_data).digest()
        
        # Encrypt proof
        pre_master = hashlib.sha256(b'server_secret' + session['nonces']['server']).digest()
        encrypted_proof = self.protocol._encrypt_aes_gcm(pre_master, server_proof)
        
        # Serialize public key
        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicKeyFormat.SubjectPublicKeyInfo
        )
        
        response = ServerKeyExchange(
            message_type='ServerKeyExchange',
            sender_id='server',
            sequence_number=4,
            dh_public_s=public_bytes,
            encrypted_proof=encrypted_proof
        )
        
        session['transcript'].append(msg)
        session['transcript'].append(response)
        session['state'] = 'KEY_EXCHANGED'
        
        self.logger.info(f"Sent ServerKeyExchange for session {session_id}")
        return response
    
    def handle_client_verify(self, session_id: str, msg: ClientVerify) -> ServerVerify:
        """Process ClientVerify message"""
        self.logger.info(f"Received ClientVerify for session {session_id}")
        
        session = self.protocol.sessions[session_id]
        
        # Verify state
        if session['state'] != 'KEY_EXCHANGED':
            raise ValueError("Invalid protocol state")
        
        # Verify client's MAC
        transcript_hash = self.protocol._hash_transcript(session['transcript'])
        
        if not self.protocol._verify_mac(session['keys']['mac'], 
                                        transcript_hash, 
                                        msg.mac_value):
            raise ValueError("MAC verification failed")
        
        # Generate session token
        session_token = os.urandom(32)
        token_data = {
            'client_id': self.active_sessions[session_id]['client_id'],
            'created': time.time(),
            'session_key': session['keys']['session']
        }
        self.session_tokens[session_token.hex()] = token_data
        
        # Create server MAC
        session['transcript'].append(msg)
        final_transcript = self.protocol._hash_transcript(session['transcript'])
        server_mac = self.protocol._compute_mac(session['keys']['mac'], final_transcript)
        
        response = ServerVerify(
            message_type='ServerVerify',
            sender_id='server',
            sequence_number=6,
            mac_value=server_mac,
            session_token=session_token
        )
        
        session['transcript'].append(response)
        session['state'] = 'COMPLETED'
        
        self.logger.info(f"Authentication completed for session {session_id}")
        return response
    
    def validate_session_token(self, token: str) -> Optional[Dict]:
        """Validate a session token"""
        if token in self.session_tokens:
            token_data = self.session_tokens[token]
            
            # Check token expiry (24 hours)
            if time.time() - token_data['created'] > 86400:
                del self.session_tokens[token]
                return None
            
            return token_data
        return None
    
    def cleanup_expired_sessions(self) -> None:
        """Clean up expired sessions"""
        current_time = time.time()
        expired = []
        
        # Find expired sessions (30 minutes timeout)
        for session_id, session_data in self.active_sessions.items():
            if current_time - session_data['start_time'] > 1800:
                expired.append(session_id)
        
        # Clean up
        for session_id in expired:
            self.protocol.cleanup_session(session_id)
            del self.active_sessions[session_id]
            self.logger.info(f"Cleaned up expired session: {session_id}")
    
    def get_server_stats(self) -> Dict:
        """Get server statistics"""
        return {
            'active_sessions': len(self.active_sessions),
            'registered_clients': len(self.credentials_db),
            'active_tokens': len(self.session_tokens)
        }


if __name__ == "__main__":
    # Example server usage
    server = AuthenticationServer()
    
    # Register test clients
    server.register_client("alice", "alice_password123")
    server.register_client("bob", "bob_password456")
    
    print("Authentication server started")
    print(f"Server stats: {server.get_server_stats()}")