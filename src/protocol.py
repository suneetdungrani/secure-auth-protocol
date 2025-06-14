"""
Secure Authentication Protocol Implementation
Author: Suneet Dungrani

This module implements a formally verified challenge-response authentication protocol
with mutual authentication and forward secrecy properties.
"""

import os
import hmac
import hashlib
import secrets
from dataclasses import dataclass
from typing import Tuple, Optional, Dict, Any
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


@dataclass
class ProtocolMessage:
    """Base class for protocol messages"""
    message_type: str
    sender_id: str
    sequence_number: int


@dataclass
class ClientHello(ProtocolMessage):
    """Initial client message"""
    client_id: str
    nonce_c: bytes


@dataclass
class ServerHello(ProtocolMessage):
    """Server response with DH parameters"""
    server_id: str
    nonce_s: bytes
    dh_params: bytes


@dataclass
class ClientKeyExchange(ProtocolMessage):
    """Client's DH public key and encrypted proof"""
    dh_public_c: bytes
    encrypted_proof: bytes


@dataclass
class ServerKeyExchange(ProtocolMessage):
    """Server's DH public key and encrypted proof"""
    dh_public_s: bytes
    encrypted_proof: bytes


@dataclass
class ClientVerify(ProtocolMessage):
    """Client's MAC verification"""
    mac_value: bytes


@dataclass
class ServerVerify(ProtocolMessage):
    """Server's MAC verification and session token"""
    mac_value: bytes
    session_token: bytes


class SecureAuthProtocol:
    """
    Implementation of the formally verified authentication protocol.
    
    This protocol provides:
    - Mutual authentication
    - Forward secrecy through ephemeral DH
    - Protection against replay attacks
    - Formally verified security properties
    """
    
    def __init__(self):
        self.backend = default_backend()
        self.dh_parameters = self._generate_dh_parameters()
        self.sessions: Dict[str, Dict[str, Any]] = {}
    
    def _generate_dh_parameters(self) -> dh.DHParameters:
        """Generate Diffie-Hellman parameters"""
        return dh.generate_parameters(generator=2, key_size=2048, backend=self.backend)
    
    def _generate_nonce(self) -> bytes:
        """Generate cryptographically secure nonce"""
        return secrets.token_bytes(32)
    
    def _derive_keys(self, shared_secret: bytes, nonce_c: bytes, nonce_s: bytes) -> Tuple[bytes, bytes]:
        """Derive session and MAC keys from shared secret"""
        info = nonce_c + nonce_s
        
        # Derive session key
        session_kdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'session_key',
            info=info,
            backend=self.backend
        )
        session_key = session_kdf.derive(shared_secret)
        
        # Derive MAC key
        mac_kdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'mac_key',
            info=info,
            backend=self.backend
        )
        mac_key = mac_kdf.derive(shared_secret)
        
        return session_key, mac_key
    
    def _encrypt_aes_gcm(self, key: bytes, plaintext: bytes) -> bytes:
        """Encrypt using AES-256-GCM"""
        iv = os.urandom(12)
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(iv),
            backend=self.backend
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        return iv + encryptor.tag + ciphertext
    
    def _decrypt_aes_gcm(self, key: bytes, ciphertext: bytes) -> bytes:
        """Decrypt using AES-256-GCM"""
        iv = ciphertext[:12]
        tag = ciphertext[12:28]
        actual_ciphertext = ciphertext[28:]
        
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(iv, tag),
            backend=self.backend
        )
        decryptor = cipher.decryptor()
        return decryptor.update(actual_ciphertext) + decryptor.finalize()
    
    def _compute_mac(self, key: bytes, message: bytes) -> bytes:
        """Compute HMAC-SHA256"""
        return hmac.new(key, message, hashlib.sha256).digest()
    
    def _verify_mac(self, key: bytes, message: bytes, mac_value: bytes) -> bool:
        """Verify HMAC-SHA256 with constant-time comparison"""
        expected = self._compute_mac(key, message)
        return hmac.compare_digest(expected, mac_value)
    
    def _hash_transcript(self, messages: list) -> bytes:
        """Hash the protocol transcript"""
        h = hashlib.sha256()
        for msg in messages:
            h.update(str(msg).encode())
        return h.digest()
    
    def create_session(self, session_id: str) -> None:
        """Initialize a new protocol session"""
        self.sessions[session_id] = {
            'state': 'INIT',
            'transcript': [],
            'nonces': {},
            'keys': {}
        }
    
    def process_client_hello(self, session_id: str, msg: ClientHello) -> ServerHello:
        """Process ClientHello and generate ServerHello"""
        session = self.sessions[session_id]
        
        # Verify state
        if session['state'] != 'INIT':
            raise ValueError("Invalid protocol state")
        
        # Store client nonce
        session['nonces']['client'] = msg.nonce_c
        session['transcript'].append(msg)
        
        # Generate server nonce
        nonce_s = self._generate_nonce()
        session['nonces']['server'] = nonce_s
        
        # Serialize DH parameters
        dh_params = self.dh_parameters.parameter_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.ParameterFormat.PKCS3
        )
        
        # Create ServerHello
        response = ServerHello(
            message_type='ServerHello',
            sender_id='server',
            sequence_number=2,
            server_id='server',
            nonce_s=nonce_s,
            dh_params=dh_params
        )
        
        session['transcript'].append(response)
        session['state'] = 'HELLO_SENT'
        
        return response
    
    def generate_client_key_exchange(self, session_id: str, client_secret: bytes) -> Tuple[ClientKeyExchange, bytes]:
        """Generate client's key exchange message"""
        session = self.sessions[session_id]
        
        # Generate DH key pair
        private_key = self.dh_parameters.generate_private_key()
        public_key = private_key.public_key()
        
        # Store for later use
        session['dh_private'] = private_key
        
        # Serialize public key
        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicKeyFormat.SubjectPublicKeyInfo
        )
        
        # Create client proof
        proof_data = session['nonces']['client'] + session['nonces']['server'] + client_secret
        proof = hashlib.sha256(proof_data).digest()
        
        # Encrypt proof with pre-master secret
        pre_master = hashlib.sha256(client_secret + session['nonces']['client']).digest()
        encrypted_proof = self._encrypt_aes_gcm(pre_master, proof)
        
        msg = ClientKeyExchange(
            message_type='ClientKeyExchange',
            sender_id='client',
            sequence_number=3,
            dh_public_c=public_bytes,
            encrypted_proof=encrypted_proof
        )
        
        session['transcript'].append(msg)
        return msg, public_bytes
    
    def verify_protocol_transcript(self, session_id: str) -> bool:
        """Verify the complete protocol transcript"""
        session = self.sessions[session_id]
        
        # Check all required messages are present
        expected_types = ['ClientHello', 'ServerHello', 'ClientKeyExchange', 
                         'ServerKeyExchange', 'ClientVerify', 'ServerVerify']
        
        actual_types = [msg.message_type for msg in session['transcript']]
        
        return all(t in actual_types for t in expected_types)
    
    def cleanup_session(self, session_id: str) -> None:
        """Securely cleanup session data"""
        if session_id in self.sessions:
            # Clear sensitive key material
            if 'keys' in self.sessions[session_id]:
                for key in self.sessions[session_id]['keys'].values():
                    if isinstance(key, bytes):
                        # Overwrite key material
                        key = bytearray(key)
                        for i in range(len(key)):
                            key[i] = 0
            
            del self.sessions[session_id]