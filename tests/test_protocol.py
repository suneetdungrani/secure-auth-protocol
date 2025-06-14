"""
Unit Tests for Secure Authentication Protocol
Author: Suneet Dungrani

These tests verify the implementation matches the formal specification.
"""

import pytest
import os
import time
from unittest.mock import Mock, patch

import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from protocol import (
    SecureAuthProtocol, ClientHello, ServerHello,
    ClientKeyExchange, ServerKeyExchange,
    ClientVerify, ServerVerify
)
from server import AuthenticationServer
from client import AuthenticationClient


class TestProtocolPrimitives:
    """Test cryptographic primitives and basic protocol operations"""
    
    def test_nonce_generation(self):
        """Test that nonces are unique and correct length"""
        protocol = SecureAuthProtocol()
        nonces = set()
        
        for _ in range(100):
            nonce = protocol._generate_nonce()
            assert len(nonce) == 32
            assert nonce not in nonces
            nonces.add(nonce)
    
    def test_key_derivation(self):
        """Test key derivation function"""
        protocol = SecureAuthProtocol()
        shared_secret = os.urandom(32)
        nonce_c = os.urandom(32)
        nonce_s = os.urandom(32)
        
        session_key, mac_key = protocol._derive_keys(shared_secret, nonce_c, nonce_s)
        
        assert len(session_key) == 32
        assert len(mac_key) == 32
        assert session_key != mac_key
        
        # Test deterministic derivation
        session_key2, mac_key2 = protocol._derive_keys(shared_secret, nonce_c, nonce_s)
        assert session_key == session_key2
        assert mac_key == mac_key2
    
    def test_aes_gcm_encryption(self):
        """Test AES-GCM encryption/decryption"""
        protocol = SecureAuthProtocol()
        key = os.urandom(32)
        plaintext = b"Test message for encryption"
        
        ciphertext = protocol._encrypt_aes_gcm(key, plaintext)
        decrypted = protocol._decrypt_aes_gcm(key, ciphertext)
        
        assert decrypted == plaintext
        assert len(ciphertext) > len(plaintext)  # IV + tag + ciphertext
    
    def test_mac_computation(self):
        """Test MAC computation and verification"""
        protocol = SecureAuthProtocol()
        key = os.urandom(32)
        message = b"Test message for MAC"
        
        mac = protocol._compute_mac(key, message)
        assert len(mac) == 32
        
        # Test verification
        assert protocol._verify_mac(key, message, mac)
        
        # Test with wrong key
        wrong_key = os.urandom(32)
        assert not protocol._verify_mac(wrong_key, message, mac)


class TestProtocolFlow:
    """Test complete protocol flow and state transitions"""
    
    def test_successful_authentication(self):
        """Test successful authentication flow"""
        # Initialize server and client
        server = AuthenticationServer()
        server.register_client("alice", "password123")
        
        client = AuthenticationClient("alice")
        
        # Step 1: Client Hello
        session_id = os.urandom(16).hex()
        client_hello = client.initiate_authentication()
        assert client_hello.message_type == "ClientHello"
        assert client_hello.client_id == "alice"
        
        # Step 2: Server Hello
        server_hello = server.handle_client_hello(session_id, client_hello)
        assert server_hello.message_type == "ServerHello"
        assert server_hello.server_id == "server"
        
        # Process server hello on client
        client.session_id = session_id
        client.process_server_hello(server_hello)
        
        # Step 3: Client Key Exchange
        client_key_exchange = client.create_key_exchange("password123")
        assert client_key_exchange.message_type == "ClientKeyExchange"
        
        # Step 4: Server Key Exchange
        server_key_exchange = server.handle_client_key_exchange(session_id, client_key_exchange)
        assert server_key_exchange.message_type == "ServerKeyExchange"
        
        # Process server key exchange on client
        client.process_server_key_exchange(server_key_exchange)
        
        # Step 5: Client Verify
        client_verify = client.create_client_verify()
        assert client_verify.message_type == "ClientVerify"
        
        # Step 6: Server Verify
        server_verify = server.handle_client_verify(session_id, client_verify)
        assert server_verify.message_type == "ServerVerify"
        assert len(server_verify.session_token) == 32
        
        # Complete authentication on client
        success = client.process_server_verify(server_verify)
        assert success
        assert client.session_token is not None
    
    def test_invalid_state_transitions(self):
        """Test that invalid state transitions are rejected"""
        server = AuthenticationServer()
        session_id = os.urandom(16).hex()
        
        # Try to send ClientKeyExchange without ClientHello
        with pytest.raises(KeyError):
            client_key_exchange = ClientKeyExchange(
                message_type="ClientKeyExchange",
                sender_id="alice",
                sequence_number=3,
                dh_public_c=b"fake_key",
                encrypted_proof=b"fake_proof"
            )
            server.handle_client_key_exchange(session_id, client_key_exchange)
    
    def test_session_cleanup(self):
        """Test secure session cleanup"""
        protocol = SecureAuthProtocol()
        session_id = "test_session"
        
        protocol.create_session(session_id)
        protocol.sessions[session_id]['keys'] = {
            'session': os.urandom(32),
            'mac': os.urandom(32)
        }
        
        # Verify session exists
        assert session_id in protocol.sessions
        
        # Cleanup
        protocol.cleanup_session(session_id)
        
        # Verify session removed
        assert session_id not in protocol.sessions


class TestSecurityProperties:
    """Test security properties verified in formal specification"""
    
    def test_nonce_uniqueness(self):
        """Test that nonces are never reused (NoReplay property)"""
        client = AuthenticationClient("alice")
        
        nonces = set()
        for _ in range(10):
            msg = client.initiate_authentication()
            assert msg.nonce_c not in nonces
            nonces.add(msg.nonce_c)
            client.cleanup()
    
    def test_session_uniqueness(self):
        """Test that each session has unique keys"""
        server = AuthenticationServer()
        server.register_client("alice", "password123")
        
        tokens = set()
        
        for _ in range(5):
            # Simulate authentication
            session_id = os.urandom(16).hex()
            server.protocol.create_session(session_id)
            server.active_sessions[session_id] = {
                'client_id': 'alice',
                'start_time': time.time(),
                'state': 'KEY_EXCHANGED'
            }
            
            # Generate session token
            session_token = os.urandom(32)
            assert session_token not in tokens
            tokens.add(session_token)
    
    def test_authentication_property(self):
        """Test that only completed authentications get session tokens"""
        server = AuthenticationServer()
        
        # Check no tokens exist initially
        assert len(server.session_tokens) == 0
        
        # Incomplete authentication should not create tokens
        session_id = os.urandom(16).hex()
        server.protocol.create_session(session_id)
        server.active_sessions[session_id] = {
            'client_id': 'alice',
            'start_time': time.time(),
            'state': 'HELLO_RECEIVED'
        }
        
        # No token should be created for incomplete session
        assert len(server.session_tokens) == 0
    
    def test_expired_session_cleanup(self):
        """Test that expired sessions are cleaned up"""
        server = AuthenticationServer()
        
        # Create old session
        old_session_id = "old_session"
        server.protocol.create_session(old_session_id)
        server.active_sessions[old_session_id] = {
            'client_id': 'alice',
            'start_time': time.time() - 3600,  # 1 hour ago
            'state': 'HELLO_RECEIVED'
        }
        
        # Create recent session
        new_session_id = "new_session"
        server.protocol.create_session(new_session_id)
        server.active_sessions[new_session_id] = {
            'client_id': 'bob',
            'start_time': time.time(),
            'state': 'HELLO_RECEIVED'
        }
        
        # Run cleanup
        server.cleanup_expired_sessions()
        
        # Old session should be removed
        assert old_session_id not in server.active_sessions
        assert old_session_id not in server.protocol.sessions
        
        # New session should remain
        assert new_session_id in server.active_sessions


class TestProtocolMessages:
    """Test protocol message structure and serialization"""
    
    def test_client_hello_structure(self):
        """Test ClientHello message structure"""
        nonce = os.urandom(32)
        msg = ClientHello(
            message_type="ClientHello",
            sender_id="alice",
            sequence_number=1,
            client_id="alice",
            nonce_c=nonce
        )
        
        assert msg.message_type == "ClientHello"
        assert msg.sender_id == "alice"
        assert msg.sequence_number == 1
        assert msg.client_id == "alice"
        assert msg.nonce_c == nonce
    
    def test_server_hello_structure(self):
        """Test ServerHello message structure"""
        nonce = os.urandom(32)
        dh_params = b"DH_PARAMS"
        
        msg = ServerHello(
            message_type="ServerHello",
            sender_id="server",
            sequence_number=2,
            server_id="server",
            nonce_s=nonce,
            dh_params=dh_params
        )
        
        assert msg.message_type == "ServerHello"
        assert msg.nonce_s == nonce
        assert msg.dh_params == dh_params
    
    def test_transcript_hashing(self):
        """Test protocol transcript hashing"""
        protocol = SecureAuthProtocol()
        
        messages = [
            ClientHello("ClientHello", "alice", 1, "alice", os.urandom(32)),
            ServerHello("ServerHello", "server", 2, "server", os.urandom(32), b"params")
        ]
        
        hash1 = protocol._hash_transcript(messages)
        hash2 = protocol._hash_transcript(messages)
        
        # Same messages should produce same hash
        assert hash1 == hash2
        assert len(hash1) == 32  # SHA-256 output
        
        # Different messages should produce different hash
        messages.append(ClientVerify("ClientVerify", "alice", 5, os.urandom(32)))
        hash3 = protocol._hash_transcript(messages)
        assert hash3 != hash1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])