"""
Simple Unit Tests for Secure Authentication Protocol
Author: Suneet Dungrani

Basic tests to verify core functionality.
"""

import pytest
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from protocol import SecureAuthProtocol


class TestBasicProtocol:
    """Test basic protocol operations"""
    
    def test_protocol_initialization(self):
        """Test protocol initialization"""
        protocol = SecureAuthProtocol()
        assert protocol is not None
        assert protocol.dh_parameters is not None
        assert len(protocol.sessions) == 0
    
    def test_nonce_generation(self):
        """Test nonce generation"""
        protocol = SecureAuthProtocol()
        nonce = protocol._generate_nonce()
        assert len(nonce) == 32
        assert isinstance(nonce, bytes)
    
    def test_session_creation(self):
        """Test session creation"""
        protocol = SecureAuthProtocol()
        session_id = "test_session"
        protocol.create_session(session_id)
        
        assert session_id in protocol.sessions
        assert protocol.sessions[session_id]['state'] == 'INIT'
        assert 'transcript' in protocol.sessions[session_id]
        assert 'nonces' in protocol.sessions[session_id]
        assert 'keys' in protocol.sessions[session_id]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])