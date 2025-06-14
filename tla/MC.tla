----------------------------- MODULE MC -----------------------------
(***************************************************************************
 * Model Checking Configuration for AuthProtocol
 * Author: Suneet Dungrani
 * 
 * This module configures the TLC model checker to verify the
 * authentication protocol specification with finite state space.
 ***************************************************************************)

EXTENDS AuthProtocol

\* Model values for finite model checking
const_Clients == {"Alice", "Bob"}
const_Servers == {"Server"}
const_Nonces == {"N1", "N2", "N3", "N4"}
const_Keys == {"K1", "K2", "K3"}
const_NULL == "NULL"

\* State constraint to limit state space
StateConstraint ==
    /\ Cardinality(messages) <= 20
    /\ Cardinality(sessionKeys) <= 4
    /\ Cardinality(compromised) <= 2

\* Properties to check
PROPERTY Authentication
PROPERTY KeySecrecy
PROPERTY SessionUniqueness
PROPERTY ProtocolConsistency
PROPERTY NoReplay

\* Temporal properties
PROPERTY EventualCompletion

================================================================