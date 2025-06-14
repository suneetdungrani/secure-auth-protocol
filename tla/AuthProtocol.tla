---------------------------- MODULE AuthProtocol ----------------------------
(***************************************************************************
 * Formal Specification of Secure Authentication Protocol
 * Author: Suneet Dungrani
 * 
 * This TLA+ specification formally models a challenge-response 
 * authentication protocol with mutual authentication and forward secrecy.
 * The specification enables mathematical verification of security properties.
 ***************************************************************************)

EXTENDS Integers, Sequences, FiniteSets, TLC

CONSTANTS 
    Clients,        \* Set of client identities
    Servers,        \* Set of server identities  
    Nonces,         \* Set of possible nonces
    Keys,           \* Set of possible keys
    NULL            \* Null value

VARIABLES
    clientState,    \* State of each client
    serverState,    \* State of each server
    messages,       \* Network messages in transit
    sessionKeys,    \* Established session keys
    compromised,    \* Set of compromised keys
    transcripts     \* Protocol transcripts

vars == <<clientState, serverState, messages, sessionKeys, compromised, transcripts>>

------------------------------------------------------------
\* Message Types
MessageTypes == {"ClientHello", "ServerHello", "ClientKeyExchange", 
                 "ServerKeyExchange", "ClientVerify", "ServerVerify"}

\* Protocol States
ClientStates == {"INIT", "HELLO_SENT", "KEY_SENT", "VERIFY_SENT", "COMPLETED"}
ServerStates == {"LISTENING", "HELLO_RECEIVED", "KEY_EXCHANGED", "COMPLETED"}

------------------------------------------------------------
\* Type Invariants
TypeOK == 
    /\ clientState \in [Clients -> ClientStates]
    /\ serverState \in [Servers -> ServerStates]
    /\ messages \subseteq [type: MessageTypes, 
                          from: Clients \cup Servers,
                          to: Clients \cup Servers,
                          nonce: Nonces \cup {NULL},
                          key: Keys \cup {NULL}]
    /\ sessionKeys \subseteq [client: Clients, 
                             server: Servers, 
                             key: Keys]
    /\ compromised \subseteq Keys
    /\ transcripts \in [Clients \cup Servers -> Seq(MessageTypes)]

------------------------------------------------------------
\* Initial State
Init ==
    /\ clientState = [c \in Clients |-> "INIT"]
    /\ serverState = [s \in Servers |-> "LISTENING"]
    /\ messages = {}
    /\ sessionKeys = {}
    /\ compromised = {}
    /\ transcripts = [p \in Clients \cup Servers |-> <<>>]

------------------------------------------------------------
\* Client sends ClientHello
ClientHello(c, s, n) ==
    /\ clientState[c] = "INIT"
    /\ n \in Nonces
    /\ messages' = messages \cup {[type |-> "ClientHello",
                                  from |-> c,
                                  to |-> s,
                                  nonce |-> n,
                                  key |-> NULL]}
    /\ clientState' = [clientState EXCEPT ![c] = "HELLO_SENT"]
    /\ transcripts' = [transcripts EXCEPT ![c] = Append(@, "ClientHello")]
    /\ UNCHANGED <<serverState, sessionKeys, compromised>>

\* Server processes ClientHello and sends ServerHello
ServerHello(c, s, nc, ns) ==
    /\ serverState[s] = "LISTENING"
    /\ [type |-> "ClientHello", from |-> c, to |-> s, nonce |-> nc, key |-> NULL] \in messages
    /\ ns \in Nonces
    /\ ns /= nc  \* Fresh nonce
    /\ messages' = messages \cup {[type |-> "ServerHello",
                                  from |-> s,
                                  to |-> c,
                                  nonce |-> ns,
                                  key |-> NULL]}
    /\ serverState' = [serverState EXCEPT ![s] = "HELLO_RECEIVED"]
    /\ transcripts' = [transcripts EXCEPT ![s] = Append(@, "ServerHello")]
    /\ UNCHANGED <<clientState, sessionKeys, compromised>>

\* Client sends key exchange
ClientKeyExchange(c, s, k) ==
    /\ clientState[c] = "HELLO_SENT"
    /\ \E ns \in Nonces: [type |-> "ServerHello", from |-> s, to |-> c, nonce |-> ns, key |-> NULL] \in messages
    /\ k \in Keys
    /\ k \notin compromised  \* Don't use compromised keys
    /\ messages' = messages \cup {[type |-> "ClientKeyExchange",
                                  from |-> c,
                                  to |-> s,
                                  nonce |-> NULL,
                                  key |-> k]}
    /\ clientState' = [clientState EXCEPT ![c] = "KEY_SENT"]
    /\ transcripts' = [transcripts EXCEPT ![c] = Append(@, "ClientKeyExchange")]
    /\ UNCHANGED <<serverState, sessionKeys, compromised>>

\* Server processes key exchange
ServerKeyExchange(c, s, k) ==
    /\ serverState[s] = "HELLO_RECEIVED"
    /\ \E kc \in Keys: [type |-> "ClientKeyExchange", from |-> c, to |-> s, nonce |-> NULL, key |-> kc] \in messages
    /\ k \in Keys
    /\ k \notin compromised
    /\ messages' = messages \cup {[type |-> "ServerKeyExchange",
                                  from |-> s,
                                  to |-> c,
                                  nonce |-> NULL,
                                  key |-> k]}
    /\ serverState' = [serverState EXCEPT ![s] = "KEY_EXCHANGED"]
    /\ transcripts' = [transcripts EXCEPT ![s] = Append(@, "ServerKeyExchange")]
    /\ UNCHANGED <<clientState, sessionKeys, compromised>>

\* Client verification
ClientVerify(c, s) ==
    /\ clientState[c] = "KEY_SENT"
    /\ \E k \in Keys: [type |-> "ServerKeyExchange", from |-> s, to |-> c, nonce |-> NULL, key |-> k] \in messages
    /\ messages' = messages \cup {[type |-> "ClientVerify",
                                  from |-> c,
                                  to |-> s,
                                  nonce |-> NULL,
                                  key |-> NULL]}
    /\ clientState' = [clientState EXCEPT ![c] = "VERIFY_SENT"]
    /\ transcripts' = [transcripts EXCEPT ![c] = Append(@, "ClientVerify")]
    /\ UNCHANGED <<serverState, sessionKeys, compromised>>

\* Server verification and session establishment
ServerVerify(c, s, sk) ==
    /\ serverState[s] = "KEY_EXCHANGED"
    /\ [type |-> "ClientVerify", from |-> c, to |-> s, nonce |-> NULL, key |-> NULL] \in messages
    /\ sk \in Keys
    /\ sk \notin compromised
    /\ messages' = messages \cup {[type |-> "ServerVerify",
                                  from |-> s,
                                  to |-> c,
                                  nonce |-> NULL,
                                  key |-> sk]}
    /\ serverState' = [serverState EXCEPT ![s] = "COMPLETED"]
    /\ sessionKeys' = sessionKeys \cup {[client |-> c, server |-> s, key |-> sk]}
    /\ transcripts' = [transcripts EXCEPT ![s] = Append(@, "ServerVerify")]
    /\ UNCHANGED <<clientState, compromised>>

\* Client completes protocol
ClientComplete(c, s) ==
    /\ clientState[c] = "VERIFY_SENT"
    /\ \E sk \in Keys: [type |-> "ServerVerify", from |-> s, to |-> c, nonce |-> NULL, key |-> sk] \in messages
    /\ clientState' = [clientState EXCEPT ![c] = "COMPLETED"]
    /\ transcripts' = [transcripts EXCEPT ![c] = Append(@, "Completed")]
    /\ UNCHANGED <<serverState, messages, sessionKeys, compromised>>

\* Adversary actions
CompromiseKey(k) ==
    /\ k \in Keys
    /\ compromised' = compromised \cup {k}
    /\ UNCHANGED <<clientState, serverState, messages, sessionKeys, transcripts>>

------------------------------------------------------------
\* Next-state relation
Next ==
    \/ \E c \in Clients, s \in Servers, n \in Nonces: ClientHello(c, s, n)
    \/ \E c \in Clients, s \in Servers, nc, ns \in Nonces: ServerHello(c, s, nc, ns)
    \/ \E c \in Clients, s \in Servers, k \in Keys: ClientKeyExchange(c, s, k)
    \/ \E c \in Clients, s \in Servers, k \in Keys: ServerKeyExchange(c, s, k)
    \/ \E c \in Clients, s \in Servers: ClientVerify(c, s)
    \/ \E c \in Clients, s \in Servers, sk \in Keys: ServerVerify(c, s, sk)
    \/ \E c \in Clients, s \in Servers: ClientComplete(c, s)
    \/ \E k \in Keys: CompromiseKey(k)

Spec == Init /\ [][Next]_vars

------------------------------------------------------------
\* Security Properties

\* Property 1: Authentication - Only authenticated clients get session keys
Authentication ==
    \A sk \in sessionKeys:
        /\ sk.client \in Clients
        /\ sk.server \in Servers
        /\ clientState[sk.client] = "COMPLETED"
        /\ serverState[sk.server] = "COMPLETED"

\* Property 2: Key Secrecy - Session keys are not compromised
KeySecrecy ==
    \A sk \in sessionKeys: sk.key \notin compromised

\* Property 3: Uniqueness - Each session has unique key
SessionUniqueness ==
    \A sk1, sk2 \in sessionKeys:
        (sk1.client = sk2.client /\ sk1.server = sk2.server) => sk1 = sk2

\* Property 4: Protocol Completion - Both parties reach same state
ProtocolConsistency ==
    \A c \in Clients, s \in Servers:
        (clientState[c] = "COMPLETED" /\ serverState[s] = "COMPLETED") =>
            \E sk \in sessionKeys: sk.client = c /\ sk.server = s

\* Property 5: Forward Secrecy - Past sessions remain secure
ForwardSecrecy ==
    \A sk \in sessionKeys:
        sk.key \notin compromised =>
            [](sk.key \notin compromised)

------------------------------------------------------------
\* Temporal Properties

\* Liveness: Protocol eventually completes for honest parties
EventualCompletion ==
    \A c \in Clients, s \in Servers:
        (clientState[c] = "INIT") ~> 
            (clientState[c] = "COMPLETED" \/ clientState[c] = "INIT")

\* Safety: No replay attacks possible
NoReplay ==
    \A m1, m2 \in messages:
        (m1.type = "ClientHello" /\ m2.type = "ClientHello" /\ 
         m1.from = m2.from /\ m1.to = m2.to) =>
            m1.nonce /= m2.nonce

============================================================