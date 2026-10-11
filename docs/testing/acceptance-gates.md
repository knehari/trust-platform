# Release security gates

G0 Legal/IP/confidentiality review before commercial activity.
G1 Lab CA: signed and independently validated X.509, no secrets in Git.
G2 Revocation, CRL, state machine, backups and restore tested.
G3 Authorization negative tests, authenticated requester binding, audit traceability.
G4 Independent security review and controlled non-critical pilot.

Every story must define testable acceptance criteria, evidence and relevant security controls. No production-readiness claim until G4.