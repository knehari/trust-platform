# ADR-0001 — Native Rust CA Core

Status: Proposed · 2026-10-11

## Context
Sovereign product requires an independently maintained native X.509 CA engine, secure parsing, controlled policies and reproducible builds.

## Decision
Implement a modular-monolith CA Core in Rust using established cryptographic libraries, not homegrown cryptographic primitives. Go and React are future control/UX planes.

## Consequences
More implementation and assurance effort than wrapping an existing CA; strict standards/interoperability testing and external audit required before pilots.