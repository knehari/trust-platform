# ADR-0002 — Durable issuance around external signing

Status: Proposed · 2026-10-11

## Decision
Use durable state transitions and unique serial reservation in PostgreSQL, an idempotent request model, signing intent and reconciliation of uncertain HSM outcomes. Never assert that external signing and DB commit are atomic.

## Acceptance
Fault-injection tests demonstrate no serial reuse, no unauthorized issuance, traceability and safe recovery.