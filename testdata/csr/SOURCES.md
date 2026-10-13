# CSR test vectors

Generated with OpenSSL 3.0.13 on 2026-10-13. The private keys were written to a
scratch directory and deleted immediately; they are not needed by the tests.

| File | Command |
|---|---|
| `p256.csr.der` | `openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout <tmp> -subj "/CN=test.example/O=trust-platform test" -addext "subjectAltName=DNS:test.example" -outform DER` |
| `ed25519.csr.der` | `openssl req -new -newkey ed25519 -nodes -keyout <tmp> -subj "/CN=ed25519.example" -outform DER` |
