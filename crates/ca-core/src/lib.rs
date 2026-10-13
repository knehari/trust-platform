//! CA core: strict CSR parsing, serial numbers and the issuance state machine.
//! Persistence lives in the `store` crate; signing goes through `crypto-provider`.

#![forbid(unsafe_code)]

pub mod csr;
pub mod issuance;
pub mod serial;
