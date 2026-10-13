//! Policy-only capability guard; not a hardware-backed provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignerCapabilityError { UnknownKey, AlgorithmDenied, Disabled, NoAttestation }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm { EcdsaP256Sha256, RsaPssSha256, MlDsa65 }
#[derive(Debug, Clone)]
pub struct SignerCapabilities<'a> { pub key_ref: &'a str, pub enabled: bool, pub attested: bool, pub algorithms: &'a [Algorithm] }
pub fn authorize_signer<'a>(items: &'a [SignerCapabilities<'a>], key: &str, algorithm: Algorithm, require_attestation: bool) -> Result<&'a SignerCapabilities<'a>, SignerCapabilityError> {
 let item=items.iter().find(|x| x.key_ref==key).ok_or(SignerCapabilityError::UnknownKey)?;
 if !item.enabled { return Err(SignerCapabilityError::Disabled); }
 if require_attestation && !item.attested { return Err(SignerCapabilityError::NoAttestation); }
 if !item.algorithms.contains(&algorithm) { return Err(SignerCapabilityError::AlgorithmDenied); }
 Ok(item)
}
#[cfg(test)] mod tests {
 use super::*;
 #[test] fn denies_unknown_disabled_and_unattested() {
 let c=[SignerCapabilities{key_ref:"issuer-1",enabled:true,attested:false,algorithms:&[Algorithm::RsaPssSha256]}];
 assert!(matches!(authorize_signer(&c,"unknown",Algorithm::RsaPssSha256,false),Err(SignerCapabilityError::UnknownKey)));
 assert!(matches!(authorize_signer(&c,"issuer-1",Algorithm::MlDsa65,false),Err(SignerCapabilityError::AlgorithmDenied)));
 assert!(matches!(authorize_signer(&c,"issuer-1",Algorithm::RsaPssSha256,true),Err(SignerCapabilityError::NoAttestation)));
 assert!(authorize_signer(&c,"issuer-1",Algorithm::RsaPssSha256,false).is_ok());
 }
}