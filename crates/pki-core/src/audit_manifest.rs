use sha2::{Digest, Sha256};
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManifestError {
    Empty,
    TooMany,
    MissingDigest,
}
pub fn manifest_digest(digests: &[[u8; 32]]) -> Result<[u8; 32], ManifestError> {
    if digests.is_empty() {
        return Err(ManifestError::Empty);
    }
    if digests.len() > 100_000 {
        return Err(ManifestError::TooMany);
    }
    if digests.contains(&[0; 32]) {
        return Err(ManifestError::MissingDigest);
    }
    let mut h = Sha256::new();
    h.update(b"trust-platform:audit-manifest:v1\0");
    h.update((digests.len() as u64).to_be_bytes());
    for (index, d) in digests.iter().enumerate() {
        h.update((index as u64).to_be_bytes());
        h.update(d);
    }
    Ok(h.finalize().into())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn manifest_is_order_sensitive_and_rejects_invalid() {
        let a = [1; 32];
        let b = [2; 32];
        assert_eq!(manifest_digest(&[a, b]), manifest_digest(&[a, b]));
        // Fixed SHA-256 vector computed independently from the documented framing.
        assert_eq!(
            manifest_digest(&[a, b]).unwrap(),
            [
                3, 182, 24, 80, 54, 183, 135, 5, 127, 206, 115, 71, 56, 5, 20, 183, 180, 249, 248,
                165, 98, 47, 39, 245, 118, 179, 146, 90, 248, 54, 192, 216,
            ]
        );
        assert_ne!(
            manifest_digest(&[a, b]).unwrap(),
            manifest_digest(&[b, a]).unwrap()
        );
        assert_eq!(manifest_digest(&[]), Err(ManifestError::Empty));
        assert_eq!(
            manifest_digest(&[[0; 32]]),
            Err(ManifestError::MissingDigest)
        );
    }
}
