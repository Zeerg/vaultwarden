//! Keep reqsign's public API and request canonicalization while supplying AWS-LC
//! digest and MAC implementations for FIPS builds.

pub use upstream::*;

#[cfg(feature = "aws-lc-fips")]
pub mod hash {
    use aws_lc_rs::{digest, hmac};

    pub use upstream::hash::{base64_decode, base64_encode};

    pub fn hex_sha1(content: &[u8]) -> String {
        hex::encode(digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, content))
    }

    pub fn hex_sha256(content: &[u8]) -> String {
        hex::encode(digest::digest(&digest::SHA256, content))
    }

    fn sign(algorithm: hmac::Algorithm, key: &[u8], content: &[u8]) -> hmac::Tag {
        hmac::sign(&hmac::Key::new(algorithm, key), content)
    }

    pub fn hmac_sha256(key: &[u8], content: &[u8]) -> Vec<u8> {
        sign(hmac::HMAC_SHA256, key, content).as_ref().to_vec()
    }

    pub fn base64_hmac_sha256(key: &[u8], content: &[u8]) -> String {
        base64_encode(sign(hmac::HMAC_SHA256, key, content).as_ref())
    }

    pub fn hex_hmac_sha1(key: &[u8], content: &[u8]) -> String {
        hex::encode(sign(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, key, content).as_ref())
    }

    pub fn hex_hmac_sha256(key: &[u8], content: &[u8]) -> String {
        hex::encode(sign(hmac::HMAC_SHA256, key, content).as_ref())
    }

    pub fn base64_hmac_sha1(key: &[u8], content: &[u8]) -> String {
        base64_encode(sign(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, key, content).as_ref())
    }
}
