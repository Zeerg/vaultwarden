use std::fmt;

use aws_lc_rs::digest;
use jsonwebtoken::{
    Algorithm, DecodingKey,
    crypto::aws_lc::DEFAULT_PROVIDER,
    jwk::{AlgorithmParameters, EllipticCurve, Jwk},
};
use openidconnect::{
    JsonWebKey, JsonWebKeyAlgorithm, JsonWebKeyId, JwsSigningAlgorithm, SignatureVerificationError,
    core::{CoreJsonWebKey, CoreJsonWebKeyType, CoreJsonWebKeyUse, CoreJwsSigningAlgorithm},
};

/// Keep openidconnect's key selection and claim verification, with AWS-LC for signature operations.
#[derive(Clone, Deserialize, Serialize)]
#[serde(transparent)]
pub struct FipsJsonWebKey(CoreJsonWebKey);

impl fmt::Debug for FipsJsonWebKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("FipsJsonWebKey").field("kid", &self.key_id()).field("kty", &self.key_type()).finish()
    }
}

impl JsonWebKey for FipsJsonWebKey {
    type KeyUse = CoreJsonWebKeyUse;
    type SigningAlgorithm = CoreJwsSigningAlgorithm;

    fn key_id(&self) -> Option<&JsonWebKeyId> {
        self.0.key_id()
    }

    fn key_type(&self) -> &CoreJsonWebKeyType {
        self.0.key_type()
    }

    fn key_use(&self) -> Option<&Self::KeyUse> {
        self.0.key_use()
    }

    fn signing_alg(&self) -> JsonWebKeyAlgorithm<&Self::SigningAlgorithm> {
        self.0.signing_alg()
    }

    fn new_symmetric(key: Vec<u8>) -> Self {
        Self(CoreJsonWebKey::new_symmetric(key))
    }

    fn verify_signature(
        &self,
        algorithm: &Self::SigningAlgorithm,
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), SignatureVerificationError> {
        let (algorithm, hash) = aws_lc_algorithm(algorithm)?;
        let invalid_key = || SignatureVerificationError::InvalidKey("invalid or unsupported OIDC signing key".into());
        let value = serde_json::to_value(&self.0).map_err(|_| invalid_key())?;
        let key: Jwk = serde_json::from_value(value).map_err(|_| invalid_key())?;
        let valid_parameters = match &key.algorithm {
            AlgorithmParameters::EllipticCurve(key) => matches!(
                (&key.curve, algorithm),
                (EllipticCurve::P256, Algorithm::ES256) | (EllipticCurve::P384, Algorithm::ES384)
            ),
            AlgorithmParameters::OctetKeyPair(key) => {
                key.curve == EllipticCurve::Ed25519 && algorithm == Algorithm::EdDSA
            }
            AlgorithmParameters::RSA(key) => {
                let n = oidc_integer(&key.n).ok_or_else(invalid_key)?;
                let e = oidc_integer(&key.e).ok_or_else(invalid_key)?;
                let bits = n.num_bits();
                (2048..=8192).contains(&bits)
                    && bits % 2 == 0
                    && n.is_odd()
                    && (17..=256).contains(&e.num_bits())
                    && e.is_odd()
            }
            _ => true,
        };
        if !valid_parameters {
            return Err(invalid_key());
        }
        let key = DecodingKey::from_jwk(&key).map_err(|_| invalid_key())?;
        if matches!(algorithm, Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512)
            && key.try_get_as_bytes().map_or(true, |bytes| bytes.len() < hash.output_len())
        {
            return Err(SignatureVerificationError::InvalidKey("OIDC HMAC key is shorter than its digest".into()));
        }
        let verifier = (DEFAULT_PROVIDER.verifier_factory)(&algorithm, &key).map_err(|_| invalid_key())?;
        verifier
            .verify(message, &signature.to_vec())
            .map_err(|_| SignatureVerificationError::CryptoError("invalid OIDC signature".into()))
    }

    fn hash_bytes(&self, bytes: &[u8], algorithm: &Self::SigningAlgorithm) -> Result<Vec<u8>, String> {
        let (_, hash) = aws_lc_algorithm(algorithm).map_err(|error| error.to_string())?;
        if algorithm.key_type().as_ref() != Some(self.key_type()) {
            return Err("OIDC signing algorithm does not match the key type".into());
        }
        Ok(digest::digest(hash, bytes).as_ref().to_vec())
    }
}

fn oidc_integer(encoded: &str) -> Option<openssl::bn::BigNum> {
    let bytes = data_encoding::BASE64URL_NOPAD.decode(encoded.as_bytes()).ok()?;
    openssl::bn::BigNum::from_slice(&bytes).ok()
}

fn aws_lc_algorithm(
    algorithm: &CoreJwsSigningAlgorithm,
) -> Result<(Algorithm, &'static digest::Algorithm), SignatureVerificationError> {
    use CoreJwsSigningAlgorithm as Jws;

    Ok(match algorithm {
        Jws::RsaSsaPkcs1V15Sha256 => (Algorithm::RS256, &digest::SHA256),
        Jws::RsaSsaPkcs1V15Sha384 => (Algorithm::RS384, &digest::SHA384),
        Jws::RsaSsaPkcs1V15Sha512 => (Algorithm::RS512, &digest::SHA512),
        Jws::RsaSsaPssSha256 => (Algorithm::PS256, &digest::SHA256),
        Jws::RsaSsaPssSha384 => (Algorithm::PS384, &digest::SHA384),
        Jws::RsaSsaPssSha512 => (Algorithm::PS512, &digest::SHA512),
        Jws::EcdsaP256Sha256 => (Algorithm::ES256, &digest::SHA256),
        Jws::EcdsaP384Sha384 => (Algorithm::ES384, &digest::SHA384),
        Jws::EdDsa => (Algorithm::EdDSA, &digest::SHA512),
        Jws::HmacSha256 => (Algorithm::HS256, &digest::SHA256),
        Jws::HmacSha384 => (Algorithm::HS384, &digest::SHA384),
        Jws::HmacSha512 => (Algorithm::HS512, &digest::SHA512),
        _ => return Err(SignatureVerificationError::UnsupportedAlg(format!("{algorithm:?}"))),
    })
}
