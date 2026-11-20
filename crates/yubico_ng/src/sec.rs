#[cfg(not(feature = "aws-lc-fips"))]
use hmac::{Hmac, KeyInit, Mac};
#[cfg(not(feature = "aws-lc-fips"))]
use sha1::Sha1;

use crate::error::YubicoError;

#[cfg(not(feature = "aws-lc-fips"))]
type HmacSha1 = Hmac<Sha1>;

#[cfg(not(feature = "aws-lc-fips"))]
pub(crate) fn build_hmac(key: &[u8], input: &[u8]) -> Result<[u8; 20], YubicoError> {
    let hmac = generate_hmac(key, input)?;
    Ok(hmac.finalize().into_bytes().into())
}

#[cfg(not(feature = "aws-lc-fips"))]
pub(crate) fn verify_hmac(key: &[u8], input: &[u8], expected: &[u8]) -> Result<(), YubicoError> {
    let hmac = generate_hmac(key, input)?;
    hmac.verify_slice(expected)
        .map_err(|_| YubicoError::SignatureMismatch)
}

//  Apply the HMAC-SHA-1 algorithm on the line as an octet string using the API key as key
#[cfg(not(feature = "aws-lc-fips"))]
fn generate_hmac(key: &[u8], input: &[u8]) -> Result<HmacSha1, YubicoError> {
    let Ok(mut hmac) = HmacSha1::new_from_slice(key) else {
        return Err(YubicoError::InvalidKeyLength);
    };

    hmac.update(input);
    Ok(hmac)
}

#[cfg(feature = "aws-lc-fips")]
fn aws_lc_key(key: &[u8]) -> Result<aws_lc_rs::hmac::Key, YubicoError> {
    if key.len() < 14 {
        return Err(YubicoError::InvalidKeyLength);
    }
    Ok(aws_lc_rs::hmac::Key::new(aws_lc_rs::hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, key))
}

#[cfg(feature = "aws-lc-fips")]
pub(crate) fn build_hmac(key: &[u8], input: &[u8]) -> Result<[u8; 20], YubicoError> {
    let mac = aws_lc_rs::hmac::sign(&aws_lc_key(key)?, input);
    let mut bytes = [0; 20];
    bytes.copy_from_slice(mac.as_ref());
    Ok(bytes)
}

#[cfg(feature = "aws-lc-fips")]
pub(crate) fn verify_hmac(key: &[u8], input: &[u8], expected: &[u8]) -> Result<(), YubicoError> {
    aws_lc_rs::hmac::verify(&aws_lc_key(key)?, input, expected).map_err(|_| YubicoError::SignatureMismatch)
}
