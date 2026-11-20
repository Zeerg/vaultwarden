use std::{collections::HashMap, io::Error, path::Path};

use aws_lc_rs::{
    encoding::AsDer,
    rsa::{KeyPair, KeySize},
};
use openssl::{
    pkey::{PKey, Private},
    rsa::Rsa,
};

pub fn install_crypto_providers() -> Result<(), Error> {
    aws_lc_rs::try_fips_mode().map_err(Error::other)?;
    if let Some(expected) = option_env!("VW_FIPS_EXPECTED_AWS_LC_VERSION")
        && aws_lc_rs::awslc_version() != expected
    {
        return Err(Error::other(format!("Expected AWS-LC version {expected}, found {}", aws_lc_rs::awslc_version())));
    }

    let provider = rustls::crypto::default_fips_provider();
    if !provider.fips() {
        return Err(Error::other("rustls provider failed its FIPS check"));
    }
    provider.install_default().map_err(|_| Error::other("a rustls provider was already installed"))?;

    let tls =
        rustls::ClientConfig::builder().with_root_certificates(rustls::RootCertStore::empty()).with_no_client_auth();
    if !tls.fips() {
        return Err(Error::other("rustls client defaults failed their FIPS check"));
    }

    jsonwebtoken::crypto::aws_lc::DEFAULT_PROVIDER
        .install_default()
        .map_err(|_| Error::other("a JWT provider was already installed"))?;
    Ok(())
}

pub fn validate_listener(config: &rocket::Config) -> Result<(), Error> {
    if config.tls.is_some() || !config.address.is_loopback() {
        return Err(Error::other(
            "FIPS mode requires a loopback ROCKET_ADDRESS and no ROCKET_TLS. Terminate HTTPS at a local FIPS-capable proxy.",
        ));
    }
    Ok(())
}

pub fn validate_database_url(value: &str, system_tls: bool) -> Result<(), Error> {
    let Some(scheme) = value.split_once(':').map(|(scheme, _)| scheme) else {
        return Ok(());
    };
    if !matches!(scheme, "mysql" | "postgres" | "postgresql") {
        return Ok(());
    }
    if !value[scheme.len()..].starts_with("://") {
        return Err(Error::other("FIPS database URLs require an explicit URI scheme"));
    }
    let url = url::Url::parse(value).map_err(|_| Error::other("Invalid FIPS database URL"))?;
    let mut params = HashMap::new();
    for (key, value) in url.query_pairs() {
        if params.insert(key, value).is_some() {
            return Err(Error::other("FIPS database URLs cannot contain duplicate parameters"));
        }
    }
    let option = |key: &str| params.get(key).map(std::borrow::Cow::as_ref);
    let single_host = url.host_str().is_some_and(|host| !host.contains([',', '%']));

    let valid = if scheme == "mysql" {
        let socket = option("unix_socket");
        option("local_infile").is_none_or(|value| value == "false")
            && if let Some(socket) = socket {
                url.host_str() == Some("localhost")
                    && url.password().is_none()
                    && Path::new(socket).is_absolute()
                    && ["ssl_mode", "ssl_ca", "ssl_cert", "ssl_key"].iter().all(|key| option(key).is_none())
            } else {
                system_tls
                    && crate::db::mysql_verify_identity_supported()
                    && single_host
                    && url.host_str() != Some("localhost")
                    && option("ssl_mode") == Some("verify_identity")
                    && option("ssl_ca").is_some_and(|path| Path::new(path).is_absolute())
            }
    } else {
        let gss_disabled = option("gssencmode") == Some("disable");
        option("service").is_none()
            && option("hostaddr").is_none()
            && option("dbname").is_none()
            && option("ssl").is_none()
            && option("requiressl").is_none()
            && gss_disabled
            && if let Some(socket) = option("host") {
                url.host_str().is_none()
                    && url.password().is_none()
                    && option("password").is_none()
                    && Path::new(socket).is_absolute()
                    && !socket.contains(',')
                    && std::env::var_os("PGHOSTADDR").is_none()
                    && std::env::var_os("PGSERVICE").is_none()
            } else {
                system_tls && single_host && option("sslmode") == Some("verify-full")
            }
    };
    if !valid {
        return Err(Error::other(
            "FIPS mode requires a local PostgreSQL/MySQL Unix socket or verified native TLS with FIPS_DATABASE_SYSTEM_TLS=true. See docs/fips.md.",
        ));
    }
    Ok(())
}

pub fn generate_rsa_key() -> Result<Rsa<Private>, crate::Error> {
    let key = KeyPair::generate(KeySize::Rsa2048).map_err(Error::other)?;
    let der = key.as_der().map_err(Error::other)?;
    Ok(PKey::private_key_from_pkcs8(der.as_ref())?.rsa()?)
}

pub fn valid_rsa_key(der: &[u8]) -> bool {
    KeyPair::from_der(der).is_ok_and(|key| key.is_valid_fips_key())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aws_lc_defaults_can_sign_and_verify_an_existing_key_format() {
        use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};

        install_crypto_providers().unwrap();
        let rsa = generate_rsa_key().unwrap();
        assert!(valid_rsa_key(&rsa.private_key_to_der().unwrap()));
        let private_key = EncodingKey::from_rsa_pem(&rsa.private_key_to_pem().unwrap()).unwrap();
        let public_key = DecodingKey::from_rsa_pem(&rsa.public_key_to_pem().unwrap()).unwrap();
        let claims = json!({"exp": jsonwebtoken::get_current_timestamp() + 60, "sub": "test"});
        let signed = jsonwebtoken::encode(&Header::new(Algorithm::RS256), &claims, &private_key).unwrap();
        let decoded =
            jsonwebtoken::decode::<serde_json::Value>(&signed, &public_key, &Validation::new(Algorithm::RS256));
        assert_eq!(decoded.unwrap().claims, claims);
    }

    #[test]
    fn checks_database_transport_policy() {
        let pg = "postgresql:///vault?user=vault&host=/run/postgresql&gssencmode=disable";
        let pg_tls = "postgresql://vault@db.example/vault?sslmode=verify-full&gssencmode=disable";
        let mysql = "mysql://vault@localhost/vault?unix_socket=/run/mysqld/mysqld.sock";
        let mysql_tls = "mysql://vault@db.example/vault?ssl_mode=verify_identity&ssl_ca=/etc/db-ca.pem";
        for dsn in ["sqlite://data/db.sqlite3", pg, mysql] {
            assert!(validate_database_url(dsn, false).is_ok(), "{dsn}");
        }
        for dsn in [pg_tls, mysql_tls] {
            assert!(validate_database_url(dsn, false).is_err(), "{dsn}");
        }
        assert!(validate_database_url(pg_tls, true).is_ok());
        assert_eq!(validate_database_url(mysql_tls, true).is_ok(), crate::db::mysql_verify_identity_supported());
        for dsn in [
            "postgresql://vault@db.example/vault?sslmode=require&gssencmode=disable",
            "postgresql://vault@db.example/vault?sslmode=verify-full",
            "postgresql://vault@db.example/vault?sslmode=verify-full&ssl=true&gssencmode=disable",
            "postgresql:vault",
            "mysql://vault@localhost/vault?unix_socket=/run/mysqld/mysqld.sock&local_infile=true",
            "mysql://vault@db.example/vault?ssl_mode=verify_identity&ssl_mode=preferred",
        ] {
            assert!(validate_database_url(dsn, true).is_err(), "{dsn}");
        }
    }
}
