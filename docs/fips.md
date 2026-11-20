# AWS-LC FIPS mode

Build with the `fips` Cargo feature to enable AWS-LC FIPS for Vaultwarden's server-side cryptography. The resulting binary checks the AWS-LC module and rustls provider at startup. HTTPS and SMTP TLS clients, server JWTs and RSA key generation, password hashing, authenticator HMAC, cryptographic randomness, and S3 SigV4 use AWS-LC. A standard build has the upstream crypto behavior.

## Build

On Linux, install a C/C++ toolchain, CMake, Go, pkg-config, OpenSSL 3 development headers, PostgreSQL client development headers and MySQL-compatible client development headers. Some targets also need libclang for Rust bindings. Build with the Rust version in `rust-toolchain.toml`.

```sh
cargo build --locked --profile release-low --features sqlite,mysql,postgresql,s3,fips
target/release-low/vaultwarden --version
```

Omit any unneeded backend feature. `sqlite_system` can be used in place of `sqlite` when using system SQLite. The version output includes the AWS-LC library version and whether its FIPS module initialized successfully.

## Test locally with Docker

Run from the repository root. This uses the checked-in Rust toolchain and Vaultwarden's `ci` Cargo test profile.

```sh
VW_RUST_VERSION=$(sed -n 's/^channel = "\(.*\)"/\1/p' rust-toolchain.toml)
docker run --rm -v "$PWD:/src:ro" -w /src -e CARGO_TARGET_DIR=/tmp/vaultwarden-target \
  -e AWS_LC_FIPS_SYS_USE_SYSTEM=0 -e AWS_LC_FIPS_SYS_STATIC=1 \
  "rust:${VW_RUST_VERSION}-bookworm" bash -euc '
    apt-get update
    apt-get install -y --no-install-recommends cmake golang-go libclang-dev libmariadb-dev-compat libpq-dev libssl-dev
    cargo test --locked --profile ci --features sqlite,mysql,postgresql,s3,fips
  '
```

## Run Vaultwarden

Set `DOMAIN` to the public HTTPS URL and `ROCKET_ADDRESS` to `127.0.0.1` or `::1`. Keep `ROCKET_TLS` unset. Deploy a TLS terminator using an approved cryptographic module in the same host or isolated network namespace. Forward to Vaultwarden's loopback port, including WebSocket upgrades, and overwrite `X-Forwarded-Proto` and the configured client-IP header. Limit trusted proxy addresses to the local terminator. Rocket 0.5.4 uses ring for built-in server TLS, so the FIPS build rejects Rocket TLS and non-loopback listeners.

Use `vaultwarden hash` from the FIPS build to generate a random login token and its SHA-256 `ADMIN_TOKEN` value. Store the hash in the server configuration and keep the login token in a separate secret store. Replace existing Argon2 admin tokens before switching. Leaving `ADMIN_TOKEN` unset disables the admin page.

## Backend configuration

| Backend | Supported configuration |
| --- | --- |
| SQLite | Bundled or system SQLite with a local database path. Protect the database and backups using the host's approved storage controls. |
| PostgreSQL | A local Unix socket with `peer` authentication, or remote TLS with a separately validated libpq crypto stack. |
| MySQL and MariaDB | A local Unix socket with `auth_socket` or `unix_socket` authentication. Remote TLS also requires a separately validated client crypto stack with `verify_identity` support. |
| Local object storage | Regular filesystem paths. Protect storage and backups at the volume or host layer. |
| S3 and S3-compatible storage | Signed requests over an explicit HTTPS endpoint. Use a regional S3 FIPS endpoint with AWS, or a separately assessed TLS endpoint for self-hosted S3. |

Local sockets use the Vaultwarden service account for database authentication. Give that account access to the socket and configure the database server for the matching peer or socket authentication method. The following `DATABASE_URL` values use Unix sockets.

```text
postgresql:///vaultwarden?user=vaultwarden&host=/run/postgresql&gssencmode=disable
mysql://vaultwarden@localhost/vaultwarden?unix_socket=/run/mysqld/mysqld.sock
```

For a remote database, enable `FIPS_DATABASE_SYSTEM_TLS=true` after verifying the linked database client's TLS library, its active approved mode, and the database endpoint. This setting lets Vaultwarden accept the following TLS configurations. The database driver handles transport and authentication through its native stack.

```text
postgresql://vaultwarden@db.example.gov/vaultwarden?sslmode=verify-full&sslrootcert=/etc/vaultwarden/db-ca.pem&gssencmode=disable
mysql://vaultwarden@db.example.gov/vaultwarden?ssl_mode=verify_identity&ssl_ca=/etc/vaultwarden/db-ca.pem
```

Builds linked against a MariaDB Connector/C version that lacks Diesel's `verify_identity` option reject remote MySQL and MariaDB URLs. Use a Unix socket with those builds. A supported MySQL client library can connect to either server over TLS.

For AWS S3, use the FIPS endpoint for your region. The following example uses GovCloud US-West. [AWS S3 endpoint reference](https://docs.aws.amazon.com/general/latest/gr/s3.html)

```sh
export ATTACHMENTS_FOLDER='s3://vaultwarden-bucket/attachments?region=us-gov-west-1&endpoint=https%3A%2F%2Fs3-fips.us-gov-west-1.amazonaws.com'
```

Supply `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, and, for temporary credentials, `AWS_SESSION_TOKEN`. Alternatively, set `FIPS_S3_CREDENTIAL_PROCESS` to a trusted credential helper returning AWS credential-process JSON. The helper's cryptography and credential exchange run outside Vaultwarden. Inline static URI credentials also work. Keep credentials out of command arguments and logs. The FIPS build bypasses the SDK's default credential chain, which includes independent STS and SSO signing. It rejects anonymous requests, S3 Express, SSE-C, and MD5 checksums. S3-side encryption and key management are storage service controls.

SMTP requires TLS with certificate and hostname verification. The build limits server-side HTTP calls to HTTPS. SSO, Duo, Yubico OTP, and WebAuthn are unavailable in this profile. Before switching an existing database, ensure users have a supported MFA method such as an authenticator app or verified email. Rotate Send passwords shorter than 14 bytes. Vault data encryption and the client KDF run in Bitwarden clients and require a separate client assessment.

## Validation scope

Record the deployed binary digest, Cargo.lock, AWS-LC source and build inputs, linked database client libraries, operational environment, and TLS terminator configuration. The bundled build currently reports AWS-LC **4.2.0**. The security policy for [CMVP certificate #5596](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/5596) identifies **4.0.0** and specifies the source archive, build procedure, and tested environment. A successful startup check establishes module operation and provider selection. Certificate applicability requires evidence for the exact module and environment.

`aws-lc-fips-sys` can link an administrator-supplied module with `AWS_LC_FIPS_SYS_SYSTEM_DIR` and matching Rust bindings. Set `VW_FIPS_EXPECTED_AWS_LC_VERSION` at build time to enforce the intended library version at runtime. Validate this build and the module's approved services on the deployment platform before federal use. See [AWS-LC system linking](https://github.com/aws/aws-lc-rs/tree/main/aws-lc-fips-sys#using-a-system-installed-aws-lc-fips-module) and the [CMVP guidance for federal users](https://csrc.nist.gov/projects/cryptographic-module-validation-program/validated-modules).
