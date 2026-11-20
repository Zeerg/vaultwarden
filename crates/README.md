# Dependency patches

The paths in this directory patch crates used by Vaultwarden's FIPS feature. Keep the pinned upstream sources and their licenses when updating the patches.

| Crate | Upstream source | Change |
| --- | --- | --- |
| `reqsign-core` 3.3.3 | [Apache Reqsign](https://github.com/apache/reqsign/tree/d935dbdb822bc2a525e49cca3e8dd13618669f93/core) | Route SigV4 hashes and MACs through AWS-LC. |
| `webauthn-rs-core` and `webauthn-attestation-ca` 0.5.5 | [Webauthn-rs](https://github.com/kanidm/webauthn-rs/tree/d2c10d53ca5ef033d37ee6462e936e9eb72ad98c) | Accept the AWS-LC FIPS target of `openssl-sys`, generate challenges through its RNG, and enforce key constraints during credential validation and signature verification. |
| `yubico_ng` 1.0.0 | [Yubico-rs](https://github.com/BlackDex/yubico-rs/tree/051da484805081d88f58c810ae611e83f725a705) | Route protocol v2 HMAC and nonce generation through AWS-LC. |
