# Context

Measurement Bound Storage (`MBS`) manages self-signed root certificate bundles and cross-signed bridge certificates for enclave services. Certificate generation, activation, and retirement are driven declaratively by an S3 configuration file polled periodically by the enclave.

## 1. Consumer-Configured Parameters

Each consuming service supplies the following bindings when wiring MBS:

- `<PUBLIC_BUCKET>`: Public S3 bucket (`@PublicBackupBucket`) storing `certificates_config.textproto`, self-signed certificates, attestation documents, and cross-signed certificates
- `<PRIVATE_BUCKET>`: Private S3 bucket (`@PrivateBackupBucket`) storing KMS-wrapped data keys, encrypted private keys, and the generation lock
- `<BASE_SUBJECT_DN>`: Base X.509 Subject Distinguished Name configured for the enclave
- `<SVC_PREFIX>`: Service metric prefix prepended by the consumer's `Metrics` implementation (`<SVC_PREFIX>_mbs*`)
- `<CW_NAMESPACE>`: Service metric namespace
- `<ENCLAVE_LOG_GROUP>`: Enclave application log group or output stream

## 2. Monitor Schedule & Configuration File

- **Configuration Schema**: `s3://<PUBLIC_BUCKET>/certificates_config.textproto` is a textproto message of type `google.mbs.v1.CertificatesConfig`, defined in [`api/google/mbs/v1/certificates_config.proto`](api/google/mbs/v1/certificates_config.proto).
- **Periodic Monitor**: Runs immediately at enclave startup and every **2 minutes** thereafter. Each iteration performs three steps in order:
  1. Fetches `s3://<PUBLIC_BUCKET>/certificates_config.textproto`.
  2. Generates any missing self-signed or cross-signed certificates declared in the configuration.
  3. Reloads the active self-signed and cross-signed certificates into memory and updates metrics.
     On failure, the enclave logs `Certificate monitor iteration finished with FAILURE` (no log on success; instead, `<SVC_PREFIX>_mbsStatus{status="success"}` is `1.0`).

## 3. S3 Bucket Layout & Distributed Lock

- **Public Bucket (`s3://<PUBLIC_BUCKET>`)**:
  - `certificates_config.textproto`: Declarative rotation configuration (`google.mbs.v1.CertificatesConfig`).
  - `public/<epoch>/root_certificate.pem`: Self-signed root X.509 certificate in PEM format.
  - `public/<epoch>/attestation_doc.base64`: Raw binary Nitro Enclave attestation document (`COSE_Sign1` CBOR bytes, despite the `.base64` filename) binding the public key.
  - `public/cross-signed/<priv_epoch>_<pub_epoch>/cross_signed_certificate.pem`: Cross-signed X.509 certificate in PEM format.
- **Private Bucket (`s3://<PRIVATE_BUCKET>`)**:
  - `private/<epoch>/root_data_key.kms`: KMS-encrypted data encryption key (`GenerateDataKey` ciphertext bounded by enclave PCRs).
  - `private/<epoch>/root_private_key.aes`: AES-GCM encrypted private key (`PKCS#8`) sealed with the data key.
  - `private/root_generation.lock`: Distributed lock object created via conditional write (`If-None-Match: "*"`) before generating missing artifacts and deleted (`Released S3 generation lock`) after generation succeeds. On any failure while held, it is intentionally left behind and blocks all generation until manually removed.
- **Backup Completeness**:
  - A self-signed epoch backup is **Complete** when all 4 objects exist across `<PUBLIC_BUCKET>` and `<PRIVATE_BUCKET>`. Generation for a declared epoch runs only when none of its backup objects exist beforehand.

## 4. Certificate Naming & Cross-Signing Rules

- **Self-Signed Subject DN Epoch Suffix**:
  - Whenever MBS generates a new self-signed certificate for `epoch_id: <E>`, it appends `" G<E>"` to the Common Name (`CN`) attribute of `<BASE_SUBJECT_DN>`.
  - Pre-existing legacy `Epoch 0` certificates in S3 that were generated prior to epoch suffixing retain their original `CN` without `G0` unless regenerated.
- **Cross-Signed Certificate Construction**:
  - Keyed in `cross_signed_certificates` by `"<priv_epoch>_<pub_epoch>"` with `private_key_epoch_id: <priv_epoch>` (signer) and `public_key_epoch_id: <pub_epoch>` (subject).
  - Both self-signed epochs `<priv_epoch>` and `<pub_epoch>` must be **Complete** in S3.
  - MBS constructs an X.509 certificate signed by `<priv_epoch>`'s private key with:
    - **Issuer / Subject Chaining**: `Issuer` = `Cert(<priv_epoch>).Subject` and `Subject` = `Cert(<pub_epoch>).Subject`.
    - **Public Key**: `SubjectPublicKeyInfo` is identical to `Cert(<pub_epoch>).PublicKey`.
    - **Validity**: `notBefore` and `notAfter` match `validity_period` in `CrossSignedCertificate`.
    - **SKI / AKI Chaining**: `SubjectKeyIdentifier` (`SKI`) defines only the public key identifier, so `SKI` on `<priv_epoch>_<pub_epoch>` equals `SKI(<pub_epoch>)`, while `AuthorityKeyIdentifier` (`AKI`) equals `SKI(<priv_epoch>)` (chaining to the signer's public key ID). Other extensions (`basicConstraints`, `keyUsage`) are copied from `Cert(<pub_epoch>)`.
    - **Signature**: Cryptographically signed by `<priv_epoch>`'s private key (validates under `Cert(<priv_epoch>)`).

## 5. Caching & S3 Change Detection (Black-Box Behavior)

- **Steady-State Caching**: Once an active certificate bundle is loaded from S3 and its private key is decrypted via KMS, MBS keeps it cached in memory across monitor cycles. As long as the active epoch set and the S3 object ETags remain unchanged, subsequent monitor ticks do not re-download the backup files from S3 or re-decrypt keys via KMS.
- **Reload on S3 Object Modification (ETag Change)**: On every monitor tick, MBS lists the S3 buckets and compares object ETags against the cached snapshot. If any S3 backup file for an active certificate changes in S3 (for example, when a corrupted or tampered object is replaced or restored), MBS detects the new ETag and reloads the updated backup from S3 on the next tick.

## 6. Metrics (`Metrics` Port / `<SVC_PREFIX>_mbs*`)

Every monitor iteration updates in-memory gauges for up to 4 status events (commonly exported as one-hot gauges with dimension `status`, where the active status has value `1.0` and all other statuses have value `0.0`) and 2 active-certificate sets (dimension `epoch`). An external host metric exporter (such as `amazon-cloudwatch-agent`, currently configured with a **1-minute** scrape interval) periodically scrapes the enclave's `/metrics` endpoint and publishes these gauges to the monitoring backend:

1. `<SVC_PREFIX>_mbsStatus` (`MonitorEvent`): `success` | `failure`
2. `<SVC_PREFIX>_mbsConfigStatus` (`ConfigEvent`): `success` | `could_not_fetch_configuration_file` | `invalid_configuration_file` | `general_failure`
3. `<SVC_PREFIX>_mbsGenerationStatus` (`GenerationEvent`): `success` | `s3_operation_failed` | `kms_operation_failed` | `waiting_for_mbs_lock` | `general_failure`
4. `<SVC_PREFIX>_mbsLoadStatus` (`LoadEvent`): `success` | `s3_operation_failed` | `kms_operation_failed` | `backup_not_found` | `stored_backup_corrupted` | `general_failure`
5. `<SVC_PREFIX>_mbsActiveSelfSignedCertificate{epoch="<E>"}`: `1.0` for each currently active self-signed epoch `<E>` (inactive epochs are removed from the gauge).
6. `<SVC_PREFIX>_mbsActiveCrossSignedCertificate{epoch="<priv>_<pub>"}`: `1.0` for each currently active cross-signed certificate ID `"<priv>_<pub>"` (inactive IDs are removed from the gauge).

---

# How to Verify MBS Operations in Integration & Rotation Tests

When a rotation test modifies `s3://<PUBLIC_BUCKET>/certificates_config.textproto`, two asynchronous periodic timers govern when the new state becomes observable:

- **MBS Monitor Timer (default: `2 minutes`)**: Each enclave instance polls S3 on a 2-minute schedule to fetch the config, generate any missing backups, and reload its in-memory trust package. Respect this delay after uploading `certificates_config.textproto` before asserting S3 artifacts, enclave logs, or service RPC responses.
- **Metric Exporter Scrape Timer (default: `1 minute`)**: The host metric exporter (e.g., `amazon-cloudwatch-agent`) scrapes the enclave's Prometheus `/metrics` endpoint and publishes gauges to the monitoring backend every 1 minute. Respect this additional delay after the monitor cycle completes before asserting `<SVC_PREFIX>_mbs*` metrics, and query only the **latest scrape data point** (using a 1-minute period rather than aggregating over a wider window such as 1 hour, which would include stale data points from earlier test steps).

Once the required propagation delays have elapsed (plus additional 1-5s propagation timer), verify MBS behavior using these checks:

1. **When a New Self-Signed Epoch `<E>` Is Declared**:

   - **Logs (`<ENCLAVE_LOG_GROUP>`)**: Enclave logs lock acquisition (`Acquired S3 generation lock`), artifact write (`Successfully wrote backup artifacts to S3 for epoch <E>`), and lock release (`Released S3 generation lock`).
   - **S3 Objects**: All 4 files exist in S3 (`public/<E>/root_certificate.pem`, `public/<E>/attestation_doc.base64`, `private/<E>/root_data_key.kms`, `private/<E>/root_private_key.aes`) and `private/root_generation.lock` is absent.
   - **X.509 Certificate Validation (`openssl x509 -in root_certificate.pem -noout -subject -issuer -dates -pubkey -ext basicConstraints,keyUsage,subjectKeyIdentifier,authorityKeyIdentifier`)**:
     - **Issuer & Subject**: Self-signed (`Subject == Issuer`), matching `<BASE_SUBJECT_DN>` with `" G<E>"` appended to `CN`.
     - **Validity**: `notBefore` and `notAfter` match the configured `validity_period` in `certificates_config.textproto`.
     - **Extensions (`SKI`, no `AKI`, `BasicConstraints`, `KeyUsage`)**: `SKI` defines only the public key ID of `<E>`, `AuthorityKeyIdentifier` (`AKI`) must **not** be present (omitted on self-signed root certificates per RFC 5280 section 4.2.1.1), and `BasicConstraints` / `KeyUsage` match the consuming service's signing role (e.g., `CA:TRUE` + `keyCertSign` for CAs, or `CA:FALSE` + `Digital Signature` for direct signers).
     - **Signature**: Validates against itself (`openssl verify -x509_strict -CAfile public/<E>/root_certificate.pem public/<E>/root_certificate.pem` returns `OK`).

2. **When a New Cross-Signed Certificate `<priv_epoch>_<pub_epoch>` Is Declared**:

   - **Logs (`<ENCLAVE_LOG_GROUP>`)**: Enclave logs lock acquisition, `Successfully wrote cross-signed certificate to S3 for <priv_epoch>_<pub_epoch>`, and lock release.
   - **S3 Object**: `s3://<PUBLIC_BUCKET>/public/cross-signed/<priv_epoch>_<pub_epoch>/cross_signed_certificate.pem` exists and `private/root_generation.lock` is absent.
   - **X.509 Certificate Validation**:
     - **Issuer & Subject Chaining**: `Issuer` equals `Subject` of `public/<priv_epoch>/root_certificate.pem`, and `Subject` equals `Subject` of `public/<pub_epoch>/root_certificate.pem`.
     - **Public Key**: `PublicKey` (`openssl x509 -pubkey -noout`) is identical to `PublicKey` of `public/<pub_epoch>/root_certificate.pem`.
     - **SKI & AKI Chaining**: `SKI` (which defines only the public key ID) equals `SKI` of `public/<pub_epoch>/root_certificate.pem`, and `AKI` equals `SKI` of `public/<priv_epoch>/root_certificate.pem`.
     - **Signature & Bidirectional Bridge Validation (`-x509_strict`)**:
       - Direct signature: `openssl verify -x509_strict -CAfile public/<priv_epoch>/root_certificate.pem cross_signed_certificate.pem` returns `OK`.
       - When a bidirectional pair (`<A>_<B>` and `<B>_<A>`) is generated between epochs `<A>` and `<B>`, both 3-certificate chains validate with `-x509_strict`:
         - `<A>` -> `<A>_<B>` -> `<B>_<A>`: `openssl verify -x509_strict -CAfile public/<A>/root_certificate.pem -untrusted public/cross-signed/<A>_<B>/cross_signed_certificate.pem public/cross-signed/<B>_<A>/cross_signed_certificate.pem` returns `OK`.
         - `<B>` -> `<B>_<A>` -> `<A>_<B>`: `openssl verify -x509_strict -CAfile public/<B>/root_certificate.pem -untrusted public/cross-signed/<B>_<A>/cross_signed_certificate.pem public/cross-signed/<A>_<B>/cross_signed_certificate.pem` returns `OK`.
     - **Validity**: `notBefore` and `notAfter` match the configured `validity_period` in `certificates_config.textproto`.

3. **On Every Successful Monitor Tick**:
   - **Metrics**:
     - `<SVC_PREFIX>_mbsStatus{status="success"}` = `1.0`
     - `<SVC_PREFIX>_mbsConfigStatus{status="success"}` = `1.0`
     - `<SVC_PREFIX>_mbsGenerationStatus{status="success"}` = `1.0`
     - `<SVC_PREFIX>_mbsLoadStatus{status="success"}` = `1.0`
     - `<SVC_PREFIX>_mbsActiveSelfSignedCertificate` has `1.0` only for the epochs listed in `active_self_signed_certificate_ids`.
     - `<SVC_PREFIX>_mbsActiveCrossSignedCertificate` has `1.0` only for the IDs listed in `active_cross_signed_certificate_ids`.

---

# Non-Destructive Testing Guidelines (Fresh Epochs `1001` & `1002`)

Because rotation testing creates new certificates, it **must not be executed on `prod`** and **must run against the primary region** (where certificates are generated). Live rotation test plans must never assume the pre-existing active epoch in an environment is `0` (it may be any existing epoch), and must never overwrite or delete pre-existing epoch backups:

1. **Before Running Tests (Backup Config & Verify Clean Lock State)**:
   - Download a backup copy of the existing `s3://<PUBLIC_BUCKET>/certificates_config.textproto` to a local scratch file (`$SCRATCH_DIR/certificates_config.textproto.bak`).
   - Confirm `s3://<PRIVATE_BUCKET>/private/root_generation.lock` does **not** exist (a leftover lock object would block MBS from generating any new certificates).
   - Do not modify or delete any pre-existing `public/<E>/*` or `private/<E>/*` backups.
2. **During Tests (Use Unused High Epoch IDs `1001` and `1002`)**:
   - Start the test suite by configuring and activating a fresh, never-before-seen epoch ID (such as `1001`, after verifying `public/1001/` and `public/1002/` do not exist in S3), then rotate from `1001` to `1002`.
   - Using fresh epochs `1001` and `1002` guarantees that both initial certificate generation (`G1001`) and rotation (`G1001` -> `G1002`) are tested cleanly regardless of whatever baseline epoch was previously active in the environment.
   - **Parameterized `validity_period` Ranges** (compute once relative to `now` at the start of the test run and keep identical across all steps in the flow):
     - **Base cert (`1001`)**: `[now - 100 days, now + 14 days]`
     - **New cert (`1002`)**: `[now - 1 day, now + 100 days]`
     - **Cross-signed certs (`1001_1002`, `1002_1001`)**: overlap of the two ranges, `[now - 1 day, now + 14 days]`
3. **After Running Tests (Restore Original Config & Delete Test Epochs)**:
   - Upload `$SCRATCH_DIR/certificates_config.textproto.bak` back to `s3://<PUBLIC_BUCKET>/certificates_config.textproto`.
   - Delete only the S3 objects created for the test epochs (`public/1001/*`, `private/1001/*`, `public/1002/*`, `private/1002/*`, and `public/cross-signed/1001_1002/*`, `public/cross-signed/1002_1001/*`).
   - Respect the monitor and metric scrape delays and confirm the enclave reloads the original configuration (`<SVC_PREFIX>_mbsStatus{status="success"}` is `1.0`).
