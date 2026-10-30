# Architecture Guidelines: Ports & Adapters (Hexagonal)

This repository follows the **Ports and Adapters (Hexagonal Architecture)** pattern. All new features, API updates, and refactorings must adhere to and recommend this pattern.

## Architectural Layers

1. **Domain (`java/com/google/mbs/domain/`, `java/com/google/mbs/qualifier/`)**

   - **Core Invariant**: Pure, technology-agnostic business logic and contracts. Keep `BUILD` `deps` restricted to the JDK, `@AutoValue`, `jakarta.inject` annotations, `flogger`, and Guava annotations (never AWS SDK, Tink, BouncyCastle, JNI, Guice `com.google.inject`, or I/O libraries).
   - **Inbound (Driving) Ports**: Interfaces consumed by callers/orchestrators (`TrustPackageProvider`, `TrustPackageReloader`, `CertificateMonitor`, `CertificateGenerator`).
   - **Outbound (Driven) Ports**: Interfaces for required external capabilities (`KmsClientInterface`, `BackupStorage`, `AttestationCollector`, `SelfSignedCertificateFactory`, `SelfSignedBundleBackupSealer`, `CrossSignedCertificateBackupGenerator`, `CertificateCodec`, `Metrics`).
   - **Domain Services, Models, Qualifiers & Exceptions**: Core domain orchestrators (`TrustPackageService`, `DefaultCertificateGenerator`, `SelfSignedBundleBackupGenerator`), immutable entities (`SelfSignedBundle`, `AttestationToken`), JSR-330 `@Qualifier` annotations (`@KmsKeyArn`, `@PublicBackupBucket`, `@PrivateBackupBucket`), and domain exceptions.

2. **Adapters (`java/com/google/mbs/adapters/`)**

   - Concrete implementations of domain ports bridging to external systems. Must translate all external SDK/JNI/crypto exceptions into `domain/` exceptions.
   - **Driven Adapters**: `AwsKmsClient`, `S3BackupStorage`, `AwsAttestationCollector`, `DefaultSelfSignedCertificateFactory`, `DefaultCrossSignedCertificateBackupGenerator`, `AeadSelfSignedBundleBackupSealer`, `PemCertificateCodec`, `nsm/` (JNI).
   - **Driving Adapters**: `ScheduledCertificateMonitor` (scheduled periodic reload).

3. **Wiring & DI (`java/com/google/mbs/`)**
   - Guice dependency injection modules (`MbsModule`, `AwsMbsModule`, `MbsCoreModule`) wiring ports to adapters.

---

## Developer & Agent Rules

- **Port-First**: Define domain models and port interfaces in `domain/` before writing implementations.
- **Isolate Infrastructure**: Keep all AWS SDK, crypto libraries (Tink, BouncyCastle), and hardware logic confined to `adapters/`.
- **Hermetic Tests**: Test domain logic with mocks/fakes of ports without AWS or Docker dependencies. Test adapters with targeted SDK mocks.
- **Nullability**: Follow JSpecify (`@NullMarked`) non-null-by-default semantics (no `@NonNull`; use `@Nullable` or `Optional<T>` explicitly) and _Effective Java_ Item 49 for runtime `Objects.requireNonNull` checks. Do not write unit tests solely asserting `NullPointerException` on non-null parameters.
