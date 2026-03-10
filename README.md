# Measurement Bound Storage (MBS)

MBS is a Java library for managing cryptographic identities within **AWS Nitro Enclaves**. It binds persistent key material to the enclave's code measurement, ensuring keys are only accessible to specific, authorized code versions. It leverages **AWS KMS** for attestation-gated decryption and **AWS S3** for persistent storage of encrypted key material.

## Problem: Persistent Identity in Enclaves

When an enclave terminates, any keys generated within its memory are wiped. This makes maintaining a persistent identity (like an X.509 certificate) difficult.

Standard workarounds compromise security:

- Injecting keys from an external host breaks the hardware root of trust.
- Enclaves lack local storage tied to their hardware state.

## Solution: Measurement-Binding

MBS solves this by cryptographically binding the encryption key to the TEE's measurement (PCR hash).

- Keys are generated inside the enclave. They never leave the boundary in plaintext.
- Decryption is gated by a hardware-signed attestation document.
- Only an enclave running the exact authorized code measurement can recover the certificate and corresponding private key.
