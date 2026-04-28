# Changelog

All notable changes to this project will be documented in this file. See [commit-and-tag-version](https://github.com/absolute-version/commit-and-tag-version) for commit guidelines.

## 0.2.0 (2026-04-28)


### Dependencies

* **deps:** Update DevKit to release-2.13.0
* **deps:** Update DevKit to release-2.14.0
* **deps:** Update DevKit to release-2.15.0
* **deps:** Update DevKit to release-3.0.0
* **deps:** Update DevKit to release-3.1.1
* **deps:** Update DevKit to release-3.2.0
* **deps:** Update DevKit to release-3.3.0
* **deps:** Update DevKit to release-3.4.0
* **deps:** Update DevKit to release-3.5.0


### Features

* Add certificate memoization
* Create AwsNsmModule and AwsAttestationModule
* customized certificate generation with MbsCertificateFactory
* Enable devkit/gitlinks check during pre-commit
* Move KeyPair generation to MbsCertificateFactory
* Split key backup bucket to key backup and cert backup buckets
* Update MbsCertificateFactory API for self-signed certificates
* Use AWS SDK for KMS operations. Remove dependency on kmstool_cli


### Bug Fixes

* Add checksum to allow for put object call to object lock bucket

## 0.1.0 (2026-03-10)


### Features

* Initial release
