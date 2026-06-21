# Changelog

## 2.1.0 - 2026-06-20

### Added

- Public-key algorithm support for DSA, ECDSA, and Ed25519 (tags 22, 27, 28) signing and verification; ECDH/Cv25519 encryption subkeys.
- Test fixtures and round-trip tests for DSA, ECDSA, and Ed25519 keys; GnuPG interop golden files for decrypt/verify.
- README section on supported public-key algorithms, hash pairings, and FIPS caveats.
- PIT mutation testing via `./gradlew pitest` (`info.solidsoft.pitest` 1.19.0, JUnit 5 plugin 1.2.2).
- `TestEnvironmentListener` so PIT's forked JVM matches the `line.separator` used by unit tests.
- OpenPGP modern encryption API: `EncryptionProtection`, `AeadAlgorithm`, `AeadPacketStyle`, `PassphraseKeyDerivation`, `Argon2Parameters`, `OpenPgpProfile`.
- `HashingAlgorithm.SHA3_256` and `SHA3_512` with explicit OpenPGP tag mapping via `getOpenPgpTag()`.
- `Encryptor.withModernDefaults()` preset (AES256, AEAD-OCB v6, Argon2 S2K).
- `EncryptionDetails` metadata on `FileMetadata` after decryption (protection mode, cipher, AEAD, Argon2, detected profile).
- `FileMetadata.Signature.getHashAlgorithm()` populated during verification.

### Changed

- `HashingAlgorithm`, `EncryptionAlgorithm`, and `CompressionAlgorithm` use explicit OpenPGP tags instead of `enum.ordinal()`.
- `JcaContextHelper` configures `SecureRandom` on passphrase encryption generators (required for Argon2).

## 2.0.0

### Breaking changes

- **Java 17+ required.** Java 8/11 support has been dropped.
- Bouncy Castle artifacts updated from `jdk15on:1.70` to `jdk18on:1.84`.
- Groovy/Spock test stack removed; tests are now JUnit 5 only.

### Added

- `JcaContextHelper` lazy provider resolution with FIPS provider auto-detection.
- System property `jpgpj.security.provider` for explicit provider class selection.
- Fail-fast when both standard and FIPS Bouncy Castle providers are on the classpath.
- GitHub Actions CI (Java 17 and 21).
- `maven-publish` and `signing` Gradle plugins (replaces legacy `mavenCentral.gradle`).

### Changed

- SLF4J updated from 1.7.x to 2.0.17.
- Gradle updated from 4.10.2 to 8.12.1.
- `bcprov-jdk18on` and `bcutil-jdk18on` are now explicit dependencies.

### Migration from 1.3

1. Upgrade your JVM to Java 17 or later.
2. Update Maven/Gradle dependencies to `org.c02e.jpgpj:jpgpj:2.0.0`.
3. Ensure Bouncy Castle `jdk18on` artifacts (1.84+) are on the classpath.
4. For FIPS deployments, replace standard BC jars with `bc-fips`, `bcutil-fips`, and `bcpg-fips`; call `JcaContextHelper.setSecurityProvider(new BouncyCastleFipsProvider())` before any JPGPJ operation. Standard and FIPS BC jars must not coexist in the same JVM.

## 1.3 - 2021-12-16

* Optional signature verification (for #40)
* Upgrade to Bouncy Castle 1.70

## 1.2 - 2021-10-06

* Refactored to allow pluggable crypto implementations through JCA (#39) -- notably, this allows the Bouncy Castle FIPS implementation to be swapped in (see #36)
* Updated encryptor/decryptor and other core classes to be cloneable (#35)
* Upgraded to Bouncy Castle 1.69

## 1.1 - 2021-05-17

* Stricter visibility for FileMetadata related fields (#34)
* Added FileMetadata#equals/hashCode implementation (#34)
* Added shortcut for encrypting bytes data array (#34)
* Added encryptor/decryptor flag to control non-essential logging (#34)
* Using java.nio.file.Path(s) instead of java.io.File(s) where applicable (#30)
* Using absolute path to ensure encrypt/decrypt not onto same file (#29)
* Promoted visibility of some useful Encryptor methods from protected to public (#29)

## 1.0 - 2020-05-16

* Fluent API support for `Encryptor`, `Decryptor`, and `FileMetadata` (#28)
* Armor headers support in encryptor and decryptor (#27)
* Provide direct encryptor stream (#26)
* `FileMetadata.toString()` implementation (#25)
* Java 8 is now minimum java version

## 0.7.1 - 2019-10-03

Fixed #23: Exception encrypting empty files.

## 0.7 - 2019-09-19

* Add the following new `Key` subclasses as a convenient way to designate the usage for a key (addresses #22):
    * `KeyForSigning`: turns off the `forVerification`, `forEncryption`, and `forDecryption` flags for each subkey, and ensures that at least one subkey has the `forSigning` flag turned on.
    * `KeyForVerification`: turns off the `forSigning`, `forEncryption`, and `forDecryption` flags for each subkey, and turns on the `forVerification` flag of each subkey.
    * `KeyForEncryption`: turns off the `forSigning`, `forVerification`, and `forDecryption` flags for each subkey, and ensures that at least one subkey has the `forEncryption` flag turned on.
    * `KeyForDecryption`: turns off the `forSigning`, `forVerification`, and `forEncryption` flags for each subkey, and turns on the `forDecryption` flag of each subkey.
* Upgrade to Bouncy Castle 1.63.

## 0.6.1 - 2019-02-20

* Better detection of unencrypted data (#18) -- will now raise a `PGPException` in most cases if you try to decrypt some data that isn't a PGP-formatted message.
* Allow public keys to be loaded from GPG2 `kbx` (aka "keybox") files (#21).
* Upgrade to Bouncy Castle 1.61.

## 0.5 - 2018-10-01

* Address #19: Allow passphrases to be supplied as char arrays, and to be zeroed after use (see https://github.com/justinludwig/jpgpj/wiki/KeyRings#cleaning-up-memory for examples of how to use this).
* Upgrade to Bouncy Castle 1.60.

## 0.4 - 2018-04-13

* Allow use of private keys with no passphrase #12
* Fix decryption failure when keys in wrong order #5
* Add explicit support for Camellia cipher

## 0.3 - 2018-03-10

Pull request #15: Use better file IO buffer size when encrypting/decrypting files, and allow the max buffer size to customized. The previous size was always 4K; the new size defaults to the smaller of 1M or the actual file size.

## 0.2 - 2018-01-24

* Replaced java.util.logging API with SLF4J (PR #10; fixes #6).
* Upgraded to Bouncy Castle 1.59.

## 0.1.4 - 2018-01-23

Fixed #11 NullPointerException thrown when verifying signatures from older PGP programs ("version 3" signatures).

## 0.1.3 - 2017-08-31

* Fixed #7 NullPointerException that can be thrown while trying to extract usage flags from a subkey.
* Upgraded to Bouncy Castle 1.58.

## 0.1.1 - 2017-05-02

Upgrade to Bouncy Castle 1.56.

# 0.1 - 2016-07-04

Initial JPGPJ release. Available from maven central as org.c02e.jpgpj:jpgpj:0.1.
