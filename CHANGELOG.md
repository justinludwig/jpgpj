# Changelog

## 2.1.0

### Added

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

## 1.3

Last release under original maintainer (2021).
