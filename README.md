Java Pretty Good Privacy Jig
============================

JPGPJ provides a simple API on top of the [Bouncy Castle](https://www.bouncycastle.org/) Java OpenPGP implementation (which is a full and robust implementation of [RFC 4880](https://tools.ietf.org/html/rfc4880), and compatible with other popular PGP implementations such as [GnuPG](https://www.gnupg.org/),  [GPGTools](https://gpgtools.org/), and [Gpg4win](https://www.gpg4win.org/)). The JPGPJ API is limited to file encryption, signing, decryption, and verification; it does not include the ability to generate, update, or sign keys, or to do clearsigning or detached signatures.

**Requirements:** Java 17 or later. Bouncy Castle `jdk18on` 1.84+ (`bcpg-jdk18on`, `bcprov-jdk18on`, `bcutil-jdk18on`).

### Modern OpenPGP (RFC 9580 / GnuPG 2.4+)

JPGPJ 2.1+ supports SHA3 signing, AEAD encryption, Argon2 passphrase key derivation, and a GnuPG-like modern preset:

```java
// gpg 2.4-style output in one call
new Encryptor(aliceKey, bobKey).withModernDefaults()
    .encrypt(plainFile, cipherFile);

// fine-grained control
new Encryptor(bobPubKey)
    .setEncryptionProtection(EncryptionProtection.Aead)
    .setAeadAlgorithm(AeadAlgorithm.Ocb)
    .setAeadPacketStyle(AeadPacketStyle.V6)
    .setEncryptionAlgorithm(EncryptionAlgorithm.AES256)
    .setSigningAlgorithm(HashingAlgorithm.SHA3_512)
    .setPassphraseKeyDerivation(PassphraseKeyDerivation.Argon2)
    .setSymmetricPassphraseChars(passphrase)
    .encrypt(plainIn, cipherOut);
```

`Decryptor` requires no format configuration — it auto-detects MDC, AEAD, Argon2, and SHA3. Inspect `FileMetadata.getEncryptionDetails()` and `FileMetadata.Signature.getHashAlgorithm()` after decryption.

### Public-key algorithms

JPGPJ uses existing keys only (no key generation). Supported public-key algorithms for signing, verification, encryption, and decryption:

| Algorithm | Signing / verify | Encryption / decrypt | Notes |
|-----------|------------------|----------------------|-------|
| **RSA** | Yes | Yes | Default for most legacy keys |
| **DSA** | Yes | No (sign-only) | Legacy; use a separate RSA/ECDH encryption subkey |
| **ECDSA** | Yes | Via **ECDH** subkey | Pair with an ECDH encryption subkey on the same keyring |
| **Ed25519** | Yes (tags 22, 27) | Via **Cv25519/X25519** subkey | Use `HashingAlgorithm.SHA512` for signing |

Recommended hash pairings (not enforced by JPGPJ; Bouncy Castle fails at runtime if invalid):

- RSA / DSA: SHA-256 or SHA-512
- ECDSA (NIST P-256): SHA-256; P-384: SHA-384; P-521: SHA-512
- Ed25519: SHA-512 (GnuPG default)

In FIPS-approved mode (`bc-fips`), RSA and AES defaults work; ECDSA and Ed25519 may be unavailable or restricted depending on your FIPS provider configuration.

Here's an example of Alice encrypting and signing a file for Bob:
```java
new Encryptor(
    new Key(new File("path/to/my/keys/alice-sec.gpg"), "password123"),
    new Key(new File("path/to/my/keys/bob-pub.gpg"))
).encrypt(
    new File("path/to/plaintext.txt"),
    new File("path/to/ciphertext.txt.gpg")
);
```
This is equivalent to the following `gpg` command (where Alice has an `alice` secret key and a `bob` public key on her keyring, and enters "password123" when prompted for her passphrase):
```shell
gpg --sign --encrypt --local-user alice --recipient alice --recipient bob \
    --output path/to/ciphertext.txt.gpg path/to/plaintext.txt
```

Here's an example of Bob decrypting and verifying the encrypted file from above:
```java
new Decryptor(
    new Key(new File("path/to/my/keys/alice-pub.gpg")),
    new Key(new File("path/to/my/keys/bob-sec.gpg"), "b0bru1z!")
).decrypt(
    new File("path/to/ciphertext.txt.gpg"),
    new File("path/back-to/plaintext.txt")
);
```
This is equivalent to the following `gpg` command (where Bob has a `bob` secret key and an `alice` public key on his keyring, and enters "b0bru1z!" when prompted for his passphrase):
```shell
gpg --decrypt --output path/back-to/plaintext.txt path/to/ciphertext.txt.gpg
```

If something goes wrong with the encryption, signing, decryption, or verification processes, a (Bouncy Castle) `PGPException` instance will be raised. If the problem is an incorrect passphrase, that exception will be a `PassphraseException`. If the problem is none of the supplied keys can decrypt the message, that exception will be a `DecryptionException`. If the problem is none of the supplied keys can verify the message -- or if one of the signatures is invalid -- that exception will be a `VerificationException`.

When encrypting, JPGPJ will attempt to encrypt the message with every encryption key supplied to it, and sign the message with every (usable) signing key supplied to it. Additionally, if a symmetric passphrase is supplied, it will also encrypt the message with a symmetric key derived from that passphrase. By default, JPGPJ will use `AES128` for encryption, `SHA256` for signing, and `ZLIB` for compression; and when encrypting with a symmetric passphrase, use `SHA512` for key derivation, at the maximum work factor. These defaults would look like this if specified as options to the `gpg` command:
```shell
gpg --cipher-algo AES --digest-algo SHA256 --compress-algo ZLIB --compress-level 6 \
    --s2k-digest-algo SHA512 --s2k-mode 3 --s2k-count 65011712
```

More Examples
-------------

Here's a fancier encryption example, using the [Java Servlet](https://docs.oracle.com/javaee/7/api/javax/servlet/Servlet.html) API to sign and encrypt the text of a servlet's "message" request parameter, and output it with ASCII Armor to the response. It uses the GnuPG 1.4.x-series default algorithms; and while it signs with Alice's key, it encrypts only with Bob's key:
```java
protected void doGet(HttpServletRequest request, HttpServletResponse response)
throws ServletException, IOException {
    // extract "message" request parameter to use as encrypted content
    String message = request.getParameter("message");
    if (message == null || message.length() == 0)
        message = "the medium is the message";

    Encryptor encryptor = null;
    try {
        // use Bob's public key for encryption
        encryptor = new Encryptor(
            new Key(new File("path/to/my/keys/bob-pub.gpg"))
        );
        // use custom encryption, signing, and compression algorithms
        encryptor.setEncryptionAlgorithm(EncryptionAlgorithm.CAST5);
        encryptor.setSigningAlgorithm(HashingAlgorithm.SHA1);
        encryptor.setCompressionAlgorithm(CompressionAlgorithm.ZLIB);
        // output with ascii armor
        encryptor.setAsciiArmored(true);

        // manipulate Alice's secret key before supplying it to the encryptor
        Key alice = new Key(new File("path/to/my/keys/alice-sec.gpg"));
        for (Subkey subkey : alice.getSubkeys()) {
            // don't use Alice's encryption subkey
            if (subkey.isForEncryption())
                subkey.setForEncryption(false);
            // unlock Alice's signing subkey with a passphrase of "password123"
            if (subkey.isForSigning())
                subkey.setPassphraseChars(new char[] {
                    'p','a','s','s','w','o','r','d','1','2','3'
                });
        }
        encryptor.getRing().getKeys().add(alice);

        // encrypt the (ascii-armored) message to the response
        response.setContentType("text/plain");
        encryptor.encrypt(
            new ByteArrayInputStream(message.getBytes("UTF-8")),
            response.getOutputStream()
        );
    } catch (PGPException e) {
        throw new ServletException(e);
    } finally {
        // zero-out passphrase and release private key material for GC
        if (encryptor != null)
            encryptor.clearSecrets();
    }
}
```

Here's a fancier "decryption" example, using the [Java Servlet](https://docs.oracle.com/javaee/7/api/javax/servlet/Servlet.html) API, the [Apache Commons FileUpload](https://commons.apache.org/proper/commons-fileupload/) library, and the [Google GSON](https://github.com/google/gson) library to verify the signatures of unencrypted files uploaded as part of a multipart post, returning the verification results as JSON. This example loads a bunch of public keys from `path/to/my/keys/ring.gpg` file, which then the decryptor uses for verification -- if none of these keys have signed an uploaded file, the example catches the `VerificationException` thrown by the decryptor (which signals verification has failed), and propagates the error message to the JSON result:
```java
protected void doPost(HttpServletRequest request, HttpServletResponse response)
throws ServletException, IOException {
    List results = new ArrayList();
    ServletFileUpload upload = new ServletFileUpload(new DiskFileItemFactory());

    try {
        // initialize decryptor with a bunch of trusted public keys
        Decryptor decryptor = new Decryptor(
            new Ring(new File("path/to/my/keys/ring.gpg"))
        );

        // add a json result entry for each uploaded file
        for (FileItem item : upload.parseRequest(request)) {
            Map result = new LinkHashMap();
            result.put("fileName", item.getName());

            try {
                // decrypt the uploaded file to verify it
                FileMetadata meta = decryptor.decrypt(
                    item.getInputStream(),
                    // ignore the decrypted content -- we just want the metadata
                    new OutputStream() {
                        public void write(int b) throws IOException {}
                    }
                );
                // extract the original metadata about the file
                // and populate the json result with it
                result.put("originalName", meta.getName());
                result.put("length", meta.getLength());
                result.put("lastModified", meta.getLastModified());

                // extract the metadata for the verified signatures
                List verifiedKeys = new ArrayList();
                for (Key key : meta.getVerified().getKeys()) {
                    Map verifiedKey = new LinkedHashMap();
                    verifiedKey.put("uids", key.getUids());
                    verifiedKey.put("shortId", key.getMaster().getShortId());
                    verifiedKey.put("fingerprint",
                        key.getMaster().getFingerprint());
                    verifiedKeys.add(verifiedKey);
                }
                result.put("verified", verifiedKeys);

            // handle case where no verified signatures were found
            // and propagate the error message from jpgpj to the client
            } catch (VerificationException e) {
                result.put("error", e.getMessage());
            }

            results.add(result);
        }

        // send back the results to the client as json
        response.setContentType("application/json");
        response.getWriter().print(new Gson().toJson(results));

    } catch (FileUploadException e) {
        throw new ServletException(e);
    } catch (PGPException e) {
        throw new ServletException(e);
    }
}
```
This servlet will produce JSON output like this:
```json
[
    {
        "fileName": "foo.txt.gpg",
        "orginalName": "foo.txt",
        "length": 1234,
        "lastModified": 1234567890,
        "verified": [
            {
                "uids": [
                    "Alice <alice@example.com>",
                    "Alice (non-commercial) <alice@example.org>"
                ],
                "shortId": "DEADBEEF",
                "fingerprint": "12341234123412341234123412341234"
            }
        ]
    },
    {
        "fileName": "bar.txt.gpg",
        "error": "content not signed with a required key"
    }
]
```

More Documentation
------------------

See the [wiki pages](https://github.com/justinludwig/jpgpj/wiki) for more details about [encryption](https://github.com/justinludwig/jpgpj/wiki/EncryptingFiles), [decryption](https://github.com/justinludwig/jpgpj/wiki/DecryptingFiles), [keys](https://github.com/justinludwig/jpgpj/wiki/KeyRings), etc. And see the [javadocs](https://justinludwig.github.io/jpgpj/javadoc/) for the full JPGPJ API.

Adding JPGPJ to Your Application
--------------------------------

### Via Maven

Add the following dependency to your `pom.xml` file:

```xml
<dependency>
    <groupId>org.c02e.jpgpj</groupId>
    <artifactId>jpgpj</artifactId>
    <version>2.1.0</version>
</dependency>
```

### Via Gradle

Add the following dependency to your `build.gradle` file:

```gradle
dependencies {
    ...
    implementation 'org.c02e.jpgpj:jpgpj:2.1.0'
    ...
}
```

### Manually

Since Bouncy Castle does all the actual crypto, the Bouncy Castle provider and OpenPGP jars are required. Download them from the [Bouncy Castle Latest Releases](https://www.bouncycastle.org/latest_releases.html) page (`bcprov-jdk18on`, `bcpg-jdk18on`, and `bcutil-jdk18on`, version 1.84 or later).

Bouncy Castle is the only dependency of JPGPJ, so you only need its jar files and the JPGPJ jar on your classpath.

### Bouncy Castle FIPS

For FIPS 140-3 certified deployments, use the Bouncy Castle FIPS artifact set instead of the standard jars:

- `bc-fips` and `bcutil-fips` (provider)
- `bcpg-fips` (OpenPGP)

**Standard and FIPS Bouncy Castle jars must not coexist in the same JVM.**

Before any JPGPJ operation, install the FIPS provider:

```java
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.c02e.jpgpj.JcaContextHelper;

JcaContextHelper.setSecurityProvider(new BouncyCastleFipsProvider());
```

Alternatively, set the system property `jpgpj.security.provider` to the fully-qualified provider class name. JPGPJ auto-detects whichever single BC stack is present on the classpath.

JPGPJ defaults (AES128, SHA256, SHA512) are suitable for FIPS environments. Legacy algorithms exposed by the API (CAST5, IDEA, MD5, SHA1, etc.) may be rejected in strict FIPS approved mode.

Building from Source
--------------------

Assuming you have git installed on your system, you can get the source from GitHub with the following command:
```shell
git clone https://github.com/justinludwig/jpgpj.git
```
This will create a `jpgpj` directory, with the source inside.

Inside the `jpgpj` directory, you can run the tests with this command:
```shell
./gradlew test
```
This will automatically download the right version of gradle for you, and run all the unit tests. You can view the test results at `build/reports/tests/index.html` (open that file in a web browser).

To run [PIT](https://pitest.org/) mutation testing (about two minutes on a typical laptop):

```shell
./gradlew pitest
```

Open `build/reports/pitest/index.html` for the report. PIT forks an isolated JVM that does not inherit Gradle `test` task settings; `TestEnvironmentListener` normalizes `line.separator` before Bouncy Castle initializes.

You can build the JPGPJ jar with this command:
```shell
./gradlew jar
```
You will find the built jar in the `build/libs` directory.
