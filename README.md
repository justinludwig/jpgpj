Java Pretty Good Privacy Jig
============================

JPGPJ provides a simple API on top of the [Bouncy Castle](https://www.bouncycastle.org/) Java OpenPGP implementation (which is full and robust implementation of [RFC 4880](https://tools.ietf.org/html/rfc4880), and compatible with other popular PGP implementations such as [GnuPG](https://www.gnupg.org/),  [GPGTools](https://gpgtools.org/), and [Gpg4win](https://www.gpg4win.org/)). The JPGPJ API is limited to file encryption, signing, decryption, and verification; it does not include the ability to generate, update, or sign keys, or to do clearsigning or detached signatures.

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

    try {
        // use Bob's public key for encryption
        Encryptor encryptor = new Encryptor(
            new Key(new File("path/to/my/keys/bob-pub.gpg"))
        );
        // use custom encryption, signing, and compression algorithms
        encryptor.setEncryptionAlgorithm(EncryptionAlgorithm.CAST5);
        encryptor.setSigningAlgorithm(HashAlgorithm.SHA1);
        encryptor.setCompressionAlgorithm(CompressionAlgorithm.ZLIB);
        // output with ascii armor
        encryptor.setAsciiArmored(true);

        // manipulate Alice's secret key before supplying it to the encryptor
        Key alice = new new Key(new File("path/to/my/keys/alice-sec.gpg"));
        for (Subkey subkey : alice.getSubkeys()) {
            // don't use Alice's encryption subkey
            if (subkey.isForEncryption())
                subkey.setForEncryption(false);
            // unlock Alice's signing subkey with a passphrase of "password123"
            if (subkey.isForSigning())
                subkey.setPassphrase("password123");
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
    <version>0.1.4</version>
</dependency>
```

### Via Gradle

Add the following dependency to your `build.gradle` file:

```gradle
dependencies {
    ...
    compile 'org.c02e.jpgpj:jpgpj:0.1.4'
    ...
}
```

### Manually

Since Bouncy Castle does all the actual crypto, the Bouncy Castle "Provider" and "OpenPGP/BCPG" jars are required. You can download them from the [Bouncy Castle Latest Releases](https://www.bouncycastle.org/latest_releases.html) page (where you specifically want the `bcprov-jdk15on-159.jar` and `bcpg-jdk15on-159.jar` jar files).

Bouncy Castle is the only dependency of JPGPJ, however, so you only need to add its jar files, and the JPGPJ jar file, to your classpath.

Building from Source
--------------------

Assuming you have git installed on your system, you can get the source from GitHub with the following command:
```shell
git checkout https://github.com/justinludwig/jpgpj.git
```
This will create a `jpgpj` directory, with the source inside.

Inside the `jpgpj` directory, you can run the tests with this command:
```shell
./gradlew test
```
This will automatically download the right version of gradle for you, and run all the unit tests. You can view the test results at `build/reports/tests/index.html` (open that file in a web browser).

You can build the JPGPJ jar with this command:
```shell
./gradlew jar
```
You will find the built jar in the `build/libs` directory.
