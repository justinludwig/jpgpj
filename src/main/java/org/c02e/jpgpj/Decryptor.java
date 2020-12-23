package org.c02e.jpgpj;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPDataValidationException;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPMarker;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPOnePassSignature;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;
import org.bouncycastle.openpgp.PGPPBEEncryptedData;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.PGPSignatureSubpacketVector;
import org.bouncycastle.openpgp.bc.BcPGPObjectFactory;
import org.bouncycastle.openpgp.operator.PBEDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.PGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.bc.BcPBEDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory;
import org.c02e.jpgpj.util.FileDetection;
import org.c02e.jpgpj.util.FileDetection.DetectionResult;
import org.c02e.jpgpj.util.Util;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Decrypts and verifies PGP messages using the decryption and verification
 * {@link Key}s supplied on this object's {@link Ring}.
 * <p>
 * To turn off verification, {@link #setVerificationRequired} to false.
 * To decrypt a message encrypted with a passphrase (instead of, or in addition
 * to, a public-key pair), use {@link #setSymmetricPassphrase} to supply
 * the passphrase.
 * <p>
 * Here's an example of Bob decrypting and verifying an encrypted file
 * that was signed by Alice:
 * <pre>{@code
 * new Decryptor(
 *     new Key(new File("path/to/my/keys/alice-pub.gpg")),
 *     new Key(new File("path/to/my/keys/bob-sec.gpg"), "b0bru1z!")
 * ).decrypt(
 *     new File("path/to/ciphertext.txt.gpg"),
 *     new File("path/back-to/plaintext.txt")
 * );
 * }</pre>
 * This is equivalent to the following `gpg` command (where Bob has a
 * `bob` secret key and an `alice` public key on his keyring, and enters
 * "b0bru1z!" when prompted for his passphrase):
 * <pre>{@code
 * gpg --decrypt --output path/back-to/plaintext.txt path/to/ciphertext.txt.gpg
 * }</pre>
 */
public class Decryptor {
    public static final int DEFAULT_MAX_FILE_BUFFER_SIZE = 0x100000; // 1MB
    public static final boolean DEFAULT_VERIFICATION_REQUIRED = true;
    public static final int DEFAULT_COPY_FILE_BUFFER_SIZE = 0x4000;

    protected boolean verificationRequired = DEFAULT_VERIFICATION_REQUIRED;
    protected char[] symmetricPassphraseChars;
    /** @deprecated Null unless explicitly set by user. */
    @Deprecated
    protected String symmetricPassphrase;
    protected int maxFileBufferSize = DEFAULT_MAX_FILE_BUFFER_SIZE; //1MB
    protected int copyFileBufferSize = DEFAULT_COPY_FILE_BUFFER_SIZE;
    protected Ring ring;
    protected final Logger log = LoggerFactory.getLogger(Decryptor.class.getName());


    /** Constructs a decryptor with an empty key ring. */
    public Decryptor() {
        this(new Ring());
    }

    /** Constructs a decryptor with the specified key ring. */
    public Decryptor(Ring ring) {
        setSymmetricPassphraseChars(null);
        setRing(ring);
    }

    /** Constructs a decryptor with the specified keys. */
    public Decryptor(Key... keys) {
        this(new Ring(keys));
    }

    /**
     * @return {@code true} to require messages be signed with
     * at least one key from ring. Defaults to true.
     */
    public boolean isVerificationRequired() {
        return verificationRequired;
    }

    /**
     * @param x {@code true} to require messages be signed with at least
     * one key from ring. Defaults to {@code true}.
     * @see #DEFAULT_VERIFICATION_REQUIRED
     */
    public void setVerificationRequired(boolean x) {
        verificationRequired = x;
    }

    /** @see #setVerificationRequired(boolean) */
    public Decryptor withVerificationRequired(boolean x) {
        setVerificationRequired(x);
        return this;
    }

    /**
     * @return Passphrase to use to decrypt with a symmetric key; or empty char[].
     * Note that this char[] itself (and not a copy) will be cached and used
     * until {@link #clearSecrets} is called (or
     * {@link #setSymmetricPassphraseChars} is called again with a different
     * passphrase, and then the char[] will be zeroed.
     */
    public char[] getSymmetricPassphraseChars() {
        return symmetricPassphraseChars;
    }

    /**
     * @param x Passphrase to use to decrypt with a symmetric key; or empty char[].
     * Note that this char[] itself (and not a copy) will be cached and used
     * until {@link #clearSecrets} is called (or
     * {@link #setSymmetricPassphraseChars} is called again with a different
     * passphrase, and then the char[] will be zeroed.
     */
    public void setSymmetricPassphraseChars(char[] x) {
        if (x == null)
            x = new char[0];

        if (!Arrays.equals(x, symmetricPassphraseChars)) {
            symmetricPassphraseChars = x;
            symmetricPassphrase = null;
        }
    }

    /** @see #setSymmetricPassphraseChars(char[]) */
    public Decryptor withSymmetricPassphraseChars(char[] x) {
        setSymmetricPassphraseChars(x);
        return this;
    }

    /**
     * @return Passphrase to use to decrypt with a symmetric key; or empty string.
     * Prefer {@link #getSymmetricPassphraseChars} to avoid creating extra copies
     * of the passphrase in memory that cannot be cleaned up.
     * @see #getSymmetricPassphraseChars
     */
    public String getSymmetricPassphrase() {
        if (symmetricPassphrase == null)
            symmetricPassphrase = new String(symmetricPassphraseChars);
        return symmetricPassphrase;
    }

    /**
     * @param x Passphrase to use to decrypt with a symmetric key; or empty string.
     * Prefer {@link #setSymmetricPassphraseChars} to avoid creating extra copies
     * of the passphrase in memory that cannot be cleaned up.
     * @see #setSymmetricPassphraseChars
     */
    public void setSymmetricPassphrase(String x) {
        setSymmetricPassphraseChars(x != null ? x.toCharArray() : null);
        symmetricPassphrase = x;
    }

    /** @see #setSymmetricPassphrase(String) */
    public Decryptor withSymmetricPassphrase(String x) {
        setSymmetricPassphrase(x);
        return this;
    }

    public int getMaxFileBufferSize() {
        return maxFileBufferSize;
    }

    /**
     * Decryptor will choose the most appropriate read/write buffer size
     * for each file. You can set the maximum value here. Defaults to 1MB.
     *
     * @param maxFileBufferSize The read/write buffer size
     * @see #DEFAULT_MAX_FILE_BUFFER_SIZE
     */
    public void setMaxFileBufferSize(int maxFileBufferSize) {
        this.maxFileBufferSize = maxFileBufferSize;
    }

    /** @see #setMaxFileBufferSize(int) */
    public Decryptor withMaxFileBufferSize(int maxFileBufferSize) {
        setMaxFileBufferSize(maxFileBufferSize);
        return this;
    }

    /**
     * @return Internal buffer size used to copy data from input ciphertext
     * stream to output plaintext stream internally
     * @see #DEFAULT_COPY_FILE_BUFFER_SIZE
     * @see #getCopyBuffer()
     */
    public int getCopyFileBufferSize() {
        return copyFileBufferSize;
    }

    /**
     * @param copyFileBufferSize Internal buffer size used to copy data from
     * input ciphertext stream to output plaintext stream internally
     * @see #DEFAULT_COPY_FILE_BUFFER_SIZE
     * @see #getCopyBuffer()
     */
    public void setCopyFileBufferSize(int copyFileBufferSize) {
        this.copyFileBufferSize = copyFileBufferSize;
    }

    /** @see #setCopyFileBufferSize(int) */
    public Decryptor withCopyFileBufferSize(int copyFileBufferSize) {
        setCopyFileBufferSize(copyFileBufferSize);
        return this;
    }

    /** @return Keys {@link Ring} to use for decryption and verification. */
    public Ring getRing() {
        return ring;
    }

    /** @param x Keys {@link Ring} to use for decryption and verification. */
    public void setRing(Ring x) {
        ring = x != null ? x : new Ring();
    }

    /** @see #setRing(Ring) */
    public Decryptor withRing(Ring x) {
        setRing(x);
        return this;
    }

    /**
     * Zeroes-out the cached passphrase for all keys,
     * and releases the extracted private key material for garbage collection.
     */
    public void clearSecrets() {
        ring.clearSecrets();

        // zero-out symmetric passphrase data
        Arrays.fill(symmetricPassphraseChars, (char) 0);
        // flag as empty
        symmetricPassphraseChars = new char[0];
        // cannot cleanup futher, release for GC
        symmetricPassphrase = null;
    }

    /**
     * Decrypts the first specified file to the output location specified
     * by the second file, and (if {@link #isVerificationRequired})
     * verifies its signatures. If a file already exists in the output file's
     * location, it will be deleted. If an exception occurs during decryption,
     * the output file will be deleted.
     * @param ciphertext File containing a PGP message, in binary or
     * ASCII Armor format.
     * @param plaintext Location of the file into which to decrypt the message.
     * @return Metadata of original file, and the list of keys that signed
     * the message with a verified signature. The original file metadata
     * values are optional, and may be missing or incorrect.
     * @throws IOException if an IO error occurs reading from or writing to
     * the underlying input or output streams.
     * @throws PGPException if the PGP message is not formatted correctly.
     * @throws PassphraseException if an incorrect passphrase was supplied
     * for one of the decryption keys, or as the
     * {@link #getSymmetricPassphrase()}.
     * @throws DecryptionException if the message was not encrypted for any
     * of the keys supplied for decryption.
     * @throws VerificationException if {@link #isVerificationRequired} and
     * the message was not signed by any of the keys supplied for verification.
     */
    public FileMetadata decrypt(File ciphertext, File plaintext)
            throws IOException, PGPException {
        if (ciphertext.equals(plaintext))
            throw new IOException("cannot decrypt " + ciphertext +
                " over itself");

        // delete old output file
        if (plaintext.delete()) {
            log.debug("decrypt({}) deleted {}", ciphertext, plaintext);
        }

        long inputSize = ciphertext.length();
        try (InputStream sourceStream = new FileInputStream(ciphertext);
             InputStream input = wrapSourceInputStream(sourceStream, inputSize);
             OutputStream targetStream = new FileOutputStream(plaintext);
             OutputStream output = wrapTargetOutputStream(targetStream, inputSize)) {
            return decrypt(input, output);
        } catch (Exception e) {
            // delete output file if anything went wrong
            if (!plaintext.delete()) {
                log.warn("decrypt({}) cannot clean up {}", ciphertext, plaintext);
            }
            throw e;
        }
    }

    /**
     * @param sourceStream Original source (ciphertext) {@link InputStream}
     * @param inputSize Expected input (ciphertext) size
     * @return A wrapper buffered stream optimized for the input size according to
     * the current encryptor settings
     * @throws IOException If failed to generate the wrapper
     */
    public InputStream wrapSourceInputStream(InputStream sourceStream, long inputSize) throws IOException {
        int bestFileBufferSize = Util.bestFileBufferSize(inputSize, getMaxFileBufferSize());
        return new BufferedInputStream(sourceStream, bestFileBufferSize);
    }

    /**
     * @param targetStream Original target (plaintext) {@link OutputStream}
     * @param inputSize Expected input (ciphertext) size
     * @return A wrapper buffered stream optimized for the input size according to
     * the current encryptor settings
     * @throws IOException If failed to generate the wrapper
     */
    public OutputStream wrapTargetOutputStream(OutputStream targetStream, long inputSize) throws IOException {
        int bestFileBufferSize = Util.bestFileBufferSize(inputSize, getMaxFileBufferSize());
        return new BufferedOutputStream(targetStream, bestFileBufferSize);
    }

    /**
     * Decrypts the specified PGP message into the specified output stream,
     * and (if {@link #isVerificationRequired}) verifies the message
     * signatures. Does not close or flush the streams.
     * <p>
     * Note that the full decrypted content will be written to the output stream
     * before the message is verified, so you may want to buffer the content
     * and not write it to its final destination until this method returns.
     * @param ciphertext PGP message, in binary or ASCII Armor format.
     * @param plaintext Decrypted content.
     * @return Metadata of original file, and the list of keys that signed
     * the message with a verified signature. The original file metadata
     * values are optional, and may be missing or incorrect.
     * @throws IOException if an IO error occurs reading from or writing to
     * the underlying input or output streams.
     * @throws PGPException if the PGP message is not formatted correctly.
     * @throws PassphraseException if an incorrect passphrase was supplied
     * for one of the decryption keys, or as the
     * {@link #getSymmetricPassphrase()}.
     * @throws DecryptionException if the message was not encrypted for any
     * of the keys supplied for decryption.
     * @throws VerificationException if {@link #isVerificationRequired} and
     * the message was not signed by any of the keys supplied for verification.
     * @see #decryptWithFullDetails(InputStream, OutputStream) decryptWithFullDetails
     */
    public FileMetadata decrypt(InputStream ciphertext, OutputStream plaintext)
            throws IOException, PGPException {
        DecryptionResult result = decryptWithFullDetails(ciphertext, plaintext);
        return result.getFileMetadata();
    }

    /**
     * Decrypts the specified PGP message into the specified output stream,
     * including the armored headers (if stream was armored and contained
     * any such headers). If {@link #isVerificationRequired} also verifies
     * the message signatures. <B>Note:</B> does not close or flush the streams.
     *
     * @param ciphertext PGP message, in binary or ASCII Armor format.
     * @param plaintext Decrypted content target {@link OutputStream}
     * @return The {@link DecryptionResult} containing all relevant
     * information that could be extracted from the encrypted data - including
     * metadata, armored headers (if any), etc...
     * @throws IOException if an IO error occurs reading from or writing to
     * the underlying input or output streams.
     * @throws PGPException if the PGP message is not formatted correctly.
     * @throws PassphraseException if an incorrect passphrase was supplied
     * for one of the decryption keys, or as the
     * {@link #getSymmetricPassphrase()}.
     * @throws DecryptionException if the message was not encrypted for any
     * of the keys supplied for decryption.
     * @throws VerificationException if {@link #isVerificationRequired} and
     * the message was not signed by any of the keys supplied for verification.
     */
    public DecryptionResult decryptWithFullDetails(
            InputStream ciphertext, OutputStream plaintext)
                throws IOException, PGPException {
        InputStream unarmoredStream = unarmor(ciphertext);
        List<FileMetadata> meta = unpack(parse(unarmoredStream), plaintext);
        if (meta.size() > 1)
            throw new PGPException("content contained more than one file");

        FileMetadata metadata = (meta.size() < 1) ? new FileMetadata() : meta.get(0);
        if (unarmoredStream instanceof ArmoredInputStream) {
            ArmoredInputStream ais = (ArmoredInputStream) unarmoredStream;
            String[] headers = ais.getArmorHeaders();
            return new DecryptionResult(metadata, true,
                ((headers == null) || (headers.length == 0))
                ? Collections.emptyList()
                : Arrays.asList(headers));
        } else {
            return new DecryptionResult(metadata, false, Collections.emptyList());
        }
     }

    /**
     * Recursively unpacks the pgp message packets,
     * writing the decrypted message content into the output stream.
     */
    protected List<FileMetadata> unpack(Iterator<?> packets, OutputStream plaintext)
            throws IOException, PGPException {
        List<FileMetadata> meta = new ArrayList<FileMetadata>();
        List<Verifier> verifiers = new ArrayList<Verifier>();

        while (packets.hasNext()) {
            Object packet = packets.next();

            log.trace("unpack {}", packet.getClass());

            if (packet instanceof PGPMarker) {
                // no-op

            } else if (packet instanceof PGPOnePassSignatureList) {
                PGPOnePassSignatureList list = (PGPOnePassSignatureList) packet;
                // in message header, initialize verifiers for these sigs
                verifiers = buildVerifiers(list.iterator());

            } else if (packet instanceof PGPSignatureList) {
                PGPSignatureList list = (PGPSignatureList) packet;
                // when in message header, initialize verifiers for these sigs
                if (Util.isEmpty(verifiers))
                    verifiers = buildVerifiers(list.iterator());
                // when in message trailer, match sigs to one-pass sigs
                // in already initialized verifiers
                else
                    matchSignatures(list.iterator(), verifiers);
            } else if (packet instanceof PGPEncryptedDataList) {
                PGPEncryptedDataList list = (PGPEncryptedDataList) packet;
                // decrypt and unpack encrypted content
                meta.addAll(unpack(parse(decrypt(list.iterator())), plaintext));
            } else if (packet instanceof PGPCompressedData) {
                InputStream i = ((PGPCompressedData) packet).getDataStream();
                // unpack compressed content
                meta.addAll(unpack(parse(i), plaintext));
            } else if (packet instanceof PGPLiteralData) {
                PGPLiteralData data = (PGPLiteralData) packet;
                FileMetadata file = new FileMetadata(data);
                InputStream i = data.getDataStream();
                // copy literal input stream to output stream
                // while also passing input bytes into verifiers
                file.setLength(copy(i, plaintext, verifiers));
                meta.add(file);
            } else {
                throw new PGPException("unexpected packet: " + packet.getClass());
            }
        }
        log.trace("unpacked all");

        // fail if verification required and any signature is bad
        verify(verifiers, meta);
        return meta;
    }

    /**
     * Builds a {@link Verifier} for each specified signature
     * for which a verification key is available.
     */
    protected List<Verifier> buildVerifiers(Iterator<?> signatures)
            throws PGPException {
        List<Verifier> verifiers = new ArrayList<Verifier>();
        while (signatures.hasNext()) {
            Verifier verifier = null;

            Object signature = signatures.next();
            if (signature instanceof PGPSignature)
                verifier = new Verifier((PGPSignature) signature);
            else if (signature instanceof PGPOnePassSignature)
                verifier = new Verifier((PGPOnePassSignature) signature);

            if (verifier != null && verifier.isKeyAvailable())
                verifiers.add(verifier);
        }
        return verifiers;
    }

    /**
     * Matches the specified trailing signatures to the specified verifiers.
     */
    protected void matchSignatures(
            Iterator<PGPSignature> signatures, List<Verifier> verifiers) {
        while (signatures.hasNext()) {
            PGPSignature signature = signatures.next();

            for (Verifier verifier : verifiers)
                verifier.match(signature);
        }
    }

    /**
     * Decrypts the encrypted data as the returned input stream.
     */
    protected InputStream decrypt(Iterator<?> data)
            throws IOException, PGPException {
        PGPPBEEncryptedData pbe = null;

        Ring decryptRing = getRing();
        while (data.hasNext()) {
            Object o = data.next();

            if (o instanceof PGPPublicKeyEncryptedData) {
                PGPPublicKeyEncryptedData pke = (PGPPublicKeyEncryptedData) o;

                // try to find decryption key for pk-encrypted data
                Long id = pke.getKeyID();
                List<Key> keys = decryptRing.findAll(id);

                for (Key key: keys) {
                    Subkey subkey = key.findById(id);
                    if (isUsableForDecryption(subkey))
                        return decrypt(pke, subkey);

                    log.info("not using decryption key {}", subkey);
                }

                if (Util.isEmpty(keys))
                    log.info("not found decryption key {}", Util.formatKeyId(id));

            } else if (o instanceof PGPPBEEncryptedData) {
                // try first symmetric-key option at the end
                if (pbe == null)
                    pbe = (PGPPBEEncryptedData) o;
            }
        }

        return decrypt(pbe);
    }

    /**
     * Decrypts the encrypted data as the returned input stream.
     */
    protected InputStream decrypt(PGPPublicKeyEncryptedData data, Subkey subkey)
            throws IOException, PGPException {
        if (data == null || subkey == null)
            throw new DecryptionException("no suitable decryption key found");

        log.info("using decryption key {}", subkey);

        return data.getDataStream(buildPublicKeyDecryptor(subkey));
    }

    /**
     * Decrypts the encrypted data as the returned input stream.
     */
    protected InputStream decrypt(PGPPBEEncryptedData data)
            throws IOException, PGPException {
        char[] passphraseChars = getSymmetricPassphraseChars();
        if ((data == null) || Util.isEmpty(passphraseChars))
            throw new DecryptionException("no suitable decryption key found");

        try {
            return data.getDataStream(
                buildSymmetricKeyDecryptor(passphraseChars));
        } catch (PGPDataValidationException e) {
            throw new PassphraseException(
                "incorrect passphrase for symmetric key", e);
        }
    }

    /**
     * Copies the content from the specified input stream
     * to the specified output stream, while also checking the content
     * with the specified list of verifiers (if verification required).
     */
    protected long copy(InputStream i, OutputStream o, List<Verifier> verifiers)
            throws IOException, PGPException {
        long total = 0;
        byte[] buf = getCopyBuffer();
        int len = i.read(buf);

        boolean verifyResult = isVerificationRequired();
        if (verifyResult && Util.isEmpty(verifiers))
            throw new VerificationException(
                "content not signed with a required key");

        while (len != -1) {
            total += len;

            if (verifyResult) {
                for (Verifier verifier : verifiers)
                    if (verifier.sig != null)
                        verifier.sig.update(buf, 0, len);
                    else
                        verifier.sig1.update(buf, 0, len);
            }

            o.write(buf, 0, len);
            len = i.read(buf);
        }

        return total;
    }

    /**
     * Verifies each verifier's signature, and adds keys
     * with verified signatures to the file metadata.
     */
    protected void verify(List<Verifier> verifiers, List<FileMetadata> meta)
            throws PGPException {
        if (!isVerificationRequired()) return;

        for (Verifier verifier : verifiers) {
            if (!verifier.verify())
                throw new VerificationException(
                        "bad signature for key " + verifier.key);
            else
                log.debug("good signature for key {}", verifier.key);

            Key key = verifier.getSignedBy();
            for (FileMetadata file : meta) {
                Ring verified = file.getVerified();
                Collection<Key> keys = verified.getKeys();
                keys.add(key);
            }
        }
    }

    /**
     * Wraps stream with ArmoredInputStream if necessary
     * (to convert ASCII-armored content back into binary data).
     */
    protected InputStream unarmor(InputStream stream)
            throws IOException, PGPException {
        DetectionResult result =
            FileDetection.detectContainer(stream, getMaxFileBufferSize());
        switch (result.type) {
            case ASCII_ARMOR:
                return new ArmoredInputStream(result.stream);
            case PGP:
                return result.stream;
            default:
                throw new PGPException("not a pgp message");
        }
    }

    /**
     * Separates stream into PGP packets.
     * @see PGPObjectFactory
     */
    protected Iterator<?> parse(InputStream stream)
            throws IOException, PGPException {
        return new BcPGPObjectFactory(stream).iterator();
    }

    /**
     * Helper for signature verification.
     */
    protected PGPContentVerifierBuilderProvider getVerifierProvider() {
        return new BcPGPContentVerifierBuilderProvider();
    }

    protected boolean isUsableForDecryption(Subkey subkey) {
        return subkey != null && subkey.isForDecryption() &&
            (subkey.isUnlocked() || !Util.isEmpty(subkey.passphraseChars));
    }

    /**
     * Builds a symmetric-encryption decryptor for the specified subkey.
     */
    protected PublicKeyDataDecryptorFactory buildPublicKeyDecryptor(Subkey subkey)
            throws PGPException {
        PGPPrivateKey privateKey = subkey.getPrivateKey();
        if (privateKey == null)
            throw new PGPException("no private key for " + subkey);
        return new BcPublicKeyDataDecryptorFactory(privateKey);
    }

    /**
     * Builds a symmetric-key decryptor for the specified passphrase.
     */
    protected PBEDataDecryptorFactory buildSymmetricKeyDecryptor(char[] passphraseChars) {
        return new BcPBEDataDecryptorFactory(passphraseChars,
            new BcPGPDigestCalculatorProvider());
    }

    public byte[] getCopyBuffer() {
        return new byte[getCopyFileBufferSize()];
    }

    /**
     * Helper for verifying a given message signature.
     */
    protected class Verifier {
        public Key key;
        public PGPSignature sig;
        public PGPOnePassSignature sig1;

        public Verifier() {
            super();
        }

        public Verifier(PGPSignature s) throws PGPException {
            setSig(s);
        }

        public Verifier(PGPOnePassSignature s) throws PGPException {
            setSig1(s);
        }

        public boolean isKeyAvailable() {
            return key != null;
        }

        public void setSig(PGPSignature s) throws PGPException {
            sig = s;
            if (sig1 != null) return;

            Subkey subkey = findVerificationSubkey(s.getKeyID());
            if (subkey != null)
                s.init(getVerifierProvider(), subkey.getPublicKey());
        }

        public void setSig1(PGPOnePassSignature s) throws PGPException {
            sig1 = s;

            Subkey subkey = findVerificationSubkey(s.getKeyID());
            if (subkey != null)
                s.init(getVerifierProvider(), subkey.getPublicKey());
        }

        /**
         * Tries to match the specified PGPSignature to this verifier's
         * PGPOnePassSignature (sig1); if found sets sig and returns true.
         */
        public boolean match(PGPSignature s) {
            if (sig1 != null && sig1.getKeyID() == s.getKeyID()) {
                sig = s;
                return true;
            }
            return false;
        }

        /**
         * True if the signature checks out.
         */
        public boolean verify() throws PGPException {
            if (key == null || sig == null) return false;
            return sig1 != null ? sig1.verify(sig) : sig.verify();
        }

        /**
         * Copy of matched key with signingUid configured
         * and only public subkeys, or null.
         */
        public Key getSignedBy() throws PGPException {
            if (key == null || sig == null) return null;

            // extract optional uid if available
            String uid = null;
            PGPSignatureSubpacketVector subpackets = sig.getHashedSubPackets();
            if (subpackets != null)
                uid = subpackets.getSignerUserID();

            Key by = key.toPublicKey();
            by.setSigningUid(uid != null ? uid : "");
            return by;
        }

        /**
         * Finds verification subkey by ID in this Decryptor's ring, or null.
         * If found, also sets "key" field to subkey's key.
         */
        private Subkey findVerificationSubkey(Long id) {
            Ring decryptorRing = getRing();
            List<Key> keys = decryptorRing.findAll(id);

            for (Key key: keys) {
                Subkey subkey = key.findById(id);

                if (subkey != null && subkey.isForVerification()) {
                    log.info("using verification key {}", subkey);
                    this.key = key;
                    return subkey;
                }

                log.info("not using verification key {}", subkey);
            }

            if (Util.isEmpty(keys))
                log.info("not found verification key {}", Util.formatKeyId(id));

            return null;
        }
    }
}
