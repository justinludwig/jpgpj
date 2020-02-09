package org.c02e.jpgpj;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.operator.PBEKeyEncryptionMethodGenerator;
import org.bouncycastle.openpgp.operator.PGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.PublicKeyKeyEncryptionMethodGenerator;
import org.bouncycastle.openpgp.operator.bc.BcPBEKeyEncryptionMethodGenerator;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyKeyEncryptionMethodGenerator;
import org.bouncycastle.util.Strings;
import org.c02e.jpgpj.util.Util;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Encrypts and signs PGP messages using the encryption and signing
 * {@link Key}s supplied on this object's {@link Ring}.
 * <p>
 * To encode a message with ASCII Armor, {@link #setAsciiArmored} to true.
 * To encrypt a message with a passphrase (instead of, or in addition
 * to, a public-key pair), use {@link #setSymmetricPassphrase} to supply
 * the passphrase.
 * <p>
 * To encrypt without signing, {@link #setSigningAlgorithm} to
 * {@link HashingAlgorithm#Unsigned}. To sign without encrypting,
 * {@link #setEncryptionAlgorithm} to {@link EncryptionAlgorithm#Unencrypted}.
 * To turn off compression, {@link #setCompressionAlgorithm} to
 * {@link CompressionAlgorithm#Uncompressed}.
 * <p>
 * <pre>{@code
 * Here's an example of Alice encrypting and signing a file for Bob:
 * new Encryptor(
 *     new Key(new File("path/to/my/keys/alice-sec.gpg"), "password123"),
 *     new Key(new File("path/to/my/keys/bob-pub.gpg"))
 * ).encrypt(
 *     new File("path/to/plaintext.txt"),
 *     new File("path/to/ciphertext.txt.gpg")
 * );
 * }</pre>
 * This is equivalent to the following `gpg` command (where Alice has an
 * `alice` secret key and a `bob` public key on her keyring, and enters
 * "password123" when prompted for her passphrase):
 * <pre>{@code
 * gpg --sign --encrypt --local-user alice --recipient alice --recipient bob \
 *     --output path/to/ciphertext.txt.gpg path/to/plaintext.txt
 * }</pre>
 */
public class Encryptor {
    public static final int MAX_ENCRYPT_COPY_BUFFER_SIZE = 0x10000;

    protected boolean asciiArmored;
    protected int compressionLevel;

    protected CompressionAlgorithm compressionAlgorithm;
    protected EncryptionAlgorithm encryptionAlgorithm;
    protected HashingAlgorithm signingAlgorithm;

    protected char[] symmetricPassphraseChars;
    /** @deprecated Null unless explicitly set by user. */
    @Deprecated
    protected String symmetricPassphrase;
    protected HashingAlgorithm keyDerivationAlgorithm;
    protected int keyDerivationWorkFactor;

    protected int maxFileBufferSize = 0x100000; //1MB

    protected Ring ring;
    protected final Logger log = LoggerFactory.getLogger(Encryptor.class.getName());

    /** Constructs an encryptor with an empty key ring. */
    public Encryptor() {
        compressionLevel = 6;
        compressionAlgorithm = CompressionAlgorithm.ZLIB;
        encryptionAlgorithm = EncryptionAlgorithm.AES128;
        signingAlgorithm = HashingAlgorithm.SHA256;
        setSymmetricPassphraseChars(null);
        keyDerivationAlgorithm = HashingAlgorithm.SHA512;
        keyDerivationWorkFactor = 255;
        ring = new Ring();
    }

    /** Constructs an encryptor with the specified key ring. */
    public Encryptor(Ring ring) {
        this();
        setRing(ring);
    }

    /** Constructs an encryptor with the specified keys. */
    public Encryptor(Key... keys) {
        this(new Ring(keys));
    }

    /** True to encode final output with ASCII Armor.  Defaults to false. */
    public boolean isAsciiArmored() {
        return asciiArmored;
    }

    /** True to encode final output with ASCII Armor.  Defaults to false. */
    public void setAsciiArmored(boolean x) {
        asciiArmored = x;
    }

    /**
     * Compression level, from 1 (fastest and biggest)
     * to 9 (slowest and smallest). Defaults to 6.
     */
    public int getCompressionLevel() {
        return compressionLevel;
    }

    /**
     * Compression level, from 1 (fastest and biggest)
     * to 9 (slowest and smallest). Defaults to 6.
     */
    public void setCompressionLevel(int x) {
        compressionLevel = x;
    }

    /**
     * Compression algorithm to use.
     * Defaults to {@link CompressionAlgorithm#ZLIB}.
     */
    public CompressionAlgorithm getCompressionAlgorithm() {
        return compressionAlgorithm;
    }

    /**
     * Compression algorithm to use.
     * Defaults to {@link CompressionAlgorithm#ZLIB}.
     */
    public void setCompressionAlgorithm(CompressionAlgorithm x) {
        compressionAlgorithm = x != null ? x : CompressionAlgorithm.Uncompressed;
    }

    /**
     * Encryption algorithm to use.
     * Defaults to {@link EncryptionAlgorithm#AES128}.
     */
    public EncryptionAlgorithm getEncryptionAlgorithm() {
        return encryptionAlgorithm;
    }

    /**
     * Encryption algorithm to use.
     * Defaults to {@link EncryptionAlgorithm#AES128}.
     */
    public void setEncryptionAlgorithm(EncryptionAlgorithm x) {
        encryptionAlgorithm = x != null ? x : EncryptionAlgorithm.Unencrypted;
    }

    /**
     * Signing algorithm to use.
     * Defaults to {@link HashingAlgorithm#SHA256}.
     */
    public HashingAlgorithm getSigningAlgorithm() {
        return signingAlgorithm;
    }

    /**
     * Signing algorithm to use.
     * Defaults to {@link HashingAlgorithm#SHA256}.
     */
    public void setSigningAlgorithm(HashingAlgorithm x) {
        signingAlgorithm = x != null ? x : HashingAlgorithm.Unsigned;
    }

    /**
     * Passphrase to use to encrypt with a symmetric key; or empty char[].
     * Note that this char[] itself (and not a copy) will be cached and used
     * until {@link #clearSecrets} is called (or
     * {@link #setSymmetricPassphraseChars} is called again with a different
     * passphrase), and then the char[] will be zeroed.
     */
    public char[] getSymmetricPassphraseChars() {
        return symmetricPassphraseChars;
    }

    /**
     * Passphrase to use to encrypt with a symmetric key; or empty char[].
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

    /**
     * Passphrase to use to encrypt with a symmetric key; or empty string.
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
     * Passphrase to use to encrypt with a symmetric key; or empty string.
     * Prefer {@link #setSymmetricPassphraseChars} to avoid creating extra copies
     * of the passphrase in memory that cannot be cleaned up.
     * @see #setSymmetricPassphraseChars
     */
    public void setSymmetricPassphrase(String x) {
        setSymmetricPassphraseChars(x != null ? x.toCharArray() : null);
        symmetricPassphrase = x;
    }

    /**
     * Key-deriviation (aka s2k digest) algorithm to use
     * (used to convert the symmetric passphrase into an encryption key).
     * Defaults to {@link HashingAlgorithm#SHA512}.
     */
    public HashingAlgorithm getKeyDeriviationAlgorithm() {
        return keyDerivationAlgorithm;
    }

    /**
     * Key-deriviation (aka s2k digest) algorithm to use
     * (used to convert the symmetric passphrase into an encryption key).
     * Defaults to {@link HashingAlgorithm#SHA512}.
     */
    public void setKeyDeriviationAlgorithm(HashingAlgorithm x) {
        keyDerivationAlgorithm = x != null ? x : HashingAlgorithm.Unsigned;
    }

    /**
     * Key-deriviation work factor (aka s2k count) to use, from 0 to 255
     * (where 1 = 1088 iterations, and 255 = 65,011,712 iterations).
     * Defaults to 255.
     */
    public int getKeyDeriviationWorkFactor() {
        return keyDerivationWorkFactor;
    }

    /**
     * Key-deriviation work factor (aka s2k count) to use, from 0 to 255
     * (where 1 = 1088 iterations, and 255 = 65,011,712 iterations).
     * Defaults to 255.
     */
    public void setKeyDeriviationWorkFactor(int x) {
        keyDerivationWorkFactor = x;
    }

    public int getMaxFileBufferSize() {
        return maxFileBufferSize;
    }

    /**
     * Encryptor will choose the most appropriate read/write buffer size
     * for each file. Defaults to 1MB.
     */
    public void setMaxFileBufferSize(int maxFileBufferSize) {
        this.maxFileBufferSize = maxFileBufferSize;
    }

    /** Keys to use for encryption and signing. */
    public Ring getRing() {
        return ring;
    }

    /** Keys to use for encryption and signing. */
    protected void setRing(Ring x) {
        ring = x != null ? x : new Ring();
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
     * Signs, compresses, and encrypts the specified file to the output location
     * specified by the second file. If a file already exists in the output
     * file's location, it will be deleted. If an exception occurs during
     * this processing, the output file will be deleted.
     * <p>
     * Use the {@link #setSigningAlgorithm}, {@link #setCompressionAlgorithm},
     * and {@link #setEncryptionAlgorithm} before running this method
     * to turn off or adjust signing, compression, or encryption.
     * @param plaintext File to encrypt.
     * @param ciphertext Location of output file.
     * @throws IOException if an IO error occurs reading from or writing to
     * the underlying input or output streams.
     * @throws PGPException if no encryption keys and no passphrase for
     * symmetric encryption were supplied (and the message is not unencrypted),
     * or if no signing keys were supplied (and the message is not unsigned).
     * @throws PassphraseException if an incorrect passphrase was supplied
     * for one of the signing keys.
     */
    public void encrypt(File plaintext, File ciphertext)
            throws IOException, PGPException {
        if (plaintext.equals(ciphertext))
            throw new IOException("cannot encrypt " + plaintext +
                " over itself");

        // delete old output file
        if (ciphertext.delete()) {
            log.debug("encrypt({}) deleted {}", plaintext, ciphertext);
        }

        InputStream input = null;
        OutputStream output = null;
        try {
            int bestFileBufferSize =
                Util.bestFileBufferSize(plaintext.length(), maxFileBufferSize);
            input = new BufferedInputStream(
                new FileInputStream(plaintext), bestFileBufferSize);
            output = new BufferedOutputStream(
                new FileOutputStream(ciphertext),
                estimateOutFileSize(plaintext.length()));
            encrypt(input, output, new FileMetadata(plaintext));
        } catch (Exception e) {
            // delete output file if anything went wrong
            if (output != null)
                try {
                    output.close();
                    ciphertext.delete();
                } catch (Exception ee) {
                    log.error("failed to delete bad output file " + plaintext, ee);
                }
            throw e;
        } finally {
            try { output.close(); } catch (Exception e) {}
            try { input.close(); } catch (Exception e) {}
        }
    }

    /**
     * Signs, compresses, and encrypts the specified content as a PGP message
     * into the specified output stream (with no optional metadata).
     * Does not close or flush the streams.
     * <p>
     * Use the {@link #setSigningAlgorithm}, {@link #setCompressionAlgorithm},
     * and {@link #setEncryptionAlgorithm} before running this method
     * to turn off or adjust signing, compression, or encryption.
     * @param plaintext Content to encrypt.
     * @param ciphertext PGP message, in binary or ASCII Armor format.
     * @throws IOException if an IO error occurs reading from or writing to
     * the underlying input or output streams.
     * @throws PGPException if no encryption keys and no passphrase for
     * symmetric encryption were supplied (and the message is not unencrypted),
     * or if no signing keys were supplied (and the message is not unsigned).
     * @throws PassphraseException if an incorrect passphrase was supplied
     * for one of the signing keys.
     */
    public void encrypt(InputStream plaintext, OutputStream ciphertext)
            throws IOException, PGPException {
        encrypt(plaintext, ciphertext, null);
    }

    /**
     * Signs, compresses, and encrypts the specified content as a PGP message
     * into the specified output stream with the specified content metadata.
     * Does not close or flush the streams.
     * <p>
     * Use the {@link #setSigningAlgorithm}, {@link #setCompressionAlgorithm},
     * and {@link #setEncryptionAlgorithm} before running this method
     * to turn off or adjust signing, compression, or encryption.
     * @param plaintext Content to encrypt.
     * @param ciphertext PGP message, in binary or ASCII Armor format.
     * @param meta Metadata of original file.
     * @throws IOException if an IO error occurs reading from or writing to
     * the underlying input or output streams.
     * @throws PGPException if no encryption keys and no passphrase for
     * symmetric encryption were supplied (and the message is not unencrypted),
     * or if no signing keys were supplied (and the message is not unsigned).
     * @throws PassphraseException if an incorrect passphrase was supplied
     * for one of the signing keys.
     */
    public void encrypt(
        InputStream plaintext, OutputStream ciphertext, FileMetadata meta)
            throws IOException, PGPException {
        if (meta == null) {
            meta = new FileMetadata();
        }

        try (OutputStream targetStream = prepareCiphertextOutputStream(ciphertext, meta)) {
            // copy plaintext bytes into encryption pipeline
            copy(plaintext, targetStream, null /* signer is inside the target */, meta);
        }
    }

    public OutputStream prepareCiphertextOutputStream(File ciphertext)
            throws IOException, PGPException {
        // delete old output file
        if (ciphertext.delete()) {
            log.debug("prepareCiphertextOutputStream - deleted {}", ciphertext);
        }

        FileMetadata meta = new FileMetadata(ciphertext);
        OutputStream fileStream = null;
        try {
            fileStream = new FileOutputStream(ciphertext);
            OutputStream wrapper = prepareCiphertextOutputStream(fileStream, meta);
            fileStream = null;  // avoid auto-close at finally clause
            return wrapper;
        } catch(Exception e) {
            // delete output file if anything went wrong
            if (fileStream != null) {
                ciphertext.delete();
            }
            throw e;
        } finally {
            if (fileStream != null) {
                fileStream.close();
            }
        }
    }

    /**
     * Prepares an {@link OutputStream} - so that everything written to it
     * is encrypted+compressed+signed - according to the encryptor's configuration
     *
     * @param ciphertext The original {@link OutputStream} into which the
     * encryption results are to be written. <B>Note:</B> the stream will
     * not be closed when the returned wrapper is closed
     * @param meta The {@link FileMetadata} - if {@code null} an ad-hoc
     * empty instance is used
     * @return A wrapper stream - <B>Note:</B> actual encryption and signature
     * is finalized when it is closed.
     * @throws IOException If failed to wrap the stream
     * @throws PGPException If failed to apply a PGP wraper
     */
    public OutputStream prepareCiphertextOutputStream(
            OutputStream ciphertext, FileMetadata meta)
                throws IOException, PGPException {
        if (meta == null)
            meta = new FileMetadata();

        // stack of output streams to close at end of process
        List<OutputStream> stack = new ArrayList<OutputStream>(6);
        stack.add(ciphertext);

        // setup encryption pipeline
        ciphertext = pipeline(armor(ciphertext), stack);
        ciphertext = pipeline(encrypt(ciphertext, meta), stack);
        ciphertext = pipeline(compress(ciphertext, meta), stack);
        SigningOutputStream signingstream = sign(ciphertext, meta);
        ciphertext = pipeline(signingstream, stack);
        ciphertext = pipeline(packet(ciphertext, meta), stack);
        return new EncryptorWrapperStream(ciphertext, signingstream, stack);
    }

    protected static class EncryptorWrapperStream extends FilterOutputStream {
        protected final AtomicBoolean finished = new AtomicBoolean(false);
        protected final SigningOutputStream signingstream;
        protected final List<? extends OutputStream> stack;
        protected final byte[] oneByte = { 0 };
        protected EncryptorWrapperStream(
                OutputStream ciphertext, SigningOutputStream signer, List<? extends OutputStream> wrappers) {
            super(ciphertext);

            signingstream = signer;
            stack = wrappers;
        }

        @Override
        public void write(int b) throws IOException {
            oneByte[0] = (byte) b;
            write(oneByte, 0, 1);
        }

        @Override   // just making sure
        public void write(byte b[]) throws IOException {
            write(b, 0, b.length);
        }

        @Override
        public void write(byte[] b, int off, int len) throws IOException {
            // FilterOutputStream implements it by writing one byte at a time
            if (signingstream != null) {
                signingstream.update(b, off, len);
            }
            out.write(b, off, len);
        }

        @Override
        public void close() throws IOException {
            // Ignore if already closed
            if (finished.getAndSet(true)) {
                return;
            }

            flush();

            finish();
        }

        protected void finish() throws IOException {
            // close all output streams except original at end of process
            IOException err = null;
            for (int i = stack.size() - 1; i > 0; i--) {
                OutputStream outputStream = stack.get(i);
                try {
                    outputStream.close();
                } catch (IOException e) {
                    if (err == null) {
                        err = e;
                    } else {
                        err.addSuppressed(e);
                    }
                }
            }

            if (err != null) {
                throw err;
            }
        }
    }

    /**
     * Pushes output stream onto stack if not null, and returns top of stack.
     */
    protected OutputStream pipeline(OutputStream out, List<OutputStream> stack) {
        if (out == null)
            return stack.get(stack.size()-1);
        stack.add(out);
        return out;
    }

    /**
     * Wraps with stream that outputs ascii-armored text.
     */
    protected OutputStream armor(OutputStream out) {
        if (asciiArmored)
            return new ArmoredOutputStream(out);
        return null;
    }

    /**
     * Wraps with stream that outputs encrypted data packet.
     */
    protected OutputStream encrypt(OutputStream out, FileMetadata meta)
    throws IOException, PGPException {
        log.trace("using encryption algorithm {}", encryptionAlgorithm);

        if (encryptionAlgorithm == EncryptionAlgorithm.Unencrypted)
            return null;

        List<Key> keys = ring.getEncryptionKeys();
        if (Util.isEmpty(keys) && Util.isEmpty(symmetricPassphraseChars))
            throw new PGPException("no suitable encryption key found");

        PGPEncryptedDataGenerator generator = buildEncryptor();
        for (Key key : keys)
            generator.addMethod(buildPublicKeyEncryptor(key));

        if (!Util.isEmpty(symmetricPassphraseChars))
            generator.addMethod(buildSymmetricKeyEncryptor());

        return generator.open(out, getEncryptionBuffer(meta));
    }

    /**
     * Wraps with stream that outputs compressed data packet.
     */
    protected OutputStream compress(OutputStream out, FileMetadata meta)
    throws IOException, PGPException {
        log.trace("using compression algorithm {} - {}",
            compressionAlgorithm, compressionLevel);

        if (compressionAlgorithm == CompressionAlgorithm.Uncompressed ||
            compressionLevel < 1 || compressionLevel > 9)
            return null;

        int algo = compressionAlgorithm.ordinal();
        int level = compressionLevel;
        byte[] buf = getCompressionBuffer(meta);
        return new PGPCompressedDataGenerator(algo, level).open(out, buf);
    }

    /**
     * Wraps with stream that ouputs literal data packet.
     */
    protected OutputStream packet(OutputStream out, FileMetadata meta)
    throws IOException, PGPException {
        char format = meta.getFormat().getCode();
        String name = meta.getName();
        Date date = meta.getLastModifiedDate();
        byte[] buf = getLiteralBuffer(meta);
        return new PGPLiteralDataGenerator().open(out, format, name, date, buf);
    }

    /**
     * Wraps with stream that outputs signature packets
     * as header and footer to envelope.
     */
    protected SigningOutputStream sign(OutputStream out, FileMetadata meta)
    throws IOException, PGPException {
        log.trace("using signing algorithm {}", signingAlgorithm);

        if (signingAlgorithm == HashingAlgorithm.Unsigned)
            return null;

        List<Key> signers = ring.getSigningKeys();
        // skip keys without a passphrase set
        for (int i = signers.size() - 1; i >= 0; i--) {
            Subkey subkey = signers.get(i).getSigning();
            if (!isUsableForSigning(subkey)) {
                log.info("not using signing key {}", subkey);
                signers.remove(i);
            }
        }

        if (Util.isEmpty(signers))
            throw new PGPException("no suitable signing key found");

        return new SigningOutputStream(out, signers, meta);
    }

    /**
     * Copies the content from the specified input stream
     * to the specified output stream.
     */
    protected void copy(InputStream i, OutputStream o, SigningOutputStream s,
    FileMetadata meta) throws IOException, PGPException {
        byte[] buf = getCopyBuffer(meta);
        int len = i.read(buf);
        while (len != -1) {
            if (s != null)
                s.update(buf, 0, len);
            o.write(buf, 0, len);
            len = i.read(buf);
        }
    }

    /**
     * Builds a PGPEncryptedDataGenerator
     * for the configured encryption algorithm.
     */
    protected PGPEncryptedDataGenerator buildEncryptor() {
        int algo = encryptionAlgorithm.ordinal();
        BcPGPDataEncryptorBuilder builder = new BcPGPDataEncryptorBuilder(algo);
        builder.setWithIntegrityPacket(true);
        return new PGPEncryptedDataGenerator(builder);
    }

    /**
     * Builds a PublicKeyKeyEncryptionMethodGenerator
     * for the specified key.
     */
    protected PublicKeyKeyEncryptionMethodGenerator buildPublicKeyEncryptor(
    Key key) {
        log.info("using encryption key {}", key.getEncryption());

        PGPPublicKey publicKey = key.getEncryption().getPublicKey();
        return new BcPublicKeyKeyEncryptionMethodGenerator(publicKey);
    }

    /**
     * Builds a PublicKeyKeyEncryptionMethodGenerator
     * for the specified key.
     */
    protected PBEKeyEncryptionMethodGenerator buildSymmetricKeyEncryptor()
    throws PGPException {
        log.info("using symmetric encryption with {} hash, work factor {}",
                keyDerivationAlgorithm, keyDerivationWorkFactor);

        int algo = keyDerivationAlgorithm.ordinal();
        return new BcPBEKeyEncryptionMethodGenerator(
            symmetricPassphraseChars,
            new BcPGPDigestCalculatorProvider().get(algo),
            keyDerivationWorkFactor);
    }

    protected boolean isUsableForSigning(Subkey subkey) {
        return subkey != null && subkey.isForSigning() &&
            (subkey.isUnlocked() || !Util.isEmpty(subkey.passphraseChars));
    }

    /**
     * Builds a PGPSignatureGenerator for the specified key and content.
     */
    protected PGPSignatureGenerator buildSigner(Key key, FileMetadata meta)
    throws PGPException {
        Subkey subkey = key.getSigning();

        log.info("using signing key {}", subkey);

        PGPContentSignerBuilder builder = buildSignerBuilder(
            subkey.getPublicKey().getAlgorithm(),
            signingAlgorithm.ordinal()
        );

        PGPSignatureGenerator generator = new PGPSignatureGenerator(builder);
        generator.init(meta.getSignatureType(), subkey.getPrivateKey());

        String uid = key.getSigningUid();
        if (!Util.isEmpty(uid)) {
            log.debug("using signing uid {}", uid);

            PGPSignatureSubpacketGenerator signer =
                new PGPSignatureSubpacketGenerator();
            signer.setSignerUserID(false, uid);
            generator.setHashedSubpackets(signer.generate());
        }

        return generator;
    }

    /**
     * Builds a PGPContentSignerBuilder for the specified algorithms.
     */
    protected PGPContentSignerBuilder buildSignerBuilder(
    int keyAlgorithm, int hashAlgorithm) {
        return new BcPGPContentSignerBuilder(keyAlgorithm, hashAlgorithm);
    }

    protected byte[] getEncryptionBuffer(FileMetadata meta) {
        return new byte[bestPacketSize(meta)];
    }

    protected byte[] getCompressionBuffer(FileMetadata meta) {
        return new byte[bestPacketSize(meta)];
    }

    protected byte[] getLiteralBuffer(FileMetadata meta) {
        return new byte[bestPacketSize(meta)];
    }

    protected byte[] getCopyBuffer(FileMetadata meta) {
        int len = (meta == null) ? 0 : (int) meta.getLength();
        if (len <= 0 || len > MAX_ENCRYPT_COPY_BUFFER_SIZE)
            len = MAX_ENCRYPT_COPY_BUFFER_SIZE;
        return new byte[len];
    }

    protected int bestPacketSize(FileMetadata meta) {
        int len = (int) meta.getLength();

        if (len > 0) {
            // add some extra space for packet flags
            len += 300;
            // round up to exact power of 2 (required for partial packets)
            len = 1 << (32 - Integer.numberOfLeadingZeros(len));
        }

        // cap size at 64k
        if (len <= 0 || len > 0x10000)
            len = 0x10000;

        return len;
    }

    protected int estimateOutFileSize(long inFileSize) {
        if (inFileSize >= maxFileBufferSize) return maxFileBufferSize;

        // start with size of original input file
        long outFileSize = inFileSize;
        // then add ~500 bytes for each key, plus ~500 for misc pgp headers
        outFileSize += (
            getRing().getEncryptionKeys().size() +
            getRing().getSigningKeys().size() + 1
        ) * 512;

        if (asciiArmored) {
            outFileSize *=
                // multiply by 4/3 for base64 encoding
                (4f / 3) *
                // and 65/64 (or 66/64) for line feed every 64 (encoded) chars
                ((64f + Strings.lineSeparator().length()) / 64);
            // then add ~80 chars for armor headers/trailers
            outFileSize += 80;
        }

        return (int) Math.min(outFileSize, maxFileBufferSize);
    }

    protected class SigningOutputStream extends FilterOutputStream {
        protected final AtomicBoolean finished = new AtomicBoolean(false);
        protected FileMetadata meta;
        protected List<PGPSignatureGenerator> sigs;

        public SigningOutputStream(OutputStream out, List<Key> keys,
        FileMetadata meta) throws IOException, PGPException {
            super(out);
            this.meta = meta;
            init(keys);
        }

        // OutputStream

        @Override
        public void write(byte[] b, int off, int len) throws IOException {
            // FilterOutputStream implements it by writing one byte at a time
            out.write(b, off, len);
        }

        @Override
        public void close() throws IOException {
            // Ignore if already closed
            if (finished.getAndSet(true)) {
                return;
            }

            flush();

            try {
                finish();
            } catch (PGPException e) {
                throw new IOException(e);
            }
        }

        // impl

        public void update(byte[] b, int off, int len) {
            for (PGPSignatureGenerator sig : sigs)
                sig.update(b, off, len);
        }

        protected void init(List<Key> keys) throws IOException, PGPException {
            // initialize signature generators
            sigs = new ArrayList<PGPSignatureGenerator>(keys.size());
            for (Key key : keys)
                sigs.add(buildSigner(key, meta));

            // write one-pass signature packets
            // with multiple signatures, all but last must be flagged "nested"
            for (int i = 0; i < sigs.size(); i++) {
                boolean nested = i != sigs.size() - 1;
                sigs.get(i).generateOnePassVersion(nested).encode(out);
            }
        }

        protected void finish() throws IOException, PGPException {
            // write full signature packets
            // first signature in header must be last signature in footer
            for (int i = sigs.size() - 1; i >= 0; i--)
                sigs.get(i).generate().encode(out);
        }
    }
}
