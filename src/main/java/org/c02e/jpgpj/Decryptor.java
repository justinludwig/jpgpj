package org.c02e.jpgpj;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.NoSuchElementException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPDataValidationException;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPMarker;
import org.bouncycastle.openpgp.PGPOnePassSignature;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;
import org.bouncycastle.openpgp.PGPPBEEncryptedData;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.bc.BcPGPObjectFactory;
import org.bouncycastle.openpgp.operator.PBEDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.PGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.bc.BcPBEDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory;
import org.c02e.jpgpj.util.Util;

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
    protected boolean verificationRequired;
    protected String symmetricPassphrase;
    protected Ring ring;
    protected Logger log = LoggerFactory.getLogger(Decryptor.class.getName());


    /** Constructs a decryptor with an empty key ring. */
    public Decryptor() {
        this(new Ring());
    }

    /** Constructs a decryptor with the specified key ring. */
    public Decryptor(Ring ring) {
        verificationRequired = true;
        symmetricPassphrase = "";
        setRing(ring);
    }

    /** Constructs a decryptor with the specified keys. */
    public Decryptor(Key... keys) {
        this(new Ring(keys));
    }

    /**
     * True to require messages be signed with at least one key from ring.
     * Defaults to true.
     */
    public boolean isVerificationRequired() {
        return verificationRequired;
    }

    /**
     * True to require messages be signed with at least one key from ring.
     * Defaults to true.
     */
    public void setVerificationRequired(boolean x) {
        verificationRequired = x;
    }

    /** Passphrase to use to decrypt with a symmetric key. */
    public String getSymmetricPassphrase() {
        return symmetricPassphrase;
    }

    /** Passphrase to use to decrypt with a symmetric key. */
    public void setSymmetricPassphrase(String x) {
        symmetricPassphrase = x != null ? x : "";
    }

    /** Keys to use for decryption and verification. */
    public Ring getRing() {
        return ring;
    }

    /** Keys to use for decryption and verification. */
    protected void setRing(Ring x) {
        ring = x != null ? x : new Ring();
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
        plaintext.delete();

        InputStream input = null;
        OutputStream output = null;
        try {
            input = new BufferedInputStream(
                new FileInputStream(ciphertext), 0x1000);
            output = new BufferedOutputStream(
                new FileOutputStream(plaintext), 0x1000);
            return decrypt(input, output);
        } catch (Exception e) {
            // delete output file if anything went wrong
            if (output != null)
                try {
                    output.close();
                    plaintext.delete();
                } catch (Exception ee) {
                    log.error("failed to delete bad output file {}", plaintext, ee);
                }
            throw e;
        } finally {
            try { output.close(); } catch (Exception e) {}
            try { input.close(); } catch (Exception e) {}
        }
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
     */
    public FileMetadata decrypt(InputStream ciphertext, OutputStream plaintext)
    throws IOException, PGPException {
        List<FileMetadata> meta = unpack(parse(unarmor(ciphertext)), plaintext);
        if (meta.size() > 1)
            throw new PGPException("content contained more than one file");
        if (meta.size() < 1)
            return new FileMetadata();
        return meta.get(0);
    }

    /**
     * Recursively unpacks the pgp message packets,
     * writing the decrypted message content into the output stream.
     */
    protected List<FileMetadata> unpack(Iterator packets,
    OutputStream plaintext) throws IOException, PGPException {
        List<FileMetadata> meta = new ArrayList<FileMetadata>();
        List<Verifier> verifiers = new ArrayList<Verifier>();

        while (packets.hasNext()) {
            Object packet = packets.next();

            if (log.isTraceEnabled())
                log.trace("unpack {} ", packet.getClass());

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
    protected List<Verifier> buildVerifiers(Iterator signatures)
    throws PGPException {
        ArrayList<Verifier> verifiers = new ArrayList<Verifier>();
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
    protected void matchSignatures(Iterator<PGPSignature> signatures,
    List<Verifier> verifiers) {
        while (signatures.hasNext()) {
            PGPSignature signature = signatures.next();

            for (Verifier verifier : verifiers)
                verifier.match(signature);
        }
    }

    /**
     * Decrypts the encrypted data as the returned input stream.
     */
    protected InputStream decrypt(Iterator data)
    throws IOException, PGPException {
        PGPPBEEncryptedData pbe = null;

        while (data.hasNext()) {
            Object o = data.next();

            if (o instanceof PGPPublicKeyEncryptedData) {
                PGPPublicKeyEncryptedData pke = (PGPPublicKeyEncryptedData) o;

                // try to find decryption key for pk-encrypted data
                Key key = ring.findById(pke.getKeyID());
                if (key != null) {
                    Subkey subkey = key.findById(pke.getKeyID());

                    if (subkey != null && subkey.isForDecryption() &&
                            !Util.isEmpty(subkey.passphrase))
                        return decrypt(pke, subkey);

                    else if (log.isInfoEnabled())
                        log.info("not using decryption key {} ", subkey);

                } else {
                    if (log.isInfoEnabled())
                        log.info("not found decryption key {} ",
                            Util.formatKeyId(pke.getKeyID()));
                }

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

        if (log.isInfoEnabled())
            log.info("using decryption key {} ", subkey);
        return data.getDataStream(buildPublicKeyDecryptor(subkey));
    }

    /**
     * Decrypts the encrypted data as the returned input stream.
     */
    protected InputStream decrypt(PGPPBEEncryptedData data)
    throws IOException, PGPException {
        if (data == null || Util.isEmpty(symmetricPassphrase))
            throw new DecryptionException("no suitable decryption key found");

        try {
            return data.getDataStream(buildSymmetricKeyDecryptor(
                symmetricPassphrase));
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
    protected long copy(InputStream i, OutputStream o,
    List<Verifier> verifiers) throws IOException, PGPException {
        long total = 0;
        byte[] buf = getCopyBuffer();
        int len = i.read(buf);

        if (verificationRequired && Util.isEmpty(verifiers))
            throw new VerificationException(
                "content not signed with a required key");

        while (len != -1) {
            total += len;

            if (verificationRequired) {
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
        if (!verificationRequired) return;

        for (Verifier verifier : verifiers) {
            if (!verifier.verify())
                throw new VerificationException(
                    "bad signature for key " + verifier.key);
            else if (log.isDebugEnabled())
                log.debug("good signature for key {} ", verifier.key);

            Key key = verifier.getSignedBy();
            for (FileMetadata file : meta)
                file.getVerified().getKeys().add(key);
        }
    }

    /**
     * Wraps stream with ArmoredInputStream if necessary
     * (to convert ascii-armored content back into binary data).
     */
    protected InputStream unarmor(InputStream stream)
    throws IOException, PGPException {
        return PGPUtil.getDecoderStream(stream);
    }

    /**
     * Separates stream into PGP packets.
     * @see PGPObjectFactory
     */
    protected Iterator parse(InputStream stream)
    throws IOException, PGPException {
        // before BCPG v1.55
        // PGPObjectFactory.iterator() doesn't work for decryption
        // because its next() method prematurely calls nextObject()
        // for the next next object, which puts the BCPGInputStream parser
        // into a broken state, resulting in errors like
        // "unknown object in stream: 27"
        //return new BcPGPObjectFactory(stream).iterator();
        final BcPGPObjectFactory factory = new BcPGPObjectFactory(stream);
        return new Iterator() {
            boolean checkedNext = false;
            Object nextElement = null;
            public boolean hasNext() {
                if (!checkedNext) {
                    checkedNext = true;
                    try {
                        nextElement = factory.nextObject();
                    } catch (IOException e) {
                        throw new RuntimeException(e);
                    }
                }
                return nextElement != null;
            }
            public Object next() {
                if (!hasNext()) throw new NoSuchElementException();
                checkedNext = false;
                return nextElement;
            }
            public void remove() {
                throw new UnsupportedOperationException();
            }
        };
    }

    /**
     * Helper for signature verification.
     */
    protected PGPContentVerifierBuilderProvider getVerifierProvider() {
        return new BcPGPContentVerifierBuilderProvider();
    }

    /**
     * Builds a symmetric-encryption decryptor for the specified passphrase.
     */
    protected PublicKeyDataDecryptorFactory buildPublicKeyDecryptor(
    Subkey subkey) throws PGPException {
        PGPPrivateKey privateKey = subkey.getPrivateKey();
        if (privateKey == null)
            throw new PGPException("no private key for " + subkey);
        return new BcPublicKeyDataDecryptorFactory(privateKey);
    }

    /**
     * Builds a symmetric-key decryptor for the specified passphrase.
     */
    protected PBEDataDecryptorFactory buildSymmetricKeyDecryptor(
    String passphrase) {
        char[] chars = !Util.isEmpty(passphrase) ?
            passphrase.toCharArray() : new char[0];
        return new BcPBEDataDecryptorFactory(chars,
            new BcPGPDigestCalculatorProvider());
    }

    protected byte[] getCopyBuffer() {
        return new byte[0x4000];
    }

    protected class Verifier {
        public Key key;
        public PGPSignature sig;
        public PGPOnePassSignature sig1;

        public Verifier() {
        }

        public Verifier(PGPSignature s) throws PGPException {
            this();
            setSig(s);
        }

        public Verifier(PGPOnePassSignature s) throws PGPException {
            this();
            setSig1(s);
        }

        public boolean isKeyAvailable() {
            return key != null;
        }

        public void setSig(PGPSignature s) throws PGPException {
            sig = s;
            if (sig1 != null) return;

            key = getRing().findById(s.getKeyID());
            if (key == null) {
                if (Decryptor.this.log.isInfoEnabled())
                    Decryptor.this.log.info("not found verification key {} ",
                        Util.formatKeyId(s.getKeyID()));
                return;
            }

            Subkey subkey = key.findById(s.getKeyID());
            if (subkey == null || !subkey.isForVerification())
                key = null;
            else
                s.init(getVerifierProvider(), subkey.getPublicKey());

            if (Decryptor.this.log.isInfoEnabled())
                Decryptor.this.log.info((key == null ? "not " : "") +
                    "using verification key " + subkey);
        }

        public void setSig1(PGPOnePassSignature s) throws PGPException {
            sig1 = s;

            key = getRing().findById(s.getKeyID());
            if (key == null) {
                if (Decryptor.this.log.isInfoEnabled())
                    Decryptor.this.log.info("not found verification key {}",
                        Util.formatKeyId(s.getKeyID()));
                return;
            }

            Subkey subkey = key.findById(s.getKeyID());
            if (subkey == null || !subkey.isForVerification())
                key = null;
            else
                s.init(getVerifierProvider(), subkey.getPublicKey());

            if (Decryptor.this.log.isInfoEnabled())
                Decryptor.this.log.info((key == null ? "not " : "") +
                    "using verification key " + subkey);
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

            Key by = key.toPublicKey();
            String uid = sig.getHashedSubPackets().getSignerUserID();
            by.setSigningUid(uid != null ? uid : "");
            return by;
        }
    }
}
