package org.c02e.jpgpj;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.regex.Pattern;

import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyFlags;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureSubpacketVector;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.PGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.c02e.jpgpj.util.ProviderService;
import org.c02e.jpgpj.util.Util;

/**
 * A single public-key pair from a full {@link Key}. It may consist of only
 * the public part of the pair, or it may include both the public
 * and private parts. Each subkey is designated for a specific
 * cryptographic purpose (or purposes), typically either certification
 * (ie signing other keys), encryption, or signing (ie signing messages).
 * The passphrase for a subkey must be provided in order to use its
 * private part (the private part is needed for signing and decryption).
 * <p>
 * The purpose of a subkey is indicated by these four methods:
 * <ul>
 * <li>{@link #isForSigning}: true if should be used for signing messages
 * <li>{@link #isForVerification}: true if should be used for verifying messages
 * <li>{@link #isForEncryption}: true if should be used for encrypting messages
 * <li>{@link #isForDecryption}: true if should be used for decrypting messages
 * </ul>
 * <p>
 * By default, when a subkey with a "sign data" flag is loaded, its
 * <code>forVerification</code> property will be set to true; and if the subkey
 * includes the private part of its public-key pair, its
 * <code>forSigning</code> property will also be set to true.
 * When a subkey with a "encrypt communications" or "encrypt storage" flag
 * is loaded, its <code>forEncryption</code> property will be set to true;
 * and if the subkey includes the private part of its public-key pair, its
 * <code>forDecryption</code> property will also be set to true.
 * <p>
 * However, before actually using a subkey for signing or decryption,
 * you must also set the subkey's passphrase, either via the
 * {@link #setPassphraseChars} method on the subkey, or the
 * {@link Key#setPassphraseChars} on its containing {@link Key}.
 * If the subkey does not have a passphrase, set the passphrase to the
 * {@link Key#NO_PASSPHRASE} constant (or use {@link #setNoPassphrase}).
 * <p>
 * When a subkey is used for signing or decryption, its private key material
 * is extracted and cached in memory. To release this memory, call the subkey's
 * {@link #clearSecrets} method. This method will zero-out the subkey's
 * passphrase (if the passphrase had been set as a char[] via
 * {@link #setPassphraseChars}) and release the cached private key material
 * (however, the private key material will not be zeroed-out; also, the
 * passphrase will not be zeroed-out if it was set via {@link #setPassphrase}).
 */
public class Subkey implements Cloneable {
    private static final char[] NO_PASSPHRASE = Key.NO_PASSPHRASE.toCharArray();
    private static final char[] EMPTY_PASSPHRASE = new char[0];

    protected boolean forSigning;
    protected boolean forVerification;
    protected boolean forEncryption;
    protected boolean forDecryption;
    protected char[] passphraseChars;
    /** @deprecated Null unless explicitly set by user. */
    @Deprecated
    protected String passphrase;
    protected PGPPublicKey publicKey;
    protected PGPSecretKey secretKey;
    /** Decrypted private key material. Null unless decrypted. */
    protected PGPPrivateKey privateKey;

    /** Constructs a blank subkey. */
    public Subkey() {
        setPassphraseChars(null);
    }

    /**
     * Display string for the subkey, including its usage flags,
     * short ID, and user IDs.
     */
    @Override
    public String toString() {
        if (publicKey == null) return "nul";

        StringBuilder b = new StringBuilder();
        b.append(secretKey != null ? "sec" : "pub");
        b.append(Util.isEmpty(passphraseChars) && privateKey == null ? ' ' : '+');
        if (forVerification)
            b.append('v');
        else if (forEncryption)
            b.append('e');
        else
            b.append(' ');
        if (forSigning)
            b.append('s');
        else if (forDecryption)
            b.append('d');
        else
            b.append(' ');
        b.append(' ');
        b.append(getShortId());
        int count = 0;
        for (String uid : getUids()) {
            if (count++ > 0)
                b.append(',');
            b.append(' ');
            b.append(uid);
        }
        return b.toString();
    }

    @Override
    public Subkey clone() {
        try {
            Subkey other = getClass().cast(super.clone());
            // Do not use setPassphrasesChars since it checks if different password provided
            other.passphraseChars = (this.passphraseChars == null) ? null : this.passphraseChars.clone();
            return other;
        } catch (CloneNotSupportedException e) {
            throw new UnsupportedOperationException("Unexpected clone failure for " + this);
        }
    }

    /** True if the subkey should be used for signing messages. */
    public boolean isForSigning() {
        return forSigning;
    }

    /** True if the subkey should be used for signing messages. */
    public void setForSigning(boolean x) {
        forSigning = x;
    }

    /** True if the subkey should be used for verifying messages. */
    public boolean isForVerification() {
        return forVerification;
    }

    /** True if the subkey should be used for verifying messages. */
    public void setForVerification(boolean x) {
        forVerification = x;
    }

    /** True if the subkey should be used for encrypting messages. */
    public boolean isForEncryption() {
        return forEncryption;
    }

    /** True if the subkey should be used for encrypting messages. */
    public void setForEncryption(boolean x) {
        forEncryption = x;
    }

    /** True if the subkey should be used for decrypting messages. */
    public boolean isForDecryption() {
        return forDecryption;
    }

    /** True if the subkey should be used for decrypting messages. */
    public void setForDecryption(boolean x) {
        forDecryption = x;
    }

    /** True if technically usable for signing. */
    public boolean isUsableForSigning() {
        return isUsableForVerification() &&
            secretKey != null && !secretKey.isPrivateKeyEmpty();
    }

    /** True if technically usable for verification. */
    public boolean isUsableForVerification() {
        int algorithm = publicKey != null ? publicKey.getAlgorithm() : 0;
        return algorithm == PublicKeyAlgorithmTags.RSA_GENERAL ||
               algorithm == PublicKeyAlgorithmTags.RSA_SIGN ||
               algorithm == PublicKeyAlgorithmTags.DSA ||
               algorithm == PublicKeyAlgorithmTags.ECDSA ||
               algorithm == PublicKeyAlgorithmTags.EDDSA;
    }

    /** True if technically usable for encryption. */
    public boolean isUsableForEncryption() {
        return publicKey != null && publicKey.isEncryptionKey();
    }

    /** True if technically usable for decryption. */
    public boolean isUsableForDecryption() {
        return isUsableForEncryption() &&
            secretKey != null && !secretKey.isPrivateKeyEmpty();
    }

    /**
     * Passphrase needed to unlock the private part
     * of the subkey's public key-pair; or empty char[].
     * Use {@link Key#NO_PASSPHRASE} to signal the private part of the subkey
     * is not protected by a passphrase.
     * Note that this char[] itself (and not a copy) will be cached and used
     * by the subkey until {@link #clearSecrets} is called (or
     * {@link #setPassphraseChars} is called again with a different passphrase),
     * and then the char[] will be zeroed.
     */
    public char[] getPassphraseChars() {
        return passphraseChars;
    }

    /**
     * Passphrase needed to unlock the private part
     * of the subkey's public key-pair; or empty char[].
     * Use {@link Key#NO_PASSPHRASE} to signal the private part of the subkey
     * is not protected by a passphrase.
     * Note that this char[] itself (and not a copy) will be cached and used
     * by the subkey until {@link #clearSecrets} is called (or
     * {@link #setPassphraseChars} is called again with a different passphrase),
     * and then the char[] will be zeroed.
     */
    public void setPassphraseChars(char[] x) {
        if (x == null)
            x = EMPTY_PASSPHRASE;

        if (!Arrays.equals(x, passphraseChars)) {
            clearSecrets();
            passphraseChars = x;
        }
    }

    /**
     * Passphrase needed to unlock the private part
     * of the subkey's public key-pair; or empty string.
     * Prefer {@link #getPassphraseChars} to avoid creating extra copies
     * of the passphrase in memory that cannot be cleaned up.
     * Use {@link Key#NO_PASSPHRASE} to signal the private part of the subkey
     * is not protected by a passphrase.
     * @see #getPassphraseChars
     */
    public String getPassphrase() {
        if (passphrase == null)
            passphrase = new String(passphraseChars);
        return passphrase;
    }

    /**
     * Passphrase needed to unlock the private part
     * of the subkey's public key-pair; or empty string.
     * Prefer {@link #setPassphraseChars} to avoid creating extra copies
     * of the passphrase in memory that cannot be cleaned up.
     * Use {@link Key#NO_PASSPHRASE} to signal the private part of the subkey
     * is not protected by a passphrase.
     * @see #setPassphraseChars
     */
    public void setPassphrase(String x) {
        setPassphraseChars(x != null ? x.toCharArray() : null);
        passphrase = x;
    }

    /**
     * True if no passphrase is needed to unlock the private part
     * of the subkey's public key-pair.
     */
    public boolean isNoPassphrase() {
        return Arrays.equals(passphraseChars, NO_PASSPHRASE);
    }

    /**
     * True if no passphrase is needed to unlock the private part
     * of the subkey's public key-pair.
     */
    public void setNoPassphrase(boolean x) {
        if (x != isNoPassphrase())
            setPassphrase(x ? Key.NO_PASSPHRASE : null);
    }

    /**
     * Bouncy castle public-key pair,
     * containing only the public part of the pair; or null.
     */
    public PGPPublicKey getPublicKey() {
        return publicKey;
    }

    /**
     * Bouncy castle public-key pair,
     * containing only the public part of the pair; or null.
     */
    public void setPublicKey(PGPPublicKey x) throws PGPException {
        publicKey = x;
        calculateUsage();
    }

    /**
     * Bouncy castle public-key pair,
     * containing both the public and private parts of the pair; or null.
     */
    public PGPSecretKey getSecretKey() {
        return secretKey;
    }

    /**
     * Bouncy castle public-key pair,
     * containing both the public and private parts of the pair; or null.
     */
    public void setSecretKey(PGPSecretKey x) throws PGPException {
        secretKey = x;
        if (secretKey != null)
            setPublicKey(secretKey.getPublicKey());
    }

    /**
     * Extracts the Bouncy castle private-key material
     * from this subkey's secret key, using the subkey's passphrase,
     * and caches it in memory until {@link #clearSecrets} is called.
     * @return null if this subkey does not have a secret key.
     * @throws PassphraseException if passphrase is incorrect.
     */
    public PGPPrivateKey getPrivateKey() throws PGPException {
        if (privateKey == null)
            privateKey = extractPrivateKey(passphraseChars);
        return privateKey;
    }

    /**
     * Fingerprint of public key,
     * or empty string if no public key.
     */
    public String getFingerprint() {
        if (publicKey == null) return "";
        return Util.formatAsHex(publicKey.getFingerprint());
    }

    /**
     * Full '0xlong' format of public key,
     * or empty string if no public key.
     */
    public String getId() {
        if (publicKey == null) return "";
        return "0x" + String.format("%016X", publicKey.getKeyID());
    }

    /**
     * Abbreviated 'short' format of public key,
     * or empty string if no public key.
     */
    public String getShortId() {
        if (publicKey == null) return "";
        return String.format("%016X", publicKey.getKeyID()).substring(8);
    }

    /**
     * User ID strings of public key
     * (ex ["My Name (comment) &lt;me@example.com&gt;"]), or empty list.
     */
    public List<String> getUids() {
        if (publicKey == null) return Collections.emptyList();

        ArrayList<String> result = new ArrayList<String>();
        Iterator<String> uids = publicKey.getUserIDs();
        while (uids.hasNext())
            result.add(uids.next());
        return result;
    }

    /**
     * Usage flags as Bouncy castle {@link PGPKeyFlags} bits.
     */
    public int getUsageFlags() throws PGPException {
        if (publicKey == null) return 0;

        int flags = 0;
        // actually only need POSITIVE_CERTIFICATION (for master key)
        // and SUBKEY_BINDING (for subkeys)
        @SuppressWarnings("unchecked")
        Iterator<PGPSignature> signatures = publicKey.getSignatures();
        while (signatures.hasNext()) {
            PGPSignature signature = signatures.next();
            PGPSignatureSubpacketVector hashedSubPackets =
                signature.getHashedSubPackets();

            if (hashedSubPackets != null)
                flags |= hashedSubPackets.getKeyFlags();
        }
        return flags;
    }

    /**
     * True if the string is a case-insensitive substring of either:
     * <ul>
     * <li>the subkey's full ID (eg "0x1234567890ABCDEF");
     * <li>the subkey's fingerprint (eg "1234567890ABCDEF1234567890ABCDEF12345678");
     * <li>any subkey's user IDs (eg "Alice (work) &lt;alice@example.com&gt;")
     * </ul>
     * <p>
     * So for example, a string "0x1234" would match the above full ID;
     * a string "90ab" would match the above fingerprint;
     * and a string "alice (work)" would match the above user ID.
     */
    public boolean matches(String id) {
        if (Util.isEmpty(id)) return false;

        Pattern regex = Pattern.compile(id,
            Pattern.CASE_INSENSITIVE | Pattern.LITERAL);
        return matches(regex);
    }

    /**
     * True if the specified pattern matches any part of either:
     * <ul>
     * <li>the subkey's full ID (eg "0x1234567890ABCDEF");
     * <li>the subkey's fingerprint (eg "1234567890ABCDEF1234567890ABCDEF12345678");
     * <li>any subkey's user IDs (eg "Alice (work) &lt;alice@example.com&gt;")
     * </ul>
     * <p>
     * So for example, a pattern /0x1234/ would match the above full ID;
     * a pattern /(?i)90ab/ would match the above fingerprint;
     * and a pattern /Alice .work./ would match the above user ID.
     */
    public boolean matches(Pattern id) {
        if (id == null || publicKey == null) return false;
        if (id.matcher(getFingerprint()).find()) return true;
        if (id.matcher(getId()).find()) return true;

        Iterator<String> uids = publicKey.getUserIDs();
        while (uids.hasNext()) {
            String uid = uids.next();
            if (id.matcher(uid).find()) return true;
        }
        return false;
    }

    /**
     * True if the private key material has been extracted from this subkey's
     * secret key and is currently cached in memory.
     */
    public boolean isUnlocked() {
        return privateKey != null;
    }

    /**
     * Extracts the private key material from this subkey's secret key
     * using the specified passphrase, and caches it in memory
     * until {@link #clearSecrets} is called. Does not cache the passphrase.
     * Does nothing if this subkey does not have a secret key.
     * @throws PassphraseException if passphrase is incorrect.
     */
    public void unlock(char[] passphraseChars) throws PGPException {
        privateKey = extractPrivateKey(passphraseChars);
    }

    /**
     * Zeroes-out the cached passphrase for this subkey,
     * and releases the extracted private key material for garbage collection.
     * Note that if {@link #getPassphrase} or {@link #setPassphrase} is
     * used to access the passphrase, the passphrase data cannot be zeroed
     * (so instead use {@link #getPassphraseChars} and
     * {@link #setPassphraseChars}).
     */
    public void clearSecrets() {
        // zero-out passphrase data
        if (passphraseChars != null)
            Arrays.fill(passphraseChars, (char) 0);
        // flag as empty
        passphraseChars = EMPTY_PASSPHRASE;
        // cannot cleanup futher, release for GC
        passphrase = null;
        // cannot cleanup futher, release for GC
        privateKey = null;
    }

    /**
     * Extracts the private key from this subkey's secret key
     * using the specified passphrase.
     */
    protected PGPPrivateKey extractPrivateKey(char[] passphraseChars)
    throws PGPException {
        if (secretKey == null) return null;
        try {
            return secretKey.extractPrivateKey(buildDecryptor(passphraseChars));
        } catch (PGPException e) {
            throw new PassphraseException(
                "incorrect passphrase for subkey " + this, e);
        }
    }

    /**
     * Builds a secret key decryptor for the specified passphrase.
     */
    protected PBESecretKeyDecryptor buildDecryptor(char[] passphraseChars) {
        char[] chars = passphraseChars != null &&
            !Arrays.equals(passphraseChars, NO_PASSPHRASE) ?
            passphraseChars : EMPTY_PASSPHRASE;
        try {
            JcaPGPDigestCalculatorProviderBuilder jcaPGPDigestCalculatorProviderBuilder = new JcaPGPDigestCalculatorProviderBuilder();
            if (ProviderService.isProviderNotNull()) {
                jcaPGPDigestCalculatorProviderBuilder.setProvider(ProviderService.getProvider());
            }
            PGPDigestCalculatorProvider digestCalculatorProvider = jcaPGPDigestCalculatorProviderBuilder.build();
            JcePBESecretKeyDecryptorBuilder jcePBESecretKeyDecryptorBuilder = new JcePBESecretKeyDecryptorBuilder(digestCalculatorProvider);
            if (ProviderService.isProviderNotNull()) {
                jcePBESecretKeyDecryptorBuilder.setProvider(ProviderService.getProvider());
            }
            return jcePBESecretKeyDecryptorBuilder.build(chars);
        } catch (PGPException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Sets forSigning etc flags based on key data.
     */
    protected void calculateUsage() throws PGPException {
        int flags = getUsageFlags();

        boolean canSign = (flags & PGPKeyFlags.CAN_SIGN) ==
            PGPKeyFlags.CAN_SIGN;
        boolean canEncrypt = ((flags & PGPKeyFlags.CAN_ENCRYPT_COMMS) ==
                PGPKeyFlags.CAN_ENCRYPT_COMMS) ||
            ((flags & PGPKeyFlags.CAN_ENCRYPT_STORAGE) ==
                PGPKeyFlags.CAN_ENCRYPT_STORAGE);

        forSigning = canSign && isUsableForSigning();
        forVerification = canSign && isUsableForVerification();
        forEncryption = canEncrypt && isUsableForEncryption();
        forDecryption = canEncrypt && isUsableForDecryption();
    }
}
