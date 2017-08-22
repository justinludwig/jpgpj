package org.c02e.jpgpj;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.regex.Pattern;

import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
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
 * <li>{@link #isForSigning}: true if can be used for signing messages
 * <li>{@link #isForVerification}: true if can be used for verifying messages
 * <li>{@link #isForEncryption}: true if can be used for encrypting messages
 * <li>{@link #isForDecryption}: true if can be used for decrypting messages
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
 * {@link #setPassphrase} method on the subkey, or the
 * {@link Key#setPassphrase} on its containing {@link Key}.
 */
public class Subkey {
    protected boolean forSigning;
    protected boolean forVerification;
    protected boolean forEncryption;
    protected boolean forDecryption;
    protected String passphrase;
    protected PGPPublicKey publicKey;
    protected PGPSecretKey secretKey;

    /** Constructs a blank subkey. */
    public Subkey() {
        passphrase = "";
    }

    /**
     * Display string for the subkey, including its usage flags,
     * short ID, and user IDs.
     */
    public String toString() {
        if (publicKey == null) return "nul";

        StringBuilder b = new StringBuilder();
        b.append(secretKey != null ? "sec" : "pub");
        b.append(Util.isEmpty(passphrase) ? ' ' : '+');
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

    /** True if the subkey can be used for signing messages. */
    public boolean isForSigning() {
        return forSigning;
    }

    /** True if the subkey can be used for signing messages. */
    public void setForSigning(boolean x) {
        forSigning = x;
    }

    /** True if the subkey can be used for verifying messages. */
    public boolean isForVerification() {
        return forVerification;
    }

    /** True if the subkey can be used for verifying messages. */
    public void setForVerification(boolean x) {
        forVerification = x;
    }

    /** True if the subkey can be used for encrypting messages. */
    public boolean isForEncryption() {
        return forEncryption;
    }

    /** True if the subkey can be used for encrypting messages. */
    public void setForEncryption(boolean x) {
        forEncryption = x;
    }

    /** True if the subkey can be used for decrypting messages. */
    public boolean isForDecryption() {
        return forDecryption;
    }

    /** True if the subkey can be used for decrypting messages. */
    public void setForDecryption(boolean x) {
        forDecryption = x;
    }

    /**
     * Passphrase needed to unlock the private part
     * of the subkey's public key-pair; or empty string.
     */
    public String getPassphrase() {
        return passphrase;
    }

    /**
     * Passphrase needed to unlock the private part
     * of the subkey's public key-pair; or empty string.
     */
    public void setPassphrase(String x) {
        passphrase = x != null ? x : "";
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
     * Extracts the Bouncy castle private key material
     * from this subkey's secret key, using the subkey's passphrase.
     * @return null if this subkey does not have a secret key.
     * @throws PassphraseException if passphrase is incorrect.
     */
    public PGPPrivateKey getPrivateKey() throws PGPException {
        return extractPrivateKey(passphrase);
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
        Iterator<PGPSignature> signatures = publicKey.getSignatures();
        while (signatures.hasNext()) {
            PGPSignature signature = signatures.next();
            PGPSignatureSubpacketVector hashedSubPackets = signature.getHashedSubPackets();
            
            if(hashedSubPackets != null) {
                flags |= hashedSubPackets.getKeyFlags();
            }
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
     * Extracts the private key from this subkey's secret key
     * using the specified passphrase.
     */
    protected PGPPrivateKey extractPrivateKey(String passphrase)
    throws PGPException {
        if (secretKey == null) return null;
        try {
            return secretKey.extractPrivateKey(buildDecryptor(passphrase));
        } catch (PGPException e) {
            throw new PassphraseException(
                "incorrect passphrase for subkey " + this, e);
        }
    }

    /**
     * Builds a secret key decryptor for the specified passphrase.
     */
    protected PBESecretKeyDecryptor buildDecryptor(String passphrase) {
        char[] chars = !Util.isEmpty(passphrase) ?
            passphrase.toCharArray() : new char[0];
        return new BcPBESecretKeyDecryptorBuilder(
            new BcPGPDigestCalculatorProvider()).build(chars);
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

        forSigning = canSign &&
            secretKey != null && !secretKey.isPrivateKeyEmpty();
        forVerification = canSign;
        forEncryption = canEncrypt;
        forDecryption = canEncrypt &&
            secretKey != null && !secretKey.isPrivateKeyEmpty();
    }
}
