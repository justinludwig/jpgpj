package org.c02e.jpgpj;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import org.bouncycastle.openpgp.PGPException;
import org.c02e.jpgpj.util.Util;

/**
 * The identity of a person (or persona, or non-human actor, etc)
 * as a collection of {@link Subkey}s.
 * A key whose subkeys contain only the public part of their public-key pair
 * is considered a "public key"; whereas a key whose subkeys contain both
 * the public part and private part their public-key pair is considered
 * a "secret key".
 * <p>
 * A key can be constructed from an armored key text block with the
 * {@link #Key(String)} constructor; or constructed from a key file with the
 * {@link #Key(File)} constructor; or constructed from an input stream
 * containing a key file (or armored key text block) with the
 * {@link #Key(InputStream)} constructor. A key can also be constructed
 * as an empty key ({@link #Key()}) and the key loaded later &mdash;
 * either via {@link #load(String)}, {@link #load(File)}, or
 * {@link #load(InputStream)}); or by adding individual {@link Subkey}s
 * to the list of subkeys that can be accessed via {@link #getSubkeys}.
 * <p>
 * The purposes for which a key can be used are indicated by these four methods:
 * <ul>
 * <li>{@link #isForSigning}: true if can be used for signing messages
 * <li>{@link #isForVerification}: true if can be used for verifying messages
 * <li>{@link #isForEncryption}: true if can be used for encrypting messages
 * <li>{@link #isForDecryption}: true if can be used for decrypting messages
 * </ul>
 * <p>
 * The subkey to use for each purpose is made available by these four methods:
 * <ul>
 * <li>{@link #getSigning}: subkey to use for signing messages, or null
 * <li>{@link #getVerification}: subkey to use for verifying messages, or null
 * <li>{@link #getEncryption}: subkey to use for encrypting messages, or null
 * <li>{@link #getDecryption}: subkey to use for decrypting messages, or null
 * </ul>
 * <p>
 * You can list the key's user IDs (the human-readable identification
 * of the key, like "Alice (work) alice@example.com") via the
 * {@link #getUids} method. When signing with a key that includes multiple
 * user IDs, you can specify the user ID to embed in the signature
 * via the {@link #setSigningUid} method (otherwise this defaults to the first
 * user ID; also note that when verifying the message, other clients
 * may ignore this setting, and display an arbitrary user ID,
 * or all user IDs, as the message signer).
 */
public class Key implements Cloneable {
    /** Use this value to set the passphrase of a passphrase-less key. */
    public static String NO_PASSPHRASE = "JPGPJ_NO_PASSPHRASE";

    protected String signingUid;
    protected List<Subkey> subkeys;

    /** Constructs a new empty key. */
    public Key() {
        this(new ArrayList<Subkey>());
    }

    /** Constructs a new key with the specified subkeys. */
    public Key(List<Subkey> subkeys) {
        setSubkeys(subkeys);
    }

    /**
     * Loads first key from the specified armored text.
     * @throws PGPException if the text contains no keys.
     */
    public Key(String armor) throws IOException, PGPException {
        this();
        load(armor);
    }

    /**
     * Loads first key from the specified armored text,
     * and sets the passphrase of all subkeys to the specified passphrase.
     * @throws PGPException if the text contains no keys.
     */
    public Key(String armor, char[] passphraseChars)
    throws IOException, PGPException {
        this(armor);
        setPassphraseChars(passphraseChars);
    }

    /**
     * Loads first key from the specified armored text,
     * and sets the passphrase of all subkeys to the specified passphrase.
     * Prefer {@link #Key(String, char[])} to avoid creating
     * extra copies of the passphrase in memory that cannot be cleaned up.
     * @throws PGPException if the text contains no keys.
     */
    public Key(String armor, String passphrase)
    throws IOException, PGPException {
        this(armor);
        setPassphrase(passphrase);
    }

    /**
     * Loads first key from the specified file.
     * @throws PGPException if the file contains no keys.
     */
    public Key(File file) throws IOException, PGPException {
        this();
        load(file);
    }

    /**
     * Loads first key from the specified file,
     * and sets the passphrase of all subkeys to the specified passphrase.
     * @throws PGPException if the file contains no keys.
     */
    public Key(File file, char[] passphraseChars) throws IOException, PGPException {
        this(file);
        setPassphraseChars(passphraseChars);
    }

    /**
     * Loads first key from the specified file,
     * and sets the passphrase of all subkeys to the specified passphrase.
     * Prefer {@link #Key(File, char[])} to avoid creating
     * extra copies of the passphrase in memory that cannot be cleaned up.
     * @throws PGPException if the file contains no keys.
     */
    public Key(File file, String passphrase) throws IOException, PGPException {
        this(file);
        setPassphrase(passphrase);
    }

    /**
     * Loads first key from the specified input stream.
     * @throws PGPException if the input streame contains no keys.
     */
    public Key(InputStream stream) throws IOException, PGPException {
        this();
        load(stream);
    }

    /**
     * Loads first key from the specified input stream,
     * and sets the passphrase of all subkeys to the specified passphrase.
     * @throws PGPException if the input streame contains no keys.
     */
    public Key(InputStream stream, char[] passphraseChars)
    throws IOException, PGPException {
        this(stream);
        setPassphraseChars(passphraseChars);
    }

    /**
     * Loads first key from the specified input stream,
     * and sets the passphrase of all subkeys to the specified passphrase.
     * Prefer {@link #Key(InputStream, char[])} to avoid creating
     * extra copies of the passphrase in memory that cannot be cleaned up.
     * @throws PGPException if the input streame contains no keys.
     */
    public Key(InputStream stream, String passphrase)
    throws IOException, PGPException {
        this(stream);
        setPassphrase(passphrase);
    }

    /**
     * Creates a copy of this with only the public parts of the key.
     */
    public Key toPublicKey() throws PGPException {
        Key copy = new Key();
        for (Subkey subkey : subkeys) {
            Subkey subcopy = new Subkey();
            subcopy.setPublicKey(subkey.getPublicKey());
            copy.subkeys.add(subcopy);
        }
        return copy;
    }

    /**
     * Display string for the key, including each subkey's usage flags,
     * short ID, and user IDs.
     */
    @Override
    public String toString() {
        if (Util.isEmpty(subkeys)) return "key empty";

        StringBuilder b = new StringBuilder();
        int count = 0;
        for (Subkey subkey : subkeys) {
            if (count++ > 0)
                b.append('\n');
            b.append(subkey.toString());
        }
        return b.toString();
    }

    @Override
    public Key clone() {
        try {
            Key other = getClass().cast(super.clone());
            List<Subkey> thisSubkeys = getSubkeys();
            other.setSubkeys((thisSubkeys == null) ? null : thisSubkeys.stream().map(Subkey::clone).collect(Collectors.toList()));
            return other;
        } catch (CloneNotSupportedException e) {
            throw new UnsupportedOperationException("Unexpected clone failure for " + this);
        }
    }

    /**
     * Sets the passphrase of all subkeys.
     * @see Subkey#setPassphraseChars
     */
    public void setPassphraseChars(char[] x) {
        for (Subkey subkey : subkeys)
            subkey.setPassphraseChars(x);
    }

    /**
     * Sets the passphrase of all subkeys.
     * Prefer {@link #setPassphraseChars} to avoid creating extra copies
     * of the passphrase in memory that cannot be cleaned up.
     * @see Subkey#setPassphraseChars
     */
    public void setPassphrase(String x) {
        for (Subkey subkey : subkeys)
            subkey.setPassphrase(x);
    }

    /**
     * True to flag all subkeys as needing no passphrase to unlock;
     * false to require a passphrase to be (re-)set on all subkeys.
     */
    public void setNoPassphrase(boolean x) {
        for (Subkey subkey : subkeys)
            subkey.setNoPassphrase(x);
    }

    /**
     * User ID strings for master subkey
     * (ex ["My Name (comment) &lt;me@example.com&gt;"]).
     */
    public List<String> getUids() {
        Subkey master = getMaster();
        if (master == null) return Collections.emptyList();
        return master.getUids();
    }

    /**
     * User ID to use for signing, or empty string.
     * By default, this is first user ID listed by the master subkey.
     */
    public String getSigningUid() {
        if (signingUid == null) {
            signingUid = "";

            List<String> uids = getUids();
            if (!uids.isEmpty())
                signingUid = uids.get(0);
        }
        return signingUid;
    }

    /** User ID to use for signing, or empty string. */
    public void setSigningUid(String x) {
        signingUid = x;
    }

    /** True if any subkey can be used for signing. */
    public boolean isForSigning() {
        return getSigning() != null;
    }

    /** True if any subkey can be used for verification. */
    public boolean isForVerification() {
        return getVerification() != null;
    }

    /** True if any subkey can be used for encryption. */
    public boolean isForEncryption() {
        return getEncryption() != null;
    }

    /** True if any subkey can be used for decryption. */
    public boolean isForDecryption() {
        return getDecryption() != null;
    }

    /** First subkey or null. */
    public Subkey getMaster() {
        return !Util.isEmpty(subkeys) ? subkeys.get(0) : null;
    }

    /** Last subkey that can sign, or null. */
    public Subkey getSigning() {
        for (int i = subkeys.size() - 1; i >= 0; i--) {
            Subkey subkey = subkeys.get(i);
            if (subkey.isForSigning())
                return subkey;
        }
        return null;
    }

    /** Last subkey that can verify, or null. */
    public Subkey getVerification() {
        for (int i = subkeys.size() - 1; i >= 0; i--) {
            Subkey subkey = subkeys.get(i);
            if (subkey.isForVerification())
                return subkey;
        }
        return null;
    }

    /** Last subkey that can encrypt, or null. */
    public Subkey getEncryption() {
        for (int i = subkeys.size() - 1; i >= 0; i--) {
            Subkey subkey = subkeys.get(i);
            if (subkey.isForEncryption())
                return subkey;
        }
        return null;
    }

    /** Last subkey that can decrypt, or null. */
    public Subkey getDecryption() {
        for (int i = subkeys.size() - 1; i >= 0; i--) {
            Subkey subkey = subkeys.get(i);
            if (subkey.isForDecryption())
                return subkey;
        }
        return null;
    }

    /** All subkeys, or an empty list. */
    public List<Subkey> getSubkeys() {
        return subkeys;
    }

    /** All subkeys, or an empty list. */
    protected void setSubkeys(List<Subkey> x) {
        subkeys = x != null ? x : new ArrayList<Subkey>();
    }

    /** Subkey with the specified full ID, or null. */
    public Subkey findById(Long id) {
        if (id == null) return null;
        for (Subkey subkey : subkeys)
            if (subkey.publicKey != null && subkey.publicKey.getKeyID() == id)
                return subkey;
        return null;
    }

    /**
     * All subkeys for which the specified string is
     * a case-insensitive substring of either:
     * <ul>
     * <li>any subkey's full ID (eg "0x1234567890ABCDEF")
     * <li>any subkey's fingerprint (eg "1234567890ABCDEF1234567890ABCDEF12345678")
     * <li>any one of any subkey's user IDs (eg "Alice (work) &lt;alice@example.com&gt;")
     * </ul>
     * <p>
     * So for example, a string "0x1234" would match the above full ID;
     * a string "90ab" would match the above fingerprint;
     * and a string "alice (work)" would match the above user ID.
     */
    public List<Subkey> findAll(String id) {
        if (Util.isEmpty(id)) return Collections.emptyList();

        Pattern regex = Pattern.compile(id,
            Pattern.CASE_INSENSITIVE | Pattern.LITERAL);
        return findAll(regex);
    }

    /**
     * All subkeys for which the specified pattern matches any part of either:
     * <ul>
     * <li>any subkey's full ID (eg "0x1234567890ABCDEF")
     * <li>any subkey's fingerprint (eg "1234567890ABCDEF1234567890ABCDEF12345678")
     * <li>any one of any subkey's user IDs (eg "Alice (work) &lt;alice@example.com&gt;")
     * </ul>
     * <p>
     * So for example, a pattern /0x1234/ would match the above full ID;
     * a pattern /(?i)90ab/ would match the above fingerprint;
     * and a pattern /Alice .work./ would match the above user ID.
     */
    public List<Subkey> findAll(Pattern id) {
        if (id == null) return Collections.emptyList();

        ArrayList<Subkey> result = new ArrayList<Subkey>();
        for (Subkey subkey : subkeys)
            if (subkey.matches(id))
                result.add(subkey);
        return result;
    }

    /**
     * True if the string is a case-insensitive substring of either:
     * <ul>
     * <li>any subkey's full ID (eg "0x1234567890ABCDEF")
     * <li>any subkey's fingerprint (eg "1234567890ABCDEF1234567890ABCDEF12345678")
     * <li>any one of any subkey's user IDs (eg "Alice (work) &lt;alice@example.com&gt;")
     * </ul>
     * <p>
     * So for example, a string "0x1234" would match the above full ID;
     * a string "90ab" would match the above fingerprint;
     * and a string "alice (work)" would match the above user ID.
     */
    public boolean matches(String id) {
        return !findAll(id).isEmpty();
    }

    /**
     * True if the specified pattern matches any part of either:
     * <ul>
     * <li>any subkey's full ID (eg "0x1234567890ABCDEF")
     * <li>any subkey's fingerprint (eg "1234567890ABCDEF1234567890ABCDEF12345678")
     * <li>any one of any subkey's user IDs (eg "Alice (work) &lt;alice@example.com&gt;")
     * </ul>
     * <p>
     * So for example, a pattern /0x1234/ would match the above full ID;
     * a pattern /(?i)90ab/ would match the above fingerprint;
     * and a pattern /Alice .work./ would match the above user ID.
     */
    public boolean matches(Pattern id) {
        return !findAll(id).isEmpty();
    }

    /**
     * Zeroes-out the cached passphrase for all subkeys,
     * and releases the extracted private key material for garbage collection.
     * Note that if {@link #setPassphrase} is
     * used to access the passphrase, the passphrase data cannot be zeroed
     * (so instead use {@link #setPassphraseChars}).
     */
    public void clearSecrets() {
        for (Subkey subkey : subkeys)
            subkey.clearSecrets();
    }

    /**
     * Loads first key from the specified armored text.
     * @throws PGPException if the text contains no keys.
     */
    public void load(String armor) throws IOException, PGPException {
        List<Key> keys = newRing().load(armor);
        if (Util.isEmpty(keys))
            throw new PGPException("no keys found");
        setSubkeys(keys.get(0).getSubkeys());
    }

    /**
     * Loads first key from the specified file.
     * @throws PGPException if the file contains no keys.
     */
    public void load(File file) throws IOException, PGPException {
        List<Key> keys = newRing().load(file);
        if (Util.isEmpty(keys))
            throw new PGPException("no keys found");
        setSubkeys(keys.get(0).getSubkeys());
    }

    /**
     * Loads first key from the specified input stream.
     * @throws PGPException if the input streame contains no keys.
     */
    public void load(InputStream stream) throws IOException, PGPException {
        List<Key> keys = newRing().load(stream);
        if (Util.isEmpty(keys))
            throw new PGPException("no keys found");
        setSubkeys(keys.get(0).getSubkeys());
    }

    protected Ring newRing() {
        return new Ring();
    }
}
