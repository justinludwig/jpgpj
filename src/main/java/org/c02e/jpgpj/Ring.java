package org.c02e.jpgpj;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.regex.Pattern;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.gpg.keybox.PublicKeyRingBlob;
import org.bouncycastle.gpg.keybox.bc.BcKeyBox;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.bc.BcPGPObjectFactory;
import org.c02e.jpgpj.util.FileDetection;
import org.c02e.jpgpj.util.FileDetection.DetectionResult;
import org.c02e.jpgpj.util.Util;

/**
 * A collection of {@link Key}s.
 * <p>
 * Keys can be added to the ring by adding them to the list returned by the
 * {@link #getKeys} method, or by loading them from ascii armor text via the
 * {@link #load(String)} method, or by loading them from a file via the
 * {@link #load(File)} method, or by loading them from an input stream via the
 * {@link #load(InputStream)} method. A ring can also be constructed from
 * an existing array of keys ({@link #Ring(Key...)}), or from an existing list
 * of keys ({@link #Ring(List)}), or from an ASCII-armor text string containing
 * the keys ({@link #Ring(String)}), or from a file containing the keys
 * ({@link #Ring(File)}), or from an input stream containing the keys
 * ({@link #Ring(InputStream)}).
 * <p>
 * Once keys have been loaded, their subkeys can be manipulated to customize
 * usage flags (to indicate whether a subkey should be used for encryption,
 * decryption, signing, or verification), and to supply the passphrase
 * needed to unlock the subkey (which is needed to use the subkey for
 * decryption and signing).
 */
public class Ring implements Cloneable {
    protected List<Key> keys;

    /** Constructs a new empty ring. */
    public Ring() {
        this(new ArrayList<Key>());
    }

    /** Constructs a new ring with the specified array of keys. */
    public Ring(Key... keys) {
        this(Arrays.asList(keys));
    }

    /** Constructs a new ring with the specified list of keys. */
    public Ring(List<Key> keys) {
        setKeys(keys);
    }

    /**
     * Loads all keys from the specified armored text.
     */
    public Ring(String armor) throws IOException, PGPException {
        this();
        load(armor);
    }

    /**
     * Loads all keys from the specified file.
     */
    public Ring(File file) throws IOException, PGPException {
        this();
        load(file);
    }

    /**
     * Loads all keys from the specified input stream.
     */
    public Ring(InputStream stream) throws IOException, PGPException {
        this();
        load(stream);
    }

    @Override
    public Ring clone() {
        try {
            Ring other = getClass().cast(super.clone());
            List<Key> thisKeys = getKeys();
            other.setKeys((thisKeys == null) ? null : new ArrayList<>(thisKeys));
            return other;
        } catch (CloneNotSupportedException e) {
            throw new UnsupportedOperationException("Unexpected clone failure for " + this);
        }
    }

    /**
     * Display string for this ring, including listing each key on the ring,
     * with each subkey's usage flags, short ID, and user IDs.
     */
    @Override
    public String toString() {
        if (Util.isEmpty(keys)) return "ring empty";

        StringBuilder b = new StringBuilder();
        int count = 0;
        for (Key key : keys) {
            if (count++ > 0)
                b.append("\n\n");
            b.append(key.toString());
        }
        return b.toString();
    }

    /** True if this contains at least one key. */
    public boolean asBoolean() {
        return !Util.isEmpty(keys);
    }

    /** All keys that can sign, or an empty list. */
    public List<Key> getSigningKeys() {
        ArrayList<Key> a = new ArrayList<Key>(keys.size());
        for (Key key : keys)
            if (key.isForSigning())
                a.add(key);
        return a;
    }

    /** All keys that can verify, or an empty list. */
    public List<Key> getVerificationKeys() {
        ArrayList<Key> a = new ArrayList<Key>(keys.size());
        for (Key key : keys)
            if (key.isForVerification())
                a.add(key);
        return a;
    }

    /** All keys that can encrypt, or an empty list. */
    public List<Key> getEncryptionKeys() {
        ArrayList<Key> a = new ArrayList<Key>(keys.size());
        for (Key key : keys)
            if (key.isForEncryption())
                a.add(key);
        return a;
    }

    /** All keys that can decrypt, or an empty list. */
    public List<Key> getDecryptionKeys() {
        ArrayList<Key> a = new ArrayList<Key>(keys.size());
        for (Key key : keys)
            if (key.isForDecryption())
                a.add(key);
        return a;
    }

    /** All keys, an or an empty list. */
    public List<Key> getKeys() {
        return keys;
    }

    /** All keys, an or an empty list. */
    protected void setKeys(List<Key> x) {
        keys = x != null ? x : new ArrayList<Key>();
    }

    /**
     * First key containing the subkey with the specified full ID, or null.
     * @deprecated Use {@link #findAll} (to find all subkeys on a ring,
     * in case the same key had been included multiple times
     * with different settings on the same ring).
     */
    @Deprecated
    public Key findById(Long id) {
        for (Key key : keys)
            if (key.findById(id) != null)
                return key;
        return null;
    }

    /**
     * All keys for which the specified ID is any subkey's full ID.
     * Normally this will return 0 or 1 keys, but if a key has been added
     * to a ring multiple times (with different settings, such as one time
     * as a public key and one time as a private key), this method may return
     * more than one key instance.
     */
    public List<Key> findAll(Long id) {
        if (id == null) return Collections.emptyList();

        ArrayList<Key> result = new ArrayList<Key>();
        for (Key key : keys)
            if (key.findById(id) != null)
                result.add(key);
        return result;
    }

    /**
     * All keys for which the specified string is
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
    public List<Key> findAll(String id) {
        if (Util.isEmpty(id)) return Collections.emptyList();

        Pattern regex = Pattern.compile(id,
            Pattern.CASE_INSENSITIVE | Pattern.LITERAL);
        return findAll(regex);
    }

    /**
     * All keys for which the specified pattern matches any part of either:
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
    public List<Key> findAll(Pattern id) {
        if (id == null) return Collections.emptyList();

        ArrayList<Key> result = new ArrayList<Key>();
        for (Key key : keys)
            if (!Util.isEmpty(key.findAll(id)))
                result.add(key);
        return result;
    }

    /**
     * Zeroes-out the cached passphrase for all keys,
     * and releases the extracted private key material for garbage collection.
     */
    public void clearSecrets() {
        for (Key key : keys)
            key.clearSecrets();
    }

    /**
     * Loads all keys from the specified armored text,
     * and adds them to this ring's existing list of keys.
     */
    public List<Key> load(String armor) throws IOException, PGPException {
        return load(new ByteArrayInputStream(armor.getBytes("ASCII")));
    }

    /**
     * Loads all keys from the specified file,
     * and adds them to this ring's existing list of keys.
     */
    public List<Key> load(File file) throws IOException, PGPException {
        InputStream stream = null;
        try {
            stream = new BufferedInputStream(new FileInputStream(file), 0x1000);
            return load(stream);
        } finally {
            try { stream.close(); } catch (Exception e) {}
        }
    }

    /**
     * Loads all keys from the specified input stream,
     * and adds them to this ring's existing list of keys.
     */
    public List<Key> load(InputStream stream) throws IOException, PGPException {
        List<Key> keys = new ArrayList<Key>();

        Iterator<?> packets = parse(stream);
        while (packets.hasNext()) {
            Object packet = packets.next();

            if (packet instanceof PGPSecretKeyRing)
                keys.add(newKey((PGPSecretKeyRing) packet));
            else if (packet instanceof PGPPublicKeyRing)
                keys.add(newKey((PGPPublicKeyRing) packet));
            else if (packet instanceof PublicKeyRingBlob)
                keys.add(newKey(
                    ((PublicKeyRingBlob) packet).getPGPPublicKeyRing()));
        }

        this.keys.addAll(keys);
        return keys;
    }

    /**
     * Separates stream into PGP packets.
     * @see PGPObjectFactory
     */
    protected Iterator<?> parse(InputStream stream)
    throws IOException, PGPException {
        DetectionResult result = FileDetection.detectContainer(stream);
        switch (result.type) {
            case ASCII_ARMOR:
                result.stream = new ArmoredInputStream(result.stream); // fall thru
            case PGP:
                return new BcPGPObjectFactory(result.stream).iterator();
            case KEYBOX:
                return new BcKeyBox(result.stream).getKeyBlobs().iterator();
            default:
                throw new PGPException("not a keyring");
        }
    }

    protected Key newKey(ArrayList<Subkey> subkeys) {
        return new Key(subkeys);
    }

    protected Key newKey(PGPPublicKeyRing ring) throws PGPException {
        ArrayList<Subkey> subkeys = new ArrayList<Subkey>();

        Iterator<PGPPublicKey> i = ring.iterator();
        while (i.hasNext())
            subkeys.add(newSubkey(i.next()));

        return newKey(subkeys);
    }

    protected Key newKey(PGPSecretKeyRing ring) throws PGPException {
        ArrayList<Subkey> subkeys = new ArrayList<Subkey>();

        Iterator<PGPSecretKey> i = ring.iterator();
        while (i.hasNext())
            subkeys.add(newSubkey(i.next()));

        return newKey(subkeys);
    }

    protected Subkey newSubkey() {
        return new Subkey();
    }

    protected Subkey newSubkey(PGPPublicKey k) throws PGPException {
        Subkey subkey = newSubkey();
        subkey.setPublicKey(k);
        return subkey;
    }

    protected Subkey newSubkey(PGPSecretKey k) throws PGPException {
        Subkey subkey = newSubkey();
        subkey.setSecretKey(k);
        return subkey;
    }
}
