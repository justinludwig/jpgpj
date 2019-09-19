package org.c02e.jpgpj.key;

import java.io.File;
import java.io.InputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.bouncycastle.openpgp.PGPException;
import org.c02e.jpgpj.Decryptor;
import org.c02e.jpgpj.Encryptor;
import org.c02e.jpgpj.Key;
import org.c02e.jpgpj.Subkey;

/**
 * Key that should be used exclusively for signing.
 * <p>
 * Regardless of PGP usage flags associated with the original key source,
 * only the last subkey flagged for signing will be used, and the key will be
 * used for nothing else (so the {@link Encryptor} will use this key only for
 * signing, and not for encryption; and the {@link Decryptor} will ignore this
 * key entirely). If no subkeys have been flagged for signing, this class
 * will automatically flag the subkey most likely to have been intended to be
 * used for signing.
 * <p>
 * Use like the following:
 * <pre>{@code
 * new Encryptor(
 *     new KeyForSigning(new File("path/to/my/keys/alice-sec.gpg"), "password123"),
 *     new KeyForEncryption(new File("path/to/my/keys/bob-pub.gpg"))
 * ).encrypt(
 *     new File("path/to/plaintext.txt"),
 *     new File("path/to/ciphertext.txt.gpg")
 * );
 * }</pre>
 * @see Key
 */
public class KeyForSigning extends Key {

    /** Constructs a new empty key. */
    public KeyForSigning() {
        super();
    }

    /** Constructs a new key with the specified subkeys. */
    public KeyForSigning(List<Subkey> subkeys) {
        super(subkeys);
    }

    /**
     * Loads first key from the specified armored text.
     * @throws PGPException if the text contains no keys.
     */
    public KeyForSigning(String armor) throws IOException, PGPException {
        super(armor);
    }

    /**
     * Loads first key from the specified armored text,
     * and sets the passphrase of all subkeys to the specified passphrase.
     * @throws PGPException if the text contains no keys.
     */
    public KeyForSigning(String armor, char[] passphraseChars)
    throws IOException, PGPException {
        super(armor, passphraseChars);
    }

    /**
     * Loads first key from the specified armored text,
     * and sets the passphrase of all subkeys to the specified passphrase.
     * Prefer {@link #KeyForSigning(String, char[])} to avoid creating
     * extra copies of the passphrase in memory that cannot be cleaned up.
     * @throws PGPException if the text contains no keys.
     */
    public KeyForSigning(String armor, String passphrase)
    throws IOException, PGPException {
        super(armor, passphrase);
    }

    /**
     * Loads first key from the specified file.
     * @throws PGPException if the file contains no keys.
     */
    public KeyForSigning(File file) throws IOException, PGPException {
        super(file);
    }

    /**
     * Loads first key from the specified file,
     * and sets the passphrase of all subkeys to the specified passphrase.
     * @throws PGPException if the file contains no keys.
     */
    public KeyForSigning(File file, char[] passphraseChars)
    throws IOException, PGPException {
        super(file, passphraseChars);
    }

    /**
     * Loads first key from the specified file,
     * and sets the passphrase of all subkeys to the specified passphrase.
     * Prefer {@link #KeyForSigning(File, char[])} to avoid creating
     * extra copies of the passphrase in memory that cannot be cleaned up.
     * @throws PGPException if the file contains no keys.
     */
    public KeyForSigning(File file, String passphrase)
    throws IOException, PGPException {
        super(file, passphrase);
    }

    /**
     * Loads first key from the specified input stream.
     * @throws PGPException if the input streame contains no keys.
     */
    public KeyForSigning(InputStream stream)
    throws IOException, PGPException {
        super(stream);
    }

    /**
     * Loads first key from the specified input stream,
     * and sets the passphrase of all subkeys to the specified passphrase.
     * @throws PGPException if the input streame contains no keys.
     */
    public KeyForSigning(InputStream stream, char[] passphraseChars)
    throws IOException, PGPException {
        super(stream, passphraseChars);
    }

    /**
     * Loads first key from the specified input stream,
     * and sets the passphrase of all subkeys to the specified passphrase.
     * Prefer {@link #KeyForSigning(InputStream, char[])} to avoid creating
     * extra copies of the passphrase in memory that cannot be cleaned up.
     * @throws PGPException if the input streame contains no keys.
     */
    public KeyForSigning(InputStream stream, String passphrase)
    throws IOException, PGPException {
        super(stream, passphrase);
    }

    @Override
    protected void setSubkeys(List<Subkey> x) {
        super.setSubkeys(x);
        setSubkeysUsage();
    }

    protected void setSubkeysUsage() {
        if (subkeys.isEmpty()) return;

        // don't use subkeys for anything but signing
        for (Subkey subkey : subkeys) {
            subkey.setForVerification(false);
            subkey.setForEncryption(false);
            subkey.setForDecryption(false);
        }

        // do nothing if already has a subkey flagged for encryption
        for (Subkey subkey : subkeys)
            if (subkey.isForSigning())
                return;

        // select one subkey to flag for signing:
        // prefer to use first subkey usable for signing in the order
        // of the original subkeys list if list is two or less;
        // otherwise prefer to use the last subkey useable for signing
        List<Subkey> preferred = new ArrayList<Subkey>(subkeys);
        if (preferred.size() > 2)
            Collections.reverse(preferred);

        for (Subkey subkey : preferred) {
            if (subkey.isUsableForSigning()) {
                subkey.setForSigning(true);
                return;
            }
        }
    }
}
