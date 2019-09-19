package org.c02e.jpgpj.key;

import java.io.File;
import java.io.InputStream;
import java.io.IOException;
import java.util.List;
import org.bouncycastle.openpgp.PGPException;
import org.c02e.jpgpj.Decryptor;
import org.c02e.jpgpj.Encryptor;
import org.c02e.jpgpj.Key;
import org.c02e.jpgpj.Subkey;

/**
 * Key that should be used exclusively for decryption.
 * <p>
 * Regardless of PGP usage flags associated with the original key source,
 * all subkeys of this key will be flagged to be used for decryption and
 * nothing else (so the {@link Decryptor} will try all subkeys of this key
 * when decrypting, but will ignore all subkeys when verifying;
 * and the {@link Encryptor} will ignore this key entirely).
 * <p>
 * Use like the following:
 * <pre>{@code
 * new Decryptor(
 *     new KeyForVerification(new File("path/to/my/keys/alice-pub.gpg")),
 *     new KeyForDecryption(new File("path/to/my/keys/bob-sec.gpg"), "b0bru1z!")
 * ).decrypt(
 *     new File("path/to/ciphertext.txt.gpg"),
 *     new File("path/back-to/plaintext.txt")
 * );
 * }</pre>
 * @see Key
 */
public class KeyForDecryption extends Key {

    /** Constructs a new empty key. */
    public KeyForDecryption() {
        super();
    }

    /** Constructs a new key with the specified subkeys. */
    public KeyForDecryption(List<Subkey> subkeys) {
        super(subkeys);
    }

    /**
     * Loads first key from the specified armored text.
     * @throws PGPException if the text contains no keys.
     */
    public KeyForDecryption(String armor) throws IOException, PGPException {
        super(armor);
    }

    /**
     * Loads first key from the specified armored text,
     * and sets the passphrase of all subkeys to the specified passphrase.
     * @throws PGPException if the text contains no keys.
     */
    public KeyForDecryption(String armor, char[] passphraseChars)
    throws IOException, PGPException {
        super(armor, passphraseChars);
    }

    /**
     * Loads first key from the specified armored text,
     * and sets the passphrase of all subkeys to the specified passphrase.
     * Prefer {@link #KeyForDecryption(String, char[])} to avoid creating
     * extra copies of the passphrase in memory that cannot be cleaned up.
     * @throws PGPException if the text contains no keys.
     */
    public KeyForDecryption(String armor, String passphrase)
    throws IOException, PGPException {
        super(armor, passphrase);
    }

    /**
     * Loads first key from the specified file.
     * @throws PGPException if the file contains no keys.
     */
    public KeyForDecryption(File file) throws IOException, PGPException {
        super(file);
    }

    /**
     * Loads first key from the specified file,
     * and sets the passphrase of all subkeys to the specified passphrase.
     * @throws PGPException if the file contains no keys.
     */
    public KeyForDecryption(File file, char[] passphraseChars)
    throws IOException, PGPException {
        super(file, passphraseChars);
    }

    /**
     * Loads first key from the specified file,
     * and sets the passphrase of all subkeys to the specified passphrase.
     * Prefer {@link #KeyForDecryption(File, char[])} to avoid creating
     * extra copies of the passphrase in memory that cannot be cleaned up.
     * @throws PGPException if the file contains no keys.
     */
    public KeyForDecryption(File file, String passphrase)
    throws IOException, PGPException {
        super(file, passphrase);
    }

    /**
     * Loads first key from the specified input stream.
     * @throws PGPException if the input streame contains no keys.
     */
    public KeyForDecryption(InputStream stream)
    throws IOException, PGPException {
        super(stream);
    }

    /**
     * Loads first key from the specified input stream,
     * and sets the passphrase of all subkeys to the specified passphrase.
     * @throws PGPException if the input streame contains no keys.
     */
    public KeyForDecryption(InputStream stream, char[] passphraseChars)
    throws IOException, PGPException {
        super(stream, passphraseChars);
    }

    /**
     * Loads first key from the specified input stream,
     * and sets the passphrase of all subkeys to the specified passphrase.
     * Prefer {@link #KeyForDecryption(InputStream, char[])} to avoid creating
     * extra copies of the passphrase in memory that cannot be cleaned up.
     * @throws PGPException if the input streame contains no keys.
     */
    public KeyForDecryption(InputStream stream, String passphrase)
    throws IOException, PGPException {
        super(stream, passphrase);
    }

    @Override
    protected void setSubkeys(List<Subkey> x) {
        super.setSubkeys(x);
        setSubkeysUsage();
    }

    protected void setSubkeysUsage() {
        for (Subkey subkey : subkeys) {
            subkey.setForSigning(false);
            subkey.setForVerification(false);
            subkey.setForEncryption(false);
            subkey.setForDecryption(subkey.isUsableForDecryption());
        }
    }
}
