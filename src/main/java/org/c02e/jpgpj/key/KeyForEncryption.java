package org.c02e.jpgpj.key;

import java.io.File;
import java.io.InputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import org.bouncycastle.openpgp.PGPException;
import org.c02e.jpgpj.Decryptor;
import org.c02e.jpgpj.Encryptor;
import org.c02e.jpgpj.Key;
import org.c02e.jpgpj.Subkey;

/**
 * Key that should be used exclusively for encryption.
 * <p>
 * Regardless of PGP usage flags associated with the original key source,
 * only the last subkey flagged for encryption will be used, and the key will be
 * used for nothing else (so the {@link Encryptor} will use this key only for
 * encryption, and not for signing; and the {@link Decryptor} will ignore this
 * key entirely). If no subkeys have been flagged for encryption, this class
 * will automatically flag the subkey most likely to have been intended to be
 * used for encryption.
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
public class KeyForEncryption extends Key {

    /** Constructs a new empty key. */
    public KeyForEncryption() {
        super();
    }

    /** Constructs a new key with the specified subkeys. */
    public KeyForEncryption(List<Subkey> subkeys) {
        super(subkeys);
    }

    /**
     * Loads first key from the specified armored text.
     * @throws PGPException if the text contains no keys.
     */
    public KeyForEncryption(String armor) throws IOException, PGPException {
        super(armor);
    }

    /**
     * Loads first key from the specified file.
     * @throws PGPException if the file contains no keys.
     */
    public KeyForEncryption(File file) throws IOException, PGPException {
        super(file);
    }

    /**
     * Loads first key from the specified input stream.
     * @throws PGPException if the input streame contains no keys.
     */
    public KeyForEncryption(InputStream stream)
    throws IOException, PGPException {
        super(stream);
    }

    @Override
    protected void setSubkeys(List<Subkey> x) {
        super.setSubkeys(x);
        setSubkeysUsage();
    }

    protected void setSubkeysUsage() {
        if (subkeys.isEmpty()) return;

        // don't use subkeys for anything but encryption
        for (Subkey subkey : subkeys) {
            subkey.setForSigning(false);
            subkey.setForVerification(false);
            subkey.setForDecryption(false);
        }

        // do nothing if already has a subkey flagged for encryption
        for (Subkey subkey : subkeys)
            if (subkey.isForEncryption())
                return;

        // select one subkey to flag for encryption:
        // prefer to use the first subkey usable for encryption in the order
        // of the original subkeys list, after the very first subkey;
        // and then the very first subkey if no other subkeys are usable
        List<Subkey> preferred = new ArrayList<Subkey>(subkeys);
        preferred.add(preferred.remove(0));

        for (Subkey subkey : preferred) {
            if (subkey.isUsableForEncryption()) {
                subkey.setForEncryption(true);
                return;
            }
        }
    }
}
