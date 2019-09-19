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
 * Key that should be used exclusively for encryption.
 * <p>
 * Regardless of PGP usage flags associated with the original key source,
 * all subkeys of this key will be flagged to be used for verification and
 * nothing else (so the {@link Decryptor} will try all subkeys of this key
 * when verifying, but will ignore all subkeys when decrypting;
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
public class KeyForVerification extends Key {

    /** Constructs a new empty key. */
    public KeyForVerification() {
        super();
    }

    /** Constructs a new key with the specified subkeys. */
    public KeyForVerification(List<Subkey> subkeys) {
        super(subkeys);
    }

    /**
     * Loads first key from the specified armored text.
     * @throws PGPException if the text contains no keys.
     */
    public KeyForVerification(String armor) throws IOException, PGPException {
        super(armor);
    }

    /**
     * Loads first key from the specified file.
     * @throws PGPException if the file contains no keys.
     */
    public KeyForVerification(File file) throws IOException, PGPException {
        super(file);
    }

    /**
     * Loads first key from the specified input stream.
     * @throws PGPException if the input streame contains no keys.
     */
    public KeyForVerification(InputStream stream)
    throws IOException, PGPException {
        super(stream);
    }

    @Override
    protected void setSubkeys(List<Subkey> x) {
        super.setSubkeys(x);
        setSubkeysUsage();
    }

    protected void setSubkeysUsage() {
        for (Subkey subkey : subkeys) {
            subkey.setForSigning(false);
            subkey.setForVerification(subkey.isUsableForVerification());
            subkey.setForEncryption(false);
            subkey.setForDecryption(false);
        }
    }
}
