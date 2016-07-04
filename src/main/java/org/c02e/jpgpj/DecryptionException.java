package org.c02e.jpgpj;

import org.bouncycastle.openpgp.PGPException;

/**
 * Indicates decryption failed,
 * because the message was not encrypted with a required key
 * or symmetric passphrase.
 */
public class DecryptionException extends PGPException {

    public DecryptionException(String message) {
        super(message);
    }

    public DecryptionException(String message, Exception cause) {
        super(message, cause);
    }
}
