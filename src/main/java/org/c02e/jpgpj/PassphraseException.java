package org.c02e.jpgpj;

import org.bouncycastle.openpgp.PGPException;

/**
 * Indicates an incorrect passphrase was used to unlock a key.
 */
public class PassphraseException extends PGPException {

    public PassphraseException(String message) {
        super(message);
    }

    public PassphraseException(String message, Exception cause) {
        super(message, cause);
    }
}
