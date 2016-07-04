package org.c02e.jpgpj;

import org.bouncycastle.openpgp.PGPException;

/**
 * Indicates verification failed,
 * either because the message was not signed with at least one required key,
 * or because the signature of a required key was invalid.
 */
public class VerificationException extends PGPException {

    public VerificationException(String message) {
        super(message);
    }

    public VerificationException(String message, Exception cause) {
        super(message, cause);
    }
}
