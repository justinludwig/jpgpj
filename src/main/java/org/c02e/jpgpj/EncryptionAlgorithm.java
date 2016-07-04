package org.c02e.jpgpj;

/**
 * Available symmetric-key encryption algorithms for encrypting message content.
 */
public enum EncryptionAlgorithm {
    Unencrypted,
    IDEA,
    TripleDES,
    CAST5,
    Blowfish,
    Reserved5,
    Reserved6,
    AES128,
    AES192,
    AES256,
    Twofish;
}
