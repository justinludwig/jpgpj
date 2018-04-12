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
    Reserved5, // SAFER-SK128
    Reserved6, // DES
    AES128,
    AES192,
    AES256,
    Twofish,
    Camellia128,
    Camellia192,
    Camellia256;
}
