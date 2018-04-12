package org.c02e.jpgpj;

/**
 * Available hash algorithms for signing message content,
 * and for deriving a symmetric key from a passphrase.
 */
public enum HashingAlgorithm {
    Unsigned,
    MD5,
    SHA1,
    RIPEMD160,
    Reserved4, // double-width SHA1
    Reserved5, // MD2
    Reserved6, // TIGER/192
    Reserved7, // HAVAL-5-160
    SHA256,
    SHA384,
    SHA512,
    SHA224;
}
