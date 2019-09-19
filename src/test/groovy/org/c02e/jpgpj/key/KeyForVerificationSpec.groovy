package org.c02e.jpgpj.key

import org.bouncycastle.openpgp.PGPException;
import spock.lang.Specification

class KeyForVerificationSpec extends Specification {

    def "load key from stream"() {
        when:
        def key = new KeyForVerification(stream('test-key-1.asc'))
        then:
        key.subkeys.passphrase == ['', '']
        key.master.publicKey
    }

    def "load key from file"() {
        when:
        def key = new KeyForVerification(file('test-key-1.asc'))
        then:
        key.subkeys.passphrase == ['', '']
        key.master.publicKey
    }

    def "load key from string"() {
        when:
        def key = new KeyForVerification(stream('test-key-1.asc').text)
        then:
        key.subkeys.passphrase == ['', '']
        key.master.publicKey
    }

    def "public key is for verification only with every technically usable subkey"() {
        when:
        def key = new KeyForVerification(stream('test-key-1-pub.asc'))
        then:
        !key.forSigning
        key.forVerification
        !key.forEncryption
        !key.forDecryption
        key.subkeys.forVerification == [true, true]

        when:
        key = new KeyForVerification(stream('test-key-2-pub.asc'))
        then:
        !key.forSigning
        key.forVerification
        !key.forEncryption
        !key.forDecryption
        key.subkeys.forVerification == [true, true, true]
    }

    def "secret key is for verification only with every technically usable subkey"() {
        when:
        def key = new KeyForVerification(stream('test-key-1.asc'))
        then:
        !key.forSigning
        key.forVerification
        !key.forEncryption
        !key.forDecryption
        key.subkeys.forVerification == [true, true]

        when:
        key = new KeyForVerification(stream('test-key-2.asc'))
        then:
        !key.forSigning
        key.forVerification
        !key.forEncryption
        !key.forDecryption
        key.subkeys.forVerification == [true, true, true]

        when:
        key = new KeyForVerification(stream('test-no-usage-3-subkeys.asc'))
        then:
        !key.forSigning
        key.forVerification
        !key.forEncryption
        !key.forDecryption
        key.subkeys.forVerification == [true, true, true]

        when:
        key = new KeyForVerification(stream('test-no-usage-ec-subkeys.asc'))
        then:
        !key.forSigning
        key.forVerification
        !key.forEncryption
        !key.forDecryption
        // first 2 subkeys of this key are ecdsa (verification/signing)
        // and 3rd subkey is ecdh (encryption/decryption)
        key.subkeys.forVerification == [true, true, false]
    }

    def "no subkeys is not for signing"() {
        expect: !new KeyForVerification().forSigning
    }

    def "no subkeys is not for verification"() {
        expect: !new KeyForVerification().forVerification
    }

    def "no subkeys is not for encryption"() {
        expect: !new KeyForVerification().forEncryption
    }

    def "no subkeys is not for decryption"() {
        expect: !new KeyForVerification().forDecryption
    }

    def "no subkeys has no master"() {
        expect: new KeyForVerification().master == null
    }

    def "setting subkeys to null makes it for no uses"() {
        setup:
        def key = new KeyForVerification(stream('test-key-1.asc'))
        when:
        key.subkeys = null
        then:
        !key.forSigning
        !key.forVerification
        !key.forEncryption
        !key.forDecryption
    }

    def "loading empty keys raises an execption"() {
        when: new KeyForVerification('')
        then: thrown PGPException
    }

    protected stream(s) {
        getClass().classLoader.getResourceAsStream s
    }

    protected file(s) {
        new File(getClass().classLoader.getResource(s).toURI())
    }
}
