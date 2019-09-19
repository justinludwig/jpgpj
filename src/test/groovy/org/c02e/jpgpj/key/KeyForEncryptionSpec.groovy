package org.c02e.jpgpj.key

import org.bouncycastle.openpgp.PGPException;
import spock.lang.Specification

class KeyForEncryptionSpec extends Specification {

    def "load key from stream"() {
        when:
        def key = new KeyForEncryption(stream('test-key-1.asc'))
        then:
        key.subkeys.passphrase == ['', '']
        key.master.publicKey
    }

    def "load key from file"() {
        when:
        def key = new KeyForEncryption(file('test-key-1.asc'))
        then:
        key.subkeys.passphrase == ['', '']
        key.master.publicKey
    }

    def "load key from string"() {
        when:
        def key = new KeyForEncryption(stream('test-key-1.asc').text)
        then:
        key.subkeys.passphrase == ['', '']
        key.master.publicKey
    }

    def "public key is for encryption only with flagged subkey"() {
        when:
        def key = new KeyForEncryption(stream('test-key-1-pub.asc'))
        then:
        !key.forSigning
        !key.forVerification
        key.forEncryption
        !key.forDecryption
        key.subkeys.forEncryption == [false, true]

        when:
        key = new KeyForEncryption(stream('test-key-2-pub.asc'))
        then:
        !key.forSigning
        !key.forVerification
        key.forEncryption
        !key.forDecryption
        key.subkeys.forEncryption == [false, true, false]
    }

    def "secret key is for encryption only with flagged subkey"() {
        when:
        def key = new KeyForEncryption(stream('test-key-1.asc'))
        then:
        !key.forSigning
        !key.forVerification
        key.forEncryption
        !key.forDecryption
        key.subkeys.forEncryption == [false, true]

        when:
        key = new KeyForEncryption(stream('test-key-2.asc'))
        then:
        !key.forSigning
        !key.forVerification
        key.forEncryption
        !key.forDecryption
        key.subkeys.forEncryption == [false, true, false]
    }

    def "secret key with no flags is for encryption only with selected subkey"() {
        when:
        def key = new KeyForEncryption(stream('test-no-usage-1-subkeys.asc'))
        then:
        !key.forSigning
        !key.forVerification
        key.forEncryption
        !key.forDecryption
        key.subkeys.forEncryption == [true]

        when:
        key = new KeyForEncryption(stream('test-no-usage-2-subkeys.asc'))
        then:
        !key.forSigning
        !key.forVerification
        key.forEncryption
        !key.forDecryption
        key.subkeys.forEncryption == [false, true]

        when:
        key = new KeyForEncryption(stream('test-no-usage-3-subkeys.asc'))
        then:
        !key.forSigning
        !key.forVerification
        key.forEncryption
        !key.forDecryption
        key.subkeys.forEncryption == [false, true, false]

        when:
        key = new KeyForEncryption(stream('test-no-usage-ec-subkeys.asc'))
        then:
        !key.forSigning
        !key.forVerification
        key.forEncryption
        !key.forDecryption
        // first 2 subkeys of this key are ecdsa (verification/signing)
        // and 3rd subkey is ecdh (encryption/decryption)
        key.subkeys.forEncryption == [false, false, true]
    }

    def "no subkeys is not for signing"() {
        expect: !new KeyForEncryption().forSigning
    }

    def "no subkeys is not for verification"() {
        expect: !new KeyForEncryption().forVerification
    }

    def "no subkeys is not for encryption"() {
        expect: !new KeyForEncryption().forEncryption
    }

    def "no subkeys is not for decryption"() {
        expect: !new KeyForEncryption().forDecryption
    }

    def "no subkeys has no master"() {
        expect: new KeyForEncryption().master == null
    }

    def "setting subkeys to null makes it for no uses"() {
        setup:
        def key = new KeyForEncryption(stream('test-key-1.asc'))
        when:
        key.subkeys = null
        then:
        !key.forSigning
        !key.forVerification
        !key.forEncryption
        !key.forDecryption
    }

    def "loading empty keys raises an execption"() {
        when: new KeyForEncryption('')
        then: thrown PGPException
    }

    protected stream(s) {
        getClass().classLoader.getResourceAsStream s
    }

    protected file(s) {
        new File(getClass().classLoader.getResource(s).toURI())
    }
}
