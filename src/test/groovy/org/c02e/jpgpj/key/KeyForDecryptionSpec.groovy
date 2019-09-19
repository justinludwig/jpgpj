package org.c02e.jpgpj.key

import org.bouncycastle.openpgp.PGPException;
import spock.lang.Specification

class KeyForDecryptionSpec extends Specification {

    def "load key from stream"() {
        when:
        def key = new KeyForDecryption(stream('test-key-1.asc'), 'foo')
        then:
        key.subkeys.passphrase == ['foo', 'foo']
        key.master.secretKey
    }

    def "load key from file"() {
        when:
        def key = new KeyForDecryption(file('test-key-1.asc'), 'foo')
        then:
        key.subkeys.passphrase == ['foo', 'foo']
        key.master.secretKey
    }

    def "load key from string"() {
        when:
        def key = new KeyForDecryption(stream('test-key-1.asc').text, 'foo')
        then:
        key.subkeys.passphrase == ['foo', 'foo']
        key.master.secretKey
    }

    def "public key is for no uses"() {
        when:
        def key = new KeyForDecryption(stream('test-key-1-pub.asc'))
        then:
        !key.forSigning
        !key.forVerification
        !key.forEncryption
        !key.forDecryption

        when:
        key = new KeyForDecryption(stream('test-key-2-pub.asc'))
        then:
        !key.forSigning
        !key.forVerification
        !key.forEncryption
        !key.forDecryption
    }

    def "secret key is for decryption only with every technically usable subkey"() {
        when:
        def key = new KeyForDecryption(stream('test-key-1.asc'))
        then:
        !key.forSigning
        !key.forVerification
        !key.forEncryption
        key.forDecryption
        key.subkeys.forDecryption == [true, true]

        when:
        key = new KeyForDecryption(stream('test-key-2.asc'))
        then:
        !key.forSigning
        !key.forVerification
        !key.forEncryption
        key.forDecryption
        // secret key available only for 2nd and 3rd subkeys
        key.subkeys.forDecryption == [false, true, true]

        when:
        key = new KeyForDecryption(stream('test-no-usage-3-subkeys.asc'))
        then:
        !key.forSigning
        !key.forVerification
        !key.forEncryption
        key.forDecryption
        key.subkeys.forDecryption == [true, true, true]

        when:
        key = new KeyForDecryption(stream('test-no-usage-ec-subkeys.asc'))
        then:
        !key.forSigning
        !key.forVerification
        !key.forEncryption
        key.forDecryption
        // first 2 subkeys of this key are ecdsa (verification/signing)
        // and 3rd subkey is ecdh (encryption/decryption)
        key.subkeys.forDecryption == [false, false, true]
    }

    def "no subkeys is not for signing"() {
        expect: !new KeyForDecryption().forSigning
    }

    def "no subkeys is not for verification"() {
        expect: !new KeyForDecryption().forVerification
    }

    def "no subkeys is not for encryption"() {
        expect: !new KeyForDecryption().forEncryption
    }

    def "no subkeys is not for decryption"() {
        expect: !new KeyForDecryption().forDecryption
    }

    def "no subkeys has no master"() {
        expect: new KeyForDecryption().master == null
    }

    def "setting subkeys to null makes it for no uses"() {
        setup:
        def key = new KeyForDecryption(stream('test-key-1.asc'))
        when:
        key.subkeys = null
        then:
        !key.forSigning
        !key.forVerification
        !key.forEncryption
        !key.forDecryption
    }

    def "loading empty keys raises an execption"() {
        when: new KeyForDecryption('')
        then: thrown PGPException
    }

    protected stream(s) {
        getClass().classLoader.getResourceAsStream s
    }

    protected file(s) {
        new File(getClass().classLoader.getResource(s).toURI())
    }
}
