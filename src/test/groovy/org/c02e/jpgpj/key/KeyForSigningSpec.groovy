package org.c02e.jpgpj.key

import org.bouncycastle.openpgp.PGPException;
import spock.lang.Specification

class KeyForSigningSpec extends Specification {

    def "load key from stream"() {
        when:
        def key = new KeyForSigning(stream('test-key-1.asc'), 'foo')
        then:
        key.subkeys.passphrase == ['foo', 'foo']
        key.master.secretKey
    }

    def "load key from file"() {
        when:
        def key = new KeyForSigning(file('test-key-1.asc'), 'foo')
        then:
        key.subkeys.passphrase == ['foo', 'foo']
        key.master.secretKey
    }

    def "load key from string"() {
        when:
        def key = new KeyForSigning(stream('test-key-1.asc').text, 'foo')
        then:
        key.subkeys.passphrase == ['foo', 'foo']
        key.master.secretKey
    }

    def "public key is for no uses"() {
        when:
        def key = new KeyForSigning(stream('test-key-1-pub.asc'))
        then:
        !key.forSigning
        !key.forVerification
        !key.forEncryption
        !key.forDecryption

        when:
        key = new KeyForSigning(stream('test-key-2-pub.asc'))
        then:
        !key.forSigning
        !key.forVerification
        !key.forEncryption
        !key.forDecryption
    }

    def "secret key is for signing only with flagged subkey"() {
        when:
        def key = new KeyForSigning(stream('test-key-1.asc'))
        then:
        key.forSigning
        !key.forVerification
        !key.forEncryption
        !key.forDecryption
        key.subkeys.forSigning == [true, false]

        when:
        key = new KeyForSigning(stream('test-key-2.asc'))
        then:
        key.forSigning
        !key.forVerification
        !key.forEncryption
        !key.forDecryption
        key.subkeys.forSigning == [false, false, true]
    }

    def "secret key with no flags is for signing only with selected subkey"() {
        when:
        def key = new KeyForSigning(stream('test-no-usage-1-subkeys.asc'))
        then:
        key.forSigning
        !key.forVerification
        !key.forEncryption
        !key.forDecryption
        key.subkeys.forSigning == [true]

        when:
        key = new KeyForSigning(stream('test-no-usage-2-subkeys.asc'))
        then:
        key.forSigning
        !key.forVerification
        !key.forEncryption
        !key.forDecryption
        key.subkeys.forSigning == [true, false]

        when:
        key = new KeyForSigning(stream('test-no-usage-3-subkeys.asc'))
        then:
        key.forSigning
        !key.forVerification
        !key.forEncryption
        !key.forDecryption
        key.subkeys.forSigning == [false, false, true]

        when:
        key = new KeyForSigning(stream('test-no-usage-ec-subkeys.asc'))
        then:
        key.forSigning
        !key.forVerification
        !key.forEncryption
        !key.forDecryption
        // first 2 subkeys of this key are ecdsa (verification/signing)
        // and 3rd subkey is ecdh (encryption/decryption)
        key.subkeys.forSigning == [false, true, false]
    }

    def "no subkeys is not for signing"() {
        expect: !new KeyForSigning().forSigning
    }

    def "no subkeys is not for verification"() {
        expect: !new KeyForSigning().forVerification
    }

    def "no subkeys is not for encryption"() {
        expect: !new KeyForSigning().forEncryption
    }

    def "no subkeys is not for decryption"() {
        expect: !new KeyForSigning().forDecryption
    }

    def "no subkeys has no master"() {
        expect: new KeyForSigning().master == null
    }

    def "setting subkeys to null makes it for no uses"() {
        setup:
        def key = new KeyForSigning(stream('test-key-1.asc'))
        when:
        key.subkeys = null
        then:
        !key.forSigning
        !key.forVerification
        !key.forEncryption
        !key.forDecryption
    }

    def "loading empty keys raises an execption"() {
        when: new KeyForSigning('')
        then: thrown PGPException
    }

    protected stream(s) {
        getClass().classLoader.getResourceAsStream s
    }

    protected file(s) {
        new File(getClass().classLoader.getResource(s).toURI())
    }
}
