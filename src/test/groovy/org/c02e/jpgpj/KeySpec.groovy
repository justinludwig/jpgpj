package org.c02e.jpgpj

import org.bouncycastle.openpgp.PGPException;
import spock.lang.Specification

class KeySpec extends Specification {

    def "load key from stream"() {
        when:
        def key = new Key(stream('test-key-1.asc'), 'foo')
        then:
        key.subkeys.passphrase == ['foo', 'foo']
        key.master.secretKey
    }

    def "load key from file"() {
        when:
        def key = new Key(file('test-key-1.asc'), 'foo')
        then:
        key.subkeys.passphrase == ['foo', 'foo']
        key.master.secretKey
    }

    def "load key from string"() {
        when:
        def key = new Key(stream('test-key-1.asc').text, 'foo')
        then:
        key.subkeys.passphrase == ['foo', 'foo']
        key.master.secretKey
    }

    def "list uids from master subkey"() {
        when:
        def key = new Key(stream('test-key-1-pub.asc'))
        then:
        key.uids == [
            'Test Key 1 <test-key-1@c02e.org>',
        ]
        when:
        key = new Key(stream('test-key-2.asc'))
        then:
        key.uids == [
            'Test Key 2 <test-key-2@c02e.org>',
            'Test 2 (CODESurvey) <test-key-2@codesurvey.org>',
        ]
    }

    def "list signing uid from master subkey"() {
        when:
        def key = new Key(stream('test-key-1-pub.asc'))
        then:
        key.signingUid == 'Test Key 1 <test-key-1@c02e.org>'
        when:
        key = new Key(stream('test-key-2.asc'))
        then:
        key.signingUid == 'Test Key 2 <test-key-2@c02e.org>'
    }

    def "public key is for verification and encryption only"() {
        when:
        def key = new Key(stream('test-key-1-pub.asc'))
        then:
        !key.forSigning
        key.forVerification
        key.forEncryption
        !key.forDecryption
        when:
        key = new Key(stream('test-key-2-pub.asc'))
        then:
        !key.forSigning
        key.forVerification
        key.forEncryption
        !key.forDecryption
    }

    def "secret key is for all uses"() {
        when:
        def key = new Key(stream('test-key-1.asc'))
        then:
        key.forSigning
        key.forVerification
        key.forEncryption
        key.forDecryption
        when:
        key = new Key(stream('test-key-2.asc'))
        then:
        key.forSigning
        key.forVerification
        key.forEncryption
        key.forDecryption
    }

    def "find subkey by id number"() {
        when:
        def key = new Key(stream('test-key-1-pub.asc'))
        then:
        !key.findById(null)
        !key.findById(0)
        !key.findById(123)
        key.findById(0x72A423A0013826C3L).shortId == '013826C3'
        key.findById(0x29DEE78E970C7061L).shortId == '970C7061'
        when:
        key = new Key(stream('test-key-2.asc'))
        then:
        key.findById(0x2B04481E880A1469L).shortId == '880A1469'
        key.findById(0x6727B00AAFAFA3C5L).shortId == 'AFAFA3C5'
        !key.findById(0xAFDB7B47L)
    }

    def "find master subkey by uid"() {
        when:
        def key = new Key(stream('test-key-1-pub.asc'))
        then:
        key.findAll('').shortId == []
        key.findAll('foo').shortId == []
        key.findAll(~/foo/).shortId == []
        key.findAll('test key').shortId == ['013826C3']
        when:
        key = new Key(stream('test-key-2.asc'))
        then:
        key.findAll('foo').shortId == []
        key.findAll('test key').shortId == ['880A1469']
        key.findAll('codesurvey').shortId == ['880A1469']
        key.findAll(~/test-key.*@c02e/).shortId == ['880A1469']
    }

    def "find subkey by short id"() {
        when:
        def key = new Key(stream('test-key-1-pub.asc'))
        then:
        key.findAll('013826C3').shortId == ['013826C3']
        !key.findAll('0x970C7061').shortId
        when:
        key = new Key(stream('test-key-2.asc'))
        then:
        key.findAll('a').shortId == ['880A1469', 'AFAFA3C5', 'BC3F6A4B']
        key.findAll('880A1469').shortId == ['880A1469']
        key.findAll('AFAFA3C5').shortId == ['AFAFA3C5']
        key.findAll('BC3F6A4B').shortId == ['BC3F6A4B']
        !key.findAll('0x880A1469').shortId
    }

    def "find subkey by long id"() {
        when:
        def key = new Key(stream('test-key-1-pub.asc'))
        then:
        key.findAll('72A423A0013826C3').shortId == ['013826C3']
        key.findAll('0x29DEE78E970C7061').shortId == ['970C7061']
        when:
        key = new Key(stream('test-key-2.asc'))
        then:
        key.findAll('a').shortId == ['880A1469', 'AFAFA3C5', 'BC3F6A4B']
        key.findAll('0x2B04481E880A1469').shortId == ['880A1469']
        key.findAll('6727B00AAFAFA3C5').shortId == ['AFAFA3C5']
        key.findAll('AFDB7B47').shortId == ['BC3F6A4B']
    }

    def "find subkey by fingerprint"() {
        when:
        def key = new Key(stream('test-key-1-pub.asc'))
        then:
        !key.findAll('B58A F7D0 AAD9 1E33 B15A  8062 72A4 23A0 0138 26C3')
        key.findAll('5C2185779AD12B6488F260E529DEE78E970C7061').shortId ==
            ['970C7061']
        when:
        key = new Key(stream('test-key-2.asc'))
        then:
        key.findAll('AE136750D165E6A4AACB1D092B04481E880A1469').shortId ==
            ['880A1469']
        key.findAll('1F62DF843110BACAE18B38DC6727B00AAFAFA3C5').shortId ==
            ['AFAFA3C5']
        key.findAll('66B9E5A5414E51C78F9B272AAFDB7B47BC3F6A4B').shortId ==
            ['BC3F6A4B']
    }

    def "empty key as string prints ring empty"() {
        when:
        def key = new Key()
        then:
        key.toString() == 'key empty'
    }

    def "as string prints each subkey on a separate line"() {
        when:
        def key = new Key(stream('test-key-2-pub.asc'))
        then:
        key.toString() == [
            [
                'pub v  880A1469 Test Key 2 <test-key-2@c02e.org>',
                'Test 2 (CODESurvey) <test-key-2@codesurvey.org>',
            ].join(', '),
            'pub e  AFAFA3C5',
            'pub v  BC3F6A4B',
        ].join('\n')
    }

    def "to public key just copies public parts of subkeys"() {
        setup:
        def key = new Key(stream('test-key-1.asc'), 'foo')
        key.signingUid = 'bar'
        when:
        def copy = key.toPublicKey()
        then:
        copy.toString() == [
            'pub v  013826C3 Test Key 1 <test-key-1@c02e.org>',
            'pub e  970C7061',
        ].join('\n')
        copy.subkeys.passphrase == ['', '']
        copy.signingUid == 'Test Key 1 <test-key-1@c02e.org>'
    }

    def "no subkeys sets no passphrase"() {
        setup: def key = new Key()
        when: key.passphrase = 'foo'
        then: key.subkeys == []
    }

    def "no subkeys has no uids"() {
        expect: new Key().uids == []
    }

    def "no subkeys has no signing uid"() {
        expect: new Key().signingUid == ""
    }

    def "no subkeys is not for signing"() {
        expect: !new Key().forSigning
    }

    def "no subkeys is not for verification"() {
        expect: !new Key().forVerification
    }

    def "no subkeys is not for encryption"() {
        expect: !new Key().forEncryption
    }

    def "no subkeys is not for decryption"() {
        expect: !new Key().forDecryption
    }

    def "no subkeys has no master"() {
        expect: new Key().master == null
    }

    def "no subkeys has no subkeys"() {
        expect: new Key().subkeys == []
    }

    def "to public key of no subkeys has no subkeys"() {
        expect: new Key().toPublicKey().subkeys == []
    }

    def "setting subkeys to null makes them an empty list"() {
        setup: def key = new Key()
        when: key.subkeys = null
        then: key.subkeys == []
    }

    def "loading empty keys raises an execption"() {
        when: new Key('')
        then: thrown PGPException
    }

    protected stream(s) {
        getClass().classLoader.getResourceAsStream s
    }

    protected file(s) {
        new File(getClass().classLoader.getResource(s).toURI())
    }
}
