package org.c02e.jpgpj

import spock.lang.Specification

class RingSpec extends Specification {

    def "load public ring"() {
        when:
        def ring = new Ring(stream('test-ring-pub.asc'))
        then:
        ring.keys.uids.flatten() == [
            'Test Key 1 <test-key-1@c02e.org>',
            'Test Key 2 <test-key-2@c02e.org>',
            'Test 2 (CODESurvey) <test-key-2@codesurvey.org>',
        ]
        ring.keys.subkeys.id.flatten() == [
            '0x72A423A0013826C3', '0x29DEE78E970C7061',
            '0x2B04481E880A1469', '0x6727B00AAFAFA3C5', '0xAFDB7B47BC3F6A4B',
        ]
        ring.keys.forSigning == [false, false]
        ring.keys.forVerification == [true, true]
        ring.keys.forEncryption == [true, true]
        ring.keys.forDecryption == [false, false]
    }

    def "load secret ring"() {
        when:
        def ring = new Ring(stream('test-ring.asc'))
        then:
        ring.keys.uids.flatten() == [
            'Test Key 1 <test-key-1@c02e.org>',
            'Test Key 2 <test-key-2@c02e.org>',
            'Test 2 (CODESurvey) <test-key-2@codesurvey.org>',
        ]
        ring.keys.subkeys.id.flatten() == [
            '0x72A423A0013826C3', '0x29DEE78E970C7061',
            '0x2B04481E880A1469', '0x6727B00AAFAFA3C5', '0xAFDB7B47BC3F6A4B',
        ]
        ring.keys.forSigning == [true, true]
        ring.keys.forVerification == [true, true]
        ring.keys.forEncryption == [true, true]
        ring.keys.forDecryption == [true, true]
    }

    def "load keybox ring"() {
        when:
        def ring = new Ring(stream('test-pubring.kbx'))
        then:
        ring.keys.uids.flatten() == [
            'Test Keybox 1 <test-kbx-1@c02e.org>',
            'Test Keybox 2 <test-kbx-2@c02e.org>',
            'Second Keybox (CODESurvey) <test-kbx-2@codesurvey.org>',
        ]
        ring.keys.subkeys.id.flatten() == [
            '0xD87CAD7157196947', '0x0077D401BA4995BA',
            '0x22B738768C6C48F8', '0x225B6180D44BFCEA', '0x96D1D02042CBE541',
        ]
        ring.keys.forSigning == [false, false]
        ring.keys.forVerification == [true, true]
        ring.keys.forEncryption == [true, true]
        ring.keys.forDecryption == [false, false]
    }

    def "load ring from file"() {
        when:
        def ring = new Ring(file('test-ring-pub.asc'))
        then:
        ring.keys.subkeys.id.flatten() == [
            '0x72A423A0013826C3', '0x29DEE78E970C7061',
            '0x2B04481E880A1469', '0x6727B00AAFAFA3C5', '0xAFDB7B47BC3F6A4B',
        ]
        !ring.signingKeys
        ring.verificationKeys.master.shortId == ['013826C3', '880A1469']
        ring.encryptionKeys.master.shortId == ['013826C3', '880A1469']
        !ring.decryptionKeys
    }

    def "load ring from string"() {
        when:
        def ring = new Ring(stream('test-ring-pub.asc').text)
        then:
        ring.keys.subkeys.id.flatten() == [
            '0x72A423A0013826C3', '0x29DEE78E970C7061',
            '0x2B04481E880A1469', '0x6727B00AAFAFA3C5', '0xAFDB7B47BC3F6A4B',
        ]
        !ring.signingKeys
        ring.verificationKeys.master.shortId == ['013826C3', '880A1469']
        ring.encryptionKeys.master.shortId == ['013826C3', '880A1469']
        !ring.decryptionKeys
    }

    def "find one key by id number"() {
        when:
        def ring = new Ring(file('test-ring-pub.asc'))
        then:
        !ring.findById(null)
        !ring.findById(0)
        !ring.findById(123)
        ring.findById(0x72A423A0013826C3L).master.shortId == '013826C3'
        ring.findById(0x29DEE78E970C7061L).master.shortId == '013826C3'
        ring.findById(0x2B04481E880A1469L).master.shortId == '880A1469'
        ring.findById(0x6727B00AAFAFA3C5L).master.shortId == '880A1469'
        !ring.findById(0xAFDB7B47L)
    }

    def "find key by id number"() {
        when:
        def ring = new Ring(file('test-ring-pub.asc'))
        // add second copy of key 1, including both public and private parts
        ring.load(file('test-key-1.asc'))
        then:
        !ring.findAll(0)
        !ring.findAll(123)
        !ring.findAll(0xAFDB7B47L)

        when:
        def key1s = ring.findAll(0x72A423A0013826C3L)
        def subkey1s = key1s*.findById(0x72A423A0013826C3L)
        then:
        subkey1s.shortId == ['013826C3', '013826C3']
        subkey1s.forSigning == [false, true]
        subkey1s.forVerification == [true, true]

        when:
        def key1e = ring.findAll(0x29DEE78E970C7061L)
        def subkey1e = key1e*.findById(0x29DEE78E970C7061L)
        then:
        subkey1e.shortId == ['970C7061', '970C7061']
        subkey1e.forEncryption == [true, true]
        subkey1e.forDecryption == [false, true]

        when:
        def key2s = ring.findAll(0x2B04481E880A1469L)
        def subkey2s = key2s*.findById(0x2B04481E880A1469L)
        then:
        subkey2s.shortId == ['880A1469']
        subkey2s.forSigning == [false]
        subkey2s.forVerification == [true]

        when:
        def key2e = ring.findAll(0x6727B00AAFAFA3C5L)
        def subkey2e = key2e*.findById(0x6727B00AAFAFA3C5L)
        then:
        subkey2e.shortId == ['AFAFA3C5']
        subkey2e.forEncryption == [true]
        subkey2e.forDecryption == [false]
    }

    def "find key by uid"() {
        when:
        def ring = new Ring(file('test-ring-pub.asc'))
        then:
        ring.findAll('').master.shortId == []
        ring.findAll('foo').master.shortId == []
        ring.findAll(~/foo/).master.shortId == []
        ring.findAll('test key').master.shortId == ['013826C3', '880A1469']
        ring.findAll('codesurvey').master.shortId == ['880A1469']
        ring.findAll(~/test-key.*@c02e/).master.shortId ==
            ['013826C3', '880A1469']
    }

    def "find key by short id"() {
        when:
        def ring = new Ring(file('test-ring-pub.asc'))
        then:
        ring.findAll('013826C3').master.shortId == ['013826C3']
        !ring.findAll('0x970C7061')
        ring.findAll('a').master.shortId == ['013826C3', '880A1469']
        ring.findAll('880A1469').master.shortId == ['880A1469']
        ring.findAll('AFAFA3C5').master.shortId == ['880A1469']
        ring.findAll('BC3F6A4B').master.shortId == ['880A1469']
        !ring.findAll('0x880A1469')
    }

    def "find key by long id"() {
        when:
        def ring = new Ring(file('test-ring-pub.asc'))
        then:
        ring.findAll('72A423A0013826C3').master.shortId == ['013826C3']
        ring.findAll('0x29DEE78E970C7061').master.shortId == ['013826C3']
        ring.findAll('0x2B04481E880A1469').master.shortId == ['880A1469']
        ring.findAll('6727B00AAFAFA3C5').master.shortId == ['880A1469']
        ring.findAll('AFDB7B47').master.shortId == ['880A1469']
    }

    def "find key by fingerprint"() {
        when:
        def ring = new Ring(file('test-ring-pub.asc'))
        then:
        !ring.findAll('B58A F7D0 AAD9 1E33 B15A  8062 72A4 23A0 0138 26C3')
        ring.findAll('5C2185779AD12B6488F260E529DEE78E970C7061').
            master.shortId == ['013826C3']
        ring.findAll('AE136750D165E6A4AACB1D092B04481E880A1469').
            master.shortId == ['880A1469']
        ring.findAll('1F62DF843110BACAE18B38DC6727B00AAFAFA3C5').
            master.shortId == ['880A1469']
        ring.findAll('66B9E5A5414E51C78F9B272AAFDB7B47BC3F6A4B').
            master.shortId == ['880A1469']
    }

    def "empty ring as string prints ring empty"() {
        when:
        def ring = new Ring()
        then:
        ring.toString() == 'ring empty'
    }

    def "as string prints each key on a separate line"() {
        when:
        def ring = new Ring(file('test-ring.asc'))
        then:
        ring.toString() == '''
sec vs 013826C3 Test Key 1 <test-key-1@c02e.org>
sec ed 970C7061

sec v  880A1469 Test Key 2 <test-key-2@c02e.org>, Test 2 (CODESurvey) <test-key-2@codesurvey.org>
sec ed AFAFA3C5
sec vs BC3F6A4B
        '''.trim()
    }

    protected stream(s) {
        getClass().classLoader.getResourceAsStream s
    }

    protected file(s) {
        new File(getClass().classLoader.getResource(s).toURI())
    }
}
