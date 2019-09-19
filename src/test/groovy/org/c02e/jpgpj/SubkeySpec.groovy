package org.c02e.jpgpj

import spock.lang.Specification

class SubkeySpec extends Specification {

    def "public key formats fingerprint"() {
        when:
        def key = new Key(stream('test-key-2-pub.asc'))
        then:
        key.subkeys.fingerprint == [
            'AE136750D165E6A4AACB1D092B04481E880A1469',
            '1F62DF843110BACAE18B38DC6727B00AAFAFA3C5',
            '66B9E5A5414E51C78F9B272AAFDB7B47BC3F6A4B',
        ]
    }

    def "secret key formats fingerprint"() {
        when:
        def key = new Key(stream('test-key-2.asc'))
        then:
        key.subkeys.fingerprint == [
            'AE136750D165E6A4AACB1D092B04481E880A1469',
            '1F62DF843110BACAE18B38DC6727B00AAFAFA3C5',
            '66B9E5A5414E51C78F9B272AAFDB7B47BC3F6A4B',
        ]
    }

    def "public key formats id"() {
        when:
        def key = new Key(stream('test-key-2-pub.asc'))
        then:
        key.subkeys.id == [
            '0x2B04481E880A1469', '0x6727B00AAFAFA3C5', '0xAFDB7B47BC3F6A4B',
        ]
    }

    def "secret key formats id"() {
        when:
        def key = new Key(stream('test-key-2.asc'))
        then:
        key.subkeys.id == [
            '0x2B04481E880A1469', '0x6727B00AAFAFA3C5', '0xAFDB7B47BC3F6A4B',
        ]
    }

    def "public key formats shortId"() {
        when:
        def key = new Key(stream('test-key-2-pub.asc'))
        then:
        key.subkeys.shortId == ['880A1469', 'AFAFA3C5', 'BC3F6A4B']
    }

    def "secret key formats shortId"() {
        when:
        def key = new Key(stream('test-key-2.asc'))
        then:
        key.subkeys.shortId == ['880A1469', 'AFAFA3C5', 'BC3F6A4B']
    }

    def "public key lists uids for master"() {
        when:
        def key = new Key(stream('test-key-2-pub.asc'))
        then:
        key.subkeys.uids == [ [
            'Test Key 2 <test-key-2@c02e.org>',
            'Test 2 (CODESurvey) <test-key-2@codesurvey.org>',
        ], [], [], ]
    }

    def "secret key lists uids for master"() {
        when:
        def key = new Key(stream('test-key-2.asc'))
        then:
        key.subkeys.uids == [ [
            'Test Key 2 <test-key-2@c02e.org>',
            'Test 2 (CODESurvey) <test-key-2@codesurvey.org>',
        ], [], [], ]
    }

    def "public key matches master subkey by uid"() {
        when:
        def key = new Key(stream('test-key-2-pub.asc'))
        then:
        key.subkeys*.matches('') == [false, false, false]
        key.subkeys*.matches('foo') == [false, false, false]
        key.subkeys*.matches('test key') == [true, false, false]
        key.subkeys*.matches('codesurvey') == [true, false, false]
        key.subkeys*.matches(~/test-key.*@c02e/) == [true, false, false]
    }

    def "secret key matches master subkey by uid"() {
        when:
        def key = new Key(stream('test-key-2.asc'))
        then:
        key.subkeys*.matches('') == [false, false, false]
        key.subkeys*.matches('foo') == [false, false, false]
        key.subkeys*.matches('test key') == [true, false, false]
        key.subkeys*.matches('codesurvey') == [true, false, false]
        key.subkeys*.matches(~/test-key.*@c02e/) == [true, false, false]
    }

    def "public key matches by short id"() {
        when:
        def key = new Key(stream('test-key-2-pub.asc'))
        then:
        key.subkeys*.matches('a') == [true, true, true]
        key.subkeys*.matches('880A1469') == [true, false, false]
        key.subkeys*.matches('AFAFA3C5') == [false, true, false]
        key.subkeys*.matches('BC3F6A4B') == [false, false, true]
        key.subkeys*.matches('0x880A1469') == [false, false, false]
    }

    def "secret key matches by short id"() {
        when:
        def key = new Key(stream('test-key-2.asc'))
        then:
        key.subkeys*.matches('a') == [true, true, true]
        key.subkeys*.matches('880A1469') == [true, false, false]
        key.subkeys*.matches('AFAFA3C5') == [false, true, false]
        key.subkeys*.matches('BC3F6A4B') == [false, false, true]
        key.subkeys*.matches('0x880A1469') == [false, false, false]
    }

    def "public key matches by long id"() {
        when:
        def key = new Key(stream('test-key-2-pub.asc'))
        then:
        key.subkeys*.matches('a') == [true, true, true]
        key.subkeys*.matches('0x2B04481E880A1469') == [true, false, false]
        key.subkeys*.matches('0x6727B00AAFAFA3C5') == [false, true, false]
        key.subkeys*.matches('0xAFDB7B47BC3F6A4B') == [false, false, true]
        key.subkeys*.matches('2B04481E880A1469') == [true, false, false]
    }

    def "secret key matches by long id"() {
        when:
        def key = new Key(stream('test-key-2.asc'))
        then:
        key.subkeys*.matches('a') == [true, true, true]
        key.subkeys*.matches('0x2B04481E880A1469') == [true, false, false]
        key.subkeys*.matches('0x6727B00AAFAFA3C5') == [false, true, false]
        key.subkeys*.matches('0xAFDB7B47BC3F6A4B') == [false, false, true]
        key.subkeys*.matches('2B04481E880A1469') == [true, false, false]
    }

    def "public key matches by fingerprint"() {
        when:
        def key = new Key(stream('test-key-2-pub.asc'))
        then:
        key.subkeys*.matches('a') == [true, true, true]
        key.subkeys*.matches('AE136750D165E6A4AACB1D092B04481E880A1469') == [true, false, false]
        key.subkeys*.matches('1F62DF843110BACAE18B38DC6727B00AAFAFA3C5') == [false, true, false]
        key.subkeys*.matches('66B9E5A5414E51C78F9B272AAFDB7B47BC3F6A4B') == [false, false, true]
        key.subkeys*.matches('0xAE136750D165E6A4AACB1D092B04481E880A1469') == [false, false, false]
    }

    def "secret key matches by fingerprint"() {
        when:
        def key = new Key(stream('test-key-2.asc'))
        then:
        key.subkeys*.matches('a') == [true, true, true]
        key.subkeys*.matches('AE136750D165E6A4AACB1D092B04481E880A1469') == [true, false, false]
        key.subkeys*.matches('1F62DF843110BACAE18B38DC6727B00AAFAFA3C5') == [false, true, false]
        key.subkeys*.matches('66B9E5A5414E51C78F9B272AAFDB7B47BC3F6A4B') == [false, false, true]
        key.subkeys*.matches('0xAE136750D165E6A4AACB1D092B04481E880A1469') == [false, false, false]
    }

    def "basic public key can be used only for verification and encryption"() {
        when:
        def key = new Key(stream('test-key-1-pub.asc'))
        then:
        key.subkeys.forSigning == [false, false]
        key.subkeys.forVerification == [true, false]
        key.subkeys.forEncryption == [false, true]
        key.subkeys.forDecryption == [false, false]
    }

    def "basic secret key can be used for anything"() {
        when:
        def key = new Key(stream('test-key-1.asc'))
        then:
        key.subkeys.forSigning == [true, false]
        key.subkeys.forVerification == [true, false]
        key.subkeys.forEncryption == [false, true]
        key.subkeys.forDecryption == [false, true]
    }

    def "enhanced public key has extra signing subkey for verification"() {
        when:
        def key = new Key(stream('test-key-2-pub.asc'))
        then:
        key.subkeys.forSigning == [false, false, false]
        key.subkeys.forVerification == [true, false, true]
        key.subkeys.forEncryption == [false, true, false]
        key.subkeys.forDecryption == [false, false, false]
    }

    def "enhanced secret key has extra signing subkey but no master private key"() {
        when:
        def key = new Key(stream('test-key-2.asc'))
        then:
        key.subkeys.forSigning == [false, false, true]
        key.subkeys.forVerification == [true, false, true]
        key.subkeys.forEncryption == [false, true, false]
        key.subkeys.forDecryption == [false, true, false]
    }

    def "secret key with no usage flags not used for anything by default"() {
        when:
        def key = new Key(stream('test-no-usage-3-subkeys.asc'))
        then:
        key.subkeys.forSigning == [false, false, false]
        key.subkeys.forVerification == [false, false, false]
        key.subkeys.forEncryption == [false, false, false]
        key.subkeys.forDecryption == [false, false, false]
    }

    def "rsa public key is technically usable for verification and encryption"() {
        when:
        def key = new Key(stream('test-key-2-pub.asc'))
        then:
        key.subkeys.usableForSigning == [false, false, false]
        key.subkeys.usableForVerification == [true, true, true]
        key.subkeys.usableForEncryption == [true, true, true]
        key.subkeys.usableForDecryption == [false, false, false]
    }

    def "rsa secret key is technically usable for all usages"() {
        when:
        def key = new Key(stream('test-key-2-master.asc'))
        then:
        key.subkeys.usableForSigning == [true, true, true]
        key.subkeys.usableForVerification == [true, true, true]
        key.subkeys.usableForEncryption == [true, true, true]
        key.subkeys.usableForDecryption == [true, true, true]
    }

    def "rsa secret key with no flags is technically usable for all usages"() {
        when:
        def key = new Key(stream('test-no-usage-3-subkeys.asc'))
        then:
        key.subkeys.usableForSigning == [true, true, true]
        key.subkeys.usableForVerification == [true, true, true]
        key.subkeys.usableForEncryption == [true, true, true]
        key.subkeys.usableForDecryption == [true, true, true]
    }

    def "ec secret key is technically usable only for e/d or v/s"() {
        when:
        // first 2 subkeys of this key are ecdsa (verification/signing)
        // and 3rd subkey is ecdh (encryption/decryption)
        def key = new Key(stream('test-no-usage-ec-subkeys.asc'))
        then:
        key.subkeys.usableForSigning == [true, true, false]
        key.subkeys.usableForVerification == [true, true, false]
        key.subkeys.usableForEncryption == [false, false, true]
        key.subkeys.usableForDecryption == [false, false, true]
    }

    def "extract private key"() {
        when:
        def key = new Key(stream('test-key-2.asc'), 'c02e')
        then:
        key.subkeys.privateKey*.asBoolean() == [null, true, true]
        key.subkeys.unlocked == [false, true, true]
    }

    def "extract private key with char array passphrase"() {
        when:
        def passphrase = 'c02e' as char[]
        def key = new Key(stream('test-key-2.asc'), passphrase)
        then:
        key.subkeys.privateKey*.asBoolean() == [null, true, true]
        key.subkeys.unlocked == [false, true, true]

        when: "original char[] is updated"
        passphrase[0] = 'x'
        then: "subkeys are shown to use original char[], not a copy"
        key.subkeys.passphraseChars == (1..3).collect { 'x02e' as char[] }
        key.subkeys.passphrase == ['x02e', 'x02e', 'x02e']
    }

    def "cannot extract private key from public key"() {
        when:
        def key = new Key(stream('test-key-2-pub.asc'), 'c02e')
        then:
        key.subkeys.privateKey*.asBoolean() == [null, null, null]
        key.subkeys.unlocked == [false, false, false]
    }

    def "cannot extract private key without correct passphrase"() {
        when:
        def key = new Key(stream('test-key-1.asc'))
        key.subkeys.privateKey
        then:
        def e = thrown(PassphraseException)
        e.message == [
            'incorrect passphrase for subkey',
            'sec vs 013826C3 Test Key 1 <test-key-1@c02e.org>',
        ].join(' ')
    }

    def "unlock private key without caching passphrase"() {
        when:
        def key = new Key(stream('test-key-2.asc'))
        key.subkeys*.unlock('c02e' as char[])
        then:
        key.subkeys.privateKey*.asBoolean() == [null, true, true]
        key.subkeys.unlocked == [false, true, true]
        key.subkeys.passphraseChars == (1..3).collect { [] as char[] }
    }

    def "clear secrets zeros passphrase and releases private key"() {
        when:
        def passphrase = 'c02e' as char[]
        def key = new Key(stream('test-key-2.asc'), passphrase)
        then:
        key.subkeys.privateKey*.asBoolean() == [null, true, true]
        key.subkeys.unlocked == [false, true, true]

        when:
        key.subkeys*.clearSecrets()
        then:
        passphrase == [0, 0, 0, 0] as char[]
        key.subkeys.unlocked == [false, false, false]
        key.subkeys.passphraseChars == (1..3).collect { [] as char[] }
        key.subkeys.passphrase == ['', '', '']
    }

    def "empty subkey as string prints nul"() {
        when:
        def subkey = new Subkey()
        then:
        subkey.toString() == 'nul'
    }

    def "public key as string"() {
        when:
        def key = new Key(stream('test-key-2-pub.asc'))
        then:
        key.subkeys*.toString() == [
            [
                'pub v  880A1469 Test Key 2 <test-key-2@c02e.org>',
                'Test 2 (CODESurvey) <test-key-2@codesurvey.org>',
            ].join(', '),
            'pub e  AFAFA3C5',
            'pub v  BC3F6A4B',
        ]
    }

    def "secret key without passphrase as string"() {
        when:
        def key = new Key(stream('test-key-2.asc'))
        then:
        key.subkeys*.toString() == [
            [
                'sec v  880A1469 Test Key 2 <test-key-2@c02e.org>',
                'Test 2 (CODESurvey) <test-key-2@codesurvey.org>',
            ].join(', '),
            'sec ed AFAFA3C5',
            'sec vs BC3F6A4B',
        ]
    }

    def "secret key with passphrase as string"() {
        when:
        def key = new Key(stream('test-key-2.asc'), 'c02e')
        then:
        key.subkeys*.toString() == [
            [
                'sec+v  880A1469 Test Key 2 <test-key-2@c02e.org>',
                'Test 2 (CODESurvey) <test-key-2@codesurvey.org>',
            ].join(', '),
            'sec+ed AFAFA3C5',
            'sec+vs BC3F6A4B',
        ]
    }

    protected stream(s) {
        getClass().classLoader.getResourceAsStream s
    }
}
