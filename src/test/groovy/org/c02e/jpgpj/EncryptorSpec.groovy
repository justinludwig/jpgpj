package org.c02e.jpgpj

import org.c02e.jpgpj.key.KeyForDecryption
import org.c02e.jpgpj.key.KeyForEncryption
import org.c02e.jpgpj.key.KeyForSigning
import org.c02e.jpgpj.key.KeyForVerification
import org.bouncycastle.openpgp.PGPException
import spock.lang.Specification

class EncryptorSpec extends Specification {
    def cipherOut = new ByteArrayOutputStream()
    def plainOut = new ByteArrayOutputStream()

    def "literal only"() {
        when:
        def encryptor = new Encryptor();
        encryptor.compressionAlgorithm = CompressionAlgorithm.Uncompressed
        encryptor.encryptionAlgorithm = EncryptionAlgorithm.Unencrypted
        encryptor.signingAlgorithm = HashingAlgorithm.Unsigned
        encryptor.encrypt plainIn, cipherOut

        def decryptor = new Decryptor()
        decryptor.verificationRequired = false
        def meta = decryptor.decrypt(cipherIn, plainOut)

        then:
        plainOut.toString() == plainText
        meta.name == ''
        meta.length == plainText.length()
        meta.lastModified == 0
        meta.format == FileMetadata.Format.BINARY
        !meta.verified
    }

    def "compress only"() {
        when:
        def encryptor = new Encryptor();
        encryptor.encryptionAlgorithm = EncryptionAlgorithm.Unencrypted
        encryptor.signingAlgorithm = HashingAlgorithm.Unsigned
        encryptor.encrypt plainIn, cipherOut

        def decryptor = new Decryptor()
        decryptor.verificationRequired = false
        decryptor.decrypt cipherIn, plainOut

        then:
        plainOut.toString() == plainText
    }

    def "encrypt without signing"() {
        when:
        def encryptor = new Encryptor(new Ring(stream('test-key-1-pub.asc')))
        encryptor.signingAlgorithm = HashingAlgorithm.Unsigned
        encryptor.encrypt plainIn, cipherOut

        def decryptor = new Decryptor(new Ring(stream('test-ring.asc')))
        decryptor.ring.keys*.passphrase = 'c02e'
        decryptor.verificationRequired = false
        decryptor.decrypt cipherIn, plainOut

        then:
        plainOut.toString() == plainText
    }

    def "encrypt without compression or signing"() {
        when:
        def encryptor = new Encryptor(new Ring(stream('test-key-1-pub.asc')))
        encryptor.compressionAlgorithm = CompressionAlgorithm.Uncompressed
        encryptor.signingAlgorithm = HashingAlgorithm.Unsigned
        encryptor.encrypt plainIn, cipherOut

        def decryptor = new Decryptor(new Ring(stream('test-ring.asc')))
        decryptor.ring.keys*.passphrase = 'c02e'
        decryptor.verificationRequired = false
        decryptor.decrypt cipherIn, plainOut

        then:
        plainOut.toString() == plainText
    }

    def "encrypt without encryption keys"() {
        when:
        def encryptor = new Encryptor()
        encryptor.signingAlgorithm = HashingAlgorithm.Unsigned
        encryptor.encrypt plainIn, cipherOut
        then:
        def e = thrown(PGPException)
        e.message == 'no suitable encryption key found'
    }

    def "encrypt symmetric without signing"() {
        when:
        def encryptor = new Encryptor()
        encryptor.signingAlgorithm = HashingAlgorithm.Unsigned
        encryptor.symmetricPassphrase = 'c02e'
        encryptor.keyDerivationWorkFactor = 10
        encryptor.encrypt plainIn, cipherOut

        def decryptor = new Decryptor()
        decryptor.symmetricPassphrase = 'c02e'
        decryptor.verificationRequired = false
        decryptor.decrypt cipherIn, plainOut

        then:
        plainOut.toString() == plainText
    }

    def "encrypt with multiple keys"() {
        when:
        def encryptor = new Encryptor(new Ring(stream('test-ring-pub.asc')))
        encryptor.signingAlgorithm = HashingAlgorithm.Unsigned
        encryptor.symmetricPassphrase = 'c02e'
        encryptor.keyDerivationWorkFactor = 10
        encryptor.encrypt plainIn, cipherOut

        // decrypt with key 1
        def decryptor = new Decryptor(new Ring(stream('test-key-1.asc')))
        decryptor.ring.keys*.passphrase = 'c02e'
        decryptor.verificationRequired = false
        decryptor.decrypt cipherIn, plainOut

        then:
        plainOut.toString() == plainText

        when:
        plainOut = new ByteArrayOutputStream()

        // decrypt with key 2
        decryptor = new Decryptor(new Ring(stream('test-key-2.asc')))
        decryptor.ring.keys*.passphrase = 'c02e'
        decryptor.verificationRequired = false
        decryptor.decrypt cipherIn, plainOut

        then:
        plainOut.toString() == plainText

        when:
        plainOut = new ByteArrayOutputStream()

        // decrypt with symmetric key
        decryptor = new Decryptor()
        decryptor.symmetricPassphrase = 'c02e'
        decryptor.verificationRequired = false
        decryptor.decrypt cipherIn, plainOut

        then:
        plainOut.toString() == plainText
    }

    def "sign without compressing or encrypting"() {
        when:
        def encryptor = new Encryptor(new Ring(stream('test-key-1.asc')))
        encryptor.compressionAlgorithm = CompressionAlgorithm.Uncompressed
        encryptor.encryptionAlgorithm = EncryptionAlgorithm.Unencrypted
        encryptor.ring.keys*.passphrase = 'c02e'
        encryptor.encrypt plainIn, cipherOut

        def decryptor = new Decryptor(new Ring(stream('test-key-1-pub.asc')))
        decryptor.decrypt cipherIn, plainOut

        then:
        plainOut.toString() == plainText
    }

    def "sign without encrypting"() {
        when:
        def encryptor = new Encryptor(new Ring(stream('test-key-1.asc')))
        encryptor.encryptionAlgorithm = EncryptionAlgorithm.Unencrypted
        encryptor.ring.keys*.passphrase = 'c02e'
        encryptor.encrypt plainIn, cipherOut

        def decryptor = new Decryptor(new Ring(stream('test-key-1-pub.asc')))
        decryptor.decrypt cipherIn, plainOut

        then:
        plainOut.toString() == plainText
    }

    def "sign without signing keys"() {
        when:
        def encryptor = new Encryptor()
        encryptor.encryptionAlgorithm = EncryptionAlgorithm.Unencrypted
        encryptor.encrypt plainIn, cipherOut

        then:
        def e = thrown(PGPException)
        e.message == 'no suitable signing key found'
    }

    def "sign without passphrase"() {
        when:
        def encryptor = new Encryptor(new Ring(stream('test-key-1.asc')))
        encryptor.encryptionAlgorithm = EncryptionAlgorithm.Unencrypted
        encryptor.encrypt plainIn, cipherOut

        then:
        def e = thrown(PGPException)
        e.message == 'no suitable signing key found'
    }

    def "sign with wrong passphrase"() {
        when:
        def encryptor = new Encryptor(new Ring(stream('test-key-1.asc')))
        encryptor.encryptionAlgorithm = EncryptionAlgorithm.Unencrypted
        encryptor.ring.keys*.passphrase = 'wrong!'
        encryptor.encrypt plainIn, cipherOut

        then:
        def e = thrown(PassphraseException)
        e.message == [
            'incorrect passphrase for subkey',
            'sec+vs 013826C3 Test Key 1 <test-key-1@c02e.org>',
        ].join(' ')
    }

    def "encrypt and sign with same key"() {
        when:
        def encryptor = new Encryptor(new Ring(stream('test-key-1.asc')))
        encryptor.ring.keys*.passphrase = 'c02e'
        encryptor.encrypt plainIn, cipherOut

        def decryptor = new Decryptor(new Ring(stream('test-key-1.asc')))
        decryptor.ring.keys*.passphrase = 'c02e'
        def meta = decryptor.decrypt(cipherIn, plainOut)

        then:
        plainOut.toString() == plainText

        meta.name == ''
        meta.length == plainText.length()
        meta.lastModified == 0
        meta.format == FileMetadata.Format.BINARY

        meta.verified
        meta.verified.keys.uids == [['Test Key 1 <test-key-1@c02e.org>']]
        meta.verified.keys.signingUid == ['Test Key 1 <test-key-1@c02e.org>']
    }

    def "encrypt and sign with ascii armor"() {
        when:
        def encryptor = new Encryptor(new Ring(stream('test-key-1.asc')))
        encryptor.asciiArmored = true
        encryptor.ring.keys*.passphrase = 'c02e'
        encryptor.encrypt plainIn, cipherOut
        //new File('build/test.gpg').withOutputStream { it << cipherOut.toByteArray() }

        def decryptor = new Decryptor(new Ring(stream('test-key-1.asc')))
        decryptor.ring.keys*.passphrase = 'c02e'
        decryptor.decrypt cipherIn, plainOut

        then:
        plainOut.toString() == plainText
        cipherOut.toString().
            replaceFirst(/(?m)^(hQEMAyne546XDHBhAQ)[\w\+\/\n]+[\w\+\/]={0,2}/, '$1...').
            replaceFirst(/(?m)^=[\w\+\/]+/, '=1234') == '''
-----BEGIN PGP MESSAGE-----
Version: BCPG v1.63

hQEMAyne546XDHBhAQ...
=1234
-----END PGP MESSAGE-----
        '''.trim() + '\n'
    }

    def "encrypt and sign file"() {
        when:
        def encryptor = new Encryptor(new Key(file('test-key-1.asc'), 'c02e'))
        def plainFile = getTestFile(plainText), cipherFile = testFile
        encryptor.encrypt plainFile, cipherFile

        def decryptor = new Decryptor(new Key(file('test-key-1.asc'), 'c02e'))
        def resultFile = testFile
        def meta = decryptor.decrypt(cipherFile, resultFile)

        then:
        resultFile.text == plainText

        meta.name == plainFile.name
        meta.length == plainText.length()
        // milliseconds are not preserved
        (meta.lastModified / 1000L) == (long) (plainFile.lastModified() / 1000L)
        meta.format == FileMetadata.Format.BINARY

        meta.verified
    }

    def "use encryption file stream wrapper"() {
        when:
        def encryptor = new Encryptor(new Key(file('test-key-1.asc'), 'c02e'))
        def plainFile = getTestFile(plainText), cipherFile = testFile
        def wrapperStream = encryptor.prepareCiphertextOutputStream(new FileMetadata(plainFile), cipherFile)
        try {
            def plainStream = new FileInputStream(plainFile)
            try {
                byte[] buf = new byte[0x1000]
                int numRead = plainStream.read(buf)
                while (numRead != -1) {
                    wrapperStream.write(buf, 0, numRead)
                    numRead = plainStream.read(buf)
                }
            } finally {
                plainStream.close()
            }
        } finally {
            wrapperStream.close()
        }

        def decryptor = new Decryptor(new Key(file('test-key-1.asc'), 'c02e'))
        def resultFile = testFile
        def meta = decryptor.decrypt(cipherFile, resultFile)

        then:
        resultFile.text == plainText

        meta.name == plainFile.name
        meta.length == plainText.length()
        // milliseconds are not preserved
        (meta.lastModified / 1000L) == (long) (plainFile.lastModified() / 1000L)
        meta.format == FileMetadata.Format.BINARY

        meta.verified
    }
    def "encrypt and sign zero-byte file"() {
        when:
        def encryptor = new Encryptor(new Key(file('test-key-1.asc'), 'c02e'))
        def plainFile = testFile, cipherFile = testFile
        encryptor.encrypt plainFile, cipherFile

        def decryptor = new Decryptor(new Key(file('test-key-1.asc'), 'c02e'))
        def resultFile = testFile
        def meta = decryptor.decrypt(cipherFile, resultFile)

        then:
        resultFile.length() == 0
        meta.length == 0
        meta.verified
    }

    def "encrypt and sign file without passphrase"() {
        when:
        def encryptor = new Encryptor(new Key(file('test-key-1.asc')))
        def plainFile = getTestFile(plainText), cipherFile = getTestFile('foo')
        encryptor.encrypt plainFile, cipherFile
        then:
        def e = thrown(PGPException)
        e.message == 'no suitable signing key found'
        !cipherFile.exists()
    }

    def "encrypt and sign same file"() {
        when:
        def encryptor = new Encryptor(new Key(file('test-key-1.asc'), 'c02e'))
        def plainFile = getTestFile(plainText)
        encryptor.encrypt plainFile, plainFile
        then:
        thrown IOException
        plainFile.text == plainText
    }

    def "encrypt and sign without compression"() {
        when:
        def encryptor = new Encryptor(new Ring(stream('test-key-1.asc')))
        encryptor.compressionAlgorithm = CompressionAlgorithm.Uncompressed
        encryptor.ring.keys*.passphrase = 'c02e'
        encryptor.encrypt plainIn, cipherOut

        def decryptor = new Decryptor(new Ring(stream('test-key-1.asc')))
        decryptor.ring.keys*.passphrase = 'c02e'
        decryptor.decrypt cipherIn, plainOut

        then:
        plainOut.toString() == plainText
    }

    def "sign with last signing subkey by default"() {
        when:
        def encryptor = new Encryptor(new Ring(stream('test-key-2-master.asc')))
        encryptor.ring.keys*.passphrase = 'c02e'
        encryptor.encrypt plainIn, cipherOut

        def decryptor = new Decryptor(new Ring(stream('test-key-2-master.asc')))
        decryptor.ring.keys*.verification.findAll {
            it.shortId != 'BC3F6A4B'
        }*.forVerification = false
        decryptor.ring.keys*.passphrase = 'c02e'
        def meta = decryptor.decrypt(cipherIn, plainOut)

        then:
        plainOut.toString() == plainText
        meta.verified.keys.signingUid == ['Test Key 2 <test-key-2@c02e.org>']
    }

    def "allow signing with non-default subkey"() {
        when:
        def encryptor = new Encryptor(new Ring(stream('test-key-2-master.asc')))
        encryptor.ring.keys*.signing.findAll {
            it.shortId != '880A1469'
        }*.forSigning = false
        encryptor.ring.keys*.passphrase = 'c02e'
        encryptor.encrypt plainIn, cipherOut

        def decryptor = new Decryptor(new Ring(stream('test-key-2-master.asc')))
        decryptor.ring.keys*.passphrase = 'c02e'
        def meta = decryptor.decrypt(cipherIn, plainOut)

        then:
        plainOut.toString() == plainText
        meta.verified.keys.signingUid == ['Test Key 2 <test-key-2@c02e.org>']
    }

    def "encrypt and sign with different keys"() {
        when:
        def encryptor = new Encryptor(new Ring(stream('test-ring.asc')))
        encryptor.ring.findAll('key-1')*.signing*.forSigning = false
        encryptor.ring.findAll('key-2')*.encryption*.forEncryption = false
        encryptor.ring.findAll('key-2')*.passphrase = 'c02e'
        encryptor.encrypt plainIn, cipherOut

        def decryptor = new Decryptor(new Ring(stream('test-ring.asc')))
        decryptor.ring.findAll('key-1')*.passphrase = 'c02e'
        def meta = decryptor.decrypt(cipherIn, plainOut)

        then:
        plainOut.toString() == plainText
        meta.verified.keys.uids.flatten() == [
            'Test Key 2 <test-key-2@c02e.org>',
            'Test 2 (CODESurvey) <test-key-2@codesurvey.org>',
        ]
        meta.verified.keys.signingUid == ['Test Key 2 <test-key-2@c02e.org>']
    }

    def "encrypt and sign with multiple keys"() {
        when:
        def encryptor = new Encryptor(new Ring(stream('test-ring.asc')))
        encryptor.ring.keys*.passphrase = 'c02e'
        encryptor.symmetricPassphrase = 'c02e'
        encryptor.keyDerivationWorkFactor = 10
        encryptor.encrypt plainIn, cipherOut

        // decrypt with key 1
        def decryptor = new Decryptor(new Ring(stream('test-ring.asc')))
        decryptor.ring.findAll('key-1')*.passphrase = 'c02e'
        encryptor.ring.findAll('key-2')*.encryption*.forDecryption = false
        def meta = decryptor.decrypt(cipherIn, plainOut)

        then:
        plainOut.toString() == plainText
        meta.verified.keys.uids.flatten() == [
            'Test Key 1 <test-key-1@c02e.org>',
            'Test Key 2 <test-key-2@c02e.org>',
            'Test 2 (CODESurvey) <test-key-2@codesurvey.org>',
        ]
        meta.verified.keys.signingUid == [
            'Test Key 1 <test-key-1@c02e.org>',
            'Test Key 2 <test-key-2@c02e.org>',
        ]

        when:
        plainOut = new ByteArrayOutputStream()

        // decrypt with key 2
        decryptor = new Decryptor(new Ring(stream('test-ring.asc')))
        encryptor.ring.findAll('key-1')*.encryption*.forDecryption = false
        decryptor.ring.findAll('key-2')*.passphrase = 'c02e'
        meta = decryptor.decrypt(cipherIn, plainOut)

        then:
        plainOut.toString() == plainText
        meta.verified.keys.uids.flatten() == [
            'Test Key 1 <test-key-1@c02e.org>',
            'Test Key 2 <test-key-2@c02e.org>',
            'Test 2 (CODESurvey) <test-key-2@codesurvey.org>',
        ]
        meta.verified.keys.signingUid == [
            'Test Key 1 <test-key-1@c02e.org>',
            'Test Key 2 <test-key-2@c02e.org>',
        ]

        when:
        plainOut = new ByteArrayOutputStream()

        // decrypt with symmetric key
        decryptor = new Decryptor(new Ring(stream('test-key-2-pub.asc')))
        decryptor.symmetricPassphrase = 'c02e'
        meta = decryptor.decrypt(cipherIn, plainOut)

        then:
        plainOut.toString() == plainText
        // only key 2 was verified
        meta.verified.keys.uids.flatten() == [
            'Test Key 2 <test-key-2@c02e.org>',
            'Test 2 (CODESurvey) <test-key-2@codesurvey.org>',
        ]
        meta.verified.keys.signingUid == ['Test Key 2 <test-key-2@c02e.org>']
    }

    def "encrypt symmetric and clear passphrase"() {
        when:
        def passphrase = 'c02e' as char[]
        def encryptor = new Encryptor()
        encryptor.signingAlgorithm = HashingAlgorithm.Unsigned
        encryptor.symmetricPassphraseChars = passphrase
        encryptor.keyDerivationWorkFactor = 10
        encryptor.encrypt plainIn, cipherOut

        def decryptor = new Decryptor()
        decryptor.symmetricPassphrase = 'c02e'
        decryptor.verificationRequired = false
        decryptor.decrypt cipherIn, plainOut

        then:
        plainOut.toString() == plainText

        when: "original char[] is updated"
        passphrase[0] = 'x'
        then: "encryptor is shown to use original char[], not a copy"
        encryptor.symmetricPassphraseChars[0] == 'x'

        when:
        encryptor.clearSecrets()
        then:
        passphrase == [0, 0, 0, 0] as char[]
        encryptor.symmetricPassphraseChars == [] as char[]
        encryptor.symmetricPassphrase == ''

        when:
        encryptor.encrypt plainIn, cipherOut
        then:
        def e = thrown(PGPException)
        e.message == 'no suitable encryption key found'
    }

    def "encrypt and sign and clear secrets"() {
        when:
        def passphrase = 'c02e' as char[]
        def key = new Key(file('test-key-1.asc'), passphrase)
        def encryptor = new Encryptor(key)
        encryptor.encrypt plainIn, cipherOut

        def decryptor = new Decryptor(key)
        def meta = decryptor.decrypt(cipherIn, plainOut)

        then:
        plainOut.toString() == plainText
        meta.verified

        when:
        encryptor.clearSecrets()
        def subkeys = encryptor.ring.keys.subkeys.flatten()
        then:
        passphrase == [0, 0, 0, 0] as char[]
        subkeys.unlocked == [false, false]
        subkeys.passphraseChars == (1..2).collect { [] as char[] }
        subkeys.passphrase == ['', '']

        when:
        encryptor.encrypt plainIn, cipherOut
        then:
        def e = thrown(PGPException)
        e.message == 'no suitable signing key found'
    }

    def "sign without caching passphrase"() {
        when:
        def encryptor = new Encryptor(new Ring(stream('test-key-1.asc')))
        encryptor.encryptionAlgorithm = EncryptionAlgorithm.Unencrypted
        // unlock just key 1 signing subkey
        encryptor.ring.keys.subkeys.flatten().find {
            it.shortId == '013826C3'
        }.unlock('c02e' as char[])
        encryptor.encrypt plainIn, cipherOut

        def decryptor = new Decryptor(new Ring(stream('test-key-1-pub.asc')))
        decryptor.decrypt cipherIn, plainOut

        then:
        plainOut.toString() == plainText

        when: "subkeys inspected"
        def subkeys = encryptor.ring.keys.subkeys.flatten()
        then: "only 1st subkey of key is 1 unlocked, and no passphrases cached"
        subkeys.unlocked == [true, false]
        subkeys.passphraseChars == (1..2).collect { [] as char[] }
        subkeys.passphrase == ['', '']
    }

    def "encrypt and sign with a specific uid"() {
        when:
        def encryptor = new Encryptor(new Ring(stream('test-key-2.asc')))
        encryptor.ring.keys*.passphrase = 'c02e'
        encryptor.ring.keys*.signingUid = 'foo'
        encryptor.encrypt plainIn, cipherOut

        def decryptor = new Decryptor(new Ring(stream('test-key-2.asc')))
        decryptor.ring.keys*.passphrase = 'c02e'
        def meta = decryptor.decrypt(cipherIn, plainOut)

        then:
        plainOut.toString() == plainText
        meta.verified.keys.uids.flatten() == [
            'Test Key 2 <test-key-2@c02e.org>',
            'Test 2 (CODESurvey) <test-key-2@codesurvey.org>',
        ]
        meta.verified.keys.signingUid == ['foo']
    }

    def "encrypt without signing with metadata"() {
        when:
        def src = new FileMetadata(
            'test.txt', FileMetadata.Format.BINARY, plainText.length(), 12345678
        )

        def encryptor = new Encryptor(new Ring(stream('test-key-2-pub.asc')))
        encryptor.signingAlgorithm = HashingAlgorithm.Unsigned
        encryptor.encrypt plainIn, cipherOut, src

        def decryptor = new Decryptor(new Ring(stream('test-key-2.asc')))
        decryptor.verificationRequired = false
        decryptor.ring.keys*.passphrase = 'c02e'
        def meta = decryptor.decrypt(cipherIn, plainOut)

        then:
        plainOut.toString() == plainText

        meta.name == src.name
        meta.length == src.length
        // milliseconds are not preserved
        (meta.lastModified / 1000L) == 12345L
        meta.format == src.format

        !meta.verified
    }

    def "encrypt and sign with metadata"() {
        when:
        def src = new FileMetadata(
            'test.txt', FileMetadata.Format.BINARY, plainText.length(), 12345678
        )

        def encryptor = new Encryptor(new Ring(stream('test-key-2.asc')))
        encryptor.ring.keys*.passphrase = 'c02e'
        encryptor.encrypt plainIn, cipherOut, src

        def decryptor = new Decryptor(new Ring(stream('test-key-2.asc')))
        decryptor.ring.keys*.passphrase = 'c02e'
        def meta = decryptor.decrypt(cipherIn, plainOut)

        then:
        plainOut.toString() == plainText

        meta.name == src.name
        meta.length == src.length
        // milliseconds are not preserved
        (meta.lastModified / 1000L) == 12345L
        meta.format == src.format

        meta.verified.keys.uids.flatten() == [
            'Test Key 2 <test-key-2@c02e.org>',
            'Test 2 (CODESurvey) <test-key-2@codesurvey.org>',
        ]
        meta.verified.keys.signingUid == ['Test Key 2 <test-key-2@c02e.org>']
    }

    def "encrypt and sign with passphrase-less key"() {
        when:
        def encryptor = new Encryptor(new Ring(stream('test-key-no-passphrase.asc')))
        encryptor.ring.keys*.noPassphrase = true
        encryptor.encrypt plainIn, cipherOut

        def decryptor = new Decryptor(new Ring(stream('test-key-no-passphrase.asc')))
        decryptor.ring.keys*.noPassphrase = true
        def meta = decryptor.decrypt(cipherIn, plainOut)

        then:
        plainOut.toString() == plainText
        meta.verified
    }

    def "encrypt and sign with no usage flags"() {
        when:
        def encryptor = new Encryptor(
            new KeyForEncryption(file('test-no-usage-ec-subkeys.asc')),
            new KeyForSigning(file('test-no-usage-ec-subkeys.asc'), 'c02e'),
        )
        encryptor.encrypt plainIn, cipherOut

        def decryptor = new Decryptor(
            new KeyForVerification(file('test-no-usage-ec-subkeys.asc')),
            new KeyForDecryption(file('test-no-usage-ec-subkeys.asc'), 'c02e'),
        )
        def meta = decryptor.decrypt(cipherIn, plainOut)

        then:
        plainOut.toString() == plainText
        meta.verified
    }

    def "best packet size"() {
        when:
        def encryptor = new Encryptor();
        def meta = new FileMetadata(length: fileSize)
        then:
        encryptor.bestPacketSize(meta) == packetSize
        where:
        fileSize << [
            -1, 0, 1,
            0x1000, 0xffff, 0x10000,
            0x10000000, 0xffffffffL, 0x100000000000L,
        ]
        packetSize << [
            0x10000, 0x10000, 0x200,
            0x2000, 0x10000, 0x10000,
            0x10000, 0x10000, 0x10000,
        ]
    }

    def "estimate unarmored output file size with no keys"() {
        setup:
        def encryptor = new Encryptor();
        expect:
        encryptor.estimateOutFileSize(inputSize) == outputSize
        where:
        inputSize << [
            -1, 0, 1,
            0x1000, 0xffff, 0x10000,
            0xfffff, 0x100000, 0x100001,
            0x10000000, 0xffffffffL, 0x100000000000L,
        ]
        outputSize << [
            0x1ff, 0x200, 0x201,
            0x1200, 0x101ff, 0x10200,
            0x100000, 0x100000, 0x100000,
            0x100000, 0x100000, 0x100000,
        ]
    }

    def "estimate armored output file size with no keys"() {
        setup:
        def encryptor = new Encryptor();
        encryptor.asciiArmored = true
        expect:
        encryptor.estimateOutFileSize(inputSize) == outputSize
        where:
        inputSize << [
            -1, 0, 1,
            0x1000, 0xffff, 0x10000,
            0xfffff, 0x100000, 0x100001,
            0x10000000, 0xffffffffL, 0x100000000000L,
        ]
        outputSize << [
            771, 773, 774,
            6320, 89518, 89520,
            0x100000, 0x100000, 0x100000,
            0x100000, 0x100000, 0x100000,
        ]
    }

    def "estimate unarmored output file size with multiple keys"() {
        setup:
        // set up 2 encryption keys and 1 signing key
        def encryptor = new Encryptor(new Ring(stream('test-ring.asc')))
        encryptor.ring.findAll('key-1')*.signing*.forSigning = false
        expect:
        encryptor.estimateOutFileSize(inputSize) == outputSize
        where:
        inputSize << [
            -1, 0, 1,
            0x1000, 0xffff, 0x10000,
            0xfffff, 0x100000, 0x100001,
            0x10000000, 0xffffffffL, 0x100000000000L,
        ]
        outputSize << [
            0x7ff, 0x800, 0x801,
            0x1800, 0x107ff, 0x10800,
            0x100000, 0x100000, 0x100000,
            0x100000, 0x100000, 0x100000,
        ]
    }

    def "check estimate against actual for unarmored output file size"() {
        setup:
        // set up 2 encryption keys and 1 signing key
        def encryptor = new Encryptor(new Ring(stream('test-ring.asc')))
        encryptor.ring.findAll('key-1')*.signing*.forSigning = false
        encryptor.ring.keys*.passphrase = 'c02e'
        // assume input already well compressed
        encryptor.compressionAlgorithm = CompressionAlgorithm.Uncompressed
        when:
        def plainIn = new ByteArrayInputStream(new byte[inputSize])
        encryptor.encrypt plainIn, cipherOut
        def estimate = encryptor.estimateOutFileSize(inputSize)
        def actual = cipherOut.size()
        then:
        estimate > actual
        estimate - actual < 0x800
        where:
        inputSize << [0, 1, 0x1000, 0xabcd, 0x10000]
    }

    def "check estimate against actual for armored output file size"() {
        setup:
        // set up 2 encryption keys and 1 signing key
        def encryptor = new Encryptor(new Ring(stream('test-ring.asc')))
        encryptor.asciiArmored = true
        encryptor.ring.findAll('key-1')*.signing*.forSigning = false
        encryptor.ring.keys*.passphrase = 'c02e'
        // assume input already well compressed
        encryptor.compressionAlgorithm = CompressionAlgorithm.Uncompressed
        when:
        def plainIn = new ByteArrayInputStream(new byte[inputSize])
        encryptor.encrypt plainIn, cipherOut
        def estimate = encryptor.estimateOutFileSize(inputSize)
        def actual = cipherOut.size()
        then:
        estimate > actual
        estimate - actual < 0x800
        where:
        inputSize << [0, 1, 0x1000, 0xabcd, 0x10000]
    }

    def "encrypt and sign a big stream"() {
        setup:
        // 1MB of zeros
        def plainIn = new ByteArrayInputStream(new byte[0x100000])
        when:
        def encryptor = new Encryptor(new Ring(stream('test-key-1.asc')))
        encryptor.ring.keys*.passphrase = 'c02e'
        encryptor.encrypt plainIn, cipherOut

        def decryptor = new Decryptor(new Ring(stream('test-key-1.asc')))
        decryptor.ring.keys*.passphrase = 'c02e'
        def meta = decryptor.decrypt(cipherIn, plainOut)

        def plainBytes = plainOut.toByteArray()
        then:
        plainBytes.length == 0x100000
        plainBytes.every { it == 0 }

        meta.length == 0x100000
        meta.verified
    }

    protected stream(s) {
        getClass().classLoader.getResourceAsStream s
    }

    protected file(s) {
        new File(getClass().classLoader.getResource(s).toURI())
    }

    protected getPlainText() {
        'test\n'
    }

    protected getPlainIn() {
        new ByteArrayInputStream(plainText.bytes)
    }

    protected getCipherIn() {
        new ByteArrayInputStream(cipherOut.toByteArray())
    }

    protected getTestFile(String s = null) {
        def f = File.createTempFile('encryptor-spec', '.txt')
        f.deleteOnExit()
        if (s) f.text = s
        return f
    }

}
