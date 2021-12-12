package org.c02e.jpgpj

import java.text.SimpleDateFormat
import org.c02e.jpgpj.Decryptor.VerificationType
import org.bouncycastle.openpgp.PGPException;
import spock.lang.Specification

class DecryptorSpec extends Specification {
    def buf = new ByteArrayOutputStream()

    def "verificationType synchronized with verificationRequired"() {
        when:
        def decryptor = new Decryptor()
        then:
        decryptor.verificationRequired
        decryptor.verificationType == VerificationType.Required

        when:
        decryptor.verificationRequired = false
        then:
        !decryptor.verificationRequired
        decryptor.verificationType == VerificationType.None

        when:
        decryptor.verificationType = VerificationType.Required
        then:
        decryptor.verificationRequired
        decryptor.verificationType == VerificationType.Required

        when:
        decryptor.verificationType = VerificationType.Optional
        then:
        !decryptor.verificationRequired
        decryptor.verificationType == VerificationType.Optional

        when:
        decryptor.verificationType = VerificationType.None
        then:
        !decryptor.verificationRequired
        decryptor.verificationType == VerificationType.None
    }

    def "decrypt without verification"() {
        when:
        def decryptor = new Decryptor(new Ring(stream('test-ring.asc')))
        decryptor.ring.keys*.passphrase = 'c02e'
        decryptor.verificationRequired = false
        def meta = decryptor.decrypt(stream(
            'test-encrypted-for-key-1.txt.asc'), buf)
        then:
        buf.toString() == 'test\n'
        meta.name == 'test.txt'
        meta.length == 5
        date(meta.lastModified) == '2016-03-17'
        meta.format == FileMetadata.Format.BINARY
        !meta.verified
        !meta.signatures
    }

    def "decrypt with verification"() {
        when:
        def decryptor = new Decryptor(new Ring(stream('test-ring.asc')))
        decryptor.ring.keys*.passphrase = 'c02e'
        def meta = decryptor.decrypt(stream(
            'test-encrypted-for-key-1-signed-by-key-2.txt.asc'), buf)
        then:
        buf.toString() == 'test\n'

        meta.name == 'test.txt'
        meta.length == 5
        date(meta.lastModified) == '2016-03-17'
        meta.format == FileMetadata.Format.BINARY

        meta.verified
        meta.verified as String == '''
pub v  880A1469 Test Key 2 <test-key-2@c02e.org>, Test 2 (CODESurvey) <test-key-2@codesurvey.org>
pub e  AFAFA3C5
pub v  BC3F6A4B
        '''.trim()
        meta.verified.keys.signingUid == ['']

        meta.signatures.verified == [true]
        meta.signatures.keyId == [0xAFDB7B47BC3F6A4B as Long]
        meta.signatures.key.master.shortId == ['880A1469']
        meta.signatures.key.signingUid == ['']
        meta.signatures.verifiedKey.master.shortId == ['880A1469']
    }

    def "decrypt file with verification"() {
        when:
        def decryptor = new Decryptor(
            new Key(file('test-key-1.asc'), 'c02e'),
            new Key(file('test-key-2-pub.asc')),
        )
        def plainFile = testFile
        def meta = decryptor.decrypt(file(
            'test-encrypted-for-key-1-signed-by-key-2.txt.asc'), plainFile)
        then:
        plainFile.text == 'test\n'
        meta.verified
        meta.signatures.verifiedKey.master.shortId == ['880A1469']
    }

    def "decrypt same file"() {
        when:
        def decryptor = new Decryptor(
            new Key(file('test-key-1.asc'), 'c02e'),
            new Key(file('test-key-2-pub.asc')),
        )
        def testFile = getTestFile('foo')
        decryptor.decrypt testFile, testFile
        then:
        thrown IOException
        testFile.text == 'foo'
    }

    def "decrypt unsigned file with verification"() {
        when:
        def decryptor = new Decryptor(
            new Key(file('test-key-1.asc'), 'c02e'),
            new Key(file('test-key-2-pub.asc')),
        )
        def plainFile = getTestFile('foo')
        decryptor.decrypt file('test-encrypted-for-key-1.txt.asc'), plainFile
        then:
        def e = thrown(VerificationException)
        e.message == 'content not signed with a required key'
        !plainFile.exists()
    }

    def "decrypt bad signature file with verification"() {
        when:
        def decryptor = new Decryptor(
            new Key(file('test-key-1.asc'), 'c02e'),
            new Key(file('test-key-2-pub.asc')),
        )
        def plainFile = getTestFile('foo')
        decryptor.decrypt file('test-encrypted-for-key-1-signed-by-key-2-with-bad-signature.txt.asc'), plainFile
        then:
        def e = thrown(VerificationException)
        e.message =~ ~/^bad signature for key pub v  880A1469 Test Key 2.+/
        !plainFile.exists()
    }

    def "decrypt signed without verification"() {
        when:
        def decryptor = new Decryptor(new Ring(stream('test-ring.asc')))
        decryptor.ring.keys*.passphrase = 'c02e'
        decryptor.verificationRequired = false
        def meta = decryptor.decrypt(stream(
            'test-encrypted-for-key-1-signed-by-key-2.txt.asc'), buf)
        then:
        buf.toString() == 'test\n'
        meta.name == 'test.txt'
        meta.length == 5
        date(meta.lastModified) == '2016-03-17'
        meta.format == FileMetadata.Format.BINARY
        !meta.verified
        !meta.signatures
    }

    def "decrypt unsigned with optional verification"() {
        when:
        def decryptor = new Decryptor(new Ring(stream('test-ring.asc')))
        decryptor.ring.keys*.passphrase = 'c02e'
        decryptor.verificationType = VerificationType.Optional
        def meta = decryptor.decrypt(stream('test-encrypted-for-key-1.txt.asc'), buf)
        then:
        buf.toString() == 'test\n'
        meta.name == 'test.txt'
        !meta.verified
        !meta.signatures
    }

    def "decrypt signed with optional verification"() {
        when:
        def decryptor = new Decryptor(new Ring(stream('test-ring.asc')))
        decryptor.ring.keys*.passphrase = 'c02e'
        decryptor.verificationType = VerificationType.Optional
        def meta = decryptor.decrypt(stream(
            'test-encrypted-for-key-1-signed-by-key-2.txt.asc'), buf)
        then:
        buf.toString() == 'test\n'
        meta.name == 'test.txt'
        meta.verified
        meta.signatures.verifiedKey.master.shortId == ['880A1469']
    }

    def "decrypt bad signature with optional verification"() {
        when:
        def decryptor = new Decryptor(new Ring(stream('test-ring.asc')))
        decryptor.ring.keys*.passphrase = 'c02e'
        decryptor.verificationType = VerificationType.Optional
        def meta = decryptor.decrypt(stream(
            'test-encrypted-for-key-1-signed-by-key-2-with-bad-signature.txt.asc'), buf)
        then:
        buf.toString() == 'test\n'
        meta.name == 'test.txt'
        !meta.verified
        meta.signatures.verified == [false]
        meta.signatures.keyId == [0xAFDB7B47BC3F6A4B as Long]
        meta.signatures.key.master.shortId == ['880A1469']
        meta.signatures.verifiedKey == [null]
    }

    def "decrypt camellia"() {
        when:
        def decryptor = new Decryptor(new Ring(stream('test-ring.asc')))
        decryptor.ring.keys*.passphrase = 'c02e'
        decryptor.verificationRequired = false
        def meta = decryptor.decrypt(stream(
            'test-encrypted-for-key-1-with-camellia.txt.asc'), buf)
        then:
        buf.toString() == 'test\n'
    }

    def "decrypt without passphrase"() {
        when:
        def decryptor = new Decryptor(new Ring(stream('test-ring.asc')))
        decryptor.decrypt stream('test-encrypted-for-key-1.txt.asc'), buf
        then:
        def e = thrown(DecryptionException)
        e.message == 'no suitable decryption key found'
    }

    def "decrypt with wrong passphrase"() {
        when:
        def decryptor = new Decryptor(new Ring(stream('test-ring.asc')))
        decryptor.ring.keys*.passphrase = 'wrong!'
        decryptor.decrypt stream('test-encrypted-for-key-1.txt.asc'), buf
        then:
        def e = thrown(PassphraseException)
        e.message == 'incorrect passphrase for subkey sec+ed 970C7061'
    }

    def "decrypt without any key"() {
        when:
        def decryptor = new Decryptor()
        decryptor.decrypt stream('test-encrypted-for-key-1.txt.asc'), buf
        then:
        def e = thrown(DecryptionException)
        e.message == 'no suitable decryption key found'
    }

    def "decrypt without secret key"() {
        when:
        def decryptor = new Decryptor(new Ring(stream('test-ring-pub.asc')))
        decryptor.decrypt stream('test-encrypted-for-key-1.txt.asc'), buf
        then:
        def e = thrown(DecryptionException)
        e.message == 'no suitable decryption key found'
    }

    def "decrypt without verification key"() {
        when:
        def decryptor = new Decryptor(new Ring(stream('test-ring.asc')))
        decryptor.ring.keys*.passphrase = 'c02e'
        // remove all but key 1
        // (leaving the decryption key, but not the verification key)
        decryptor.ring.keys = decryptor.ring.keys.findAll { it.findAll 'key-1' }
        decryptor.decrypt stream(
            'test-encrypted-for-key-1-signed-by-key-2.txt.asc'), buf
        then:
        def e = thrown(VerificationException)
        e.message == 'content not signed with a required key'
    }

    def "decrypt without verification key with optional verification"() {
        when:
        def decryptor = new Decryptor(new Ring(stream('test-ring.asc')))
        decryptor.ring.keys*.passphrase = 'c02e'
        // remove all but key 1
        // (leaving the decryption key, but not the verification key)
        decryptor.ring.keys = decryptor.ring.keys.findAll { it.findAll 'key-1' }
        decryptor.verificationType = VerificationType.Optional
        def meta = decryptor.decrypt(stream(
            'test-encrypted-for-key-1-signed-by-key-2.txt.asc'), buf)
        then:
        buf.toString() == 'test\n'
        meta.name == 'test.txt'
        !meta.verified
        meta.signatures.verified == [false]
        meta.signatures.keyId == [0xAFDB7B47BC3F6A4B as Long]
        meta.signatures.key == [null]
        meta.signatures.verifiedKey == [null]
    }

    def "decrypt with public and private versions of same key"() {
        when:
        def decryptor = new Decryptor(
            new Key(file('test-key-1-pub.asc')),
            new Key(file('test-key-1.asc'), 'c02e'),
            new Key(file('test-key-2-pub.asc')),
        )
        def meta = decryptor.decrypt(stream(
            'test-encrypted-for-key-1-signed-by-key-2.txt.asc'), buf)
        then:
        buf.toString() == 'test\n'
        meta.verified
        meta.signatures.verifiedKey.master.shortId == ['880A1469']
    }

    def "decrypt symmetric without verification"() {
        when:
        def meta = new Decryptor()
            .withVerificationRequired(false)
            .withSymmetricPassphrase('c02e')
            .decrypt(stream('test-encrypted-with-passphrase.txt.asc'), buf)
        then:
        buf.toString() == 'test\n'
        meta.name == 'test.txt'
        meta.length == 5
        date(meta.lastModified) == '2016-03-23'
        meta.format == FileMetadata.Format.BINARY
        !meta.verified
        !meta.signatures
    }

    def "decrypt symmetric with wrong passphrase"() {
        when:
        def decryptor = new Decryptor()
            .withVerificationRequired(false)
            .withSymmetricPassphrase('foo')
            .decrypt(stream('test-encrypted-with-passphrase.txt.asc'), buf)
        then:
        def e = thrown(PassphraseException)
        e.message == 'incorrect passphrase for symmetric key'
    }

    def "decrypt symmetric without verification key"() {
        when:
        def decryptor = new Decryptor()
            .withSymmetricPassphrase('c02e')
            .decrypt stream('test-encrypted-with-passphrase.txt.asc'), buf
        then:
        def e = thrown(VerificationException)
        e.message == 'content not signed with a required key'
    }

    def "decrypt symmetric without verification key with optional verification"() {
        when:
        def meta = new Decryptor()
            .withSymmetricPassphrase('c02e')
            .withVerificationType(VerificationType.Optional)
            .decrypt(stream('test-encrypted-for-key-1-and-passphrase-signed-by-key-2.txt.asc'), buf)
        then:
        buf.toString() == 'test\n'

        meta.name == 'test.txt'
        meta.length == 5
        date(meta.lastModified) == '2016-03-23'
        meta.format == FileMetadata.Format.BINARY

        !meta.verified
        meta.signatures.verified == [false]
        meta.signatures.keyId == [0xAFDB7B47BC3F6A4B as Long]
        meta.signatures.key == [null]
        meta.signatures.verifiedKey == [null]
    }

    def "decrypt symmetric with verification"() {
        when:
        def decryptor = new Decryptor(new Ring(stream('test-ring-pub.asc')))
            .withSymmetricPassphrase('c02e')
        def meta = decryptor.decrypt(stream(
            'test-encrypted-for-key-1-and-passphrase-signed-by-key-2.txt.asc'), buf)
        then:
        buf.toString() == 'test\n'

        meta.name == 'test.txt'
        meta.length == 5
        date(meta.lastModified) == '2016-03-23'
        meta.format == FileMetadata.Format.BINARY

        meta.verified
        meta.signatures.verifiedKey.master.shortId == ['880A1469']
    }

    def "decrypt optional symmetric with key instead"() {
        when:
        def decryptor = new Decryptor(new Ring(stream('test-ring.asc')))
        decryptor.ring.keys*.passphrase = 'c02e'
        decryptor.symmetricPassphrase = 'foo'
        def meta = decryptor.decrypt(stream(
            'test-encrypted-for-key-1-and-passphrase-signed-by-key-2.txt.asc'), buf)
        then:
        buf.toString() == 'test\n'

        meta.name == 'test.txt'
        meta.length == 5
        date(meta.lastModified) == '2016-03-23'
        meta.format == FileMetadata.Format.BINARY

        meta.verified
        meta.signatures.verifiedKey.master.shortId == ['880A1469']
    }

    def "decrypt symmetric and clear passphrase"() {
        when:
        def passphrase = 'c02e' as char[]
        def decryptor = new Decryptor(new Ring(stream('test-ring-pub.asc')))
            .withSymmetricPassphraseChars(passphrase)
        def meta = decryptor.decrypt(stream(
            'test-encrypted-for-key-1-and-passphrase-signed-by-key-2.txt.asc'), buf)
        then:
        buf.toString() == 'test\n'
        meta.verified

        when: "original char[] is updated"
        passphrase[0] = 'x'
        then: "decryptor is shown to use original char[], not a copy"
        decryptor.symmetricPassphraseChars[0] == 'x'

        when:
        decryptor.decrypt stream('test-encrypted-with-passphrase.txt.asc'), buf
        then:
        def e = thrown(PassphraseException)
        e.message == 'incorrect passphrase for symmetric key'

        when:
        decryptor.clearSecrets()
        then:
        passphrase == [0, 0, 0, 0] as char[]
        decryptor.symmetricPassphraseChars == [] as char[]
        decryptor.symmetricPassphrase == ''

        when:
        decryptor.decrypt stream('test-encrypted-with-passphrase.txt.asc'), buf
        then:
        e = thrown(DecryptionException)
        e.message == 'no suitable decryption key found'
    }

    def "decrypt and clear secrets"() {
        when:
        def passphrase = 'c02e' as char[]
        def decryptor = new Decryptor(
            new Key(file('test-key-1.asc'), passphrase),
            new Key(file('test-key-2-pub.asc')),
        )
        def meta = decryptor.decrypt(stream(
            'test-encrypted-for-key-1-signed-by-key-2.txt.asc'), buf)
        then:
        buf.toString() == 'test\n'
        meta.verified

        when:
        decryptor.clearSecrets()
        def subkeys = decryptor.ring.keys.subkeys.flatten()
        then:
        passphrase == [0, 0, 0, 0] as char[]
        subkeys.unlocked == (1..5).collect { false }
        subkeys.passphraseChars == (1..5).collect { [] as char[] }
        subkeys.passphrase == (1..5).collect { '' }

        when:
        decryptor.decrypt(stream(
            'test-encrypted-for-key-1-signed-by-key-2.txt.asc'), buf)
        then:
        def e = thrown(DecryptionException)
        e.message == 'no suitable decryption key found'
    }

    def "decrypt without caching passphrase"() {
        when:
        def decryptor = new Decryptor(
            new Key(file('test-key-1.asc')),
            new Key(file('test-key-2-pub.asc')),
        )
        // unlock just key 1 encryption subkey
        decryptor.ring.keys.subkeys.flatten().find {
            it.shortId == '970C7061'
        }.unlock('c02e' as char[])
        def meta = decryptor.decrypt(stream(
            'test-encrypted-for-key-1-signed-by-key-2.txt.asc'), buf)
        then:
        buf.toString() == 'test\n'
        meta.verified

        when: "subkeys inspected"
        def subkeys = decryptor.ring.keys.subkeys.flatten()
        then: "only 2nd subkey of key 1 is unlocked, and no passphrases cached"
        subkeys.unlocked == [false, true, false, false, false]
        subkeys.passphraseChars == (1..5).collect { [] as char[] }
        subkeys.passphrase == (1..5).collect { '' }
    }

    def "decrypt with old style signature verification"() {
        when:
        def decryptor = new Decryptor(new Ring(stream('test-ring.asc')))
        decryptor.ring.keys*.passphrase = 'c02e'
        def meta = decryptor.decrypt(stream(
            'test-encrypted-for-key-1-signed-by-key-2-with-pgp2-compatibility.txt.asc'), buf)
        then:
        buf.toString() == 'test\n'

        meta.name == 'test.txt'
        meta.length == 5
        date(meta.lastModified) == '2018-01-18'
        meta.format == FileMetadata.Format.BINARY

        meta.verified
        meta.verified as String == '''
pub v  880A1469 Test Key 2 <test-key-2@c02e.org>, Test 2 (CODESurvey) <test-key-2@codesurvey.org>
pub e  AFAFA3C5
pub v  BC3F6A4B
        '''.trim()
        meta.verified.keys.signingUid == ['']

        meta.signatures.verifiedKey.master.shortId == ['880A1469']
    }

    def "verify signed by 1 of 2 keys"() {
        when:
        def decryptor = new Decryptor(new Ring(stream('test-ring-pub.asc')))
        def meta = decryptor.decrypt(stream(
            'test-signed-by-key-1.txt.asc'), buf)
        then:
        buf.toString() == 'test\n'

        meta.name == 'test.txt'
        meta.length == 5
        date(meta.lastModified) == '2016-03-22'
        meta.format == FileMetadata.Format.BINARY

        meta.verified
        meta.verified.keys.master.shortId == ['013826C3']
        meta.verified.keys.signingUid == ['']

        meta.signatures.verifiedKey.master.shortId == ['013826C3']
    }

    def "verify signed by multiple keys"() {
        when:
        def decryptor = new Decryptor(new Ring(stream('test-ring-pub.asc')))
        def meta = decryptor.decrypt(stream(
            'test-signed-by-key-1-and-key-2.txt.asc'), buf)
        then:
        buf.toString() == 'test\n'

        meta.name == 'test.txt'
        meta.length == 5
        date(meta.lastModified) == '2016-03-22'
        meta.format == FileMetadata.Format.BINARY

        meta.verified
        meta.verified.keys.master.shortId == ['880A1469', '013826C3']
        meta.verified.keys.signingUid == ['', '']

        meta.signatures.verifiedKey.master.shortId == ['880A1469', '013826C3']
    }

    def "verify without any key"() {
        when:
        def decryptor = new Decryptor()
        decryptor.decrypt stream('test-signed-by-key-1.txt.asc'), buf
        then:
        def e = thrown(VerificationException)
        e.message == 'content not signed with a required key'
    }

    def "verify optionally without any key"() {
        when:
        def decryptor = new Decryptor()
        decryptor.verificationType = VerificationType.Optional
        def meta = decryptor.decrypt(stream(
            'test-signed-by-key-1.txt.asc'), buf)
        then:
        buf.toString() == 'test\n'

        meta.name == 'test.txt'
        meta.length == 5
        date(meta.lastModified) == '2016-03-22'
        meta.format == FileMetadata.Format.BINARY

        !meta.verified
        meta.signatures.verified == [false]
        meta.signatures.keyId == [0x72A423A0013826C3 as Long]
        meta.signatures.key == [null]
        meta.signatures.verifiedKey == [null]
    }

    def "decrypt null stream"() {
        when:
        def decryptor = new Decryptor()
        decryptor.decrypt null, buf
        then:
        def e = thrown(PGPException)
        e.message == 'not a pgp message'
    }

    def "decrypt empty message"() {
        when:
        def decryptor = new Decryptor()
        decryptor.decrypt content(''), buf
        then:
        def e = thrown(PGPException)
        e.message == 'not a pgp message'
    }

    def "decrypt garbage"() {
        when:
        def decryptor = new Decryptor()
        decryptor.decrypt content('garbage'), buf
        then:
        def e = thrown(PGPException)
        e.message == 'not a pgp message'
    }

    def "decrypt stream without mark support"() {
        when:
        def decryptor = new Decryptor(
            new Key(markUnsupported('test-key-1.asc'), 'c02e'),
            new Key(markUnsupported('test-key-2-pub.asc')),
        )
        def meta = decryptor.decrypt(markUnsupported(
            'test-encrypted-for-key-1-signed-by-key-2.txt.asc'), buf)
        then:
        buf.toString() == 'test\n'
        meta.verified
    }

    protected markUnsupported(s) {
        return new MarkUnsupportedInputStream(stream(s))
    }

    protected content(s) {
        new ByteArrayInputStream(s.bytes)
    }

    protected stream(s) {
        getClass().classLoader.getResourceAsStream s
    }

    protected file(s) {
        new File(getClass().classLoader.getResource(s).toURI())
    }

    protected date(t) {
        def fmt = new SimpleDateFormat('yyyy-MM-dd')
        fmt.timeZone = TimeZone.getTimeZone('GMT')
        fmt.format new Date(t)
    }

    protected getTestFile(String s = null) {
        def f = File.createTempFile('encryptor-spec', '.txt')
        f.deleteOnExit()
        if (s) f.text = s
        return f
    }

}

class MarkUnsupportedInputStream extends BufferedInputStream {
    MarkUnsupportedInputStream(InputStream wrapped) {
        super(wrapped)
    }

    boolean markSupported() {
        return false
    }
}
