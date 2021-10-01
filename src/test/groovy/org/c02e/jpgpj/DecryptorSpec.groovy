package org.c02e.jpgpj

import org.bouncycastle.jce.provider.BouncyCastleProvider

import java.security.Security
import java.text.SimpleDateFormat
import org.bouncycastle.openpgp.PGPException;
import spock.lang.Specification

class DecryptorSpec extends Specification {
    def buf = new ByteArrayOutputStream()

    def setupSpec() {
        Security.addProvider(new BouncyCastleProvider())
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

    def "decrypt unsigned with verification"() {
        when:
        def decryptor = new Decryptor(new Ring(stream('test-ring.asc')))
        decryptor.ring.keys*.passphrase = 'c02e'
        decryptor.decrypt stream('test-encrypted-for-key-1.txt.asc'), buf
        then:
        def e = thrown(VerificationException)
        e.message == 'content not signed with a required key'
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
        meta.verified.keys.master.shortId == ['880A1469']
        meta.verified.keys.signingUid == ['']
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
        meta.verified.keys.master.shortId == ['880A1469']
        meta.verified.keys.signingUid == ['']
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
    }

    def "verify without any key"() {
        when:
        def decryptor = new Decryptor()
        decryptor.decrypt stream('test-signed-by-key-1.txt.asc'), buf
        then:
        def e = thrown(VerificationException)
        e.message == 'content not signed with a required key'
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
