package org.c02e.jpgpj

import java.text.SimpleDateFormat
import java.util.logging.Level
import java.util.logging.Logger
import spock.lang.Specification

class DecryptorSpec extends Specification {

    /*
    static {
        Logger.getLogger('').handlers*.level = Level.FINEST
        Logger.getLogger('org.c02e.jpgpj.Decryptor').level = Level.FINEST
    }
    */

    def buf = new ByteArrayOutputStream()

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

    def "decrypt symmetric without verification"() {
        when:
        def decryptor = new Decryptor()
        decryptor.verificationRequired = false
        decryptor.symmetricPassphrase = 'c02e'
        def meta = decryptor.decrypt(stream(
            'test-encrypted-with-passphrase.txt.asc'), buf)
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
        decryptor.verificationRequired = false
        decryptor.symmetricPassphrase = 'foo'
        decryptor.decrypt stream('test-encrypted-with-passphrase.txt.asc'), buf
        then:
        def e = thrown(PassphraseException)
        e.message == 'incorrect passphrase for symmetric key'
    }

    def "decrypt symmetric without verification key"() {
        when:
        def decryptor = new Decryptor()
        decryptor.symmetricPassphrase = 'c02e'
        decryptor.decrypt stream('test-encrypted-with-passphrase.txt.asc'), buf
        then:
        def e = thrown(VerificationException)
        e.message == 'content not signed with a required key'
    }

    def "decrypt symmetric with verification"() {
        when:
        def decryptor = new Decryptor(new Ring(stream('test-ring-pub.asc')))
        decryptor.symmetricPassphrase = 'c02e'
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
