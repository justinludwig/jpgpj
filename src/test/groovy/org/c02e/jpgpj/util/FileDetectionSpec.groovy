package org.c02e.jpgpj.util

import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.c02e.jpgpj.CompressionAlgorithm
import org.c02e.jpgpj.Encryptor
import org.c02e.jpgpj.EncryptionAlgorithm
import org.c02e.jpgpj.HashingAlgorithm
import org.c02e.jpgpj.Ring
import spock.lang.Specification

import java.security.Security

import static org.c02e.jpgpj.util.FileDetection.ContainerType.*

class FileDetectionSpec extends Specification {
    def cipherOut = new ByteArrayOutputStream()

    def setupSpec() {
        Security.addProvider(new BouncyCastleProvider())
    }

    // detectContainer

    def "detect unknown container when null"() {
        expect: FileDetection.detectContainer(null).type == UNKNOWN
    }

    def "detect unknown container when empty"() {
        expect: FileDetection.detectContainer(content('')).type == UNKNOWN
    }

    def "detect unknown container when garbage"() {
        expect:
        FileDetection.detectContainer(content('foo')).type == UNKNOWN
        FileDetection.detectContainer(content('''
The quick brown fox jumps over the lazy dog!@#$%^&*() 1234567890
jA0EAwMCRPdXu3qZeLBgySHwRvh2vWI8YHXCNDwHDzkMr6ZoR9iZFDM8gaWyIz1T
        '''.trim())).type == UNKNOWN
    }

    def "detect armor container when armor body without headers"() {
        expect: FileDetection.detectContainer(content('''
jA0EAwMCRPdXu3qZeLBgySHwRvh2vWI8YHXCNDwHDzkMr6ZoR9iZFDM8gaWyIz1T
x/o=
=AqCM
        '''.trim())).type == ASCII_ARMOR
    }

    def "detect armor container"() {
        expect:
        FileDetection.detectContainer(stream(
            'test-encrypted-for-key-1.txt.asc')).type == ASCII_ARMOR
        FileDetection.detectContainer(stream(
            'test-key-1.asc')).type == ASCII_ARMOR
        FileDetection.detectContainer(stream(
            'test-key-1-pub.asc')).type == ASCII_ARMOR
    }

    def "detect keybox container"() {
        expect:
        FileDetection.detectContainer(stream('test-pubring.kbx')).type == KEYBOX
    }

    def "detect pgp container signed without compressing or encrypting"() {
        when:
        def encryptor = new Encryptor(new Ring(stream('test-key-1.asc')))
        encryptor.compressionAlgorithm = CompressionAlgorithm.Uncompressed
        encryptor.encryptionAlgorithm = EncryptionAlgorithm.Unencrypted
        encryptor.ring.keys*.passphrase = 'c02e'
        encryptor.encrypt plainIn, cipherOut

        then:
        FileDetection.detectContainer(cipherIn).type == PGP
    }

    def "detect pgp container signed without encrypting"() {
        when:
        def encryptor = new Encryptor(new Ring(stream('test-key-1.asc')))
        encryptor.encryptionAlgorithm = EncryptionAlgorithm.Unencrypted
        encryptor.ring.keys*.passphrase = 'c02e'
        encryptor.encrypt plainIn, cipherOut

        then:
        FileDetection.detectContainer(cipherIn).type == PGP
    }

    def "detect pgp container encrypted and signed"() {
        when:
        def encryptor = new Encryptor(new Ring(stream('test-key-1.asc')))
        encryptor.ring.keys*.passphrase = 'c02e'
        encryptor.encrypt plainIn, cipherOut

        then:
        FileDetection.detectContainer(cipherIn).type == PGP
    }

    def "detect pgp container encrypted symmetric"() {
        when:
        def encryptor = new Encryptor()
        encryptor.signingAlgorithm = HashingAlgorithm.Unsigned
        encryptor.symmetricPassphrase = 'c02e'
        encryptor.keyDerivationWorkFactor = 10
        encryptor.encrypt plainIn, cipherOut

        then:
        FileDetection.detectContainer(cipherIn).type == PGP
    }

    protected content(s) {
        new ByteArrayInputStream(s.bytes)
    }

    protected stream(s) {
        getClass().classLoader.getResourceAsStream s
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
}
