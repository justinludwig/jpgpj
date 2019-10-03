package org.c02e.jpgpj.util

import spock.lang.Specification

class UtilSpec extends Specification {

    // isEmpty

    def "char array is empty when blank"() {
        expect: Util.isEmpty([] as char[])
    }

    def "char array is not empty when not blank"() {
        expect: !Util.isEmpty([0] as char[])
    }

    def "string is empty when blank"() {
        expect: Util.isEmpty('')
    }

    def "string is not empty when not blank"() {
        expect: !Util.isEmpty('0')
    }

    def "collection is empty when empty"() {
        expect: Util.isEmpty([])
    }

    def "collection is not empty when not empty"() {
        expect: !Util.isEmpty([0])
    }

    def "map is empty when empty"() {
        expect: Util.isEmpty([:])
    }

    def "map is not empty when not empty"() {
        expect: !Util.isEmpty(['':null])
    }

    // formatKeyId

    def "null key formats as 0x0"() {
        expect: Util.formatKeyId(null) == '0x0000000000000000'
    }

    def "0 key formats as 0x0"() {
        expect: Util.formatKeyId(0) == '0x0000000000000000'
    }

    def "key formats as upper-case hex padded to 16 chars"() {
        expect: Util.formatKeyId(1234) == '0x00000000000004D2'
    }

    def "biggest key formats correctly"() {
        expect: Util.formatKeyId(0xffffffffffffffffL) == '0xFFFFFFFFFFFFFFFF'
    }

    // bestFileBufferSize

    def "best file buffer size is no smaller than 1"() {
        expect:
        Util.bestFileBufferSize(fileSize, maxSize) == expectedSize
        where:
        fileSize << [
            -1, -1, -1,
            0, 0, 0,
            1, 1, 1,
        ]
        maxSize << [
            -1, 0, 1,
            -1, 0, 1,
            -1, 0, 1,
        ]
        expectedSize << [
            1, 1, 1,
            1, 1, 1,
            1, 1, 1,
        ]
    }

    def "best file buffer size is no larger than file size"() {
        expect:
        Util.bestFileBufferSize(fileSize, maxSize) == expectedSize
        where:
        fileSize << [
            -1, 0, 1,
            0x1000, 0xffff, 0x10000,
            0xfffff, 0x100000, 0x100001,
            0x10000000, 0xffffffffL, 0x100000000000L,
        ]
        maxSize << [
            Integer.MAX_VALUE, Integer.MAX_VALUE, Integer.MAX_VALUE,
            Integer.MAX_VALUE, Integer.MAX_VALUE, Integer.MAX_VALUE,
            Integer.MAX_VALUE, Integer.MAX_VALUE, Integer.MAX_VALUE,
            Integer.MAX_VALUE, Integer.MAX_VALUE, Integer.MAX_VALUE,
        ]
        expectedSize << [
            1, 1, 1,
            0x1000, 0xffff, 0x10000,
            0xfffff, 0x100000, 0x100001,
            0x10000000, Integer.MAX_VALUE, Integer.MAX_VALUE,
        ]
    }

    def "best file buffer size is no larger than max buffer size"() {
        expect:
        Util.bestFileBufferSize(fileSize, maxSize) == expectedSize
        where:
        fileSize << [
            Long.MAX_VALUE, Long.MAX_VALUE, Long.MAX_VALUE,
            Long.MAX_VALUE, Long.MAX_VALUE, Long.MAX_VALUE,
            Long.MAX_VALUE, Long.MAX_VALUE, Long.MAX_VALUE,
            Long.MAX_VALUE, Long.MAX_VALUE, Long.MAX_VALUE,
        ]
        maxSize << [
            -1, 0, 1,
            0x1000, 0xffff, 0x10000,
            0xfffff, 0x100000, 0x100001,
            0x10000000, Integer.MAX_VALUE, Integer.MIN_VALUE,
        ]
        expectedSize << [
            1, 1, 1,
            0x1000, 0xffff, 0x10000,
            0xfffff, 0x100000, 0x100001,
            0x10000000, Integer.MAX_VALUE, 1,
        ]
    }
}
