package org.c02e.jpgpj.util

import spock.lang.Specification

class UtilSpec extends Specification {

    // isEmpty

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
}
