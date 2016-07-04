package org.c02e.jpgpj.util;

import java.util.Collection;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Utility functions, used internally by JPGPJ.
 */
public class Util {

    /**
     * True if the specified string is null or empty.
     */
    public static boolean isEmpty(String s) {
        return s == null || s.length() == 0;
    }

    /**
     * True if the specified collection is null or empty.
     */
    public static boolean isEmpty(Collection c) {
        return c == null || c.isEmpty();
    }

    /**
     * True if the specified map is null or empty.
     */
    public static boolean isEmpty(Map m) {
        return m == null || m.isEmpty();
    }

    /**
     * Formats the specified key id in the "0xlong" format.
     */
    public static String formatKeyId(Long id) {
        if (id == null) id = 0L;
        return "0x" + String.format("%016X", id);
    }

    protected static final char[] hexDigits = "0123456789ABCDEF".toCharArray();
    /**
     * Formats the specified byte array as a hex string.
     */
    public static String formatAsHex(byte[] bytes) {
        if (bytes == null || bytes.length == 0) return "";
        char[] chars = new char[bytes.length * 2];
        for (int i = 0; i < bytes.length; i++) {
            int b = bytes[i] & 0xff;
            chars[i * 2] = hexDigits[b >>> 4];
            chars[i * 2 + 1] = hexDigits[b & 0x0f];
        }
        return new String(chars);
    }
}
