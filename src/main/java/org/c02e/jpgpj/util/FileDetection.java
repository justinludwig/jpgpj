package org.c02e.jpgpj.util;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.IOException;

/**
 * File detection utilities.
 */
public class FileDetection {
    protected static final int SCAN_AHEAD = 64;

    public enum ContainerType {
        /** Not a recognized format. */
        UNKNOWN,
        /** PGP binary container. */
        PGP,
        /** ASCII armor container. */
        ASCII_ARMOR,
        /** GPG keybox container. */
        KEYBOX,
    }

    public static class DetectionResult {
        /** Wrapper around original input stream. */
        public InputStream stream;
        /** Container type that was detected. */
        public ContainerType type;

        public DetectionResult() {
            this(null, null);
        }

        public DetectionResult(InputStream stream, ContainerType type) {
            this.stream = stream != null ? stream
                : new ByteArrayInputStream(new byte[0]);
            this.type = type != null ? type : ContainerType.UNKNOWN;
        }
    }

    /**
     * Scans the first few bytes of the specified input stream,
     * and tries to determine if it's a known PGP container format.
     * Since this function reads the first few bytes from the passed
     * input stream, it will pass back a reference to another input stream
     * as part of the detection result. Use the returned stream to read from
     * the start of the original stream. (If the original input stream supports
     * marking and reseting, it will be reset and passed back; otherwise it
     * will be wrapped with a new buffered input stream, and the wrapper stream
     * will be passed back.)
     * @param stream Input stream to check.
     * @return Detection result, including likely container type,
     * and the wrapper input stream.
     */
    public static DetectionResult detectContainer(InputStream stream)
    throws IOException {
        return detectContainer(stream, 0x100000); // 1 MB buffer
    }

    /**
     * Scans the first few bytes of the specified input stream,
     * and tries to determine if it's a known PGP container format.
     * Since this function reads the first few bytes from the passed
     * input stream, it will pass back a reference to another input stream
     * as part of the detection result. Use the returned stream to read from
     * the start of the original stream. (If the original input stream supports
     * marking and reseting, it will be reset and passed back; otherwise it
     * will be wrapped with a new buffered input stream, and the wrapper stream
     * will be passed back.)
     * @param stream Input stream to check.
     * @param bufferSize Size of buffer to create if the input stream
     * does not support marking and resetting.
     * @return Detection result, including likely container type,
     * and the wrapper input stream.
     */
    public static DetectionResult detectContainer(
    InputStream stream, int bufferSize) throws IOException {
        if (stream == null) return new DetectionResult();
        if (!stream.markSupported())
            stream = new BufferedInputStream(stream, bufferSize);

        stream.mark(SCAN_AHEAD);
        byte[] buf = new byte[SCAN_AHEAD];
        int read = stream.read(buf);
        stream.reset();

        // too small to have content
        if (read < 4) return new DetectionResult(stream, ContainerType.UNKNOWN);

        // possible pgp packet start
        if ((buf[0] & 0x80) == 0x80)
            return new DetectionResult(stream, ContainerType.PGP);

        // likely ascii-armor header
        if (buf[0] == '-' && buf[1] == '-' && buf[2] == '-' && buf[3] == '-'
                && buf[4] == '-')
            return new DetectionResult(stream, ContainerType.ASCII_ARMOR);

        // definite keybox signature
        if (buf[8] == 'K' && buf[9] == 'B' && buf[10] == 'X' && buf[11] == 'f')
            return new DetectionResult(stream, ContainerType.KEYBOX);

        // if first 64 bytes looks like ascii-armor body, it's probably that
        if (read == SCAN_AHEAD && isAllArmor(buf))
            return new DetectionResult(stream, ContainerType.ASCII_ARMOR);

        return new DetectionResult(stream, ContainerType.UNKNOWN);
    }

    protected static boolean isAllArmor(byte[] buf) {
        for (int i = 0; i < buf.length; i++)
            if (!isArmorByte(buf[i])) return false;
        return true;
    }

    protected static boolean isArmorByte(byte b) {
        return (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z')
            || (b >= '0' && b <= '9') || b == '+' || b == '/';
    }
}
