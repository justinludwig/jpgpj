package org.c02e.jpgpj;

import java.io.File;
import java.util.Date;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPSignature;

/**
 * Optional PGP message metadata.
 */
public class FileMetadata {
    /**
     * Format for line-ending normalization.
     */
    public enum Format {
        /** No line-ending normalization (default). */
        BINARY('b'),
        /** Text with CRLF line-endings. */
        TEXT('t'),
        /** UTF-8 encoded text with CRLF line-endings. */
        UTF8('u');

        protected char code;

        Format(char code) {
            this.code = code;
        }

        public char getCode() {
            return code;
        }

        public static Format byCode(char code) {
            switch (code) {
                case 'b': return BINARY;
                case 't': return TEXT;
                case 'u': return UTF8;
                default: return null;
            }
        }
    }

    protected String name;
    protected long length;
    protected long lastModified;
    protected Format format;
    protected Ring verified;

    /** Constructs a metadata object with default values. */
    public FileMetadata() {
        this("");
    }

    /** Constructs a metadata object from Bouncy Castle message data. */
    public FileMetadata(PGPLiteralData data) {
        this(data.getFileName(), Format.byCode((char) data.getFormat()));

        if (data.getModificationTime() != null)
            setLastModified(data.getModificationTime().getTime());
    }

    /** Constructs a metadata object from a file. */
    public FileMetadata(File file) {
        this();
        setFile(file);
    }

    /** Constructs a metadata object with the specified file name. */
    public FileMetadata(String name) {
        this(name, Format.BINARY);
    }

    /**
     * Constructs a metadata object with the specified file name
     * and line-ending format.
     */
    public FileMetadata(String name, Format format) {
        setName(name);
        setFormat(format);
        verified = new Ring();
    }

    /**
     * Constructs a metadata object with the specified file name,
     * line-ending format, length in bytes,
     * and modified date in ms since the epoch.
     */
    public FileMetadata(String name, Format format,
    long length, long lastModified) {
        this(name, format);
        setLength(length);
        setLastModified(lastModified);
    }

    /** Original file name ("foo.txt"), or empty string (""). */
    public String getName() {
        return name;
    }
    /** Original file name ("foo.txt"), or empty string (""). */
    public void setName(String x) {
        name = x != null ? x : "";
    }

    /** Original file length in bytes, or 0. */
    public long getLength() {
        return length;
    }
    /** Original file length in bytes, or 0. */
    public void setLength(long x) {
        length = x;
    }

    /** Original file modified date in ms since epoch, or 0. */
    public long getLastModified() {
        return lastModified;
    }
    /** Original file modified date in ms since epoch, or 0. */
    public void setLastModified(long x) {
        lastModified = x;
    }
    /** Original file modified date, or date of the epoch. */
    public Date getLastModifiedDate() {
        return new Date(lastModified);
    }

    /** Original file format, or binary. */
    public Format getFormat() {
        return format;
    }
    /** Original file format, or binary. */
    public void setFormat(Format x) {
        format = x != null ? x : Format.BINARY;
    }

    /**
     * Keys that signed the file with a verified signature.
     * If a specific userid was included in a key's signature
     * (such as "Alice &lt;alice@example.com&gt;"),
     * it will be available via the key's {@link Key#getSigningUid} method.
     */
    public Ring getVerified() {
        return verified;
    }

    /**
     * Original file from which to extract the metadata.
     * Does not extract {@link Format} metadata.
     */
    public void setFile(File file) {
        if (file == null) return;

        setName(file.getName());
        setLength(file.length());
        setLastModified(file.lastModified());
    }

    /**
     * PGP code for the signature type appropriate for the line-ending format
     * of the original file.
     */
    public int getSignatureType() {
        return format == Format.TEXT || format == Format.UTF8 ?
            PGPSignature.CANONICAL_TEXT_DOCUMENT : PGPSignature.BINARY_DOCUMENT;
    }
}
