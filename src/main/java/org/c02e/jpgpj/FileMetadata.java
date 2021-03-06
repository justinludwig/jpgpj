package org.c02e.jpgpj;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileTime;
import java.util.Date;
import java.util.Objects;
import java.util.concurrent.TimeUnit;

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

    public static final String DEFAULT_NAME = "";
    public static final Format DEFAULT_FORMAT = Format.BINARY;

    protected String name;
    protected Format format;
    protected long length;
    protected long lastModified;
    protected Ring verified = new Ring();

    /** Constructs a metadata object with default values. */
    public FileMetadata() {
        this(DEFAULT_NAME);
    }

    /** Constructs a metadata object from Bouncy Castle message data. */
    public FileMetadata(PGPLiteralData data) {
        this(data.getFileName(), Format.byCode((char) data.getFormat()));

        Date modificationTime = data.getModificationTime();
        if (modificationTime != null) {
            setLastModified(modificationTime.getTime());
        }
    }

    /** Constructs a metadata object from a file. */
    public FileMetadata(File file) {
        this((file == null) ? null : file.toPath());
    }

    /** Constructs a metadata object from a file. */
    public FileMetadata(Path file) {
        this(DEFAULT_NAME, DEFAULT_FORMAT); // in case file is null
        setFile(file);
    }

    /** Constructs a metadata object with the specified file name . */
    public FileMetadata(String name) {
        this(name, DEFAULT_FORMAT);
    }

    /**
     * Constructs a metadata object with the specified file name
     * and line-ending format.
     */
    public FileMetadata(String name, Format format) {
        this(name, format, 0L, 0L);
    }

    /**
     * Constructs a metadata object with the specified file name,
     * line-ending format, length in bytes,
     * and modified date in ms since the epoch.
     */
    public FileMetadata(String name, Format format, long length, long lastModified) {
        setName(name);
        setFormat(format);
        setLength(length);
        setLastModified(lastModified);
    }

    /** @return Original file name (&quot;foo.txt&quot;), or {@value #DEFAULT_NAME}. */
    public String getName() {
        return name;
    }

    /**
     * @param x Original file name (&quot;foo.txt&quot;) - set to
     * {@value #DEFAULT_NAME} if {@code null}
     */
    public void setName(String x) {
        name = x != null ? x : DEFAULT_NAME;
    }

    /** @see #setName(String) */
    public FileMetadata withName(String x) {
        setName(x);
        return this;
    }

    /** @return Original file length in bytes, or 0. */
    public long getLength() {
        return length;
    }

    /** @param x Original file length in bytes, or 0. */
    public void setLength(long x) {
        length = x;
    }

    /** @see #setLength(long) */
    public FileMetadata withLength(long x) {
        setLength(x);
        return this;
    }

    /** @return Original file modified date in ms since epoch, or 0. */
    public long getLastModified() {
        return lastModified;
    }

    /** @param x Original file modified date in ms since epoch, or 0. */
    public void setLastModified(long x) {
        lastModified = x;
    }

    /** @see #setLastModified(long) */
    public FileMetadata withLastModified(long x) {
        setLastModified(x);
        return this;
    }

    /**
     * @return Original file modified date, or date of the epoch.
     * @see #getLastModified()
     * @see #setLastModified(long)
     * @see #withLastModified(long)
     */
    public Date getLastModifiedDate() {
        return new Date(getLastModified());
    }

    /** @return Original file format, or binary. */
    public Format getFormat() {
        return format;
    }

    /** @param x Original file format, or {@link #DEFAULT_FORMAT} if {@code null}. */
    public void setFormat(Format x) {
        format = x != null ? x : Format.BINARY;
    }

    /** @see #setFormat(Format) */
    public FileMetadata withFormat(Format x) {
        setFormat(x);
        return this;
    }

    /**
     * Keys that signed the file with a verified signature.
     * If a specific userid was included in a key's signature
     * (such as &quot;Alice &lt;alice@example.com&gt;&quot;),
     * it will be available via the key's {@link Key#getSigningUid} method.
     */
    public Ring getVerified() {
        return verified;
    }

    /**
     * @param file Original {@link File} from which to extract the
     * metadata - ignored if {@code null}
     * Does not extract {@link Format} metadata.
     */
    public void setFile(File file) {
        setFile((file == null) ? null : file.toPath());
    }

    /**
     * @param file Original {@link Path} from which to extract the
     * metadata - ignored if {@code null}
     * Does not extract {@link Format} metadata.
     */
    public void setFile(Path file) {
        if (file == null) return;

        setName(Objects.toString(file.getFileName()));

        try {
            BasicFileAttributes attrs = Files.readAttributes(file, BasicFileAttributes.class);
            setLength((attrs == null) ? 0L : attrs.size());

            FileTime lastModified = (attrs == null) ? null : attrs.lastModifiedTime();
            setLastModified((lastModified == null) ? 0L : lastModified.toMillis());
        } catch (IOException e) {
            // ignored
        }
    }

    /** @see #withFile(Path) */
    public FileMetadata withFile(File file) {
        return withFile((file == null) ? null : file.toPath());
    }

    /** @see #setFile(Path) */
    public FileMetadata withFile(Path file) {
        setFile(file);
        return this;
    }

    /**
     * PGP code for the signature type appropriate for the line-ending format
     * of the original file.
     */
    public int getSignatureType() {
        return format == Format.TEXT || format == Format.UTF8 ?
            PGPSignature.CANONICAL_TEXT_DOCUMENT : PGPSignature.BINARY_DOCUMENT;
    }

    @Override
    public int hashCode() {
        return Objects.hash(getName(), getFormat())
             + 31 * Long.hashCode(getLength())
             + 37 * Long.hashCode(TimeUnit.MILLISECONDS.toSeconds(getLastModified()))
             ;
    }

    @Override
    public boolean equals(Object o) {
        if (o == null) {
            return false;
        }
        if (o == this) {
            return true;
        }
        if (getClass() != o.getClass()) {
            return false;
        }

        FileMetadata that = (FileMetadata) o;
        return Objects.equals(getName(), that.getName())
            && Objects.equals(getFormat(), that.getFormat())
            && (getLength() == that.getLength())
            && (TimeUnit.MILLISECONDS.toSeconds(getLastModified()) == TimeUnit.MILLISECONDS.toSeconds(that.getLastModified()))
            ;
    }

    @Override
    public String toString() {
        return getClass().getSimpleName()
            + "[name=" + getName()
            + ", length=" + getLength()
            + ", format=" + getFormat()
            + ", lastModified=" + getLastModifiedDate()
            + "]";
    }
}
