package org.c02e.jpgpj.support;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import java.util.TimeZone;
import java.util.function.Function;

import org.c02e.jpgpj.FileMetadata;
import org.c02e.jpgpj.Key;
import org.c02e.jpgpj.Ring;
import org.c02e.jpgpj.Subkey;

public final class PgpTestSupport {

    public static final String PASSPHRASE = "c02e";

    private PgpTestSupport() {
    }

    public static InputStream loadResource(String name) {
        InputStream stream = PgpTestSupport.class.getClassLoader().getResourceAsStream(name);
        if (stream == null) {
            throw new IllegalArgumentException("Test resource not found: " + name);
        }
        return stream;
    }

    public static File loadResourceFile(String name) {
        try {
            return new File(PgpTestSupport.class.getClassLoader().getResource(name).toURI());
        } catch (Exception e) {
            throw new IllegalArgumentException("Test resource not found: " + name, e);
        }
    }

    public static String loadResourceAsString(String name) throws IOException {
        try (InputStream stream = loadResource(name)) {
            return new String(stream.readAllBytes(), StandardCharsets.US_ASCII);
        }
    }

    /** Alias for {@link #loadResourceAsString(String)}. */
    public static String loadResourceText(String name) throws IOException {
        return loadResourceAsString(name);
    }

    public static void unlockKey(Key key) {
        key.setPassphrase(PASSPHRASE);
    }

    public static void unlockKey(Ring ring, String passphrase) {
        for (Key key : ring.getKeys()) {
            key.setPassphrase(passphrase);
        }
    }

    public static void unlockKeys(Ring ring) {
        unlockKey(ring, PASSPHRASE);
    }

    public static String plainText() {
        return "test\n";
    }

    public static List<String> subkeyPassphrases(Key key) {
        return key.getSubkeys().stream().map(Subkey::getPassphrase).toList();
    }

    public static List<Boolean> subkeyFlags(Key key, SubkeyFlag flag) {
        return key.getSubkeys().stream().map(flag.getter).toList();
    }

    public enum SubkeyFlag {
        FOR_SIGNING(Subkey::isForSigning),
        FOR_VERIFICATION(Subkey::isForVerification),
        FOR_ENCRYPTION(Subkey::isForEncryption),
        FOR_DECRYPTION(Subkey::isForDecryption);

        private final Function<Subkey, Boolean> getter;

        SubkeyFlag(Function<Subkey, Boolean> getter) {
            this.getter = getter;
        }
    }

    public static String formatDateGmt(long timestamp) {
        SimpleDateFormat fmt = new SimpleDateFormat("yyyy-MM-dd");
        fmt.setTimeZone(TimeZone.getTimeZone("GMT"));
        return fmt.format(new Date(timestamp));
    }

    /** Groovy {@code !meta.verified} — empty ring is falsy, not null. */
    public static boolean isVerified(FileMetadata meta) {
        return meta.getVerified() != null && meta.getVerified().asBoolean();
    }

    /** Groovy {@code !meta.signatures} — empty list is falsy. */
    public static boolean hasSignatures(FileMetadata meta) {
        return meta.getSignatures() != null && !meta.getSignatures().isEmpty();
    }
}
