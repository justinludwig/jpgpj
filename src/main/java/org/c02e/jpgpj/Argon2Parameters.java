package org.c02e.jpgpj;

import java.security.SecureRandom;
import java.util.Objects;

import org.bouncycastle.bcpg.S2K;

/**
 * Argon2 parameters for symmetric passphrase encryption (RFC 9580).
 * Immutable value object mapping to Bouncy Castle {@link S2K.Argon2Params}.
 *
 * @since 2.1.0
 */
public final class Argon2Parameters {
    public static final Argon2Parameters GPG_RECOMMENDED =
            fromBc(S2K.Argon2Params.universallyRecommendedParameters());
    public static final Argon2Parameters MEMORY_CONSTRAINED =
            fromBc(S2K.Argon2Params.memoryConstrainedParameters());

    private final int passes;
    private final int parallelism;
    private final int memorySizeExponent;

    public Argon2Parameters(int passes, int parallelism, int memorySizeExponent) {
        if (passes < 1) {
            throw new IllegalArgumentException("passes must be >= 1");
        }
        if (parallelism < 1) {
            throw new IllegalArgumentException("parallelism must be >= 1");
        }
        if (memorySizeExponent < 1) {
            throw new IllegalArgumentException("memorySizeExponent must be >= 1");
        }
        this.passes = passes;
        this.parallelism = parallelism;
        this.memorySizeExponent = memorySizeExponent;
    }

    public static Argon2Parameters fromBc(S2K.Argon2Params params) {
        return new Argon2Parameters(
                params.getPasses(),
                params.getParallelism(),
                params.getMemSizeExp());
    }

    public int getPasses() {
        return passes;
    }

    public int getParallelism() {
        return parallelism;
    }

    /**
     * Memory cost as exponent: allocated memory is {@code 2^memorySizeExponent} KiB.
     */
    public int getMemorySizeExponent() {
        return memorySizeExponent;
    }

    S2K.Argon2Params toBcParams() {
        return new S2K.Argon2Params(passes, parallelism, memorySizeExponent, new SecureRandom());
    }

    @Override
    public boolean equals(Object o) {
        if (o == this) {
            return true;
        }
        if (!(o instanceof Argon2Parameters)) {
            return false;
        }
        Argon2Parameters that = (Argon2Parameters) o;
        return passes == that.passes
                && parallelism == that.parallelism
                && memorySizeExponent == that.memorySizeExponent;
    }

    @Override
    public int hashCode() {
        return Objects.hash(passes, parallelism, memorySizeExponent);
    }

    @Override
    public String toString() {
        return "Argon2Parameters[passes=" + passes
                + ", parallelism=" + parallelism
                + ", memorySizeExponent=" + memorySizeExponent + "]";
    }
}
