package org.c02e.jpgpj;

import java.util.Map;

import org.bouncycastle.bcpg.ArmoredOutputStream;

@FunctionalInterface
public interface EncryptedAsciiArmorHeadersManipulator {
    /**
     * A manipulator that ignores all headers manipulations
     */
    EncryptedAsciiArmorHeadersManipulator EMPTY = (name, value) -> { /* do nothing */ };

    /**
     * Set the specified header value - replace any previous value
     *
     * @param name Case <U>sensitive</U> name of header to set. <B>Note:</B> this
     * method can be used to <U>override</U> the default version header value.
     * @param value Value to set - if {@code null} then equivalent to header removal
     */
    void setHeader(String name, String value);

    /**
     * Removes specified header - no-op if header not set anyway
     *
     * @param name Case <U>sensitive</U> name of header to set. <B>Note:</B> this
     * method can be used to <U>remove</U> the default version header value.
     */
    default void removeHeader(String name) {
        setHeader(name, null);
    }

    /**
     * Replaces existing headers and adds missing ones
     *
     * @param headers The headers to update - ignored if {@code null}.
     * <B>Note:</B> header name is case <U>sensitive</U>
     */
    default void updateHeaders(Map<String, String> headers) {
        if (headers != null) {
            headers.forEach((name, value) -> setHeader(name, value));
        }
    }

    /**
     * Wraps an {@link ArmoredOutputStream}
     *
     * @param aos The stream to wrap - ignored if {@code null}
     * @return The manipulator wrapping
     */
    static EncryptedAsciiArmorHeadersManipulator wrap(ArmoredOutputStream aos) {
        return (aos == null) ? EMPTY : (name, value) -> aos.setHeader(name, value);
    }
}
