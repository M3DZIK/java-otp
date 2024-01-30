package dev.medzik.otp;

import lombok.AccessLevel;
import lombok.AllArgsConstructor;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

@AllArgsConstructor(access = AccessLevel.PRIVATE)
public final class HOTPGenerator {
    private OneTimePasswordParameters params;

    /**
     * Generate HOTP code from the given parameters for the given counter.
     * @param params The OTP parameters.
     * @param counter The HOTP counter.
     * @return The generated code.
     * @throws IllegalArgumentException If the counter is negative.
     */
    public static String generate(OneTimePasswordParameters params, long counter) throws IllegalArgumentException {
        return new HOTPGenerator(params).generate(counter);
    }

    private String generate(long counter) throws IllegalArgumentException {
        if (counter < 0) {
            throw new IllegalArgumentException("Counter cannot be negative");
        }

        byte[] counterBytes = longToBytes(counter);

        byte[] hash = generateHash(params.getSecret().getValue(), counterBytes);
        int code = getCodeFromHash(hash);

        // left pad with 0s for an n-digit code
        return String.format("%0" + params.getDigits().getValue() + "d", code);
    }

    private static byte[] longToBytes(long value) {
        return ByteBuffer.allocate(Long.BYTES).putLong(value).array();
    }

    private byte[] generateHash(byte[] secret, byte[] data) {
        Mac mac;

        SecretKeySpec key = new SecretKeySpec(secret, "RAW");

        try {
            mac = Mac.getInstance(params.getAlgorithm().getHmacAlgorithm());
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Algorithm should be supported");
        }

        try {
            mac.init(key);
        } catch (InvalidKeyException e) {
            throw new IllegalArgumentException(e);
        }

        return mac.doFinal(data);
    }

    private int getCodeFromHash(byte[] hash) {
        int digits = params.getDigits().getValue();

        int offset = hash[hash.length - 1] & 0x0f;
        int truncatedHash = ((hash[offset] & 0x7f) << 24) |
                ((hash[offset + 1] & 0xff) << 16) |
                ((hash[offset + 2] & 0xff) << 8) |
                (hash[offset + 3] & 0xff);

        return truncatedHash % (int) Math.pow(10, digits);
    }
}
