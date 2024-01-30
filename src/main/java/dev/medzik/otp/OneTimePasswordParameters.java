package dev.medzik.otp;

import lombok.*;
import org.apache.commons.codec.binary.Base32;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

@AllArgsConstructor
@Builder(builderClassName = "ParametersBuilder")
@Getter
@Setter
public final class OneTimePasswordParameters {
    @NonNull
    private OneTimePasswordType type;
    @NonNull
    private Secret secret;
    @NonNull
    private Label label;
    @NonNull
    private Issuer issuer;
    @NonNull
    @Builder.Default
    private Algorithm algorithm = Algorithm.SHA1;
    @NonNull
    @Builder.Default
    private Digits digits = Digits.SIX;
    private Period period;
    private Counter counter;

    public static ParametersBuilder builder() {
        return new ParametersBuilder(){
            @Override
            public OneTimePasswordParameters build() throws IllegalArgumentException {
                // add default period parameter for TOTP
                if (super.type == OneTimePasswordType.TOTP && super.period == null) {
                    super.period = Period.THIRTY;
                }

                return super.build();
            }
        };
    }

    public String getEncoded() {
        return null;
    }

    @AllArgsConstructor
    @Getter
    public final static class Secret {
        private static final int DEFAULT_BITS = 160;

        private final byte[] value;

        /**
         * Generate OTP secret with default number of bits.
         * @return The randomly generated secret.
         */
        public static Secret generate() {
            return generate(DEFAULT_BITS);
        }

        /**
         * Generate OTP secret with specified number of bits.
         * @param bits The number of bits to generate.
         * @return The randomly generated secret.
         */
        public static Secret generate(int bits) {
            if (bits <= 0) {
                throw new IllegalArgumentException("Bits must be grater than 0");
            }

            byte[] bytes = new byte[bits / Byte.SIZE];
            new SecureRandom().nextBytes(bytes);

            return new Secret(bytes);
        }

        public String getEncoded() {
            return Base32Util.encode(value);
        }

        public Secret(String value) {
            this.value = Base32Util.decode(value);
        }
    }

    @AllArgsConstructor
    @Getter
    public final static class Label {
        private final String value;
    }

    @AllArgsConstructor
    @Getter
    public final static class Issuer {
        private final String value;

        public String getEncoded() {
            try {
                return URLEncoder.encode(value, StandardCharsets.UTF_8.toString());
            } catch (UnsupportedEncodingException e) {
                throw new IllegalStateException("URL Encoding should be supported");
            }
        }
    }

    @AllArgsConstructor
    @Getter
    public enum Algorithm {
        SHA1("sha1", "HmacSHA1"),
        SHA256("sha256", "HmacSHA256"),
        SHA512("sha512", "HmacSHA512");

        private final String value;
        private final String hmacAlgorithm;
    }

    @AllArgsConstructor
    @Getter
    public enum Digits {
        SIX(6),
        SEVEN(7),
        EIGHT(8);

        private final int value;

        public static Digits valueOf(int value) throws IllegalArgumentException {
            switch (value) {
                case 6:
                    return SIX;
                case 7:
                    return SEVEN;
                case 8:
                    return EIGHT;
                default:
                    throw new IllegalArgumentException("Invalid value: " + value);
            }
        }
    }

    @AllArgsConstructor
    @Getter
    public enum Period {
        FIFTEEN(15),
        THIRTY(30),
        SIXTY(60);

        private final int value;

        public static Period valueOf(int value) throws IllegalArgumentException {
            switch (value) {
                case 15:
                    return FIFTEEN;
                case 30:
                    return THIRTY;
                case 60:
                    return SIXTY;
                default:
                    throw new IllegalArgumentException("Invalid value: " + value);
            }
        }
    }

    @AllArgsConstructor
    @Getter
    public final static class Counter {
        private final long value;
    }

    private final static class Base32Util {
        public static String encode(byte[] value) {
            return new Base32().encodeToString(value);
        }

        public static byte[] decode(String value) {
            return new Base32().decode(value);
        }
    }
}
