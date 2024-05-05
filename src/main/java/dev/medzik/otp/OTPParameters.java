package dev.medzik.otp;

import lombok.*;
import org.apache.commons.codec.binary.Base32;

import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * OTP parameters for TOTP and HOTP.
 */
@AllArgsConstructor
@Builder(builderClassName = "ParametersBuilder")
@Getter
@Setter
public final class OTPParameters {
    @NonNull
    private OTPType type;
    @NonNull
    @Builder.Default
    private String label = "";
    private String issuer;
    @NonNull
    private Secret secret;
    @NonNull
    @Builder.Default
    private Algorithm algorithm = Algorithm.SHA1;
    @NonNull
    @Builder.Default
    private Digits digits = Digits.SIX;
    private Period period;
    private Counter counter;

    /**
     * Parses the given OTP URI and returns the corresponding parameters.
     *
     * @param uri the OTP Auth URI to parse
     * @return The parameters associated with the OTP.
     * @throws URISyntaxException If the given URI is invalid.
     * @throws IllegalArgumentException If any parameter in the URI is invalid.
     */
    public static OTPParameters parseUrl(String uri) throws URISyntaxException, IllegalArgumentException {
        OTPParameters.ParametersBuilder paramsBuilder = OTPParameters.builder();

        URI parsedUri = new URI(uri);

        String type = parsedUri.getHost();
        paramsBuilder.type(OTPType.get(type));

        // omit the leading "/"
        String label = parsedUri.getPath().substring(1);
        paramsBuilder.label(label);

        Map<String, String> query = splitQuery(parsedUri);

        for (Map.Entry<String, String> param : query.entrySet()) {
            switch (param.getKey()) {
                case "secret":
                    paramsBuilder.secret(new OTPParameters.Secret(param.getValue()));
                    break;
                case "issuer":
                    paramsBuilder.issuer(param.getValue());
                    break;
                case "algorithm":
                    paramsBuilder.algorithm(OTPParameters.Algorithm.valueOfParam(param.getValue()));
                    break;
                case "digits":
                    paramsBuilder.digits(OTPParameters.Digits.valueOf(Integer.parseInt(param.getValue())));
                    break;
                case "period":
                    paramsBuilder.period(OTPParameters.Period.valueOf(Integer.parseInt(param.getValue())));
                    break;
                case "counter":
                    paramsBuilder.counter(new OTPParameters.Counter(Long.parseLong(param.getValue())));
                    break;
            }
        }

        return paramsBuilder.build();
    }

    private static Map<String, String> splitQuery(URI url) {
        try {
            Map<String, String> query_pairs = new LinkedHashMap<>();
            String query = url.getQuery();
            String[] pairs = query.split("&");
            for (String pair : pairs) {
                int idx = pair.indexOf("=");
                query_pairs.put(
                        URLDecoder.decode(pair.substring(0, idx), StandardCharsets.UTF_8.toString()),
                        URLDecoder.decode(pair.substring(idx + 1), StandardCharsets.UTF_8.toString())
                );
            }

            return query_pairs;
        } catch (UnsupportedEncodingException e) {
            throw new IllegalStateException("URL Decoding should be supported");
        }
    }

    public static class ParametersBuilder {}

    public static ParametersBuilder builder() {
        return new ParametersBuilder() {
            @Override
            public OTPParameters build() throws IllegalArgumentException {
                // add default period parameter for TOTP
                if (super.type == OTPType.TOTP && super.period == null) {
                    super.period = Period.THIRTY;
                }

                if (super.type == OTPType.HOTP && super.counter == null) {
                    super.counter = new Counter(0);
                }

                return super.build();
            }
        };
    }

    /**
     * Encodes the parameters as an OTPAuth URL.
     *
     * @return The encoded OTPAuth URL.
     */
    public String encodeToUrl() {
        StringBuilder sb = new StringBuilder();

        // scheme
        sb.append("otpauth://");

        // otp type
        sb.append(type.getValue()).append("/");

        sb.append(uriEncode(label));

        // secret
        sb.append("?secret=").append(secret.getEncoded());

        // issuer
        if (issuer != null) {
            sb.append("&issuer=").append(uriEncode(issuer));
        }

        // algorithm
        if (algorithm != Algorithm.SHA1) {
            sb.append("&algorithm=").append(algorithm.getValue());
        }

        // digits
        if (digits != Digits.SIX) {
            sb.append("&digits=").append(digits.getValue());
        }

        // period
        if (type == OTPType.TOTP && period != Period.THIRTY) {
            sb.append("&period=").append(period.getValue());
        }

        // counter
        if (type == OTPType.HOTP) {
            sb.append("&counter=").append(counter.getValue());
        }

        return sb.toString();
    }

    @AllArgsConstructor
    @Getter
    public final static class Secret {
        private static final int DEFAULT_BITS = 160;

        private final byte[] value;

        /**
         * Generates OTP secret with default number of bits.
         *
         * @return The randomly generated secret.
         */
        public static Secret generate() {
            return generate(DEFAULT_BITS);
        }

        /**
         * Generates OTP secret with specified number of bits.
         *
         * @param bits the number of bits to generate
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
    public enum Algorithm {
        SHA1("sha1", "HmacSHA1"),
        SHA256("sha256", "HmacSHA256"),
        SHA512("sha512", "HmacSHA512");

        private final String value;
        private final String hmacAlgorithm;

        public static Algorithm valueOfParam(String value) throws IllegalArgumentException {
            switch (value.toLowerCase()) {
                case "sha1":
                    return SHA1;
                case "sha256":
                    return SHA256;
                case "sha512":
                    return SHA512;
                default:
                    throw new IllegalArgumentException("Invalid value: " + value);
            }
        }
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

    private String uriEncode(String value) {
        try {
            return URLEncoder.encode(value, StandardCharsets.UTF_8.toString());
        } catch (UnsupportedEncodingException e) {
            throw new IllegalStateException("URL Encoding should be supported");
        }
    }
}
