package dev.medzik.otp;

import java.net.URISyntaxException;
import java.time.Clock;
import java.util.concurrent.TimeUnit;

/**
 * Time-based one-time password (TOTP) generator.
 */
public final class TOTPGenerator {
    /**
     * Generate TOTP code from the given parameters for the current period.
     *
     * @param params The TOTP parameters.
     * @return The TOTP code.
     * @throws IllegalArgumentException If the OTP type is not TOTP.
     */
    public static String now(OTPParameters params) throws IllegalArgumentException {
        checkOtpType(params);
        long counter = calculateCounter(Clock.systemUTC(), params.getPeriod());
        return HOTPGenerator.generate(params, counter);
    }

    /**
     * Generate TOTP code from the given parameters for the given period.
     *
     * @param params The TOTP parameters.
     * @return The TOTP code.
     * @throws IllegalArgumentException If the OTP type is not TOTP.
     */
    public static String at(OTPParameters params, long unixSeconds) throws IllegalArgumentException {
        checkOtpType(params);
        long counter = calculateCounter(unixSeconds, params.getPeriod());
        return HOTPGenerator.generate(params, counter);
    }

    /**
     * Generate TOTP code from the OTPAuth URL.
     * @param url The OTPAuth URL.
     * @return The TOTP code.
     * @throws URISyntaxException If the OTP type is not TOTP.
     */
    public static String fromUrl(String url) throws URISyntaxException {
        OTPParameters params = OTPParameters.parseUrl(url);
        return now(params);
    }

    /**
     * Checks if the given HOTP code is valid.
     *
     * @param params The OTP parameters.
     * @param code The HOTP code.
     * @return True if the code is valid, false otherwise.
     * @throws IllegalArgumentException If the OTP type is not TOTP.
     */
    public static boolean verify(OTPParameters params, String code) throws IllegalArgumentException {
        return verify(params, code, 1);
    }

    /**
     * Checks if the given HOTP code is valid.
     *
     * @param params The OTP parameters.
     * @param code The HOTP code.
     * @param counterOffset The counter offset.
     * @return True if the code is valid, false otherwise.
     * @throws IllegalArgumentException If the OTP type is not TOTP.
     */
    public static boolean verify(OTPParameters params, String code, int counterOffset) throws IllegalArgumentException {
        checkOtpType(params);
        long counter = calculateCounter(Clock.systemUTC(), params.getPeriod());
        return HOTPGenerator.verify(params, code, counter, counterOffset);
    }

    /**
     * Calculates the TOTP counter for the given period and time.
     *
     * @param unixSeconds The unix time in seconds.
     * @param period The TOTP period.
     * @return The TOTP counter.
     */
    public static long calculateCounter(long unixSeconds, OTPParameters.Period period) {
        return TimeUnit.SECONDS.toMillis(unixSeconds) / TimeUnit.SECONDS.toMillis(period.getValue());
    }

    /**
     * Calculates the TOTP counter for the given period and time.
     *
     * @param clock The clock to use for calculating the current time.
     * @param period The TOTP period.
     * @return The TOTP counter.
     */
    public static long calculateCounter(Clock clock, OTPParameters.Period period) {
        return clock.millis() / TimeUnit.SECONDS.toMillis(period.getValue());
    }

    private static void checkOtpType(OTPParameters params) throws IllegalArgumentException {
        if (params.getType() != OTPType.TOTP) {
            throw new IllegalArgumentException("Invalid OTP type");
        }
    }
}
