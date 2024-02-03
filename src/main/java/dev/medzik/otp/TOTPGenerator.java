package dev.medzik.otp;

import java.time.Clock;
import java.util.concurrent.TimeUnit;

/**
 * Time-based one-time password (TOTP) generator.
 */
public final class TOTPGenerator {
    /**
     * Generate TOTP code from the given parameters for the current period.
     * @param params The TOTP parameters.
     * @return The generated code.
     * @throws IllegalArgumentException If the OTP type is not TOTP.
     */
    public static String now(OneTimePasswordParameters params) throws IllegalArgumentException {
        checkOtpType(params);
        long counter = calculateCounter(Clock.systemUTC(), params.getPeriod());
        return HOTPGenerator.generate(params, counter);
    }

    /**
     * Generate TOTP code from the given parameters for the given period.
     * @param params The TOTP parameters.
     * @return The generated code.
     * @throws IllegalArgumentException If the OTP type is not TOTP.
     */
    public static String at(OneTimePasswordParameters params, long unixSeconds) throws IllegalArgumentException {
        checkOtpType(params);
        long counter = calculateCounter(unixSeconds, params.getPeriod());
        return HOTPGenerator.generate(params, counter);
    }

    private static void checkOtpType(OneTimePasswordParameters params) throws IllegalArgumentException {
        if (params.getType() != OneTimePasswordType.TOTP) {
            throw new IllegalArgumentException("Invalid OTP type");
        }
    }

    private static long calculateCounter(long unixSeconds, OneTimePasswordParameters.Period period) {
        return TimeUnit.SECONDS.toMillis(unixSeconds) / TimeUnit.SECONDS.toMillis(period.getValue());
    }

    private static long calculateCounter(Clock clock, OneTimePasswordParameters.Period period) {
        return clock.millis() / TimeUnit.SECONDS.toMillis(period.getValue());
    }
}
