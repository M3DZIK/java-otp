package dev.medzik.otp;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.experimental.PackagePrivate;

/**
 * OTPType represents a type of the one-time password.
 */
@AllArgsConstructor
@Getter
public enum OTPType {
    /**
     * Time-based one-time password (TOTP) generator.
     */
    TOTP("totp"),
    /**
     * HMAC-based one-time password (HOTP) generator.
     */
    HOTP("hotp");

    private final String value;

    @PackagePrivate
    static OTPType get(String value) throws IllegalArgumentException {
        switch (value.toLowerCase()) {
            case "totp":
                return TOTP;
            case "hotp":
                return HOTP;
            default:
                throw new IllegalArgumentException("Unknown OtpType: " + value);
        }
    }
}
