package dev.medzik.otp;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.experimental.PackagePrivate;

@AllArgsConstructor
@Getter
public enum OTPType {
    TOTP("totp"),
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
