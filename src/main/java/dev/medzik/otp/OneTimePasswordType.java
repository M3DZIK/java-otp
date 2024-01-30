package dev.medzik.otp;

import lombok.AllArgsConstructor;
import lombok.Getter;

@AllArgsConstructor
@Getter
public enum OneTimePasswordType {
    TOTP,
    HOTP;

    public static OneTimePasswordType get(String value) throws IllegalArgumentException {
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
