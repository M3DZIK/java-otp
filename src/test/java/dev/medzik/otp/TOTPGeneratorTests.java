package dev.medzik.otp;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertNotNull;

public class TOTPGeneratorTests {
    @Test
    public void testGenerateTOTP() {
        OneTimePasswordParameters params = OneTimePasswordParameters.builder()
                .type(OneTimePasswordType.TOTP)
                .secret(OneTimePasswordParameters.Secret.generate())
                .label(new OneTimePasswordParameters.Label("test"))
                .issuer(new OneTimePasswordParameters.Issuer("test"))
                .build();

        String code = TOTPGenerator.now(params);

        assertNotNull(code);
    }
}
