package dev.medzik.otp;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

public class TOTPGeneratorTests {
    @Test
    public void testGenerateTOTP() {
        OneTimePasswordParameters params = OneTimePasswordParameters.builder()
                .type(OneTimePasswordType.TOTP)
                .secret(OneTimePasswordParameters.Secret.generate())
                .label(new OneTimePasswordParameters.Label("test"))
                .build();

        String code = TOTPGenerator.now(params);

        assertNotNull(code);
    }

    @Test
    public void testTOTP() {
        OneTimePasswordParameters params = OneTimePasswordParameters.builder()
                .type(OneTimePasswordType.TOTP)
                .secret(new OneTimePasswordParameters.Secret("JBSWY3DPEHPK3PXP"))
                .label(new OneTimePasswordParameters.Label("test"))
                .build();

        assertEquals(TOTPGenerator.at(params, 1707566984), "785021");
        assertEquals(TOTPGenerator.at(params, 1707567150), "342204");
        assertEquals(TOTPGenerator.at(params, 1707567162), "342204");
    }
}
