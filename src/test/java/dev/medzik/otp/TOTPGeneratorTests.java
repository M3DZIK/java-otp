package dev.medzik.otp;

import org.junit.jupiter.api.Test;

import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

public class TOTPGeneratorTests {
    @Test
    public void testGenerateTOTP() throws InterruptedException {
        OneTimePasswordParameters params = OneTimePasswordParameters.builder()
                .type(OneTimePasswordType.TOTP)
                .secret(OneTimePasswordParameters.Secret.generate())
                .label(new OneTimePasswordParameters.Label("test"))
                .build();

        String code = TOTPGenerator.now(params);
        assertNotNull(code);

        assertTrue(TOTPGenerator.verify(params, code));

        Thread.sleep(TimeUnit.SECONDS.toMillis(30));
        assertTrue(TOTPGenerator.verify(params, code, 3));
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
