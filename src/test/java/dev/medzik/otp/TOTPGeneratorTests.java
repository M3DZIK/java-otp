package dev.medzik.otp;

import org.junit.jupiter.api.Test;

import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

public class TOTPGeneratorTests {
    @Test
    public void testGenerateTOTP() throws InterruptedException {
        OTPParameters params = OTPParameters.builder()
                .type(OTPType.TOTP)
                .secret(OTPParameters.Secret.generate())
                .label(new OTPParameters.Label("test"))
                .build();

        String code = TOTPGenerator.now(params);
        assertNotNull(code);

        assertTrue(TOTPGenerator.verify(params, code));

        Thread.sleep(TimeUnit.SECONDS.toMillis(30));
        assertTrue(TOTPGenerator.verify(params, code, 3));
    }

    @Test
    public void testTOTP() {
        OTPParameters params = OTPParameters.builder()
                .type(OTPType.TOTP)
                .secret(new OTPParameters.Secret("JBSWY3DPEHPK3PXP"))
                .label(new OTPParameters.Label("test"))
                .build();

        assertEquals(TOTPGenerator.at(params, 1707566984), "785021");
        assertEquals(TOTPGenerator.at(params, 1707567150), "342204");
        assertEquals(TOTPGenerator.at(params, 1707567162), "342204");
    }
}
