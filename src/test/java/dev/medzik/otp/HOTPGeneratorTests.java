package dev.medzik.otp;

import org.junit.jupiter.api.Test;

import java.net.URISyntaxException;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class HOTPGeneratorTests {
    @Test
    public void testHOTPFromUrl() throws URISyntaxException {
        String uri = "otpauth://hotp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example&algorithm=SHA256&digits=7&counter=0";
        String code = HOTPGenerator.fromUrl(uri, 1);
        assertNotNull(code);
    }

    @Test
    public void testHOTP() {
        OTPParameters params = OTPParameters.builder()
                .type(OTPType.HOTP)
                .secret(new OTPParameters.Secret("JBSWY3DPEHPK3PXP"))
                .build();

        String code = HOTPGenerator.generate(params, 1);
        assertTrue(HOTPGenerator.verify(params, code, 1));
    }
}
