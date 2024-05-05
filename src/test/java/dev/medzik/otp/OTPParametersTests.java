package dev.medzik.otp;

import org.junit.jupiter.api.Test;

import java.net.URISyntaxException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

public class OTPParametersTests {
    @Test
    public void testBuildOTPAuthURL() throws URISyntaxException {
        String uri = "otpauth://hotp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example&algorithm=SHA256&digits=7&counter=0";

        OTPParameters params = OTPParameters.parseUrl(uri);

        String encoded = params.encodeToUrl();
        System.out.println(encoded);

        OTPParameters decoded = OTPParameters.parseUrl(encoded);

        assertEquals(decoded.getType(), OTPType.HOTP);
        assertEquals(decoded.getSecret().getEncoded(), "JBSWY3DPEHPK3PXP");
        assertEquals(decoded.getIssuer(), "Example");
        assertEquals(decoded.getAlgorithm(), OTPParameters.Algorithm.SHA256);
        assertEquals(decoded.getDigits(), OTPParameters.Digits.SEVEN);
        assertNull(decoded.getPeriod());
        assertEquals(decoded.getCounter().getValue(), 0);
    }
}
