package dev.medzik.otp;

import org.junit.jupiter.api.Test;

import java.net.URISyntaxException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

public class OneTimePasswordParametersTests {
    @Test
    public void testBuildOTPAuthURL() throws URISyntaxException {
        String uri = "otpauth://hotp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example&algorithm=SHA256&digits=7&counter=0";

        OneTimePasswordParameters params = OneTimePasswordParser.parse(uri);

        String encoded = params.buildOTPAuthURL();
        System.out.println(encoded);

        OneTimePasswordParameters decoded = OneTimePasswordParser.parse(encoded);

        assertEquals(decoded.getType(), OneTimePasswordType.HOTP);
        assertEquals(decoded.getSecret().getEncoded(), "JBSWY3DPEHPK3PXP");
        assertEquals(decoded.getIssuer().getValue(), "Example");
        assertEquals(decoded.getAlgorithm(), OneTimePasswordParameters.Algorithm.SHA256);
        assertEquals(decoded.getDigits(), OneTimePasswordParameters.Digits.SEVEN);
        assertNull(decoded.getPeriod());
        assertEquals(decoded.getCounter().getValue(), 0);
    }
}
