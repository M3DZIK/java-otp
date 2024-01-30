package dev.medzik.otp;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

public class OneTimePasswordParserTests {
    @Test
    public void testParseTOTPFirst() throws Exception {
        String uri = "otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example";

        OneTimePasswordParameters params = OneTimePasswordParser.parse(uri);

        assertEquals(params.getType(), OneTimePasswordType.TOTP);
        assertEquals(params.getSecret().getEncoded(), "JBSWY3DPEHPK3PXP");
        assertEquals(params.getIssuer().getValue(), "Example");
        assertEquals(params.getAlgorithm(), OneTimePasswordParameters.Algorithm.SHA1);
        assertEquals(params.getDigits(), OneTimePasswordParameters.Digits.SIX);
        assertEquals(params.getPeriod(), OneTimePasswordParameters.Period.THIRTY);
        assertNull(params.getCounter());
    }

    @Test
    public void testParseTOTPSecond() throws Exception {
        String uri = "otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example&algorithm=SHA512&digits=8&period=15";

        OneTimePasswordParameters params = OneTimePasswordParser.parse(uri);

        assertEquals(params.getType(), OneTimePasswordType.TOTP);
        assertEquals(params.getSecret().getEncoded(), "JBSWY3DPEHPK3PXP");
        assertEquals(params.getIssuer().getValue(), "Example");
        assertEquals(params.getAlgorithm(), OneTimePasswordParameters.Algorithm.SHA512);
        assertEquals(params.getDigits(), OneTimePasswordParameters.Digits.EIGHT);
        assertEquals(params.getPeriod(), OneTimePasswordParameters.Period.FIFTEEN);
        assertNull(params.getCounter());
    }

    @Test
    public void testParseHOTPFirst() throws Exception {
        String uri = "otpauth://hotp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example&algorithm=SHA256&digits=7&counter=0";

        OneTimePasswordParameters params = OneTimePasswordParser.parse(uri);

        assertEquals(params.getType(), OneTimePasswordType.HOTP);
        assertEquals(params.getSecret().getEncoded(), "JBSWY3DPEHPK3PXP");
        assertEquals(params.getIssuer().getValue(), "Example");
        assertEquals(params.getAlgorithm(), OneTimePasswordParameters.Algorithm.SHA256);
        assertEquals(params.getDigits(), OneTimePasswordParameters.Digits.SEVEN);
        assertNull(params.getPeriod());
        assertEquals(params.getCounter().getValue(), 0);
    }
}
