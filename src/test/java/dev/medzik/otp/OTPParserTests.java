package dev.medzik.otp;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

public class OTPParserTests {
    @Test
    public void testParseTOTPFirst() throws Exception {
        String uri = "otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example";

        OTPParameters params = OTPParameters.parseUrl(uri);

        assertEquals(params.getType(), OTPType.TOTP);
        assertEquals(params.getSecret().getEncoded(), "JBSWY3DPEHPK3PXP");
        assertEquals(params.getIssuer(), "Example");
        assertEquals(params.getAlgorithm(), OTPParameters.Algorithm.SHA1);
        assertEquals(params.getDigits(), OTPParameters.Digits.SIX);
        assertEquals(params.getPeriod(), OTPParameters.Period.THIRTY);
        assertNull(params.getCounter());
    }

    @Test
    public void testParseTOTPSecond() throws Exception {
        String uri = "otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example&algorithm=SHA512&digits=8&period=15";

        OTPParameters params = OTPParameters.parseUrl(uri);

        assertEquals(params.getType(), OTPType.TOTP);
        assertEquals(params.getSecret().getEncoded(), "JBSWY3DPEHPK3PXP");
        assertEquals(params.getIssuer(), "Example");
        assertEquals(params.getAlgorithm(), OTPParameters.Algorithm.SHA512);
        assertEquals(params.getDigits(), OTPParameters.Digits.EIGHT);
        assertEquals(params.getPeriod(), OTPParameters.Period.FIFTEEN);
        assertNull(params.getCounter());
    }

    @Test
    public void testParseHOTPFirst() throws Exception {
        String uri = "otpauth://hotp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example&algorithm=SHA256&digits=7&counter=0";

        OTPParameters params = OTPParameters.parseUrl(uri);

        assertEquals(params.getType(), OTPType.HOTP);
        assertEquals(params.getSecret().getEncoded(), "JBSWY3DPEHPK3PXP");
        assertEquals(params.getIssuer(), "Example");
        assertEquals(params.getAlgorithm(), OTPParameters.Algorithm.SHA256);
        assertEquals(params.getDigits(), OTPParameters.Digits.SEVEN);
        assertNull(params.getPeriod());
        assertEquals(params.getCounter().getValue(), 0);
    }
}
