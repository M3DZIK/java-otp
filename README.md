# One-time password generator

A simple and easy-to-use Java library with TOTP (Time-based One-Time Password)
and HOTP (HMAC-based One-Time Password) implementations.

## Getting started

First, add the library as a dependency to your Maven project.

```xml
<dependency>
    <groupId>dev.medzik</groupId>
    <artifactId>otp</artifactId>
    <version>1.0.1</version>
</dependency>
```

## Usage

### Parse OTPAuth URI

```java
import dev.medzik.otp.OTPParameters;

String uri = "otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example&algorithm=SHA512&digits=8";

OTPParameters params = OTPParameters.parseUrl(uri);
```

### HOTP (HMAC-based One-Time Passwords)

```java
import dev.medzik.otp.HOTPGenerator;

OTPParameters params = OTPParameters.builder()
        .type(OTPType.HOTP)
        .secret(new OTPParameters.Secret("secret"))
        // more options are available
        .build();

long counter = 1;

String code = HOTPGenerator.generate(params, counter);
boolean valid = HOTPGenerator.verify(params, code, counter);
```

### TOTP (Time-based One-Time Passwords)

```java
import dev.medzik.otp.TOTPGenerator;

OTPParameters params = OTPParameters.builder()
        .type(OTPType.TOTP)
        .secret(new OTPParameters.Secret("secret"))
        // more options are available
        .build();

String code = TOTPGenerator.now(params);
boolean valid = TOTPGenerator.verify(params, code);
```
