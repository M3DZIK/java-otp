package dev.medzik.otp;

import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

public final class OneTimePasswordParser {
    /**
     * Parses the given OTP URI and returns the corresponding parameters.
     * @param uri The OTP Auth URI to parse.
     * @return The associated parameters.
     * @throws URISyntaxException If the given URI is invalid.
     * @throws IllegalArgumentException If any parameter in the URI is invalid.
     */
    public static OneTimePasswordParameters parse(String uri) throws URISyntaxException, IllegalArgumentException {
        OneTimePasswordParameters.ParametersBuilder paramsBuilder = OneTimePasswordParameters.builder();

        URI parsedUri = new URI(uri);

        String type = parsedUri.getHost();
        paramsBuilder.type(OneTimePasswordType.get(type));

        // omit the leading "/"
        String label = parsedUri.getPath().substring(1);
        paramsBuilder.label(new OneTimePasswordParameters.Label(label));

        Map<String, String> query = splitQuery(parsedUri);

        for (Map.Entry<String, String> param : query.entrySet()) {
            switch (param.getKey()) {
                case "secret":
                    paramsBuilder.secret(new OneTimePasswordParameters.Secret(param.getValue()));
                    break;
                case "issuer":
                    paramsBuilder.issuer(new OneTimePasswordParameters.Issuer(param.getValue()));
                    break;
                case "algorithm":
                    paramsBuilder.algorithm(OneTimePasswordParameters.Algorithm.valueOf(param.getValue()));
                    break;
                case "digits":
                    paramsBuilder.digits(OneTimePasswordParameters.Digits.valueOf(Integer.parseInt(param.getValue())));
                    break;
                case "period":
                    paramsBuilder.period(OneTimePasswordParameters.Period.valueOf(Integer.parseInt(param.getValue())));
                    break;
                case "counter":
                    paramsBuilder.counter(new OneTimePasswordParameters.Counter(Long.parseLong(param.getValue())));
                    break;
            }
        }

        return paramsBuilder.build();
    }

    private static Map<String, String> splitQuery(URI url) {
        try {
            Map<String, String> query_pairs = new LinkedHashMap<>();
            String query = url.getQuery();
            String[] pairs = query.split("&");
            for (String pair : pairs) {
                int idx = pair.indexOf("=");
                query_pairs.put(
                        URLDecoder.decode(pair.substring(0, idx), StandardCharsets.UTF_8.toString()),
                        URLDecoder.decode(pair.substring(idx + 1), StandardCharsets.UTF_8.toString())
                );
            }

            return query_pairs;
        } catch (UnsupportedEncodingException e) {
            throw new IllegalStateException("URL Decoding should be supported");
        }
    }
}
