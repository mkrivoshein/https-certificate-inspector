package org.agencyapi.x509.inspector.config;

import org.springframework.core.env.Environment;
import org.springframework.util.StringUtils;

import java.nio.file.Path;

final class TlsConfigurationProperties {
    static final String CERTIFICATE_PROPERTY = "inspector.tls.certificate";
    static final String CERTIFICATE_ENV = "INSPECTOR_TLS_CERTIFICATE";
    static final String CERTIFICATE_SHORT_ENV = "INSPECTOR_TLS_CERT";
    static final String PRIVATE_KEY_PROPERTY = "inspector.tls.private-key";
    static final String PRIVATE_KEY_ENV = "INSPECTOR_TLS_PRIVATE_KEY";
    static final String PRIVATE_KEY_SHORT_ENV = "INSPECTOR_TLS_KEY";
    static final String CLIENT_CA_PROPERTY = "inspector.tls.client-ca";
    static final String CLIENT_CA_ENV = "INSPECTOR_TLS_CLIENT_CA";

    private TlsConfigurationProperties() {
    }

    static String certificate(Environment environment) {
        return getFirstPresent(environment, CERTIFICATE_PROPERTY, CERTIFICATE_ENV, CERTIFICATE_SHORT_ENV);
    }

    static String privateKey(Environment environment) {
        return getFirstPresent(environment, PRIVATE_KEY_PROPERTY, PRIVATE_KEY_ENV, PRIVATE_KEY_SHORT_ENV);
    }

    static String clientCa(Environment environment) {
        return getFirstPresent(environment, CLIENT_CA_PROPERTY, CLIENT_CA_ENV);
    }

    static String getFirstPresent(Environment environment, String... names) {
        for (var name : names) {
            var value = environment.getProperty(name);
            if (StringUtils.hasText(value)) {
                return value.trim();
            }
        }
        return null;
    }

    static String normalizeResourceLocation(String location) {
        if (location.startsWith("classpath:")
                || location.startsWith("file:")
                || location.startsWith("http:")
                || location.startsWith("https:")) {
            return location;
        }

        var path = Path.of(location);
        if (path.isAbsolute()) {
            return path.toUri().toString();
        }

        return location;
    }
}
