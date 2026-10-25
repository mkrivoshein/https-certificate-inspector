package org.agencyapi.x509.inspector.config;

import org.springframework.core.env.Environment;
import org.springframework.util.StringUtils;

import java.nio.file.Path;

final class TlsConfigurationProperties {
    static final String BUNDLE_NAME = "inspector";
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
        if (location.startsWith("http:")) {
            throw new IllegalArgumentException("Plain HTTP TLS material locations are not supported: " + location);
        }

        if (isPemContent(location)
                || location.startsWith("classpath:")
                || location.startsWith("file:")
                || location.startsWith("https:")) {
            return location;
        }

        // Resolve plain paths against the working directory so every consumer sees the same file,
        // regardless of which ResourceLoader it uses.
        return Path.of(location).toAbsolutePath().normalize().toUri().toString();
    }

    /**
     * Spring Boot can only watch TLS material for changes when it lives on the filesystem.
     */
    static boolean isWatchable(String normalizedLocation) {
        return normalizedLocation.startsWith("file:");
    }

    private static boolean isPemContent(String location) {
        return location.startsWith("-----BEGIN");
    }
}
