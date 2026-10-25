package org.agencyapi.x509.inspector.config;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.EnvironmentPostProcessor;
import org.springframework.boot.context.config.ConfigDataEnvironmentPostProcessor;
import org.springframework.core.Ordered;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.MapPropertySource;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Enables HTTPS only when a server certificate and private key are supplied.
 */
public class ConditionalTlsEnvironmentPostProcessor implements EnvironmentPostProcessor, Ordered {
    private static final String PROPERTY_SOURCE_NAME = "inspectorConditionalTls";
    private static final String BUNDLE_PREFIX = "spring.ssl.bundle.pem." + TlsConfigurationProperties.BUNDLE_NAME;

    @Override
    public void postProcessEnvironment(ConfigurableEnvironment environment, SpringApplication application) {
        var certificate = TlsConfigurationProperties.certificate(environment);
        var privateKey = TlsConfigurationProperties.privateKey(environment);
        var clientCa = TlsConfigurationProperties.clientCa(environment);

        if (!StringUtils.hasText(certificate) && !StringUtils.hasText(privateKey) && !StringUtils.hasText(clientCa)) {
            return;
        }

        if (!StringUtils.hasText(certificate) || !StringUtils.hasText(privateKey)) {
            throw new IllegalStateException("""
                    Both inspector.tls.certificate and inspector.tls.private-key must be provided to enable HTTPS/mTLS.
                    Leave all TLS settings unset to run plain HTTP.""");
        }

        var locations = new ArrayList<>(List.of(
                TlsConfigurationProperties.normalizeResourceLocation(certificate),
                TlsConfigurationProperties.normalizeResourceLocation(privateKey)));

        Map<String, Object> properties = new LinkedHashMap<>();
        properties.put("server.ssl.enabled", "true");
        properties.put("server.ssl.bundle", TlsConfigurationProperties.BUNDLE_NAME);
        properties.put(BUNDLE_PREFIX + ".keystore.certificate", locations.get(0));
        properties.put(BUNDLE_PREFIX + ".keystore.private-key", locations.get(1));

        if (StringUtils.hasText(clientCa)) {
            var clientCaLocation = TlsConfigurationProperties.normalizeResourceLocation(clientCa);
            locations.add(clientCaLocation);
            properties.put(BUNDLE_PREFIX + ".truststore.certificate", clientCaLocation);
            properties.put("server.ssl.client-auth", "need");
        }

        // Hot-reload rotated material when Spring Boot can watch it; classpath or inline PEM content cannot be watched.
        if (locations.stream().allMatch(TlsConfigurationProperties::isWatchable)) {
            properties.put(BUNDLE_PREFIX + ".reload-on-update", "true");
        }

        environment.getPropertySources().remove(PROPERTY_SOURCE_NAME);
        environment.getPropertySources().addFirst(new MapPropertySource(PROPERTY_SOURCE_NAME, properties));
    }

    /**
     * Runs after config data is loaded so {@code inspector.tls.*} from {@code application.yml}, profiles and
     * config imports is visible; the derived properties are still added with the highest precedence.
     */
    @Override
    public int getOrder() {
        return ConfigDataEnvironmentPostProcessor.ORDER + 1;
    }
}
