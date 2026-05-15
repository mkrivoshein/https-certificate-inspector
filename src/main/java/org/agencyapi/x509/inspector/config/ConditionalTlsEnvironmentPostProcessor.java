package org.agencyapi.x509.inspector.config;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.EnvironmentPostProcessor;
import org.springframework.core.Ordered;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.MapPropertySource;
import org.springframework.util.StringUtils;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Enables HTTPS only when a server certificate and private key are supplied.
 */
public class ConditionalTlsEnvironmentPostProcessor implements EnvironmentPostProcessor, Ordered {
    private static final String PROPERTY_SOURCE_NAME = "inspectorConditionalTls";
    private static final String BUNDLE_NAME = "inspector";

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

        Map<String, Object> properties = new LinkedHashMap<>();
        properties.put("server.ssl.enabled", "true");
        properties.put("server.ssl.bundle", BUNDLE_NAME);
        properties.put("spring.ssl.bundle.pem." + BUNDLE_NAME + ".keystore.certificate",
                TlsConfigurationProperties.normalizeResourceLocation(certificate));
        properties.put("spring.ssl.bundle.pem." + BUNDLE_NAME + ".keystore.private-key",
                TlsConfigurationProperties.normalizeResourceLocation(privateKey));

        if (StringUtils.hasText(clientCa)) {
            properties.put("spring.ssl.bundle.pem." + BUNDLE_NAME + ".truststore.certificate",
                    TlsConfigurationProperties.normalizeResourceLocation(clientCa));
            properties.put("server.ssl.client-auth", "need");
        }

        environment.getPropertySources().remove(PROPERTY_SOURCE_NAME);
        environment.getPropertySources().addFirst(new MapPropertySource(PROPERTY_SOURCE_NAME, properties));
    }

    @Override
    public int getOrder() {
        return Ordered.HIGHEST_PRECEDENCE;
    }
}
