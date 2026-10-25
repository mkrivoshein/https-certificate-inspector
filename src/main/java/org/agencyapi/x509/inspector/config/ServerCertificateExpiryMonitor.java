package org.agencyapi.x509.inspector.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.ssl.SslBundles;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;

/**
 * Exits the application when the TLS material it is actually serving is about to expire.
 * <p>
 * Certificates are read from the live {@code inspector} SSL bundle rather than from disk, so a check always
 * reflects what the web server presents, including material hot-reloaded by Spring Boot after rotation.
 */
@Component
public class ServerCertificateExpiryMonitor implements ApplicationRunner, DisposableBean {
    private static final Logger logger = LoggerFactory.getLogger(ServerCertificateExpiryMonitor.class);
    private static final Duration EXPIRY_EXIT_WINDOW = Duration.ofMinutes(10);
    private static final Duration CHECK_INTERVAL = Duration.ofMinutes(5);
    private static final String THREAD_NAME = "inspector-cert-expiry-monitor";

    private final Environment environment;
    private final SslBundles sslBundles;
    private final ConfigurableApplicationContext applicationContext;
    private final Clock clock;
    private ScheduledExecutorService executorService;

    @Autowired
    public ServerCertificateExpiryMonitor(Environment environment,
                                          SslBundles sslBundles,
                                          ConfigurableApplicationContext applicationContext) {
        this(environment, sslBundles, applicationContext, Clock.systemUTC());
    }

    ServerCertificateExpiryMonitor(Environment environment,
                                   SslBundles sslBundles,
                                   ConfigurableApplicationContext applicationContext,
                                   Clock clock) {
        this.environment = environment;
        this.sslBundles = sslBundles;
        this.applicationContext = applicationContext;
        this.clock = clock;
    }

    @Override
    public void run(ApplicationArguments args) {
        if (!StringUtils.hasText(TlsConfigurationProperties.certificate(environment))) {
            return;
        }

        executorService = Executors.newSingleThreadScheduledExecutor(certificateMonitorThreadFactory());
        executorService.scheduleWithFixedDelay(this::checkCertificates, 0, CHECK_INTERVAL.toSeconds(), TimeUnit.SECONDS);
    }

    @Override
    public void destroy() {
        if (executorService != null) {
            executorService.shutdownNow();
        }
    }

    void checkCertificates() {
        if (isShuttingDown()) {
            return;
        }
        try {
            var stores = sslBundles.getBundle(TlsConfigurationProperties.BUNDLE_NAME).getStores();
            if (checkExpiry(serverCertificates(stores.getKeyStore()), "server TLS certificate")) {
                checkExpiry(trustedCertificates(stores.getTrustStore()), "client CA certificate");
            }
        } catch (Exception e) {
            if (isShuttingDown()) {
                logger.debug("Skipping TLS certificate expiry check during shutdown.", e);
                return;
            }
            logger.error("Unable to verify TLS certificate expiry. Exiting.", e);
            exitApplication();
        }
    }

    /**
     * @return {@code true} if every certificate is outside the exit window
     */
    private boolean checkExpiry(List<X509Certificate> certificates, String description) {
        var exitThreshold = clock.instant().plus(EXPIRY_EXIT_WINDOW);
        for (var certificate : certificates) {
            var expiresAt = certificate.getNotAfter().toInstant();
            if (!expiresAt.isAfter(exitThreshold)) {
                logger.error("{} {} expires at {}, within the {} minute exit window. Exiting.",
                        description, certificate.getSubjectX500Principal().getName(), expiresAt,
                        EXPIRY_EXIT_WINDOW.toMinutes());
                exitApplication();
                return false;
            }
            logger.debug("{} {} expires at {}", description, certificate.getSubjectX500Principal().getName(), expiresAt);
        }
        return true;
    }

    /**
     * Every certificate in each key entry's chain, i.e. the leaf and any intermediates presented to clients.
     */
    static List<X509Certificate> serverCertificates(KeyStore keyStore) throws KeyStoreException {
        var certificates = new ArrayList<X509Certificate>();
        for (var alias : Collections.list(keyStore.aliases())) {
            if (keyStore.isKeyEntry(alias) && keyStore.getCertificateChain(alias) instanceof Certificate[] chain) {
                for (var certificate : chain) {
                    if (certificate instanceof X509Certificate x509) {
                        certificates.add(x509);
                    }
                }
            }
        }
        if (certificates.isEmpty()) {
            throw new IllegalStateException("No server certificate found in SSL bundle "
                    + TlsConfigurationProperties.BUNDLE_NAME);
        }
        return certificates;
    }

    static List<X509Certificate> trustedCertificates(KeyStore trustStore) throws KeyStoreException {
        if (trustStore == null) {
            return List.of();
        }
        var certificates = new ArrayList<X509Certificate>();
        for (var alias : Collections.list(trustStore.aliases())) {
            if (trustStore.isCertificateEntry(alias) && trustStore.getCertificate(alias) instanceof X509Certificate certificate) {
                certificates.add(certificate);
            }
        }
        return certificates;
    }

    void exitApplication() {
        var exitCode = SpringApplication.exit(applicationContext, () -> 1);
        System.exit(exitCode);
    }

    private boolean isShuttingDown() {
        return Thread.currentThread().isInterrupted() || (executorService != null && executorService.isShutdown());
    }

    static ThreadFactory certificateMonitorThreadFactory() {
        return runnable -> {
            var thread = new Thread(runnable, THREAD_NAME);
            thread.setDaemon(true);
            return thread;
        };
    }
}
