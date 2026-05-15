package org.agencyapi.x509.inspector.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.core.env.Environment;
import org.springframework.core.io.ResourceLoader;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.io.InputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;

@Component
public class ServerCertificateExpiryMonitor implements ApplicationRunner, DisposableBean {
    private static final Logger logger = LoggerFactory.getLogger(ServerCertificateExpiryMonitor.class);
    private static final Duration EXPIRY_EXIT_WINDOW = Duration.ofMinutes(10);
    private static final Duration CHECK_INTERVAL = Duration.ofMinutes(5);
    private static final String THREAD_NAME = "inspector-cert-expiry-monitor";

    private final Environment environment;
    private final ResourceLoader resourceLoader;
    private final ConfigurableApplicationContext applicationContext;
    private final Clock clock;
    private ScheduledExecutorService executorService;

    @Autowired
    public ServerCertificateExpiryMonitor(Environment environment,
                                          ResourceLoader resourceLoader,
                                          ConfigurableApplicationContext applicationContext) {
        this(environment, resourceLoader, applicationContext, Clock.systemUTC());
    }

    ServerCertificateExpiryMonitor(Environment environment,
                                   ResourceLoader resourceLoader,
                                   ConfigurableApplicationContext applicationContext,
                                   Clock clock) {
        this.environment = environment;
        this.resourceLoader = resourceLoader;
        this.applicationContext = applicationContext;
        this.clock = clock;
    }

    @Override
    public void run(ApplicationArguments args) {
        var certificateLocation = TlsConfigurationProperties.certificate(environment);
        var clientCaLocation = TlsConfigurationProperties.clientCa(environment);
        if (!StringUtils.hasText(certificateLocation) && !StringUtils.hasText(clientCaLocation)) {
            return;
        }

        executorService = Executors.newSingleThreadScheduledExecutor(certificateMonitorThreadFactory());
        executorService.scheduleWithFixedDelay(
                () -> checkCertificates(certificateLocation, clientCaLocation),
                0,
                CHECK_INTERVAL.toSeconds(),
                TimeUnit.SECONDS);
    }

    @Override
    public void destroy() {
        if (executorService != null) {
            executorService.shutdownNow();
        }
    }

    private void checkCertificates(String certificateLocation, String clientCaLocation) {
        if (isShuttingDown()) {
            return;
        }
        if (StringUtils.hasText(certificateLocation)) {
            checkCertificate(certificateLocation, "server TLS certificate", true);
        }
        if (StringUtils.hasText(clientCaLocation)) {
            checkCertificate(clientCaLocation, "client CA certificate", false);
        }
    }

    void checkCertificate(String certificateLocation, String description, boolean firstCertificateOnly) {
        try {
            for (var certificate : loadCertificates(certificateLocation, firstCertificateOnly)) {
                var expiresAt = certificate.getNotAfter().toInstant();
                var exitThreshold = clock.instant().plus(EXPIRY_EXIT_WINDOW);
                if (!expiresAt.isAfter(exitThreshold)) {
                    logger.error("{} expires at {}, within the {} minute exit window. Exiting.",
                            description, expiresAt, EXPIRY_EXIT_WINDOW.toMinutes());
                    exitApplication();
                } else {
                    logger.debug("{} expires at {}", description, expiresAt);
                }
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            logger.debug("Skipping {} expiry check due to thread interruption.", description, e);
        } catch (Exception e) {
            if (Thread.currentThread().isInterrupted() || isShuttingDown()) {
                logger.debug("Skipping {} expiry check during shutdown.", description, e);
                return;
            }
            logger.error("Unable to verify {} expiry. Exiting.", description, e);
            exitApplication();
        }
    }

    List<X509Certificate> loadCertificates(String certificateLocation, boolean firstCertificateOnly) throws Exception {
        var resourceLocation = TlsConfigurationProperties.normalizeResourceLocation(certificateLocation);
        var resource = resourceLoader.getResource(resourceLocation);
        try (InputStream inputStream = resource.getInputStream()) {
            var certificateFactory = CertificateFactory.getInstance("X.509");
            Collection<X509Certificate> certificates = certificateFactory.generateCertificates(inputStream)
                    .stream()
                    .filter(X509Certificate.class::isInstance)
                    .map(X509Certificate.class::cast)
                    .toList();
            if (certificates.isEmpty()) {
                throw new IllegalStateException("No X.509 certificate found in " + certificateLocation);
            }

            if (firstCertificateOnly) {
                return List.of(certificates.iterator().next());
            }

            return new ArrayList<>(certificates);
        }
    }

    void exitApplication() {
        var exitCode = SpringApplication.exit(applicationContext, () -> 1);
        System.exit(exitCode);
    }

    private boolean isShuttingDown() {
        return executorService != null && executorService.isShutdown();
    }

    static ThreadFactory certificateMonitorThreadFactory() {
        return runnable -> {
            var thread = new Thread(runnable, THREAD_NAME);
            thread.setDaemon(true);
            return thread;
        };
    }
}
