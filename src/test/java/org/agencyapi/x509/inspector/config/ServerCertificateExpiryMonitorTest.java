package org.agencyapi.x509.inspector.config;

import org.junit.jupiter.api.Test;
import org.springframework.context.support.StaticApplicationContext;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.Clock;
import java.util.List;
import java.util.concurrent.Executors;

import static org.assertj.core.api.Assertions.assertThat;

class ServerCertificateExpiryMonitorTest {
    @Test
    void certificateMonitorThreadFactoryCreatesNamedDaemonThread() {
        var thread = ServerCertificateExpiryMonitor.certificateMonitorThreadFactory()
                .newThread(() -> {
                });

        assertThat(thread.getName()).isEqualTo("inspector-cert-expiry-monitor");
        assertThat(thread.isDaemon()).isTrue();
    }

    @Test
    void doesNotExitWhenCertificateLoadingIsInterrupted() {
        var monitor = new TestableServerCertificateExpiryMonitor(new InterruptedException("shutdown"));

        Thread.currentThread().interrupt();
        try {
            monitor.checkCertificate("ignored", "server TLS certificate", true);

            assertThat(monitor.exitCalled).isFalse();
            assertThat(Thread.currentThread().isInterrupted()).isTrue();
        } finally {
            Thread.interrupted();
        }
    }

    @Test
    void doesNotExitWhenCertificateCheckFailsDuringShutdown() {
        var monitor = new TestableServerCertificateExpiryMonitor(new IllegalStateException("boom"));
        var executorService = Executors.newSingleThreadScheduledExecutor();
        executorService.shutdownNow();
        ReflectionTestUtils.setField(monitor, "executorService", executorService);
        try {
            monitor.checkCertificate("ignored", "server TLS certificate", true);

            assertThat(monitor.exitCalled).isFalse();
        } finally {
            executorService.shutdownNow();
        }
    }

    private static final class TestableServerCertificateExpiryMonitor extends ServerCertificateExpiryMonitor {
        private final Exception failure;
        private boolean exitCalled;

        private TestableServerCertificateExpiryMonitor(Exception failure) {
            super(null, new DefaultResourceLoader(), new StaticApplicationContext(), Clock.systemUTC());
            this.failure = failure;
        }

        @Override
        List<java.security.cert.X509Certificate> loadCertificates(String certificateLocation, boolean firstCertificateOnly) throws Exception {
            throw failure;
        }

        @Override
        void exitApplication() {
            exitCalled = true;
        }
    }
}
