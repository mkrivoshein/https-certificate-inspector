package org.agencyapi.x509.inspector.config;

import org.junit.jupiter.api.Test;

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
}
