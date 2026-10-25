package org.agencyapi.x509.inspector.config;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.boot.ssl.DefaultSslBundleRegistry;
import org.springframework.boot.ssl.SslBundle;
import org.springframework.boot.ssl.jks.JksSslStoreBundle;
import org.springframework.boot.ssl.jks.JksSslStoreDetails;
import org.springframework.context.support.StaticApplicationContext;
import org.springframework.test.util.ReflectionTestUtils;

import java.nio.file.Path;
import java.security.KeyStoreException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Executors;

import static org.assertj.core.api.Assertions.assertThat;

class ServerCertificateExpiryMonitorTest {
    private static final String BUNDLE = TlsConfigurationProperties.BUNDLE_NAME;
    private static final String PASSWORD = "changeit";
    private static final Duration INSIDE_WINDOW = Duration.ofMinutes(5);
    private static final Duration OUTSIDE_WINDOW = Duration.ofHours(1);

    @TempDir
    static Path tlsDirectory;

    /**
     * Generates throwaway TLS material with the JDK's keytool so no key material is committed.
     * Expiry order: client CA (30 days) &lt; server (60 days) &lt; rotated server (90 days).
     */
    @BeforeAll
    static void generateTlsMaterial() throws Exception {
        keytool("-genkeypair", "-keystore", "client-ca.p12", "-alias", "ca", "-dname", "CN=Test Client CA",
                "-ext", "bc:c", "-validity", "30");
        keytool("-exportcert", "-keystore", "client-ca.p12", "-alias", "ca", "-file", "client-ca.crt");
        keytool("-importcert", "-noprompt", "-keystore", "truststore.p12", "-alias", "ca", "-file", "client-ca.crt");
        keytool("-genkeypair", "-keystore", "server.p12", "-alias", "server", "-dname", "CN=localhost",
                "-validity", "60");
        keytool("-genkeypair", "-keystore", "rotated-server.p12", "-alias", "server", "-dname", "CN=localhost",
                "-validity", "90");
    }

    @Test
    void certificateMonitorThreadFactoryCreatesNamedDaemonThread() {
        var thread = ServerCertificateExpiryMonitor.certificateMonitorThreadFactory()
                .newThread(() -> {
                });

        assertThat(thread.getName()).isEqualTo("inspector-cert-expiry-monitor");
        assertThat(thread.isDaemon()).isTrue();
    }

    @Test
    void doesNotExitWhenServedCertificateIsOutsideExitWindow() throws Exception {
        var bundle = bundle("server.p12", null);
        var monitor = monitor(new DefaultSslBundleRegistry(BUNDLE, bundle), serverNotAfter(bundle).minus(OUTSIDE_WINDOW));

        monitor.checkCertificates();

        assertThat(monitor.exitCalled).isFalse();
    }

    @Test
    void exitsWhenServedCertificateIsWithinExitWindow() throws Exception {
        var bundle = bundle("server.p12", null);
        var monitor = monitor(new DefaultSslBundleRegistry(BUNDLE, bundle), serverNotAfter(bundle).minus(INSIDE_WINDOW));

        monitor.checkCertificates();

        assertThat(monitor.exitCalled).isTrue();
    }

    @Test
    void exitsWhenClientCaIsWithinExitWindow() throws Exception {
        var bundle = bundle("server.p12", "truststore.p12");
        var clientCaNotAfter = ServerCertificateExpiryMonitor.trustedCertificates(bundle.getStores().getTrustStore())
                .getFirst().getNotAfter().toInstant();
        var monitor = monitor(new DefaultSslBundleRegistry(BUNDLE, bundle), clientCaNotAfter.minus(INSIDE_WINDOW));

        monitor.checkCertificates();

        assertThat(monitor.exitCalled).isTrue();
    }

    @Test
    void checksReloadedBundleRatherThanStartupBundle() throws Exception {
        var startupBundle = bundle("server.p12", null);
        var registry = new DefaultSslBundleRegistry(BUNDLE, startupBundle);
        var monitor = monitor(registry, serverNotAfter(startupBundle).minus(INSIDE_WINDOW));

        registry.updateBundle(BUNDLE, bundle("rotated-server.p12", null));
        monitor.checkCertificates();

        assertThat(monitor.exitCalled).isFalse();
    }

    @Test
    void exitsWhenBundleCannotBeRead() {
        var monitor = monitor(new DefaultSslBundleRegistry(), Instant.EPOCH);

        monitor.checkCertificates();

        assertThat(monitor.exitCalled).isTrue();
    }

    @Test
    void doesNotExitWhenCheckFailsDuringShutdown() {
        var monitor = monitor(new DefaultSslBundleRegistry(), Instant.EPOCH);
        var executorService = Executors.newSingleThreadScheduledExecutor();
        executorService.shutdownNow();
        ReflectionTestUtils.setField(monitor, "executorService", executorService);

        monitor.checkCertificates();

        assertThat(monitor.exitCalled).isFalse();
    }

    private static void keytool(String... args) throws Exception {
        var command = new ArrayList<>(List.of(Path.of(System.getProperty("java.home"), "bin", "keytool").toString()));
        command.addAll(List.of(args));
        command.addAll(List.of("-storetype", "PKCS12", "-storepass", PASSWORD));
        if (List.of(args).contains("-genkeypair")) {
            command.addAll(List.of("-keyalg", "EC", "-groupname", "secp256r1"));
        }
        var process = new ProcessBuilder(command).directory(tlsDirectory.toFile()).redirectErrorStream(true).start();
        var output = new String(process.getInputStream().readAllBytes());
        assertThat(process.waitFor()).as("keytool %s%n%s", List.of(args), output).isZero();
    }

    private static SslBundle bundle(String keyStore, String trustStore) {
        return SslBundle.of(new JksSslStoreBundle(store(keyStore), trustStore != null ? store(trustStore) : null));
    }

    private static JksSslStoreDetails store(String fileName) {
        return new JksSslStoreDetails("PKCS12", null, tlsDirectory.resolve(fileName).toUri().toString(), PASSWORD);
    }

    private static Instant serverNotAfter(SslBundle bundle) throws KeyStoreException {
        return ServerCertificateExpiryMonitor.serverCertificates(bundle.getStores().getKeyStore())
                .getFirst().getNotAfter().toInstant();
    }

    private static RecordingMonitor monitor(DefaultSslBundleRegistry registry, Instant now) {
        return new RecordingMonitor(registry, Clock.fixed(now, ZoneOffset.UTC));
    }

    private static final class RecordingMonitor extends ServerCertificateExpiryMonitor {
        private boolean exitCalled;

        private RecordingMonitor(DefaultSslBundleRegistry registry, Clock clock) {
            super(null, registry, new StaticApplicationContext(), clock);
        }

        @Override
        void exitApplication() {
            exitCalled = true;
        }
    }
}
