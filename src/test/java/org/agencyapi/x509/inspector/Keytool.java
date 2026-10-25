package org.agencyapi.x509.inspector;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Generates throwaway PKCS12 key material with the JDK's keytool so no key material is committed.
 */
final class Keytool {
    static final String PASSWORD = "changeit";

    private Keytool() {
    }

    /**
     * Generates a self-signed EC key pair in {@code keyStore} under {@code alias}, passing any extra keytool arguments
     * (for example {@code "-ext", "aia=ocsp:uri:http://ocsp.example.test"}).
     */
    static void genKeyPair(Path directory, String keyStore, String alias, String dname, String... extraArgs) throws Exception {
        var args = new ArrayList<>(List.of("-genkeypair", "-keystore", keyStore, "-alias", alias, "-dname", dname,
                "-keyalg", "EC", "-groupname", "secp256r1"));
        args.addAll(List.of(extraArgs));
        run(directory, args);
    }

    static X509Certificate exportCertificate(Path directory, String keyStore, String alias) throws Exception {
        var file = alias + ".crt";
        run(directory, List.of("-exportcert", "-keystore", keyStore, "-alias", alias, "-file", file));
        try (InputStream in = Files.newInputStream(directory.resolve(file))) {
            return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(in);
        } catch (IOException | CertificateException e) {
            throw new IllegalStateException("Unable to read exported certificate " + file, e);
        }
    }

    private static void run(Path directory, List<String> args) throws Exception {
        var command = new ArrayList<>(List.of(Path.of(System.getProperty("java.home"), "bin", "keytool").toString()));
        command.addAll(args);
        command.addAll(List.of("-storetype", "PKCS12", "-storepass", PASSWORD));
        var process = new ProcessBuilder(command).directory(directory.toFile()).redirectErrorStream(true).start();
        var output = new String(process.getInputStream().readAllBytes());
        assertThat(process.waitFor()).as("keytool %s%n%s", args, output).isZero();
    }
}
