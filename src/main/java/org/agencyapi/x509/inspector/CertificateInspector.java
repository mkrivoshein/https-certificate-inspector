package org.agencyapi.x509.inspector;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;

import java.io.IOException;
import java.net.URISyntaxException;

@SpringBootApplication
public class CertificateInspector {
    private final CertificateFetcher certificateFetcher;

    public CertificateInspector(CertificateFetcher certificateFetcher) {
        this.certificateFetcher = certificateFetcher;
    }

    static void main(String[] args) {
        SpringApplication.run(CertificateInspector.class, args);
    }

    @EventListener(ApplicationReadyEvent.class)
    public void onApplicationStartup() throws IOException, URISyntaxException {
        var result = certificateFetcher.fetchCertificate("https://agencyapi.org", true);
        result.forEach(CertificateUtils::printCertificateDetails);
    }
}
