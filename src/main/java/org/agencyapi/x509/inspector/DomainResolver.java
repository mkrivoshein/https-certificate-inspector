package org.agencyapi.x509.inspector;

import org.springframework.stereotype.Component;
import org.xbill.DNS.AAAARecord;
import org.xbill.DNS.ARecord;
import org.xbill.DNS.Lookup;
import org.xbill.DNS.Name;
import org.xbill.DNS.Resolver;
import org.xbill.DNS.TextParseException;
import org.xbill.DNS.Type;

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;

/**
 * Resolves a domain's A and AAAA records with dnsjava, so every address the domain publishes can be inspected
 * rather than only the one the OS resolver picks. CNAME chains are followed.
 */
@Component
public class DomainResolver {
    private final Resolver resolver;

    public DomainResolver() {
        this(Lookup.getDefaultResolver());
    }

    DomainResolver(Resolver resolver) {
        this.resolver = resolver;
    }

    /**
     * @return the IPv4 (A) addresses followed by the IPv6 (AAAA) addresses, each in the order the DNS server returned them
     * @throws UnknownHostException if the domain has neither A nor AAAA records
     * @throws IOException if either lookup fails, so a partial answer is never mistaken for a complete one
     */
    public List<InetAddress> resolve(String domain) throws IOException {
        Name name;
        try {
            name = Name.fromString(domain, Name.root);
        } catch (TextParseException e) {
            throw new IllegalArgumentException("Invalid domain name: " + domain, e);
        }

        var addresses = new LinkedHashSet<InetAddress>();
        for (var type : List.of(Type.A, Type.AAAA)) {
            addresses.addAll(lookup(name, type));
        }
        if (addresses.isEmpty()) {
            throw new UnknownHostException("No A or AAAA records found for " + domain);
        }
        return List.copyOf(addresses);
    }

    private List<InetAddress> lookup(Name name, int type) throws IOException {
        var lookup = new Lookup(name, type);
        lookup.setResolver(resolver);
        // a per-lookup cache: answers are not reused across requests
        lookup.setCache(null);
        var records = lookup.run();

        return switch (lookup.getResult()) {
            case Lookup.SUCCESSFUL -> {
                var addresses = new ArrayList<InetAddress>();
                for (var record : records) {
                    if (record instanceof ARecord a) {
                        addresses.add(a.getAddress());
                    } else if (record instanceof AAAARecord aaaa) {
                        addresses.add(aaaa.getAddress());
                    }
                }
                yield addresses;
            }
            case Lookup.HOST_NOT_FOUND, Lookup.TYPE_NOT_FOUND -> List.of();
            default -> throw new IOException("DNS " + Type.string(type) + " lookup for " + name + " failed: " + lookup.getErrorString());
        };
    }
}
