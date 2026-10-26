package org.agencyapi.x509.inspector;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.xbill.DNS.AAAARecord;
import org.xbill.DNS.ARecord;
import org.xbill.DNS.Lookup;
import org.xbill.DNS.Name;
import org.xbill.DNS.Resolver;
import org.xbill.DNS.TextParseException;
import org.xbill.DNS.Type;

import java.io.IOException;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;

/**
 * Resolves a domain's A and AAAA records with dnsjava, so every address the domain publishes can be inspected
 * rather than only the one the OS resolver picks. CNAME chains are followed. When dnsjava can't resolve the name, the
 * OS resolver is tried as well, which also covers names that only exist in /etc/hosts or behind a search domain.
 */
@Component
public class DomainResolver {
    private static final Logger logger = LoggerFactory.getLogger(DomainResolver.class);

    /**
     * The OS resolver's lookup, {@link InetAddress#getAllByName} outside tests.
     */
    @FunctionalInterface
    interface OsResolver {
        InetAddress[] resolve(String host) throws UnknownHostException;
    }

    private final Resolver resolver;
    private final OsResolver osResolver;

    public DomainResolver() {
        this(Lookup.getDefaultResolver(), InetAddress::getAllByName);
    }

    DomainResolver(Resolver resolver, OsResolver osResolver) {
        this.resolver = resolver;
        this.osResolver = osResolver;
    }

    /**
     * @return the IPv4 (A) addresses followed by the IPv6 (AAAA) addresses, each in the order the resolver returned them
     * @throws UnknownHostException if neither dnsjava nor the OS resolver finds an address
     * @throws IOException if a dnsjava lookup fails and the OS resolver finds no address either; a failed dnsjava
     *                     lookup is never taken as a complete answer
     */
    public List<InetAddress> resolve(String domain) throws IOException {
        Name name;
        try {
            name = Name.fromString(domain, Name.root);
        } catch (TextParseException e) {
            throw new IllegalArgumentException("Invalid domain name: " + domain, e);
        }

        try {
            return resolveWithDnsjava(name, domain);
        } catch (IOException dnsjavaFailure) {
            logger.info("dnsjava could not resolve {} ({}), trying the OS resolver", domain, dnsjavaFailure.getMessage());
            try {
                return resolveWithOs(domain);
            } catch (UnknownHostException osFailure) {
                // report the dnsjava failure, which tells "no records" (404) apart from "lookup failed" (502)
                dnsjavaFailure.addSuppressed(osFailure);
                throw dnsjavaFailure;
            }
        }
    }

    private List<InetAddress> resolveWithDnsjava(Name name, String domain) throws IOException {
        var addresses = new LinkedHashSet<InetAddress>();
        for (var type : List.of(Type.A, Type.AAAA)) {
            addresses.addAll(lookup(name, type));
        }
        if (addresses.isEmpty()) {
            throw new UnknownHostException("No A or AAAA records found for " + domain);
        }
        return List.copyOf(addresses);
    }

    private List<InetAddress> resolveWithOs(String domain) throws UnknownHostException {
        var addresses = List.of(osResolver.resolve(domain));
        if (addresses.isEmpty()) {
            throw new UnknownHostException("The OS resolver found no address for " + domain);
        }
        // same order as the dnsjava answer: IPv4 first, then IPv6
        var ordered = new LinkedHashSet<InetAddress>();
        addresses.stream().filter(Inet4Address.class::isInstance).forEach(ordered::add);
        ordered.addAll(addresses);
        return List.copyOf(ordered);
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
