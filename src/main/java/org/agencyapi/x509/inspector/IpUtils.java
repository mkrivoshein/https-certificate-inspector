package org.agencyapi.x509.inspector;

import com.google.common.net.InetAddresses;

public class IpUtils {
    private IpUtils() {
        // hide constructor
    }

    /**
     * Validates IPv4 address format
     */
    public static boolean isValidIPv4(String ip) {
        if (ip == null || ip.isEmpty()) {
            return false;
        }

        var parts = ip.split("\\.");
        if (parts.length != 4) {
            return false;
        }

        try {
            for (String part : parts) {
                int value = Integer.parseInt(part);
                if (value < 0 || value > 255) {
                    return false;
                }
            }
            return true;
        } catch (NumberFormatException e) {
            return false;
        }
    }

    public static boolean isValidIpAddress(String ip) {
        return InetAddresses.isInetAddress(ip);
    }
}
