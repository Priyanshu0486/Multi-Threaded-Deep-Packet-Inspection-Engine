package com.packetanalyzer.dpi;

import java.nio.charset.StandardCharsets;
import java.util.Optional;

public final class SniExtractor {
    private SniExtractor() {
    }

    public static Optional<String> extractTlsSni(byte[] payload) {
        if (payload.length < 9 || (payload[0] & 0xFF) != 0x16) {
            return Optional.empty();
        }

        int version = NetUtil.readUInt16BE(payload, 1);
        if (version < 0x0300 || version > 0x0304) {
            return Optional.empty();
        }

        int recordLength = NetUtil.readUInt16BE(payload, 3);
        if (recordLength > payload.length - 5 || (payload[5] & 0xFF) != 0x01) {
            return Optional.empty();
        }

        int offset = 9;
        if (offset + 34 >= payload.length) {
            return Optional.empty();
        }

        offset += 2;
        offset += 32;

        int sessionIdLength = payload[offset] & 0xFF;
        offset += 1 + sessionIdLength;
        if (offset + 2 > payload.length) {
            return Optional.empty();
        }

        int cipherSuitesLength = NetUtil.readUInt16BE(payload, offset);
        offset += 2 + cipherSuitesLength;
        if (offset >= payload.length) {
            return Optional.empty();
        }

        int compressionMethodsLength = payload[offset] & 0xFF;
        offset += 1 + compressionMethodsLength;
        if (offset + 2 > payload.length) {
            return Optional.empty();
        }

        int extensionsLength = NetUtil.readUInt16BE(payload, offset);
        offset += 2;
        int extensionsEnd = Math.min(payload.length, offset + extensionsLength);

        while (offset + 4 <= extensionsEnd) {
            int extensionType = NetUtil.readUInt16BE(payload, offset);
            int extensionLength = NetUtil.readUInt16BE(payload, offset + 2);
            offset += 4;
            if (offset + extensionLength > extensionsEnd) {
                return Optional.empty();
            }
            if (extensionType == 0x0000 && extensionLength >= 5) {
                int sniType = payload[offset + 2] & 0xFF;
                int sniLength = NetUtil.readUInt16BE(payload, offset + 3);
                if (sniType != 0x00 || sniLength > extensionLength - 5) {
                    return Optional.empty();
                }
                return Optional.of(new String(payload, offset + 5, sniLength, StandardCharsets.UTF_8));
            }
            offset += extensionLength;
        }

        return Optional.empty();
    }

    public static Optional<String> extractHttpHost(byte[] payload) {
        if (!looksLikeHttp(payload)) {
            return Optional.empty();
        }

        String body = new String(payload, StandardCharsets.ISO_8859_1);
        String[] lines = body.split("\\r?\\n");
        for (String line : lines) {
            if (line.regionMatches(true, 0, "Host:", 0, 5)) {
                String host = line.substring(5).trim();
                int portIndex = host.indexOf(':');
                if (portIndex >= 0) {
                    host = host.substring(0, portIndex);
                }
                return host.isBlank() ? Optional.empty() : Optional.of(host);
            }
        }
        return Optional.empty();
    }

    public static Optional<String> extractDnsQuery(byte[] payload) {
        if (payload.length < 12 || (payload[2] & 0x80) != 0) {
            return Optional.empty();
        }

        int questionCount = NetUtil.readUInt16BE(payload, 4);
        if (questionCount == 0) {
            return Optional.empty();
        }

        int offset = 12;
        StringBuilder domain = new StringBuilder();
        while (offset < payload.length) {
            int labelLength = payload[offset] & 0xFF;
            if (labelLength == 0) {
                break;
            }
            if (labelLength > 63 || offset + 1 + labelLength > payload.length) {
                return Optional.empty();
            }
            if (domain.length() > 0) {
                domain.append('.');
            }
            domain.append(new String(payload, offset + 1, labelLength, StandardCharsets.UTF_8));
            offset += 1 + labelLength;
        }
        return domain.length() == 0 ? Optional.empty() : Optional.of(domain.toString());
    }

    private static boolean looksLikeHttp(byte[] payload) {
        String[] methods = {"GET ", "POST", "PUT ", "HEAD", "DELE", "PATC", "OPTI"};
        if (payload.length < 4) {
            return false;
        }
        for (String method : methods) {
            if (payload[0] == method.charAt(0)
                && payload[1] == method.charAt(1)
                && payload[2] == method.charAt(2)
                && payload[3] == method.charAt(3)) {
                return true;
            }
        }
        return false;
    }
}
