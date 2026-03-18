package com.packetanalyzer.dpi;

import java.util.Optional;

public final class ClassificationEngine {
    private ClassificationEngine() {
    }

    public static void classify(ParsedPacket packet, FlowRecord flow) {
        if ((flow.appType() == AppType.UNKNOWN || flow.appType() == AppType.HTTPS)
            && flow.sni().isEmpty()
            && packet.hasTcp()
            && packet.dstPort() == 443
            && packet.payloadLength() > 5) {
            Optional<String> sni = SniExtractor.extractTlsSni(packet.payload());
            if (sni.isPresent()) {
                flow.sni(sni.get());
                flow.appType(AppType.fromSni(sni.get()));
                flow.classified(true);
                return;
            }
        }

        if ((flow.appType() == AppType.UNKNOWN || flow.appType() == AppType.HTTP)
            && flow.sni().isEmpty()
            && packet.hasTcp()
            && packet.dstPort() == 80) {
            Optional<String> host = SniExtractor.extractHttpHost(packet.payload());
            if (host.isPresent()) {
                flow.sni(host.get());
                flow.appType(AppType.fromSni(host.get()));
                flow.classified(true);
                return;
            }
        }

        if (flow.appType() == AppType.UNKNOWN && (packet.dstPort() == 53 || packet.srcPort() == 53)) {
            flow.appType(AppType.DNS);
            flow.classified(true);
            if (flow.sni().isEmpty()) {
                SniExtractor.extractDnsQuery(packet.payload()).ifPresent(flow::sni);
            }
            return;
        }

        if (flow.appType() == AppType.UNKNOWN) {
            if (packet.dstPort() == 443) {
                flow.appType(AppType.HTTPS);
            } else if (packet.dstPort() == 80) {
                flow.appType(AppType.HTTP);
            }
        }
    }
}
