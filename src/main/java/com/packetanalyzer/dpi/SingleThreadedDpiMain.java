package com.packetanalyzer.dpi;

import java.io.IOException;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

public final class SingleThreadedDpiMain {
    private SingleThreadedDpiMain() {
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            printUsage();
            return;
        }

        Path input = Path.of(args[0]);
        Path output = Path.of(args[1]);
        BlockingRules rules = parseRules(args, 2);
        StatsCollector stats = new StatsCollector();
        Map<FiveTuple, FlowRecord> flows = new HashMap<>();

        System.out.println("DPI Engine v1.0 (Java, single-threaded)");

        try (PcapReader reader = new PcapReader(input);
             PcapWriter writer = new PcapWriter(output, reader.globalHeader())) {

            RawPacket rawPacket;
            while ((rawPacket = reader.readNextPacket()) != null) {
                Optional<ParsedPacket> parsedOptional = PacketParser.parse(rawPacket);
                if (parsedOptional.isEmpty()) {
                    continue;
                }

                ParsedPacket packet = parsedOptional.get();
                if (!packet.hasIp() || (!packet.hasTcp() && !packet.hasUdp())) {
                    continue;
                }

                stats.recordIngress(packet);
                FiveTuple tuple = new FiveTuple(
                    NetUtil.ipToInt(packet.srcIp()),
                    NetUtil.ipToInt(packet.dstIp()),
                    packet.srcPort(),
                    packet.dstPort(),
                    packet.protocol()
                );

                FlowRecord flow = flows.computeIfAbsent(tuple, FlowRecord::new);
                flow.incrementPackets();
                flow.addBytes(packet.rawPacket().data().length);
                ClassificationEngine.classify(packet, flow);

                if (!flow.blocked()) {
                    boolean blocked = rules.isBlocked(tuple.srcIp(), flow.appType(), flow.sni());
                    flow.blocked(blocked);
                    if (blocked) {
                        System.out.printf("[BLOCKED] %s -> %s (%s%s)%n",
                            packet.srcIp(),
                            packet.dstIp(),
                            flow.appType().displayName(),
                            flow.sni().isEmpty() ? "" : ": " + flow.sni());
                    }
                }

                stats.recordClassification(flow.appType(), flow.sni());
                if (flow.blocked()) {
                    stats.recordDropped();
                } else {
                    stats.recordForwarded();
                    writer.writePacket(rawPacket);
                }
            }
        } catch (IOException exception) {
            System.err.println("Failed to process PCAP: " + exception.getMessage());
            throw exception;
        }

        ConsoleReport.printSingleThreadReport(stats, flows.size());
        System.out.println();
        System.out.println("Output written to: " + output.toAbsolutePath());
    }

    private static BlockingRules parseRules(String[] args, int startIndex) {
        BlockingRules rules = new BlockingRules();
        for (int i = startIndex; i < args.length; i++) {
            switch (args[i]) {
                case "--block-ip" -> {
                    if (i + 1 < args.length) {
                        rules.blockIp(args[++i]);
                    }
                }
                case "--block-app" -> {
                    if (i + 1 < args.length) {
                        rules.blockApp(args[++i]);
                    }
                }
                case "--block-domain" -> {
                    if (i + 1 < args.length) {
                        rules.blockDomain(args[++i]);
                    }
                }
                default -> {
                }
            }
        }
        return rules;
    }

    private static void printUsage() {
        System.out.println("Usage: java ... SingleThreadedDpiMain <input.pcap> <output.pcap> [options]");
        System.out.println("Options:");
        System.out.println("  --block-ip <ip>");
        System.out.println("  --block-app <app>");
        System.out.println("  --block-domain <domain>");
    }
}
