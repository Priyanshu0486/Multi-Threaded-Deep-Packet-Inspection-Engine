package com.packetanalyzer.dpi;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicLong;

public final class StatsCollector {
    private final AtomicLong totalPackets = new AtomicLong();
    private final AtomicLong totalBytes = new AtomicLong();
    private final AtomicLong forwarded = new AtomicLong();
    private final AtomicLong dropped = new AtomicLong();
    private final AtomicLong tcpPackets = new AtomicLong();
    private final AtomicLong udpPackets = new AtomicLong();
    private final Map<AppType, AtomicLong> appCounts = new ConcurrentHashMap<>();
    private final Map<String, AppType> detectedDomains = new ConcurrentHashMap<>();
    private final List<DroppedPacketInfo> droppedPackets = new CopyOnWriteArrayList<>();

    public void recordIngress(ParsedPacket packet) {
        totalPackets.incrementAndGet();
        totalBytes.addAndGet(packet.rawPacket().data().length);
        if (packet.hasTcp()) {
            tcpPackets.incrementAndGet();
        } else if (packet.hasUdp()) {
            udpPackets.incrementAndGet();
        }
    }

    public void recordClassification(AppType appType, String sni) {
        appCounts.computeIfAbsent(appType, unused -> new AtomicLong()).incrementAndGet();
        if (sni != null && !sni.isBlank()) {
            detectedDomains.putIfAbsent(sni, appType);
        }
    }

    public void recordForwarded() {
        forwarded.incrementAndGet();
    }

    public void recordDropped(ParsedPacket packet, AppType appType, String sni) {
        dropped.incrementAndGet();
        droppedPackets.add(new DroppedPacketInfo(
            packet.srcIp(), packet.dstIp(), packet.srcPort(), packet.dstPort(), packet.protocol(), appType, sni
        ));
    }

    public List<DroppedPacketInfo> getDroppedPackets() {
        return droppedPackets;
    }

    public long totalPackets() {
        return totalPackets.get();
    }

    public long totalBytes() {
        return totalBytes.get();
    }

    public long forwarded() {
        return forwarded.get();
    }

    public long dropped() {
        return dropped.get();
    }

    public long tcpPackets() {
        return tcpPackets.get();
    }

    public long udpPackets() {
        return udpPackets.get();
    }

    public Map<AppType, AtomicLong> appCounts() {
        return appCounts;
    }

    public Map<String, AppType> detectedDomains() {
        return detectedDomains;
    }
}
