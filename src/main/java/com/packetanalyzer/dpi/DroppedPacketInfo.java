package com.packetanalyzer.dpi;

public record DroppedPacketInfo(
    String srcIp,
    String dstIp,
    int srcPort,
    int dstPort,
    int protocol,
    AppType appType,
    String sni
) {}
