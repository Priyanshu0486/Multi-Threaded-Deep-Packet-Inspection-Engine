package com.packetanalyzer.dpi;

public record RawPacket(PcapPacketHeader header, byte[] data) {
}
