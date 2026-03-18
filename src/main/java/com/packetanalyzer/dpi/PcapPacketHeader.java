package com.packetanalyzer.dpi;

public record PcapPacketHeader(long tsSec, long tsUsec, long inclLen, long origLen) {
}
