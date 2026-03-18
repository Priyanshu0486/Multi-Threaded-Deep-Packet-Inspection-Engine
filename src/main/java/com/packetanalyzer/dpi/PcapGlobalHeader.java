package com.packetanalyzer.dpi;

public record PcapGlobalHeader(
    int magicNumber,
    int versionMajor,
    int versionMinor,
    int thisZone,
    long sigFigs,
    long snapLen,
    long network,
    boolean littleEndian
) {
}
