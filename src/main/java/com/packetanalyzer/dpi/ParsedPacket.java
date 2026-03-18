package com.packetanalyzer.dpi;

public final class ParsedPacket {
    private final RawPacket rawPacket;
    private final boolean hasIp;
    private final String srcIp;
    private final String dstIp;
    private final int protocol;
    private final boolean hasTcp;
    private final boolean hasUdp;
    private final int srcPort;
    private final int dstPort;
    private final int tcpFlags;
    private final int payloadOffset;
    private final int payloadLength;

    public ParsedPacket(
        RawPacket rawPacket,
        boolean hasIp,
        String srcIp,
        String dstIp,
        int protocol,
        boolean hasTcp,
        boolean hasUdp,
        int srcPort,
        int dstPort,
        int tcpFlags,
        int payloadOffset,
        int payloadLength
    ) {
        this.rawPacket = rawPacket;
        this.hasIp = hasIp;
        this.srcIp = srcIp;
        this.dstIp = dstIp;
        this.protocol = protocol;
        this.hasTcp = hasTcp;
        this.hasUdp = hasUdp;
        this.srcPort = srcPort;
        this.dstPort = dstPort;
        this.tcpFlags = tcpFlags;
        this.payloadOffset = payloadOffset;
        this.payloadLength = payloadLength;
    }

    public RawPacket rawPacket() {
        return rawPacket;
    }

    public boolean hasIp() {
        return hasIp;
    }

    public String srcIp() {
        return srcIp;
    }

    public String dstIp() {
        return dstIp;
    }

    public int protocol() {
        return protocol;
    }

    public boolean hasTcp() {
        return hasTcp;
    }

    public boolean hasUdp() {
        return hasUdp;
    }

    public int srcPort() {
        return srcPort;
    }

    public int dstPort() {
        return dstPort;
    }

    public int tcpFlags() {
        return tcpFlags;
    }

    public int payloadLength() {
        return payloadLength;
    }

    public byte[] payload() {
        if (payloadLength <= 0) {
            return new byte[0];
        }
        byte[] payload = new byte[payloadLength];
        System.arraycopy(rawPacket.data(), payloadOffset, payload, 0, payloadLength);
        return payload;
    }
}
