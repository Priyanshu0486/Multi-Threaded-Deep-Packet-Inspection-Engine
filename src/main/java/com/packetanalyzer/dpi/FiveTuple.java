package com.packetanalyzer.dpi;

import java.util.Objects;

public final class FiveTuple {
    private final int srcIp;
    private final int dstIp;
    private final int srcPort;
    private final int dstPort;
    private final int protocol;

    public FiveTuple(int srcIp, int dstIp, int srcPort, int dstPort, int protocol) {
        this.srcIp = srcIp;
        this.dstIp = dstIp;
        this.srcPort = srcPort;
        this.dstPort = dstPort;
        this.protocol = protocol;
    }

    public int srcIp() {
        return srcIp;
    }

    public int dstIp() {
        return dstIp;
    }

    public int srcPort() {
        return srcPort;
    }

    public int dstPort() {
        return dstPort;
    }

    public int protocol() {
        return protocol;
    }

    public FiveTuple reverse() {
        return new FiveTuple(dstIp, srcIp, dstPort, srcPort, protocol);
    }

    public String describe() {
        return NetUtil.intToIp(srcIp) + ":" + srcPort
            + " -> " + NetUtil.intToIp(dstIp) + ":" + dstPort
            + " (" + (protocol == 6 ? "TCP" : protocol == 17 ? "UDP" : protocol) + ")";
    }

    @Override
    public boolean equals(Object object) {
        if (this == object) {
            return true;
        }
        if (!(object instanceof FiveTuple that)) {
            return false;
        }
        return srcIp == that.srcIp
            && dstIp == that.dstIp
            && srcPort == that.srcPort
            && dstPort == that.dstPort
            && protocol == that.protocol;
    }

    @Override
    public int hashCode() {
        return Objects.hash(srcIp, dstIp, srcPort, dstPort, protocol);
    }
}
