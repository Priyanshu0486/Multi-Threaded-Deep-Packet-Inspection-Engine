package com.packetanalyzer.dpi;

import java.util.Optional;

public final class PacketParser {
    private static final int ETHERNET_HEADER_LENGTH = 14;
    private static final int ETHER_TYPE_IPV4 = 0x0800;
    private static final int TCP = 6;
    private static final int UDP = 17;

    private PacketParser() {
    }

    public static Optional<ParsedPacket> parse(RawPacket rawPacket) {
        byte[] data = rawPacket.data();
        if (data.length < ETHERNET_HEADER_LENGTH) {
            return Optional.empty();
        }

        int etherType = NetUtil.readUInt16BE(data, 12);
        if (etherType != ETHER_TYPE_IPV4) {
            return Optional.empty();
        }

        int ipOffset = ETHERNET_HEADER_LENGTH;
        if (data.length < ipOffset + 20) {
            return Optional.empty();
        }

        int version = (data[ipOffset] >>> 4) & 0x0F;
        int ihl = data[ipOffset] & 0x0F;
        int ipHeaderLength = ihl * 4;
        if (version != 4 || ipHeaderLength < 20 || data.length < ipOffset + ipHeaderLength) {
            return Optional.empty();
        }

        int protocol = data[ipOffset + 9] & 0xFF;
        String srcIp = NetUtil.intToIp((int) NetUtil.readUInt32BE(data, ipOffset + 12));
        String dstIp = NetUtil.intToIp((int) NetUtil.readUInt32BE(data, ipOffset + 16));

        int transportOffset = ipOffset + ipHeaderLength;
        boolean hasTcp = false;
        boolean hasUdp = false;
        int srcPort = 0;
        int dstPort = 0;
        int tcpFlags = 0;
        int payloadOffset = transportOffset;

        if (protocol == TCP) {
            if (data.length < transportOffset + 20) {
                return Optional.empty();
            }
            hasTcp = true;
            srcPort = NetUtil.readUInt16BE(data, transportOffset);
            dstPort = NetUtil.readUInt16BE(data, transportOffset + 2);
            int tcpHeaderLength = ((data[transportOffset + 12] >>> 4) & 0x0F) * 4;
            if (tcpHeaderLength < 20 || data.length < transportOffset + tcpHeaderLength) {
                return Optional.empty();
            }
            tcpFlags = data[transportOffset + 13] & 0xFF;
            payloadOffset = transportOffset + tcpHeaderLength;
        } else if (protocol == UDP) {
            if (data.length < transportOffset + 8) {
                return Optional.empty();
            }
            hasUdp = true;
            srcPort = NetUtil.readUInt16BE(data, transportOffset);
            dstPort = NetUtil.readUInt16BE(data, transportOffset + 2);
            payloadOffset = transportOffset + 8;
        }

        int payloadLength = Math.max(0, data.length - payloadOffset);
        return Optional.of(new ParsedPacket(
            rawPacket,
            true,
            srcIp,
            dstIp,
            protocol,
            hasTcp,
            hasUdp,
            srcPort,
            dstPort,
            tcpFlags,
            payloadOffset,
            payloadLength
        ));
    }
}
