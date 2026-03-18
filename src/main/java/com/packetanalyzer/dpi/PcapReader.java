package com.packetanalyzer.dpi;

import java.io.BufferedInputStream;
import java.io.Closeable;
import java.io.EOFException;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Path;

public final class PcapReader implements Closeable {
    private static final int MAGIC_NATIVE = 0xA1B2C3D4;
    private static final int MAGIC_SWAPPED = 0xD4C3B2A1;

    private final InputStream inputStream;
    private final PcapGlobalHeader globalHeader;

    public PcapReader(Path file) throws IOException {
        this.inputStream = new BufferedInputStream(new FileInputStream(file.toFile()));
        this.globalHeader = readGlobalHeader();
    }

    public PcapGlobalHeader globalHeader() {
        return globalHeader;
    }

    public RawPacket readNextPacket() throws IOException {
        byte[] packetHeaderBytes = inputStream.readNBytes(16);
        if (packetHeaderBytes.length == 0) {
            return null;
        }
        if (packetHeaderBytes.length < 16) {
            throw new EOFException("Truncated PCAP packet header");
        }

        long tsSec = readUInt32(packetHeaderBytes, 0, globalHeader.littleEndian());
        long tsUsec = readUInt32(packetHeaderBytes, 4, globalHeader.littleEndian());
        long inclLen = readUInt32(packetHeaderBytes, 8, globalHeader.littleEndian());
        long origLen = readUInt32(packetHeaderBytes, 12, globalHeader.littleEndian());

        if (inclLen < 0 || inclLen > globalHeader.snapLen() || inclLen > 65535) {
            throw new IOException("Invalid packet length: " + inclLen);
        }

        byte[] data = inputStream.readNBytes((int) inclLen);
        if (data.length != inclLen) {
            throw new EOFException("Truncated PCAP packet data");
        }

        return new RawPacket(new PcapPacketHeader(tsSec, tsUsec, inclLen, origLen), data);
    }

    private PcapGlobalHeader readGlobalHeader() throws IOException {
        byte[] header = inputStream.readNBytes(24);
        if (header.length < 24) {
            throw new EOFException("Missing PCAP global header");
        }

        int magic = readInt32Native(header, 0);
        boolean littleEndian;
        if (magic == MAGIC_NATIVE) {
            littleEndian = true;
        } else if (magic == MAGIC_SWAPPED) {
            littleEndian = false;
        } else {
            throw new IOException("Invalid PCAP magic number: 0x" + Integer.toHexString(magic));
        }

        return new PcapGlobalHeader(
            magic,
            readUInt16(header, 4, littleEndian),
            readUInt16(header, 6, littleEndian),
            readInt32(header, 8, littleEndian),
            readUInt32(header, 12, littleEndian),
            readUInt32(header, 16, littleEndian),
            readUInt32(header, 20, littleEndian),
            littleEndian
        );
    }

    private static int readInt32Native(byte[] data, int offset) {
        return (data[offset] & 0xFF)
            | ((data[offset + 1] & 0xFF) << 8)
            | ((data[offset + 2] & 0xFF) << 16)
            | ((data[offset + 3] & 0xFF) << 24);
    }

    private static int readUInt16(byte[] data, int offset, boolean littleEndian) {
        if (littleEndian) {
            return (data[offset] & 0xFF) | ((data[offset + 1] & 0xFF) << 8);
        }
        return ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);
    }

    private static int readInt32(byte[] data, int offset, boolean littleEndian) {
        return (int) readUInt32(data, offset, littleEndian);
    }

    private static long readUInt32(byte[] data, int offset, boolean littleEndian) {
        if (littleEndian) {
            return (data[offset] & 0xFFL)
                | ((data[offset + 1] & 0xFFL) << 8)
                | ((data[offset + 2] & 0xFFL) << 16)
                | ((data[offset + 3] & 0xFFL) << 24);
        }
        return ((data[offset] & 0xFFL) << 24)
            | ((data[offset + 1] & 0xFFL) << 16)
            | ((data[offset + 2] & 0xFFL) << 8)
            | (data[offset + 3] & 0xFFL);
    }

    @Override
    public void close() throws IOException {
        inputStream.close();
    }
}
