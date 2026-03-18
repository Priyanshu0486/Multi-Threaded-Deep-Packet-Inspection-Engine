package com.packetanalyzer.dpi;

import java.io.BufferedOutputStream;
import java.io.Closeable;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Path;

public final class PcapWriter implements Closeable {
    private final OutputStream outputStream;
    private final boolean littleEndian;

    public PcapWriter(Path file, PcapGlobalHeader header) throws IOException {
        this.outputStream = new BufferedOutputStream(new FileOutputStream(file.toFile()));
        this.littleEndian = header.littleEndian();
        writeGlobalHeader(header);
    }

    public synchronized void writePacket(RawPacket packet) throws IOException {
        writeUInt32(packet.header().tsSec());
        writeUInt32(packet.header().tsUsec());
        writeUInt32(packet.header().inclLen());
        writeUInt32(packet.header().origLen());
        outputStream.write(packet.data());
    }

    private void writeGlobalHeader(PcapGlobalHeader header) throws IOException {
        writeInt32(header.magicNumber());
        writeUInt16(header.versionMajor());
        writeUInt16(header.versionMinor());
        writeInt32(header.thisZone());
        writeUInt32(header.sigFigs());
        writeUInt32(header.snapLen());
        writeUInt32(header.network());
    }

    private void writeUInt16(int value) throws IOException {
        if (littleEndian) {
            outputStream.write(value & 0xFF);
            outputStream.write((value >>> 8) & 0xFF);
        } else {
            outputStream.write((value >>> 8) & 0xFF);
            outputStream.write(value & 0xFF);
        }
    }

    private void writeInt32(int value) throws IOException {
        writeUInt32(value & 0xFFFFFFFFL);
    }

    private void writeUInt32(long value) throws IOException {
        if (littleEndian) {
            outputStream.write((int) (value & 0xFF));
            outputStream.write((int) ((value >>> 8) & 0xFF));
            outputStream.write((int) ((value >>> 16) & 0xFF));
            outputStream.write((int) ((value >>> 24) & 0xFF));
        } else {
            outputStream.write((int) ((value >>> 24) & 0xFF));
            outputStream.write((int) ((value >>> 16) & 0xFF));
            outputStream.write((int) ((value >>> 8) & 0xFF));
            outputStream.write((int) (value & 0xFF));
        }
    }

    @Override
    public void close() throws IOException {
        outputStream.close();
    }
}
