package com.packetanalyzer.dpi;

public final class FlowRecord {
    private final FiveTuple tuple;
    private AppType appType = AppType.UNKNOWN;
    private String sni = "";
    private long packets;
    private long bytes;
    private boolean blocked;
    private boolean classified;

    public FlowRecord(FiveTuple tuple) {
        this.tuple = tuple;
    }

    public FiveTuple tuple() {
        return tuple;
    }

    public AppType appType() {
        return appType;
    }

    public void appType(AppType appType) {
        this.appType = appType;
    }

    public String sni() {
        return sni;
    }

    public void sni(String sni) {
        this.sni = sni;
    }

    public void incrementPackets() {
        packets++;
    }

    public void addBytes(long packetBytes) {
        bytes += packetBytes;
    }

    public boolean blocked() {
        return blocked;
    }

    public void blocked(boolean blocked) {
        this.blocked = blocked;
    }

    public boolean classified() {
        return classified;
    }

    public void classified(boolean classified) {
        this.classified = classified;
    }
}
