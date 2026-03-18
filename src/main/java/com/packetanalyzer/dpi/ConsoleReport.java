package com.packetanalyzer.dpi;

import java.util.Comparator;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

public final class ConsoleReport {
    private ConsoleReport() {
    }

    public static void printSingleThreadReport(StatsCollector stats, int flowCount) {
        System.out.println();
        System.out.println("==============================================================");
        System.out.println("Processing Report");
        System.out.println("==============================================================");
        System.out.printf("Total Packets : %d%n", stats.totalPackets());
        System.out.printf("Forwarded     : %d%n", stats.forwarded());
        System.out.printf("Dropped       : %d%n", stats.dropped());
        System.out.printf("Active Flows  : %d%n", flowCount);
        printApps(stats);
        printDomains(stats);
    }

    public static void printMultiThreadReport(
        StatsCollector stats,
        long[] loadBalancerCounts,
        long[] fastPathCounts
    ) {
        System.out.println();
        System.out.println("==============================================================");
        System.out.println("Processing Report");
        System.out.println("==============================================================");
        System.out.printf("Total Packets : %d%n", stats.totalPackets());
        System.out.printf("Total Bytes   : %d%n", stats.totalBytes());
        System.out.printf("TCP Packets   : %d%n", stats.tcpPackets());
        System.out.printf("UDP Packets   : %d%n", stats.udpPackets());
        System.out.printf("Forwarded     : %d%n", stats.forwarded());
        System.out.printf("Dropped       : %d%n", stats.dropped());
        for (int i = 0; i < loadBalancerCounts.length; i++) {
            System.out.printf("LB%-11d: %d%n", i, loadBalancerCounts[i]);
        }
        for (int i = 0; i < fastPathCounts.length; i++) {
            System.out.printf("FP%-11d: %d%n", i, fastPathCounts[i]);
        }
        printApps(stats);
        printDomains(stats);
    }

    private static void printApps(StatsCollector stats) {
        System.out.println();
        System.out.println("Application Breakdown");
        stats.appCounts().entrySet().stream()
            .sorted(Comparator.comparingLong((Map.Entry<AppType, AtomicLong> entry) -> entry.getValue().get()).reversed())
            .forEach(entry -> {
                double percentage = stats.totalPackets() == 0 ? 0.0 : 100.0 * entry.getValue().get() / stats.totalPackets();
                int barLength = (int) (percentage / 5.0);
                System.out.printf("%-15s %8d %6.1f%% %s%n",
                    entry.getKey().displayName(),
                    entry.getValue().get(),
                    percentage,
                    "#".repeat(Math.max(0, barLength)));
            });
    }

    private static void printDomains(StatsCollector stats) {
        if (stats.detectedDomains().isEmpty()) {
            return;
        }
        System.out.println();
        System.out.println("Detected Domains");
        stats.detectedDomains().entrySet().stream()
            .sorted(Map.Entry.comparingByKey())
            .forEach(entry -> System.out.println(" - " + entry.getKey() + " -> " + entry.getValue().displayName()));
    }
}
