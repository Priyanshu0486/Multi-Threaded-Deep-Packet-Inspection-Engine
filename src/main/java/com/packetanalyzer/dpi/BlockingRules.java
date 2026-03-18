package com.packetanalyzer.dpi;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

public final class BlockingRules {
    private final Set<Integer> blockedIps = ConcurrentHashMap.newKeySet();
    private final Set<AppType> blockedApps = ConcurrentHashMap.newKeySet();
    private final List<String> blockedDomains = new ArrayList<>();

    public void blockIp(String ip) {
        blockedIps.add(NetUtil.ipToInt(ip));
        System.out.println("[Rules] Blocked IP: " + ip);
    }

    public void blockApp(String app) {
        AppType type = AppType.fromName(app);
        if (type == AppType.UNKNOWN) {
            System.err.println("[Rules] Unknown app: " + app);
            return;
        }
        blockedApps.add(type);
        System.out.println("[Rules] Blocked app: " + type.displayName());
    }

    public synchronized void blockDomain(String domain) {
        blockedDomains.add(domain.toLowerCase());
        System.out.println("[Rules] Blocked domain: " + domain);
    }

    public synchronized boolean isBlocked(int srcIp, AppType appType, String sni) {
        if (blockedIps.contains(srcIp) || blockedApps.contains(appType)) {
            return true;
        }
        String candidate = sni == null ? "" : sni.toLowerCase();
        for (String domain : blockedDomains) {
            if (!candidate.isEmpty() && candidate.contains(domain)) {
                return true;
            }
        }
        return false;
    }
}
