package com.packetanalyzer.dpi;

import java.util.Locale;

public enum AppType {
    UNKNOWN("Unknown"),
    HTTP("HTTP"),
    HTTPS("HTTPS"),
    DNS("DNS"),
    TLS("TLS"),
    QUIC("QUIC"),
    GOOGLE("Google"),
    FACEBOOK("Facebook"),
    YOUTUBE("YouTube"),
    TWITTER("Twitter/X"),
    INSTAGRAM("Instagram"),
    NETFLIX("Netflix"),
    AMAZON("Amazon"),
    MICROSOFT("Microsoft"),
    APPLE("Apple"),
    WHATSAPP("WhatsApp"),
    TELEGRAM("Telegram"),
    TIKTOK("TikTok"),
    SPOTIFY("Spotify"),
    ZOOM("Zoom"),
    DISCORD("Discord"),
    GITHUB("GitHub"),
    CLOUDFLARE("Cloudflare");

    private final String displayName;

    AppType(String displayName) {
        this.displayName = displayName;
    }

    public String displayName() {
        return displayName;
    }

    public static AppType fromName(String value) {
        if (value == null || value.isBlank()) {
            return UNKNOWN;
        }
        String normalized = value.trim().toLowerCase(Locale.ROOT);
        for (AppType type : values()) {
            if (type.displayName.toLowerCase(Locale.ROOT).equals(normalized)
                || type.name().toLowerCase(Locale.ROOT).equals(normalized)) {
                return type;
            }
        }
        return UNKNOWN;
    }

    public static AppType fromSni(String sni) {
        if (sni == null || sni.isBlank()) {
            return UNKNOWN;
        }

        String lower = sni.toLowerCase(Locale.ROOT);

        if (containsAny(lower, "youtube", "ytimg", "yt3.ggpht") || domainMatches(lower, "youtu.be")) {
            return YOUTUBE;
        }
        if (containsAny(lower, "google", "gstatic", "googleapis", "ggpht", "gvt1")) {
            return GOOGLE;
        }
        if (containsAny(lower, "facebook", "fbcdn", "fbsbx", "meta.com") || domainMatches(lower, "fb.com")) {
            return FACEBOOK;
        }
        if (containsAny(lower, "instagram", "cdninstagram")) {
            return INSTAGRAM;
        }
        if (containsAny(lower, "whatsapp") || domainMatches(lower, "wa.me")) {
            return WHATSAPP;
        }
        if (containsAny(lower, "twitter", "twimg") || domainMatches(lower, "x.com") || domainMatches(lower, "t.co")) {
            return TWITTER;
        }
        if (containsAny(lower, "netflix", "nflxvideo", "nflximg")) {
            return NETFLIX;
        }
        if (containsAny(lower, "amazon", "amazonaws", "cloudfront", "aws")) {
            return AMAZON;
        }
        if (containsAny(lower, "microsoft", "msn.com", "office", "azure", "live.com", "outlook", "bing")) {
            return MICROSOFT;
        }
        if (containsAny(lower, "apple", "icloud", "mzstatic", "itunes")) {
            return APPLE;
        }
        if (containsAny(lower, "telegram") || domainMatches(lower, "t.me")) {
            return TELEGRAM;
        }
        if (containsAny(lower, "tiktok", "tiktokcdn", "musical.ly", "bytedance")) {
            return TIKTOK;
        }
        if (containsAny(lower, "spotify") || domainMatches(lower, "scdn.co")) {
            return SPOTIFY;
        }
        if (containsAny(lower, "zoom")) {
            return ZOOM;
        }
        if (containsAny(lower, "discord", "discordapp")) {
            return DISCORD;
        }
        if (containsAny(lower, "github", "githubusercontent")) {
            return GITHUB;
        }
        if (containsAny(lower, "cloudflare", "cf-")) {
            return CLOUDFLARE;
        }

        return HTTPS;
    }

    private static boolean containsAny(String value, String... patterns) {
        for (String pattern : patterns) {
            if (value.contains(pattern)) {
                return true;
            }
        }
        return false;
    }

    private static boolean domainMatches(String value, String domain) {
        return value.equals(domain) || value.endsWith("." + domain);
    }
}
