import * as config from "config";

export interface DimensionConfig {
    web: {
        port: number;
        address: string;
    };
    homeserver: {
        name: string;
        accessToken: string;
        clientServerUrl: string;
        federationUrl: string;
        mediaUrl: string;
    };
    widgetBlacklist: string[];
    database: {
        file: string;
        botData: string;
        uri: string;
    };
    admins: string[];
    goneb: {
        avatars: {
            [botType: string]: string; // mxc
        };
    };
    telegram: {
        botToken: string;
    };
    bigbluebutton: {
        apiBaseUrl: string;
        sharedSecret: string;
        widgetName: string;
        widgetTitle: string;
        widgetAvatarUrl: string;
    };
    stickers: {
        enabled: boolean;
        stickerBot: string;
        managerUrl: string;
    };
    dimension: {
        publicUrl: string;
    };
    security: {
        // Trust the X-Forwarded-* headers from this many reverse-proxy hops.
        // Set to 0 to disable (don't trust any proxy).
        // Set to 1 if behind a single reverse proxy (caddy/nginx/cloudflare).
        trustProxyHops: number;

        // Max request body size accepted by body-parser. Default 1mb.
        // The previous default of 512mb was a DoS vector — see CVE mitigation in
        // SECURITY.md § "Express hardening (v2)".
        bodyLimit: string;

        // CORS allowlist. Empty array = same-origin only (no CORS).
        // Put full origins here, e.g. ["https://element.example.com"].
        corsOrigins: string[];

        // Rate-limit window for the API surface (per IP). 0 disables.
        rateLimitWindowMs: number;
        rateLimitMax: number;

        // Allow the deprecated `scalar_token` query-param auth (Matrix legacy).
        // Defaults to false; set true ONLY during migration from legacy Scalar.
        allowLegacyScalarToken: boolean;

        // Set Content-Security-Policy: default-src 'self'. If your frontend
        // talks to additional origins (e.g. embedded widgets, CDNs), add them
        // to cspExtraConnectSrc / cspExtraFrameSrc / cspExtraScriptSrc.
        cspEnabled: boolean;
        cspExtraConnectSrc: string[];
        cspExtraFrameSrc: string[];
        cspExtraScriptSrc: string[];
        cspExtraStyleSrc: string[];
        cspExtraImgSrc: string[];
    };
}

//TODO: We should better use the .get function from node config
export default config as unknown as DimensionConfig;
