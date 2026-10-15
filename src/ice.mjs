/*
 * The ICE servers GET /ice hands out, from providers:
 *
 * - stunProvider: static STUN URLs.
 * - coturnProvider: a coturn TURN server with use-auth-secret (its "REST API"): credentials made here from the shared secret.
 * - cloudflareProvider: Cloudflare Realtime TURN, credentials from its API.
 *
 * A provider is { name, servers(now) } and answers a list of RTCIceServer entries (or a promise of one); another TURN service is one more provider. Entries that carry credentials go only to the pages of the allowed origins (when there is such a list); entries without (STUN) go to everyone.
 */

import crypto from 'node:crypto';


/**
 * TURN credentials for coturn's use-auth-secret (the "REST API"): the username is "<expiry>:<random>", the credential base64(HMAC-SHA1(secret, username)).
 */
export function turnCredentials(secret, ttlSeconds, nowMs) {
    const username = Math.floor(nowMs / 1000 + ttlSeconds) + ':' + crypto.randomBytes(6).toString('hex');
    return { username, credential: crypto.createHmac('sha1', secret).update(username).digest('base64') };
}


export function stunProvider(urls) {
    return {
        name:    'STUN',
        servers: () => (urls.length ? [{ urls: urls.slice() }] : [])
    };
}

export function coturnProvider({ urls, secret, ttl }) {
    return {
        name:    'coturn TURN',
        servers: (now) => [Object.assign({ urls: urls.slice() }, turnCredentials(secret, ttl, now))]
    };
}


export const CLOUDFLARE_API = 'https://rtc.live.cloudflare.com/v1/turn/keys/';

// Browsers block port 53, so such a URL only times out, and FrameTrail waits for ICE gathering to complete (up to 3 s) before it sends its offer or answer.
function usableURL(url) {
    return typeof url === 'string' && !/:53(\?|$)/.test(url);
}

// Cloudflare's iceServers, without the URLs a browser cannot use and anything that is not an RTCIceServer.
function cleanServers(list) {
    return (Array.isArray(list) ? list : []).flatMap((entry) => {
        if (!entry || typeof entry !== 'object') { return []; }
        const urls = (Array.isArray(entry.urls) ? entry.urls : [entry.urls]).filter(usableURL);
        if (!urls.length) { return []; }
        const server = { urls };
        if (typeof entry.username === 'string' && typeof entry.credential === 'string') {
            server.username = entry.username;
            server.credential = entry.credential;
        }
        return [server];
    });
}

/**
 * Cloudflare Realtime TURN. I mint one set of credentials and hand it out for an hour (options.reuse), so a set has between 23 and 24 hours left when a client gets it, and Cloudflare is not asked on every request. Afterwards I mint a new one in the background and keep handing out the old one meanwhile, while at least half its lifetime is left. When Cloudflare cannot be reached and nothing usable is left, the answer is no TURN (STUN comes from STUN_URLS); I try again at most every 30 s (options.retry).
 *
 * options: keyId, token, ttl (s), now() (ms), fetch, log(level, line), reuse, retry, timeout (ms).
 */
export function cloudflareProvider(options) {

    const ttl       = options.ttl,
          now       = options.now || Date.now,
          fetchImpl = options.fetch || globalThis.fetch,
          log       = options.log || (() => {}),
          reuse     = options.reuse   || 3600000,
          retry     = options.retry   || 30000,
          timeout   = options.timeout || 5000,
          url       = CLOUDFLARE_API + encodeURIComponent(options.keyId) + '/credentials/generate-ice-servers';

    let cached = null,          // { servers, minted, expires } (ms)
        pending = null,
        failedAt = -Infinity;

    const fresh  = (t) => cached && t - cached.minted < reuse,
          usable = (t) => cached && cached.expires - t >= ttl * 500;

    async function mint() {
        const response = await fetchImpl(url, {
            method:  'POST',
            headers: { 'Authorization': 'Bearer ' + options.token, 'Content-Type': 'application/json' },
            body:    JSON.stringify({ ttl }),
            signal:  AbortSignal.timeout(timeout)
        });
        if (!response.ok) { throw new Error('Cloudflare answered ' + response.status); }
        const servers = cleanServers((await response.json()).iceServers);
        if (!servers.some((server) => server.credential)) { throw new Error('Cloudflare answered without TURN credentials'); }
        return servers;
    }

    function refresh() {
        const t = now();
        if (pending) { return pending; }
        if (t - failedAt < retry) { return Promise.resolve(); }
        pending = mint().then((servers) => {
            cached = { servers, minted: t, expires: t + ttl * 1000 };
            failedAt = -Infinity;
        }, (error) => {
            failedAt = t;
            // The message names the status or the network error, never the token.
            log('warn', 'Cloudflare TURN credentials: ' + ((error && error.message) || 'failed') + (usable(now()) ? ' (still handing out the last ones)' : ' (handing out no TURN)'));
        }).finally(() => { pending = null; });
        return pending;
    }

    return {
        name: 'Cloudflare TURN',
        servers(t) {
            if (fresh(t)) { return cached.servers; }
            const refreshing = refresh();
            if (usable(t)) { return cached.servers; }
            return refreshing.then(() => (usable(now()) ? cached.servers : []));
        },
        // At startup: credentials ready before the first request.
        warm: refresh
    };

}


/**
 * An origin as browsers send it (scheme, host, port; no path). Throws on anything else.
 */
export function normalizeOrigin(text) {
    let url;
    try { url = new URL(String(text).trim()); } catch (e) { url = null; }
    if (!url || !/^https?:$/.test(url.protocol) || (url.pathname !== '/' || url.search || url.hash) || url.username || url.password) {
        throw new Error('not an origin (scheme://host[:port], without a path): ' + text);
    }
    return url.origin;
}

const hasCredentials = (server) => server.username !== undefined || server.credential !== undefined;

/**
 * I put the providers' servers together for a request from a page of `origin`: entries with credentials only for allowed origins (all, without a list), every URL once (the first provider that names it keeps it).
 */
export function createIce({ providers = [], allowedOrigins = [] } = {}) {

    const origins = new Set(allowedOrigins.map(normalizeOrigin));

    return {

        providers,

        allowsCredentials(origin) {
            return origins.size === 0 || origins.has(String(origin || ''));
        },

        async servers(origin, now) {
            const results = await Promise.allSettled(providers.map((provider) => provider.servers(now))),
                  credentials = this.allowsCredentials(origin),
                  seen = new Set(),
                  out = [];
            for (const result of results) {
                if (result.status !== 'fulfilled' || !Array.isArray(result.value)) { continue; }
                for (const server of result.value) {
                    if (hasCredentials(server) && !credentials) { continue; }
                    const urls = [].concat(server.urls).filter((url) => !seen.has(url));
                    if (!urls.length) { continue; }
                    urls.forEach((url) => seen.add(url));
                    out.push(Object.assign({}, server, { urls }));
                }
            }
            return out;
        }

    };

}
