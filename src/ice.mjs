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
export const CLOUDFLARE_GRAPHQL = 'https://api.cloudflare.com/client/v4/graphql';

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

const gigabytes = (bytes) => (bytes / 1e9).toFixed(1) + ' GB';
const monthOf = (t) => new Date(t).toISOString().slice(0, 7);

/**
 * Cloudflare Realtime TURN. I mint one set of credentials and hand it out for an hour (options.reuse), so a set has between 23 and 24 hours left when a client gets it, and Cloudflare is not asked on every request. Afterwards I mint a new one in the background and keep handing out the old one meanwhile, while at least half its lifetime is left. When Cloudflare cannot be reached and nothing usable is left, the answer is no TURN (STUN comes from STUN_URLS); I try again at most every 30 s (options.retry).
 *
 * With options.guard I keep the month's bill in check, since anyone can fetch credentials from /ice and relay through them: every 5 minutes (guard.every) I ask Cloudflare's analytics how many bytes this TURN key relayed to clients since the 1st of the month (UTC), which is what Cloudflare bills. At 80 % of guard.limit I warn once; at the limit I hand out no TURN until the next month and revoke every set I issued that has not expired, which ends the relays made with them. When the analytics cannot be read, TURN stays as it is and the log says so.
 *
 * options: keyId, token, ttl (s), now() (ms), fetch, log(level, line), reuse, retry, timeout (ms); guard: { accountId, token, limit (bytes), every (ms) }.
 */
export function cloudflareProvider(options) {

    const ttl       = options.ttl,
          now       = options.now || Date.now,
          fetchImpl = options.fetch || globalThis.fetch,
          log       = options.log || (() => {}),
          reuse     = options.reuse   || 3600000,
          retry     = options.retry   || 30000,
          timeout   = options.timeout || 5000,
          guard     = options.guard || null,
          key       = CLOUDFLARE_API + encodeURIComponent(options.keyId),
          headers   = { 'Authorization': 'Bearer ' + options.token, 'Content-Type': 'application/json' };

    let cached = null,          // { servers, minted, expires } (ms)
        pending = null,
        failedAt = -Infinity,
        issued = [],            // every set minted and not yet revoked: { username, expires } (ms)
        blocked = null,         // the month (YYYY-MM) whose limit is reached: no TURN
        warned = null,          // the month whose 80 % have been warned about
        guardWorks = null,      // did the last look at the analytics work? (logged when that changes)
        timer = null;

    const fresh  = (t) => cached && t - cached.minted < reuse,
          usable = (t) => cached && cached.expires - t >= ttl * 500;

    async function mint() {
        const response = await fetchImpl(key + '/credentials/generate-ice-servers', {
            method:  'POST',
            headers,
            body:    JSON.stringify({ ttl }),
            signal:  AbortSignal.timeout(timeout)
        });
        if (!response.ok) { throw new Error('Cloudflare answered ' + response.status); }
        const servers = cleanServers((await response.json()).iceServers);
        if (!servers.some((server) => server.credential)) { throw new Error('Cloudflare answered without TURN credentials'); }
        return servers;
    }

    // Ends a set at Cloudflare, with the relays made with it.
    async function revoke(username) {
        const response = await fetchImpl(key + '/credentials/' + encodeURIComponent(username) + '/revoke', { method: 'POST', headers, signal: AbortSignal.timeout(timeout) });
        if (!response.ok) { throw new Error('Cloudflare answered ' + response.status); }
    }

    function refresh() {
        const t = now();
        if (pending) { return pending; }
        if (blocked || t - failedAt < retry) { return Promise.resolve(); }
        pending = mint().then((servers) => {
            const usernames = servers.filter((server) => server.username).map((server) => server.username);
            // The limit was reached while this set was being minted: it goes back at once.
            if (blocked) { return Promise.allSettled(usernames.map(revoke)); }
            cached = { servers, minted: t, expires: t + ttl * 1000 };
            issued = issued.filter((set) => set.expires > t).concat(usernames.map((username) => ({ username, expires: t + ttl * 1000 })));
            failedAt = -Infinity;
        }, (error) => {
            failedAt = t;
            // The message names the status or the network error, never the token.
            log('warn', 'Cloudflare TURN credentials: ' + ((error && error.message) || 'failed') + (usable(now()) ? ' (still handing out the last ones)' : ' (handing out no TURN)'));
        }).finally(() => { pending = null; });
        return pending;
    }

    // How many bytes this key relayed to clients this month, from Cloudflare's GraphQL analytics.
    async function usage(t) {
        const filter = '{ keyId: ' + JSON.stringify(options.keyId) + ', date_geq: ' + JSON.stringify(monthOf(t) + '-01') + ', date_leq: ' + JSON.stringify(new Date(t).toISOString().slice(0, 10)) + ' }',
              query = 'query { viewer { accounts(filter: { accountTag: ' + JSON.stringify(guard.accountId) + ' }) { callsTurnUsageAdaptiveGroups(limit: 10000, filter: ' + filter + ') { sum { egressBytes } } } } }';
        const response = await fetchImpl(CLOUDFLARE_GRAPHQL, {
            method:  'POST',
            headers: { 'Authorization': 'Bearer ' + guard.token, 'Content-Type': 'application/json' },
            body:    JSON.stringify({ query }),
            signal:  AbortSignal.timeout(timeout * 2)
        });
        if (!response.ok) { throw new Error('Cloudflare analytics answered ' + response.status); }
        const json = await response.json();
        if (json && Array.isArray(json.errors) && json.errors.length) { throw new Error('Cloudflare analytics: ' + json.errors[0].message); }
        const accounts = json && json.data && json.data.viewer && json.data.viewer.accounts;
        if (!Array.isArray(accounts) || !accounts.length) { throw new Error('Cloudflare analytics: no such account, or the token may not read it'); }
        return (accounts[0].callsTurnUsageAdaptiveGroups || []).reduce((sum, group) => sum + (Number(group && group.sum && group.sum.egressBytes) || 0), 0);
    }

    async function checkUsage() {
        const t = now(), month = monthOf(t);
        let bytes;
        try {
            bytes = await usage(t);
        } catch (error) {
            if (guardWorks !== false) {
                log('warn', 'Cloudflare TURN usage guard: ' + ((error && error.message) || 'failed') + (blocked ? ' (TURN stays off)' : ' (TURN stays on)'));
            }
            guardWorks = false;
            return;
        }
        if (guardWorks !== true) {
            log('info', 'Cloudflare TURN usage this month: ' + gigabytes(bytes) + ' of the limit of ' + gigabytes(guard.limit));
        }
        guardWorks = true;
        if (blocked && blocked !== month && bytes < guard.limit) {
            blocked = null;
            log('info', 'Cloudflare TURN on again for a new month (' + gigabytes(bytes) + ' of ' + gigabytes(guard.limit) + ')');
        }
        if (!blocked && bytes >= guard.limit) {
            blocked = month;
            cached = null;
            const live = issued.filter((set) => set.expires > t);
            issued = [];
            const results = await Promise.allSettled(live.map((set) => revoke(set.username))),
                  failed = results.filter((result) => result.status === 'rejected').length;
            log('warn', 'Cloudflare TURN usage this month: ' + gigabytes(bytes) + ', the limit of ' + gigabytes(guard.limit) + ' is reached. No TURN until next month; revoked '
                + (live.length - failed) + ' of ' + live.length + ' credential sets.');
        } else if (!blocked && bytes >= guard.limit * 0.8 && warned !== month) {
            warned = month;
            log('warn', 'Cloudflare TURN usage this month: ' + gigabytes(bytes) + ', 80 % of the limit of ' + gigabytes(guard.limit));
        }
    }

    return {
        name: 'Cloudflare TURN' + (guard ? ' (at most ' + gigabytes(guard.limit) + ' a month)' : ''),
        servers(t) {
            if (blocked) { return []; }
            if (fresh(t)) { return cached.servers; }
            const refreshing = refresh();
            if (usable(t)) { return cached.servers; }
            return refreshing.then(() => (!blocked && usable(now()) ? cached.servers : []));
        },
        // Credentials ready before the first request.
        warm: refresh,
        checkUsage,
        // At startup: the usage first (it may be over the limit already), then credentials, then a look at the usage every 5 minutes.
        async start() {
            if (guard && !timer) {
                timer = setInterval(checkUsage, guard.every || 300000);
                timer.unref();
                await checkUsage();
            }
            await refresh();
        },
        stop() {
            clearInterval(timer);
            timer = null;
        },
        get blocked() { return blocked; }
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
