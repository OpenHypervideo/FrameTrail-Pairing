#!/usr/bin/env node
/*
 * The FrameTrail pairing broker: the small HTTP service through which a FrameTrail player (the host) and phones (the guests) exchange their WebRTC offers and answers. It implements contract v1 (FrameTrail's docs/PAIRING.md, "Broker Contract") and grew from FrameTrail's stub (scripts/pairing-broker.mjs), whose options it keeps. Node 20 or later, no dependencies:
 *
 *     node src/pairing-broker.mjs                   # http://localhost:8787, LAN only (GET /ice: no servers)
 *     node src/pairing-broker.mjs --help            # every option and its environment variable
 *
 * Beyond the stub: the rate limit counts per client (behind a trusted proxy, the address the proxy forwards), TURN credentials can be kept to the pages of listed origins and come from coturn or from Cloudflare Realtime TURN, memory is bounded, and the log never holds an address, a blob or a whole id (an SDP holds IP addresses).
 */

import http from 'node:http';
import https from 'node:https';
import fs from 'node:fs';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { clientAddress, rateKey, trustedProxies } from './address.mjs';
import { createIce, stunProvider, coturnProvider, cloudflareProvider, turnCredentials } from './ice.mjs';
import { readConfig, usage } from './config.mjs';

export { turnCredentials };

export const DEFAULTS = {
    roomTTL:    120000,             // ms; renewed by every call of the host
    blobTTL:    60000,              // ms; offers and answers
    maxBlob:    65536,              // bytes
    maxOffers:  64,                 // waiting offers per room
    maxAnswers: 128,                // answers per room
    maxRooms:   10000,
    maxStored:  64 * 1024 * 1024,   // bytes of offers and answers in all rooms together
    rateLimit:  1200,               // requests per client and window, sustained
    rateBurst:  null,               // requests at once; null: half of rateLimit
    rateWindow: 60000,              // ms
    maxClients: 100000,             // clients the rate limit tells apart; more share one allowance
    // s; lifetime of TURN credentials. The player fetches /ice once, when pairing starts, and opens relays with those credentials for every phone that joins while its QR code is up: a whole school day, perhaps. Cloudflare ends a relayed session when its credentials expire (coturn does not), so they have to last that long.
    turnTTL:    86400,
    logLevel:   'info',             // all | info (no successful polls) | warn | off
    summaryEvery: 600000            // ms; at info: a summary line, when something happened
};

const LEVELS = { all: 0, info: 1, warn: 2, off: 3 };

const ID = '([A-Za-z0-9_-]{16,64})';
const ROUTES = [
    { method: 'GET',    pattern: /^\/ice$/,                                         action: 'ice' },
    { method: 'PUT',    pattern: new RegExp('^/rooms/' + ID + '$'),                 action: 'openRoom' },
    { method: 'DELETE', pattern: new RegExp('^/rooms/' + ID + '$'),                 action: 'closeRoom' },
    { method: 'POST',   pattern: new RegExp('^/rooms/' + ID + '/offers/' + ID + '$'),  action: 'postOffer' },
    { method: 'GET',    pattern: new RegExp('^/rooms/' + ID + '/offers$'),          action: 'listOffers' },
    { method: 'PUT',    pattern: new RegExp('^/rooms/' + ID + '/answers/' + ID + '$'), action: 'putAnswer' },
    { method: 'GET',    pattern: new RegExp('^/rooms/' + ID + '/answers/' + ID + '$'), action: 'getAnswer' }
];


function hashKey(key) {
    return crypto.createHash('sha256').update(key).digest();
}

function shortId(id) {
    return id.slice(0, 4) + '…';
}


/**
 * I make a broker: handle(req, res) answers the requests of the contract.
 *
 * options: now() (ms; the clock, injectable for tests); the ICE servers: stun and turn (lists of URLs), turnSecret, turnTTL, cfTurnKeyId and cfTurnToken (Cloudflare), iceProviders (more providers, see ice.mjs), allowedOrigins (who gets TURN credentials; empty: everyone), fetch (for Cloudflare); trustedProxies (addresses and CIDR ranges whose X-Forwarded-For counts); log (a function taking a line, or null for silence), logLevel; and the limits in DEFAULTS.
 */
export function createBroker(options = {}) {

    const config  = Object.assign({}, DEFAULTS, options),
          now     = config.now || Date.now,
          write   = (config.log === undefined) ? console.log : config.log,
          level   = LEVELS[config.logLevel] ?? LEVELS.info,
          burst   = config.rateBurst || Math.max(1, Math.floor(config.rateLimit / 2)),
          perMs   = config.rateLimit / config.rateWindow,
          trusted = trustedProxies(config.trustedProxies || []),
          rooms   = new Map(),
          buckets = new Map();

    let lastSweep = 0,
        stored    = 0,
        counts    = { requests: 0, offers: 0, answers: 0, limited: 0, since: now() };

    function log(at, line) {
        if (write && LEVELS[at] >= level) { write(line); }
    }

    const providers = [];
    if (config.stun && config.stun.length) { providers.push(stunProvider(config.stun)); }
    if (config.turn && config.turn.length && config.turnSecret) {
        providers.push(coturnProvider({ urls: config.turn, secret: config.turnSecret, ttl: config.turnTTL }));
    }
    if (config.cfTurnKeyId && config.cfTurnToken) {
        providers.push(cloudflareProvider({ keyId: config.cfTurnKeyId, token: config.cfTurnToken, ttl: config.turnTTL, now, fetch: config.fetch, log }));
    }
    if (config.iceProviders) { providers.push(...config.iceProviders); }

    const ice = createIce({ providers, allowedOrigins: config.allowedOrigins || [] });


    /* -- the store ------------------------------------------------------ */

    function forget(room, kind, guest) {
        const entry = room[kind].get(guest);
        if (entry) {
            stored -= entry.size;
            room[kind].delete(guest);
        }
    }

    function dropRoom(id) {
        const room = rooms.get(id);
        if (!room) { return; }
        for (const guest of [...room.offers.keys()]) { forget(room, 'offers', guest); }
        for (const guest of [...room.answers.keys()]) { forget(room, 'answers', guest); }
        rooms.delete(id);
    }

    function sweep() {
        const t = now();
        if (t - lastSweep < 1000) { return; }
        lastSweep = t;
        for (const [id, room] of rooms) {
            if (room.expires <= t) { dropRoom(id); continue; }
            for (const [guest, offer] of room.offers) { if (offer.expires <= t) { forget(room, 'offers', guest); } }
            for (const [guest, answer] of room.answers) { if (answer.expires <= t) { forget(room, 'answers', guest); } }
        }
        for (const [key, bucket] of buckets) {
            if (bucket.tokens + (t - bucket.at) * perMs >= burst) { buckets.delete(key); }
        }
        if (counts.requests && t - counts.since >= config.summaryEvery) {
            log('info', 'summary of the last ' + Math.round((t - counts.since) / 60000) + ' min: requests ' + counts.requests + ', offers ' + counts.offers
                + ', answers ' + counts.answers + ', rate limited ' + counts.limited + '; rooms open now ' + rooms.size);
            counts = { requests: 0, offers: 0, answers: 0, limited: 0, since: t };
        }
    }

    function liveRoom(id) {
        const room = rooms.get(id);
        if (room && room.expires <= now()) { dropRoom(id); return null; }
        return room || null;
    }


    /* -- the rate limit: a token bucket per client ---------------------- */

    // 0, or the seconds until the client may ask again.
    function rateLimited(key) {
        const t = now();
        let bucket = buckets.get(key);
        if (!bucket && buckets.size >= config.maxClients) {
            key = '(more clients)';
            bucket = buckets.get(key);
        }
        if (!bucket) {
            bucket = { tokens: burst, at: t };
            buckets.set(key, bucket);
        } else {
            bucket.tokens = Math.min(burst, bucket.tokens + (t - bucket.at) * perMs);
            bucket.at = t;
        }
        if (bucket.tokens >= 1) {
            bucket.tokens -= 1;
            return 0;
        }
        return Math.max(1, Math.ceil((1 - bucket.tokens) / perMs / 1000));
    }


    /* -- requests ------------------------------------------------------- */

    function send(res, status, body, type, headers) {
        const all = Object.assign({
            'Access-Control-Allow-Origin':  '*',
            'Access-Control-Allow-Methods': 'GET, PUT, POST, DELETE, OPTIONS',
            'Access-Control-Allow-Headers': 'Authorization, Content-Type',
            'Access-Control-Max-Age':       '600',
            'Cache-Control':                'no-store'
        }, headers);
        if (body !== undefined) {
            all['Content-Type'] = type || 'application/json';
        }
        res.writeHead(status, all);
        res.end(body === undefined ? undefined : ((typeof body === 'string') ? body : JSON.stringify(body)));
        return status;
    }

    // Is the request the host of this room? 401 without a key, 403 with another.
    function hostCheck(req, room) {
        const match = /^Bearer\s+(\S+)$/.exec(req.headers['authorization'] || '');
        if (!match) { return 401; }
        if (room && !crypto.timingSafeEqual(hashKey(match[1]), room.keyHash)) { return 403; }
        return 0;
    }

    function readBody(req) {
        return new Promise((resolve) => {
            const chunks = [];
            let size = 0, tooLarge = false;
            req.on('data', (chunk) => {
                size += chunk.length;
                if (size > config.maxBlob) { tooLarge = true; return; }
                if (!tooLarge) { chunks.push(chunk); }
            });
            req.on('end', () => resolve(tooLarge ? null : Buffer.concat(chunks).toString('utf8')));
            req.on('error', () => resolve(null));
        });
    }

    // Room for size more bytes in the store?
    function fits(size) {
        return stored + size <= config.maxStored;
    }

    const actions = {

        async ice(req, res) {
            const servers = await ice.servers(req.headers['origin'], now());
            // None: the local network only. An empty list rather than an error, so a browser logs nothing. The answer depends on the page's origin: Vary, for any cache on the way.
            return send(res, 200, { iceServers: servers }, null, { 'Vary': 'Origin' });
        },

        openRoom(req, res, [id]) {
            const room = liveRoom(id),
                  refused = hostCheck(req, room);
            if (refused) { return send(res, refused, { error: 'host key' }); }
            if (room) {
                room.expires = now() + config.roomTTL;
                return send(res, 204);
            }
            if (rooms.size >= config.maxRooms) { return send(res, 503, { error: 'too many rooms' }); }
            const key = /^Bearer\s+(\S+)$/.exec(req.headers['authorization'])[1];
            rooms.set(id, { keyHash: hashKey(key), expires: now() + config.roomTTL, cursor: 0, offers: new Map(), answers: new Map() });
            return send(res, 204);
        },

        closeRoom(req, res, [id]) {
            const room = liveRoom(id);
            // Gone already (expired): nothing to delete, which is what was asked.
            if (!room) { return send(res, 204); }
            const refused = hostCheck(req, room);
            if (refused) { return send(res, refused, { error: 'host key' }); }
            dropRoom(id);
            return send(res, 204);
        },

        async postOffer(req, res, [id, guest]) {
            const body = await readBody(req),
                  room = liveRoom(id);
            if (body === null) { return send(res, 413, { error: 'too large' }); }
            if (!room) { return send(res, 404, { error: 'no room' }); }
            if (!body) { return send(res, 400, { error: 'empty' }); }
            if (!room.offers.has(guest) && room.offers.size >= config.maxOffers) { return send(res, 429, { error: 'too many offers' }); }
            const size = Buffer.byteLength(body);
            forget(room, 'offers', guest);
            forget(room, 'answers', guest);
            if (!fits(size)) { return send(res, 503, { error: 'busy' }); }
            room.cursor++;
            room.offers.set(guest, { cursor: room.cursor, blob: body, size, expires: now() + config.blobTTL });
            stored += size;
            counts.offers++;
            return send(res, 204);
        },

        listOffers(req, res, [id], query) {
            const room = liveRoom(id);
            if (!room) { return send(res, 404, { error: 'no room' }); }
            const refused = hostCheck(req, room);
            if (refused) { return send(res, refused, { error: 'host key' }); }
            room.expires = now() + config.roomTTL;
            const after = parseInt(query.get('after') || '0', 10) || 0,
                  t     = now(),
                  offers = [];
            for (const [guest, offer] of room.offers) {
                if (offer.cursor > after && offer.expires > t) { offers.push({ guest, cursor: offer.cursor, blob: offer.blob }); }
            }
            offers.sort((a, b) => a.cursor - b.cursor);
            return send(res, 200, { offers, cursor: room.cursor });
        },

        async putAnswer(req, res, [id, guest]) {
            const body = await readBody(req),
                  room = liveRoom(id);
            if (body === null) { return send(res, 413, { error: 'too large' }); }
            if (!room) { return send(res, 404, { error: 'no room' }); }
            const refused = hostCheck(req, room);
            if (refused) { return send(res, refused, { error: 'host key' }); }
            if (!body) { return send(res, 400, { error: 'empty' }); }
            room.expires = now() + config.roomTTL;
            if (!room.answers.has(guest) && room.answers.size >= config.maxAnswers) { return send(res, 429, { error: 'too many answers' }); }
            const size = Buffer.byteLength(body);
            forget(room, 'answers', guest);
            if (!fits(size)) { return send(res, 503, { error: 'busy' }); }
            room.answers.set(guest, { blob: body, size, expires: now() + config.blobTTL });
            stored += size;
            counts.answers++;
            return send(res, 204);
        },

        getAnswer(req, res, [id, guest]) {
            const room = liveRoom(id),
                  answer = room && room.answers.get(guest);
            if (!room) { return send(res, 404, { error: 'no room' }); }
            // Not yet: no content, which a browser does not log as a failed request (a 404 would be, once a second).
            if (!answer || answer.expires <= now()) { return send(res, 204); }
            return send(res, 200, answer.blob, 'text/plain; charset=utf-8');
        }

    };

    // What a request is worth logging at: the polls that find nothing new (or their answer) are routine.
    function levelOf(action, status) {
        if (status >= 400) { return 'warn'; }
        if ((action === 'listOffers' && status === 200) || (action === 'getAnswer' && status === 204)) { return 'all'; }
        return 'info';
    }

    async function handle(req, res) {

        const started = now();

        sweep();

        const url    = new URL(req.url, 'http://broker'),
              where  = url.pathname.replace(/[A-Za-z0-9_-]{16,64}/g, shortId).slice(0, 120);
        let status, action = null;

        if (req.method === 'OPTIONS') {
            status = send(res, 204);
        } else {
            counts.requests++;
            const wait = rateLimited(rateKey(clientAddress(req, trusted)));
            if (wait) {
                counts.limited++;
                status = send(res, 429, { error: 'rate limited' }, null, { 'Retry-After': String(wait) });
            } else {
                const route = ROUTES.find((r) => r.method === req.method && r.pattern.test(url.pathname));
                if (!route) {
                    status = send(res, 404, { error: 'not part of the contract' });
                } else {
                    const ids = route.pattern.exec(url.pathname).slice(1);
                    action = route.action;
                    try {
                        status = await actions[route.action](req, res, ids, url.searchParams);
                    } catch (error) {
                        log('warn', 'broker error in ' + route.action + ': ' + ((error && error.message) || error));
                        status = res.headersSent ? 500 : send(res, 500, { error: 'broker error' });
                    }
                }
            }
        }

        log(req.method === 'OPTIONS' ? 'all' : levelOf(action, status), req.method + ' ' + where + ' ' + status + ' ' + (now() - started) + 'ms');

    }

    return {
        handle,
        ice,
        // At startup: credentials from providers that fetch them (Cloudflare), ready before the first request.
        warm() {
            return Promise.all(providers.filter((provider) => provider.warm).map((provider) => provider.warm()));
        },
        get rooms() { return rooms; },
        get stored() { return stored; }
    };

}


/**
 * I start a broker on a port (0: any free one). Resolves with the server; server.address().port tells which port, server.broker is the broker.
 */
export function startBroker(options = {}) {
    const broker = createBroker(options),
          server = (options.cert && options.key)
                 ? https.createServer({ cert: fs.readFileSync(options.cert), key: fs.readFileSync(options.key) }, broker.handle)
                 : http.createServer(broker.handle);
    // Slow clients do not hold a connection for long: every request of the contract is small.
    server.headersTimeout = 10000;
    server.requestTimeout = 15000;
    server.broker = broker;
    return new Promise((resolve, reject) => {
        server.once('error', reject);
        server.listen(options.port || 0, options.host || 'localhost', () => resolve(server));
    });
}


// What the broker hands out and how it limits, for the first line of the log (no secrets).
function describe(options) {
    const ice = [];
    if (options.stun.length) { ice.push('STUN'); }
    if (options.turn.length) { ice.push('coturn TURN'); }
    if (options.cfTurnKeyId) { ice.push('Cloudflare TURN'); }
    const credentials = (options.turn.length || options.cfTurnKeyId)
        ? '; TURN credentials for ' + Math.round(options.turnTTL / 3600 * 10) / 10 + ' h, to ' + (options.allowedOrigins.length ? options.allowedOrigins.join(' ') : 'every origin')
        : '';
    return 'ICE servers: ' + (ice.join(' + ') || 'none (LAN only)') + credentials
        + '. Rate limit: ' + options.rateLimit + '/min, burst ' + (options.rateBurst || Math.max(1, Math.floor(options.rateLimit / 2)))
        + ', trusted proxies: ' + (options.trustedProxies.join(' ') || 'none') + '. Log: ' + options.logLevel + '.';
}

function main(argv, env) {

    let parsed;
    try {
        parsed = readConfig(argv, env);
    } catch (error) {
        console.error(error.message + ' (see --help)');
        process.exit(1);
    }
    if (parsed.help) {
        console.log(usage());
        process.exit(0);
    }

    const options = parsed.options;

    startBroker(options).then((server) => {
        const scheme = options.cert ? 'https' : 'http';
        if (options.logLevel !== 'off') {
            console.log('Pairing broker (contract v1) at ' + scheme + '://' + options.host + ':' + server.address().port + '/. ' + describe(options));
        }
        server.broker.warm();
        const stop = () => {
            server.close(() => process.exit(0));
            setTimeout(() => process.exit(0), 5000).unref();
        };
        process.once('SIGTERM', stop);
        process.once('SIGINT', stop);
    }, (error) => {
        console.error(error.message);
        process.exit(1);
    });

}

function isMain() {
    try {
        return Boolean(process.argv[1]) && fs.realpathSync(process.argv[1]) === fs.realpathSync(fileURLToPath(import.meta.url));
    } catch (e) {
        return false;
    }
}

if (isMain()) {
    main(process.argv.slice(2), process.env);
}
