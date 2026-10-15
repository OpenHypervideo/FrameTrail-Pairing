/*
 * A minimal STUN/TURN client (RFC 8489, RFC 8656), enough to check the ICE servers a broker hands out without a browser: a STUN Binding, and a TURN Allocate with long-term credentials, CreatePermission and Refresh, over UDP, TCP or TLS. The tests use it against a deployed broker (and coturn in a container); FrameTrail itself leaves all of this to the browser.
 *
 *     const server = parseIceURL('turns:turn.example.org:5349?transport=tcp');
 *     const session = await allocate(server, { username, credential });
 *     session.relayed;                         // { family, address, port }
 *     await session.createPermission('10.0.0.1');   // → { ok: false, code: 403 } on a hardened server
 *     await session.close();
 */

import crypto from 'node:crypto';
import dgram from 'node:dgram';
import dns from 'node:dns/promises';
import net from 'node:net';
import tls from 'node:tls';
import { ipv6Groups } from './address.mjs';

const MAGIC = 0x2112A442;

export const METHOD = { BINDING: 0x001, ALLOCATE: 0x003, REFRESH: 0x004, CREATE_PERMISSION: 0x008 };
export const CLASS  = { REQUEST: 0x000, SUCCESS: 0x100, ERROR: 0x110 };

export const ATTR = {
    MAPPED_ADDRESS:      0x0001,
    USERNAME:            0x0006,
    MESSAGE_INTEGRITY:   0x0008,
    ERROR_CODE:          0x0009,
    LIFETIME:            0x000D,
    XOR_PEER_ADDRESS:    0x0012,
    REALM:               0x0014,
    NONCE:               0x0015,
    XOR_RELAYED_ADDRESS: 0x0016,
    REQUESTED_TRANSPORT: 0x0019,
    XOR_MAPPED_ADDRESS:  0x0020,
    SOFTWARE:            0x8022,
    FINGERPRINT:         0x8028
};


/* ---------------------------------------------------------------------- */
/*  Messages                                                              */
/* ---------------------------------------------------------------------- */

export function transactionId() {
    return crypto.randomBytes(12);
}

/**
 * A STUN message: type (method | class), the 12-byte transaction id, attributes as [type, Buffer] pairs. With a key, MESSAGE-INTEGRITY comes last (no FINGERPRINT: it is optional, and no server here needs it).
 */
export function encode(type, id, attributes = [], key = null) {
    const parts = [];
    for (const [attr, value] of attributes) {
        const header = Buffer.alloc(4);
        header.writeUInt16BE(attr, 0);
        header.writeUInt16BE(value.length, 2);
        parts.push(header, value, Buffer.alloc((4 - value.length % 4) % 4));
    }
    let body = Buffer.concat(parts);
    const head = Buffer.alloc(20);
    head.writeUInt16BE(type, 0);
    head.writeUInt16BE(body.length + (key ? 24 : 0), 2);
    head.writeUInt32BE(MAGIC, 4);
    id.copy(head, 8);
    if (key) {
        const mac = crypto.createHmac('sha1', key).update(Buffer.concat([head, body])).digest(),
              header = Buffer.alloc(4);
        header.writeUInt16BE(ATTR.MESSAGE_INTEGRITY, 0);
        header.writeUInt16BE(20, 2);
        body = Buffer.concat([body, header, mac]);
    }
    return Buffer.concat([head, body]);
}

/**
 * The parts of a STUN message: { type, method, class, id, attributes: [{ type, value, offset }] }, or null when it is not one.
 */
export function decode(buffer) {
    if (buffer.length < 20 || buffer.readUInt32BE(4) !== MAGIC || (buffer[0] & 0xC0)) { return null; }
    const length = buffer.readUInt16BE(2);
    if (buffer.length < 20 + length) { return null; }
    const type = buffer.readUInt16BE(0),
          attributes = [];
    for (let offset = 20; offset + 4 <= 20 + length;) {
        const attr = buffer.readUInt16BE(offset), size = buffer.readUInt16BE(offset + 2);
        attributes.push({ type: attr, value: buffer.subarray(offset + 4, offset + 4 + size), offset });
        offset += 4 + size + (4 - size % 4) % 4;
    }
    return { type, method: type & 0x3EEF, class: type & 0x0110, id: buffer.subarray(8, 20), attributes, raw: buffer.subarray(0, 20 + length) };
}

export function attribute(message, type) {
    const found = message.attributes.find((a) => a.type === type);
    return found ? found.value : null;
}

// The long-term credential key: MD5(username ":" realm ":" password). (No SASLprep: these are ASCII.)
export function longTermKey(username, realm, password) {
    return crypto.createHash('md5').update(username + ':' + realm + ':' + password).digest();
}

// Does the message's MESSAGE-INTEGRITY match the key? (Attributes after it, FINGERPRINT, are left out as the RFC says.)
export function checkIntegrity(message, key) {
    const mi = message.attributes.find((a) => a.type === ATTR.MESSAGE_INTEGRITY);
    if (!mi) { return false; }
    const head = Buffer.from(message.raw.subarray(0, mi.offset));
    head.writeUInt16BE(mi.offset + 24 - 20, 2);
    return crypto.timingSafeEqual(crypto.createHmac('sha1', key).update(head).digest(), mi.value);
}

/** An XOR-…-ADDRESS value: { family: 4 | 6, address, port }. */
export function xorAddress(value, id) {
    const family = value[1] === 0x01 ? 4 : 6,
          port = value.readUInt16BE(2) ^ (MAGIC >>> 16),
          mask = Buffer.concat([Buffer.from([0x21, 0x12, 0xA4, 0x42]), id]),
          bytes = Buffer.from(value.subarray(4, family === 4 ? 8 : 20)).map((b, i) => b ^ mask[i]);
    if (family === 4) { return { family, address: bytes.join('.'), port }; }
    const groups = [];
    for (let i = 0; i < 16; i += 2) { groups.push(bytes.readUInt16BE(i).toString(16)); }
    // The URL parser writes an IPv6 address in its canonical short form.
    return { family, address: new URL('http://[' + groups.join(':') + ']').hostname.slice(1, -1), port };
}

export function encodeXorAddress(address, port, id) {
    const family = net.isIP(address),
          mask = Buffer.concat([Buffer.from([0x21, 0x12, 0xA4, 0x42]), id]);
    let bytes;
    if (family === 4) {
        bytes = Buffer.from(address.split('.').map(Number));
    } else {
        bytes = Buffer.alloc(16);
        ipv6Groups(address).forEach((group, i) => bytes.writeUInt16BE(group, i * 2));
    }
    const value = Buffer.alloc(4 + bytes.length);
    value[1] = family === 4 ? 0x01 : 0x02;
    value.writeUInt16BE(port ^ (MAGIC >>> 16), 2);
    bytes.forEach((b, i) => { value[4 + i] = b ^ mask[i]; });
    return value;
}

export function errorCode(value) {
    return value ? { code: (value[2] & 0x07) * 100 + value[3], reason: value.subarray(4).toString('utf8') } : null;
}

function uint32(n) {
    const b = Buffer.alloc(4);
    b.writeUInt32BE(n, 0);
    return b;
}


/* ---------------------------------------------------------------------- */
/*  ICE server URLs                                                       */
/* ---------------------------------------------------------------------- */

/**
 * { scheme, host, port, transport, secure } of a stun:, stuns:, turn: or turns: URL (RFC 7064, RFC 7065), or null.
 */
export function parseIceURL(url) {
    const m = /^(stuns?|turns?):(\[[0-9a-fA-F:.]+\]|[^:?\[\]]+)(?::(\d+))?(?:\?transport=(udp|tcp))?$/i.exec(String(url));
    if (!m) { return null; }
    const scheme = m[1].toLowerCase(),
          secure = scheme.endsWith('s');
    return {
        scheme,
        host:      m[2].replace(/^\[|\]$/g, ''),
        port:      m[3] ? Number(m[3]) : (secure ? 5349 : 3478),
        transport: secure ? 'tls' : (m[4] ? m[4].toLowerCase() : 'udp'),
        secure
    };
}


/* ---------------------------------------------------------------------- */
/*  Transports                                                            */
/* ---------------------------------------------------------------------- */

/**
 * A connection to a STUN/TURN server: request(buffer, id) resolves with the decoded response of that transaction (over UDP sent again after 0.5, 1.5 and 3.5 s), close(). options: timeout (ms, per request), ca (extra CA for TLS).
 */
export async function connect(server, options = {}) {

    const timeout = options.timeout || 5000,
          waiting = new Map();       // transaction id (hex) → { resolve, reject, timer }
    const { address, family } = await dns.lookup(server.host);

    function deliver(buffer) {
        const message = decode(buffer);
        if (!message) { return; }
        const key = message.id.toString('hex'), entry = waiting.get(key);
        if (entry) {
            waiting.delete(key);
            entry.done();
            entry.resolve(message);
        }
    }

    function failAll(error) {
        for (const entry of waiting.values()) { entry.done(); entry.reject(error); }
        waiting.clear();
    }

    let send, close;

    if (server.transport === 'udp') {
        const socket = dgram.createSocket(family === 6 ? 'udp6' : 'udp4');
        socket.on('message', deliver);
        socket.on('error', failAll);
        send = (buffer) => socket.send(buffer, server.port, address);
        close = () => { try { socket.close(); } catch (e) { /* closed */ } };
    } else {
        const socket = await new Promise((resolve, reject) => {
            const s = (server.transport === 'tls')
                ? tls.connect({ host: address, port: server.port, servername: net.isIP(server.host) ? undefined : server.host, ca: options.ca })
                : net.connect({ host: address, port: server.port });
            const timer = setTimeout(() => { s.destroy(); reject(new Error('timeout connecting to ' + server.host + ':' + server.port)); }, timeout);
            s.once(server.transport === 'tls' ? 'secureConnect' : 'connect', () => { clearTimeout(timer); resolve(s); });
            s.once('error', (error) => { clearTimeout(timer); reject(error); });
        });
        // A stream: STUN messages one after the other, each 20 bytes of header plus its length.
        let pending = Buffer.alloc(0);
        socket.on('data', (chunk) => {
            pending = Buffer.concat([pending, chunk]);
            while (pending.length >= 20 && pending.length >= 20 + pending.readUInt16BE(2)) {
                const size = 20 + pending.readUInt16BE(2);
                deliver(pending.subarray(0, size));
                pending = pending.subarray(size);
            }
        });
        socket.on('error', failAll);
        socket.on('close', () => failAll(new Error('connection closed')));
        send = (buffer) => socket.write(buffer);
        close = () => socket.destroy();
    }

    return {
        request(buffer, id) {
            return new Promise((resolve, reject) => {
                const timers = [];
                const done = () => timers.forEach(clearTimeout);
                waiting.set(id.toString('hex'), { resolve, reject, done });
                send(buffer);
                if (server.transport === 'udp') {
                    for (const at of [500, 1500, 3500]) {
                        if (at < timeout) { timers.push(setTimeout(() => send(buffer), at)); }
                    }
                }
                timers.push(setTimeout(() => {
                    waiting.delete(id.toString('hex'));
                    done();
                    reject(new Error('no answer from ' + server.host + ':' + server.port + ' (' + server.transport + ')'));
                }, timeout));
            });
        },
        close
    };

}


/* ---------------------------------------------------------------------- */
/*  STUN and TURN                                                         */
/* ---------------------------------------------------------------------- */

/** A STUN Binding: resolves with the address the server saw ({ family, address, port }). */
export async function binding(server, options) {
    const connection = await connect(server, options);
    try {
        const id = transactionId(),
              response = await connection.request(encode(METHOD.BINDING | CLASS.REQUEST, id), id);
        if (response.class !== CLASS.SUCCESS) { throw new Error('Binding failed: ' + JSON.stringify(errorCode(attribute(response, ATTR.ERROR_CODE)))); }
        const xor = attribute(response, ATTR.XOR_MAPPED_ADDRESS);
        if (!xor) { throw new Error('Binding answer without XOR-MAPPED-ADDRESS'); }
        return xorAddress(xor, response.id);
    } finally {
        connection.close();
    }
}

/**
 * A TURN allocation (a UDP relay) with long-term credentials. Resolves with { relayed, mapped, lifetime, createPermission(peer), close() }; rejects with an Error whose code is the server's error code (401: the credentials).
 */
export async function allocate(server, { username, credential }, options) {

    const connection = await connect(server, options);
    let realm = null, nonce = null, key = null;

    // A request with the credentials; once again with a fresh nonce when the server says it is stale (438). attributes(id): the request's own attributes (an XOR address depends on the transaction id).
    async function authenticated(method, attributes) {
        for (let attempt = 0; attempt < 2; attempt++) {
            const id = transactionId(),
                  request = encode(method | CLASS.REQUEST, id, [
                      [ATTR.USERNAME, Buffer.from(username)],
                      [ATTR.REALM, Buffer.from(realm)],
                      [ATTR.NONCE, Buffer.from(nonce)],
                      ...attributes(id)
                  ], key),
                  response = await connection.request(request, id),
                  error = errorCode(attribute(response, ATTR.ERROR_CODE));
            if (error && error.code === 438 && attribute(response, ATTR.NONCE)) {
                nonce = attribute(response, ATTR.NONCE).toString();
                continue;
            }
            return { response, error };
        }
        throw new Error('the nonce stays stale');
    }

    try {
        const transport = [ATTR.REQUESTED_TRANSPORT, Buffer.from([17, 0, 0, 0])],
              id = transactionId(),
              challenge = await connection.request(encode(METHOD.ALLOCATE | CLASS.REQUEST, id, [transport]), id),
              first = errorCode(attribute(challenge, ATTR.ERROR_CODE));
        if (!first || first.code !== 401 || !attribute(challenge, ATTR.REALM) || !attribute(challenge, ATTR.NONCE)) {
            throw new Error('expected a 401 challenge, got ' + (first ? first.code + ' ' + first.reason : 'success'));
        }
        realm = attribute(challenge, ATTR.REALM).toString();
        nonce = attribute(challenge, ATTR.NONCE).toString();
        key = longTermKey(username, realm, credential);

        const { response, error } = await authenticated(METHOD.ALLOCATE, () => [transport]);
        if (error) { throw Object.assign(new Error('Allocate refused: ' + error.code + ' ' + error.reason), { code: error.code }); }
        if (!checkIntegrity(response, key)) { throw new Error('Allocate answer fails MESSAGE-INTEGRITY'); }

        const relayed = attribute(response, ATTR.XOR_RELAYED_ADDRESS),
              mapped  = attribute(response, ATTR.XOR_MAPPED_ADDRESS),
              lifetime = attribute(response, ATTR.LIFETIME);
        if (!relayed) { throw new Error('Allocate answer without XOR-RELAYED-ADDRESS'); }

        return {
            relayed:  xorAddress(relayed, response.id),
            mapped:   mapped ? xorAddress(mapped, response.id) : null,
            lifetime: lifetime ? lifetime.readUInt32BE(0) : null,
            realm,
            // May the relay send to this peer? { ok, code } (403: the server refuses this peer).
            async createPermission(peer) {
                const { error } = await authenticated(METHOD.CREATE_PERMISSION, (id) => [[ATTR.XOR_PEER_ADDRESS, encodeXorAddress(peer, 0, id)]]);
                return error ? { ok: false, code: error.code, reason: error.reason } : { ok: true };
            },
            // Gives the relay back (Refresh with lifetime 0) and closes the connection.
            async close() {
                try { await authenticated(METHOD.REFRESH, () => [[ATTR.LIFETIME, uint32(0)]]); } catch (e) { /* gone anyway */ }
                connection.close();
            }
        };
    } catch (error) {
        connection.close();
        throw error;
    }

}
