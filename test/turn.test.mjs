/*
 * The STUN/TURN client: checked against the test vectors of RFC 5769, then used on the ICE servers a deployed broker hands out (BROKER_URL with BROKER_ORIGIN): a STUN Binding, and a relay over every TURN URL. With TURN_EXPECT_DENIED=1 (a coturn of our own, deploy/coturn), the relay must refuse private, loopback and link-local peers. TURN_CA names an extra CA certificate for turns: (a self-signed one in a local test).
 */

import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { ATTR, CLASS, METHOD, allocate, attribute, binding, checkIntegrity, decode, encode, encodeXorAddress, longTermKey, parseIceURL, xorAddress } from '../src/turn-client.mjs';
import { REMOTE, REMOTE_ORIGIN } from './helpers.mjs';

const hex = (text) => Buffer.from(text.replace(/\s+/g, ''), 'hex');

// RFC 5769, 2.2 and 2.3: responses with XOR-MAPPED-ADDRESS, MESSAGE-INTEGRITY and FINGERPRINT.
const RESPONSE_V4 = hex(`
    0101003c 2112a442 b7e7a701 bc34d686 fa87dfae
    8022000b 74657374 20766563 746f7220
    00200008 0001a147 e112a643
    00080014 2b91f599 fd9e90c3 8c7489f9 2af9ba53 f06be7d7
    80280004 c07d4c96`);
const RESPONSE_V6 = hex(`
    01010048 2112a442 b7e7a701 bc34d686 fa87dfae
    8022000b 74657374 20766563 746f7220
    00200014 0002a147 0113a9fa a5d3f179 bc25f4b5 bed2b9d9
    00080014 a382954e 4be67bf1 1784c97c 8292c275 bfe3ed41
    80280004 c8fb0b4c`);
// RFC 5769, 2.4: a request with long-term credentials.
const REQUEST_LTC = hex(`
    00010060 2112a442 78ad3433 c6ad72c0 29da412e
    00060012 e3839ee3 8388e383 aae38383 e382afe3 82b90000
    0015001c 662f2f34 39396b39 35346436 4f4c3334 6f4c3946 53547679 36347341
    0014000b 6578616d 706c652e 6f726700
    00080014 f6702465 6dd64a3e 02b8e071 2e85c9a2 8ca89666`);

const SHORT_TERM_PASSWORD = 'VOkJxbRl1RmTxUk/WvJxBt';

describe('STUN/TURN client', () => {

    test('RFC 5769: XOR-MAPPED-ADDRESS (IPv4 and IPv6) and MESSAGE-INTEGRITY of a response', () => {
        const v4 = decode(RESPONSE_V4), v6 = decode(RESPONSE_V6);
        assert.equal(v4.class, CLASS.SUCCESS);
        assert.equal(v4.method, METHOD.BINDING);
        assert.deepStrictEqual(xorAddress(attribute(v4, ATTR.XOR_MAPPED_ADDRESS), v4.id), { family: 4, address: '192.0.2.1', port: 32853 });
        assert.deepStrictEqual(xorAddress(attribute(v6, ATTR.XOR_MAPPED_ADDRESS), v6.id), { family: 6, address: '2001:db8:1234:5678:11:2233:4455:6677', port: 32853 });
        assert.equal(attribute(v4, ATTR.SOFTWARE).toString(), 'test vector');
        assert.ok(checkIntegrity(v4, Buffer.from(SHORT_TERM_PASSWORD)), 'up to MESSAGE-INTEGRITY, FINGERPRINT left out');
        assert.ok(checkIntegrity(v6, Buffer.from(SHORT_TERM_PASSWORD)));
        assert.ok(!checkIntegrity(v4, Buffer.from('wrong')));
    });

    test('RFC 5769: a request with long-term credentials, byte for byte', () => {
        const username = 'マトリックス',
              key = longTermKey(username, 'example.org', 'TheMatrIX'),
              request = decode(REQUEST_LTC);
        const encoded = encode(METHOD.BINDING | CLASS.REQUEST, request.id, [
            [ATTR.USERNAME, Buffer.from(username)],
            [ATTR.NONCE, Buffer.from('f//499k954d6OL34oL9FSTvy64sA')],
            [ATTR.REALM, Buffer.from('example.org')]
        ], key);
        assert.equal(encoded.toString('hex'), REQUEST_LTC.toString('hex'));
        assert.ok(checkIntegrity(request, key));
    });

    test('XOR addresses: encoded and decoded again', () => {
        const id = Buffer.from('000102030405060708090a0b', 'hex');
        for (const address of ['10.0.0.1', '203.0.113.200', '2001:db8::1', 'fe80::1:2:3', '::1']) {
            assert.deepStrictEqual(xorAddress(encodeXorAddress(address, 3478, id), id), { family: address.includes(':') ? 6 : 4, address, port: 3478 });
        }
    });

    test('ICE server URLs', () => {
        assert.deepStrictEqual(parseIceURL('turn:turn.cloudflare.com:3478?transport=udp'), { scheme: 'turn', host: 'turn.cloudflare.com', port: 3478, transport: 'udp', secure: false });
        assert.deepStrictEqual(parseIceURL('turn:turn.cloudflare.com:80?transport=tcp'), { scheme: 'turn', host: 'turn.cloudflare.com', port: 80, transport: 'tcp', secure: false });
        assert.deepStrictEqual(parseIceURL('turns:turn.cloudflare.com:443?transport=tcp'), { scheme: 'turns', host: 'turn.cloudflare.com', port: 443, transport: 'tls', secure: true });
        assert.deepStrictEqual(parseIceURL('stun:stun.cloudflare.com'), { scheme: 'stun', host: 'stun.cloudflare.com', port: 3478, transport: 'udp', secure: false });
        assert.deepStrictEqual(parseIceURL('turns:[2001:db8::1]'), { scheme: 'turns', host: '2001:db8::1', port: 5349, transport: 'tls', secure: true });
        assert.equal(parseIceURL('https://example.org'), null);
        assert.equal(parseIceURL('turn:host:3478?transport=sctp'), null);
    });

});


// Private, loopback, link-local, CGNAT and reserved IPv4 peers a hardened relay refuses (deploy/coturn/turnserver.conf).
const DENIED_PEERS = ['10.0.0.1', '172.16.0.1', '192.168.1.1', '127.0.0.1', '169.254.1.1', '100.64.0.1', '0.0.0.1', '240.0.0.1'];
// Any public address outside the TURN operator's own network (Cloudflare refuses its own 1.1.1.1 over UDP). A permission sends nothing.
const PUBLIC_PEER = '8.8.8.8';

const why = !REMOTE ? 'with BROKER_URL and BROKER_ORIGIN only' : (!REMOTE_ORIGIN ? 'set BROKER_ORIGIN to an origin that gets TURN credentials' : false);

describe('the deployed ICE servers' + (REMOTE ? ' of ' + REMOTE : ''), { skip: why }, () => {

    let servers = [];
    const options = { timeout: 5000, ca: process.env.TURN_CA ? fs.readFileSync(process.env.TURN_CA) : undefined };
    const urls = (kind) => servers.flatMap((server) => [].concat(server.urls).filter((url) => url.startsWith(kind)).map((url) => ({ url, server })));

    test('/ice hands out STUN and TURN', async () => {
        servers = (await (await fetch(REMOTE + 'ice', { headers: { 'Origin': REMOTE_ORIGIN } })).json()).iceServers;
        assert.ok(urls('stun:').length, 'STUN');
        assert.ok(urls('turn').length, 'TURN');
    });

    test('STUN: the server sees this machine', async () => {
        for (const { url } of urls('stun:')) {
            const mapped = await binding(parseIceURL(url), options);
            assert.ok(mapped.address && mapped.port, url);
        }
    });

    test('TURN: a relay over every URL (udp, tcp, tls)', async (t) => {
        for (const { url, server } of urls('turn')) {
            await t.test(url, async () => {
                const session = await allocate(parseIceURL(url), server, options);
                try {
                    assert.ok(session.relayed.address && session.relayed.port, 'a relayed address');
                    assert.ok(session.lifetime > 0);
                    assert.deepStrictEqual(await session.createPermission(PUBLIC_PEER), { ok: true }, 'a public peer');
                    if (process.env.TURN_EXPECT_DENIED === '1') {
                        for (const peer of DENIED_PEERS) {
                            const result = await session.createPermission(peer);
                            assert.equal(result.code, 403, peer + ' refused');
                        }
                    }
                } finally {
                    await session.close();
                }
            });
        }
    });

    test('TURN: wrong credentials are refused', async () => {
        const [first] = urls('turn:');
        if (!first) { return; }
        // RFC 8656 says 401; Cloudflare answers 400 over UDP. Refused either way.
        await assert.rejects(allocate(parseIceURL(first.url), { username: first.server.username, credential: 'wrong' }, options), (error) => [400, 401].includes(error.code));
    });

});
