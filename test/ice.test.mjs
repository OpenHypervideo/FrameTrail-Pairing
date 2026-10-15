/*
 * GET /ice: who gets which servers (origin gating), and the providers:
 * coturn REST credentials and Cloudflare Realtime TURN (its API mocked).
 */

import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { CLOUDFLARE_API, cloudflareProvider, coturnProvider, createIce, normalizeOrigin, stunProvider, turnCredentials } from '../src/ice.mjs';
import { withBroker } from './helpers.mjs';

const ORIGIN = 'https://www.example.org';

// What Cloudflare's API answers (its documented shape), with the port-53 URLs it includes.
function cloudflareAnswer(username = 'cf-user') {
    return {
        iceServers: [
            { urls: ['stun:stun.cloudflare.com:3478', 'stun:stun.cloudflare.com:53'] },
            {
                urls: [
                    'turn:turn.cloudflare.com:3478?transport=udp', 'turn:turn.cloudflare.com:53?transport=udp',
                    'turn:turn.cloudflare.com:3478?transport=tcp', 'turn:turn.cloudflare.com:80?transport=tcp',
                    'turns:turn.cloudflare.com:5349?transport=tcp', 'turns:turn.cloudflare.com:443?transport=tcp'
                ],
                username,
                credential: 'cf-credential'
            }
        ]
    };
}

// A stand-in for fetch: answers from a queue of (request) => Response, records the requests.
function mockFetch(...answers) {
    const calls = [];
    const fetch = async (url, init) => {
        calls.push({ url, init });
        const answer = answers.length > 1 ? answers.shift() : answers[0];
        return answer({ url, init });
    };
    return { fetch, calls };
}

const ok = (body) => () => new Response(JSON.stringify(body), { status: 201, headers: { 'Content-Type': 'application/json' } });
const status = (code) => () => new Response('{"error":"nope"}', { status: code });
const offline = () => { throw new TypeError('fetch failed'); };

describe('ICE servers', () => {

    test('origins: only scheme, host and port', () => {
        assert.equal(normalizeOrigin('https://www.example.org/'), ORIGIN);
        assert.equal(normalizeOrigin('HTTPS://WWW.Example.ORG'), ORIGIN);
        assert.equal(normalizeOrigin('https://example.org:443'), 'https://example.org', 'the default port is no part of an origin');
        assert.equal(normalizeOrigin('http://localhost:8080'), 'http://localhost:8080');
        for (const wrong of ['www.example.org', 'https://www.example.org/FrameTrail/', 'https://a.example/?x', 'file:///x', 'null', '']) {
            assert.throws(() => normalizeOrigin(wrong), /not an origin/, wrong);
        }
    });

    test('credentials only for the allowed origins; STUN for everyone; every URL once', async () => {
        const ice = createIce({
            providers: [
                stunProvider(['stun:stun.cloudflare.com:3478']),
                coturnProvider({ urls: ['turn:turn.example.org:3478'], secret: 's', ttl: 600 }),
                { name: 'more', servers: async () => [{ urls: ['stun:stun.cloudflare.com:3478', 'stun:stun.example.org:3478'] }] }
            ],
            allowedOrigins: [ORIGIN + '/']
        });
        const allowed = await ice.servers(ORIGIN, 1000000);
        assert.deepStrictEqual(allowed.map((s) => s.urls), [['stun:stun.cloudflare.com:3478'], ['turn:turn.example.org:3478'], ['stun:stun.example.org:3478']]);
        assert.ok(allowed[1].username && allowed[1].credential);
        for (const origin of [undefined, '', 'https://evil.example', 'https://www.example.org.evil.example', 'null']) {
            const servers = await ice.servers(origin, 1000000);
            assert.ok(servers.every((s) => !s.credential && !s.username), 'no credentials for ' + origin);
            assert.equal(servers.length, 2, 'but STUN');
        }
        const open = createIce({ providers: [coturnProvider({ urls: ['turn:t.example:3478'], secret: 's', ttl: 600 })] });
        assert.ok((await open.servers(undefined, 1000000))[0].credential, 'no list: credentials for every page');
    });

    test('a provider that fails leaves the others', async () => {
        const ice = createIce({ providers: [{ servers: () => Promise.reject(new Error('down')) }, stunProvider(['stun:s.example:3478'])] });
        assert.deepStrictEqual(await ice.servers(ORIGIN, 0), [{ urls: ['stun:s.example:3478'] }]);
    });

    test('coturn REST credentials', () => {
        const { username, credential } = turnCredentials('s3cret', 86400, 1700000000000);
        assert.match(username, /^1700086400:[0-9a-f]{12}$/);
        assert.equal(credential, crypto.createHmac('sha1', 's3cret').update(username).digest('base64'));
        assert.notEqual(turnCredentials('s3cret', 86400, 1700000000000).username, username, 'a new random part every time');
    });

    describe('Cloudflare Realtime TURN', () => {

        function provider(fetch, extra = {}) {
            let t = 1000000;
            const lines = [];
            const p = cloudflareProvider(Object.assign({ keyId: 'key-id', token: 'SECRET-TOKEN', ttl: 86400, now: () => t, fetch, log: (level, line) => lines.push(level + ' ' + line) }, extra));
            return { p, lines, advance: (ms) => { t += ms; }, now: () => t };
        }

        test('asks the API as documented', async () => {
            const { fetch, calls } = mockFetch(ok(cloudflareAnswer()));
            const { p, now } = provider(fetch);
            await p.servers(now());
            assert.equal(calls.length, 1);
            assert.equal(calls[0].url, CLOUDFLARE_API + 'key-id/credentials/generate-ice-servers');
            assert.equal(calls[0].init.method, 'POST');
            assert.equal(calls[0].init.headers['Authorization'], 'Bearer SECRET-TOKEN');
            assert.equal(calls[0].init.headers['Content-Type'], 'application/json');
            assert.deepStrictEqual(JSON.parse(calls[0].init.body), { ttl: 86400 });
            assert.ok(calls[0].init.signal, 'with a timeout');
        });

        test('hands out its servers without the port-53 URLs', async () => {
            const { p, now } = provider(mockFetch(ok(cloudflareAnswer())).fetch);
            const servers = await p.servers(now());
            assert.deepStrictEqual(servers[0], { urls: ['stun:stun.cloudflare.com:3478'] });
            assert.deepStrictEqual(servers[1].urls, [
                'turn:turn.cloudflare.com:3478?transport=udp', 'turn:turn.cloudflare.com:3478?transport=tcp', 'turn:turn.cloudflare.com:80?transport=tcp',
                'turns:turn.cloudflare.com:5349?transport=tcp', 'turns:turn.cloudflare.com:443?transport=tcp'
            ]);
            assert.equal(servers[1].username, 'cf-user');
            assert.equal(servers[1].credential, 'cf-credential');
        });

        test('one set for an hour, then a new one, minted in the background', async () => {
            const { fetch, calls } = mockFetch(ok(cloudflareAnswer('first')), ok(cloudflareAnswer('second')));
            const { p, advance, now } = provider(fetch);
            assert.equal((await p.servers(now()))[1].username, 'first');
            advance(3599000);
            assert.equal((await p.servers(now()))[1].username, 'first', 'within the hour: the same set');
            assert.equal(calls.length, 1);
            advance(2000);
            const meanwhile = p.servers(now());
            assert.ok(Array.isArray(meanwhile), 'after the hour: the old set at once, not waiting for Cloudflare');
            assert.equal(meanwhile[1].username, 'first');
            await p.warm();
            assert.equal(calls.length, 2);
            assert.equal((await p.servers(now()))[1].username, 'second');
        });

        test('Cloudflare unreachable: the old set while half its lifetime is left, then no TURN', async () => {
            const { fetch, calls } = mockFetch(ok(cloudflareAnswer('first')), offline);
            const { p, advance, now, lines } = provider(fetch);
            await p.warm();
            advance(11 * 3600000);
            assert.equal((await p.servers(now()))[1].username, 'first');
            await p.warm();
            assert.equal((await p.servers(now()))[1].username, 'first', '13 h left: still handed out');
            assert.match(lines.join('\n'), /warn Cloudflare TURN credentials: fetch failed \(still handing out the last ones\)/);
            advance(2 * 3600000);
            assert.deepStrictEqual(await p.servers(now()), [], '11 h left: no more');
            assert.ok(calls.length >= 3);
            assert.ok(!lines.join('\n').includes('SECRET-TOKEN'), 'the token is never logged');
        });

        test('after a failure, Cloudflare is asked again at most every 30 s, and nobody waits for it', async () => {
            const { fetch, calls } = mockFetch(status(401));
            const { p, advance, now, lines } = provider(fetch);
            assert.deepStrictEqual(await p.servers(now()), [], 'refused: no TURN');
            assert.match(lines[0], /^warn Cloudflare TURN credentials: Cloudflare answered 401 \(handing out no TURN\)$/);
            assert.deepStrictEqual(await p.servers(now()), []);
            advance(29000);
            assert.deepStrictEqual(await p.servers(now()), []);
            assert.equal(calls.length, 1);
            advance(2000);
            await p.servers(now());
            assert.equal(calls.length, 2);
        });

        test('an answer without TURN credentials counts as a failure', async () => {
            const { p, now, lines } = provider(mockFetch(ok({ iceServers: [{ urls: 'stun:stun.cloudflare.com:3478' }] })).fetch);
            assert.deepStrictEqual(await p.servers(now()), []);
            assert.match(lines[0], /without TURN credentials/);
        });

        test('through the broker: STUN from STUN_URLS for all, Cloudflare TURN for the allowed origin', () => withBroker({
            stun: ['stun:stun.cloudflare.com:3478'], cfTurnKeyId: 'key-id', cfTurnToken: 'SECRET-TOKEN', allowedOrigins: [ORIGIN],
            fetch: mockFetch(ok(cloudflareAnswer())).fetch, logLevel: 'all'
        }, async ({ base, lines }) => {
            const allowed = await (await fetch(base + 'ice', { headers: { 'Origin': ORIGIN } })).json();
            assert.deepStrictEqual(allowed.iceServers[0], { urls: ['stun:stun.cloudflare.com:3478'] }, 'once, though Cloudflare names it too');
            assert.equal(allowed.iceServers[1].username, 'cf-user');
            assert.equal(allowed.iceServers.length, 2);
            const other = await fetch(base + 'ice');
            assert.deepStrictEqual((await other.json()).iceServers, [{ urls: ['stun:stun.cloudflare.com:3478'] }]);
            assert.equal(other.headers.get('vary'), 'Origin');
            assert.equal(other.headers.get('access-control-allow-origin'), '*', 'CORS stays open');
            assert.ok(!lines.join('\n').includes('SECRET-TOKEN'));
        }));

    });

});
