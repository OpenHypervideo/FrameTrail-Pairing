/*
 * Broker contract v1, from FrameTrail's tests/run-js.mjs ("pairing broker (contract v1, …)"), run through FrameTrail's own client. In-process by default; with BROKER_URL against a deployed broker, where the tests that need the test clock or other options are skipped. With BROKER_ORIGIN as well, /ice is checked for TURN credentials with and without that origin.
 */

import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { Pairing, REMOTE, REMOTE_ORIGIN, ids, withBroker, withTarget } from './helpers.mjs';

const LOCAL_ONLY = REMOTE ? 'needs the test clock or broker options (in-process only)' : false;

describe('pairing broker (contract v1)' + (REMOTE ? ' at ' + REMOTE : ''), () => {

    test('a handshake: room, offer, answer', () => withTarget({}, async ({ client }) => {
        const { room, hostKey, guest } = ids();
        await client.openRoom(room, hostKey);
        await client.openRoom(room, hostKey);
        assert.deepStrictEqual(await client.listOffers(room, hostKey, 0), { offers: [], cursor: 0 });
        const offer = Pairing.offerBlob('v=0 offer', 'iPhone');
        await client.postOffer(room, guest, offer);
        const listed = await client.listOffers(room, hostKey, 0);
        assert.deepStrictEqual(listed, { offers: [{ guest, cursor: 1, blob: offer }], cursor: 1 });
        assert.deepStrictEqual(await client.listOffers(room, hostKey, listed.cursor), { offers: [], cursor: 1 }, 'after the cursor: nothing new');
        assert.equal(await client.getAnswer(room, guest), null, 'no answer yet');
        await client.putAnswer(room, guest, hostKey, Pairing.answerBlob('v=0 answer'));
        assert.deepStrictEqual(await client.getAnswer(room, guest), { v: 1, sdp: 'v=0 answer' });
        await client.closeRoom(room, hostKey);
        await assert.rejects(client.postOffer(room, guest, offer), { code: 'noRoom' });
        await assert.rejects(client.listOffers(room, hostKey, 0), { code: 'noRoom' });
        await assert.rejects(client.getAnswer(room, guest), { code: 'noRoom' }, 'a phone waiting for an answer learns that the room is gone');
        await client.closeRoom(room, hostKey);
    }));

    test('the normal course answers no request with an error status (a browser would log it)', () => withTarget({}, async ({ base }) => {
        const { room, hostKey, guest } = ids(),
              statuses = [];
        const logged = Pairing.brokerClient(base, { fetch: (url, init) => fetch(url, init).then((response) => { statuses.push(init.method + ' ' + response.status); return response; }) });
        await logged.ice();
        await logged.openRoom(room, hostKey);
        await logged.listOffers(room, hostKey, 0);
        await logged.postOffer(room, guest, Pairing.offerBlob('v=0'));
        await logged.getAnswer(room, guest);
        await logged.putAnswer(room, guest, hostKey, Pairing.answerBlob('v=0'));
        await logged.getAnswer(room, guest);
        await logged.closeRoom(room, hostKey);
        await logged.closeRoom(room, hostKey);
        assert.deepStrictEqual(statuses, ['GET 200', 'PUT 204', 'GET 200', 'POST 204', 'GET 204', 'PUT 204', 'GET 200', 'DELETE 204', 'DELETE 204']);
    }));

    test('only the host of a room acts as its host', () => withTarget({}, async ({ base, client }) => {
        const { room, hostKey, guest } = ids();
        await client.openRoom(room, hostKey);
        const other = Pairing.randomId();
        await assert.rejects(client.openRoom(room, other), { code: 'forbidden' });
        await assert.rejects(client.listOffers(room, other, 0), { code: 'forbidden' });
        await assert.rejects(client.putAnswer(room, guest, other, Pairing.answerBlob('x')), { code: 'forbidden' });
        await assert.rejects(client.closeRoom(room, other), { code: 'forbidden' });
        const anonymous = await fetch(base + 'rooms/' + room + '/offers?after=0');
        assert.equal(anonymous.status, 401);
        await client.closeRoom(room, hostKey);
    }));

    test('limits: blob size, ids', () => withTarget({}, async ({ base, client }) => {
        const { room, hostKey, guest } = ids();
        await client.openRoom(room, hostKey);
        await assert.rejects(client.postOffer(room, guest, { v: 1, sdp: 'x'.repeat(Pairing.MAX_BLOB) }), { code: 'tooLarge' });
        assert.equal((await fetch(base + 'rooms/short/offers/' + guest, { method: 'POST', body: '{}' })).status, 404, 'not an id: not part of the contract');
        await client.closeRoom(room, hostKey);
    }));

    test('limits: rate', { skip: LOCAL_ONLY }, () => withBroker({ rateLimit: 30 }, async ({ base, client }) => {
        const { room, hostKey, guest } = ids();
        await client.openRoom(room, hostKey);
        let limited = null;
        for (let i = 0; i < 40 && !limited; i++) {
            const response = await fetch(base + 'rooms/' + room + '/answers/' + guest);
            if (response.status === 429) { limited = response; }
        }
        assert.ok(limited, 'rate limited');
        assert.ok(parseInt(limited.headers.get('retry-after'), 10) > 0);
    }));

    test('rooms and blobs expire', { skip: LOCAL_ONLY }, () => withBroker({}, async ({ client, advance }) => {
        const { room, hostKey, guest } = ids();
        await client.openRoom(room, hostKey);
        advance(100000);
        await client.listOffers(room, hostKey, 0);
        advance(100000);
        await client.postOffer(room, guest, Pairing.offerBlob('v=0'));
        assert.equal((await client.listOffers(room, hostKey, 0)).offers.length, 1, 'every call of the host renews the room');
        advance(61000);
        assert.deepStrictEqual((await client.listOffers(room, hostKey, 0)).offers, [], 'an offer lives 60 s');
        await client.putAnswer(room, guest, hostKey, Pairing.answerBlob('v=0'));
        advance(61000);
        await client.listOffers(room, hostKey, 0);
        assert.equal(await client.getAnswer(room, guest), null, 'so does an answer');
        advance(121000);
        await assert.rejects(client.postOffer(room, guest, Pairing.offerBlob('v=0')), { code: 'noRoom' }, 'a room lives 120 s after the host\'s last call');
    }));

    test('CORS: any origin, preflight answered', () => withTarget({}, async ({ base }) => {
        const { room } = ids();
        const response = await fetch(base + 'rooms/' + room, { method: 'OPTIONS', headers: { 'Origin': 'https://example.org', 'Access-Control-Request-Method': 'PUT', 'Access-Control-Request-Headers': 'authorization' } });
        assert.equal(response.status, 204);
        assert.equal(response.headers.get('access-control-allow-origin'), '*');
        assert.match(response.headers.get('access-control-allow-headers'), /Authorization/);
        assert.match(response.headers.get('access-control-allow-methods'), /DELETE/);
    }));

    test('GET /ice: none (LAN only), STUN, TURN with coturn REST credentials', { skip: LOCAL_ONLY }, async () => {
        await withBroker({}, async ({ base, client }) => {
            assert.deepStrictEqual(await (await fetch(base + 'ice')).json(), { iceServers: [] });
            assert.deepStrictEqual(await client.ice(), []);
        });
        assert.deepStrictEqual(await Pairing.brokerClient('http://broker/', { fetch: async () => new Response('', { status: 404 }) }).ice(), [], 'a broker that answers 404: LAN only as well');
        await withBroker({ stun: ['stun:stun.example.org:3478'], turn: ['turn:turn.example.org:3478'], turnSecret: 's3cret', turnTTL: 600 }, async ({ client }) => {
            const servers = await client.ice();
            assert.deepStrictEqual(servers[0], { urls: ['stun:stun.example.org:3478'] });
            assert.deepStrictEqual(servers[1].urls, ['turn:turn.example.org:3478']);
            const [expiry] = servers[1].username.split(':');
            assert.equal(parseInt(expiry, 10), 1000 + 600, 'expiry: now + ttl, in seconds');
            assert.equal(servers[1].credential, crypto.createHmac('sha1', 's3cret').update(servers[1].username).digest('base64'));
        });
    });

    test('GET /ice: what the deployed broker hands out', { skip: REMOTE ? false : 'with BROKER_URL only' }, async () => {
        const without = (await (await fetch(REMOTE + 'ice')).json()).iceServers;
        assert.ok(Array.isArray(without), 'a list');
        for (const server of without) {
            assert.ok([].concat(server.urls).length, 'every entry has URLs');
            assert.ok([].concat(server.urls).every((url) => /^(stuns?|turns?):/.test(url)));
        }
        if (!REMOTE_ORIGIN) { return; }
        const response = await fetch(REMOTE + 'ice', { headers: { 'Origin': REMOTE_ORIGIN } }),
              withOrigin = (await response.json()).iceServers;
        assert.match(response.headers.get('vary') || '', /Origin/i);
        assert.ok(withOrigin.some((server) => server.username && server.credential), 'TURN credentials for ' + REMOTE_ORIGIN);
        assert.ok(withOrigin.some((server) => !server.credential && [].concat(server.urls).some((url) => url.startsWith('stun:'))), 'and STUN');
        assert.ok(!without.some((server) => server.credential), 'no credentials without an Origin');
        const other = (await (await fetch(REMOTE + 'ice', { headers: { 'Origin': 'https://not-allowed.example' } })).json()).iceServers;
        assert.ok(!other.some((server) => server.credential), 'nor for another origin');
    });

    test('pollAnswer waits for the answer, or gives up', () => withTarget({}, async ({ client }) => {
        const { room, hostKey, guest } = ids();
        await client.openRoom(room, hostKey);
        setTimeout(() => { client.putAnswer(room, guest, hostKey, Pairing.answerBlob('late')); }, 60);
        assert.deepStrictEqual(await Pairing.pollAnswer(client, room, guest, { interval: 20, timeout: 5000 }), { v: 1, sdp: 'late' });
        await assert.rejects(Pairing.pollAnswer(client, room, Pairing.randomId(), { interval: 10, timeout: 50 }), { code: 'timeout' });
        const controller = new AbortController();
        setTimeout(() => controller.abort(), 30);
        await assert.rejects(Pairing.pollAnswer(client, room, Pairing.randomId(), { interval: 10, timeout: 5000, signal: controller.signal }), { code: 'aborted' });
        await client.closeRoom(room, hostKey);
    }));

    test('no broker there', async () => {
        await assert.rejects(Pairing.brokerClient('http://127.0.0.1:9/').ice(), { code: 'network' });
    });

});
