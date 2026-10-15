/*
 * What the production broker adds to the stub: the rate limit as a token bucket, bounded memory, and a log without addresses, blobs or whole ids.
 */

import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { Pairing, ids, withBroker } from './helpers.mjs';

describe('broker', () => {

    test('the rate limit: a burst, then the sustained rate', () => withBroker({ rateLimit: 60, rateBurst: 2 }, async ({ base, advance }) => {
        const { room, guest } = ids(),
              poll = () => fetch(base + 'rooms/' + room + '/answers/' + guest);
        assert.equal((await poll()).status, 404);
        assert.equal((await poll()).status, 404);
        const limited = await poll();
        assert.equal(limited.status, 429);
        assert.equal(limited.headers.get('retry-after'), '1', 'one request a second: the next one in a second');
        assert.equal(limited.headers.get('access-control-allow-origin'), '*', 'readable for the page');
        advance(1000);
        assert.equal((await poll()).status, 404);
        assert.equal((await poll()).status, 429);
        advance(60000);
        assert.equal((await poll()).status, 404, 'refilled up to the burst');
        assert.equal((await poll()).status, 404);
        assert.equal((await poll()).status, 429);
    }));

    test('preflights do not count', () => withBroker({ rateLimit: 2, rateBurst: 1 }, async ({ base }) => {
        const { room } = ids();
        for (let i = 0; i < 5; i++) {
            assert.equal((await fetch(base + 'rooms/' + room, { method: 'OPTIONS' })).status, 204);
        }
        assert.equal((await fetch(base + 'ice')).status, 200);
    }));

    test('the default burst is half the rate limit', () => withBroker({ rateLimit: 8 }, async ({ base }) => {
        const statuses = [];
        for (let i = 0; i < 5; i++) { statuses.push((await fetch(base + 'ice')).status); }
        assert.deepStrictEqual(statuses, [200, 200, 200, 200, 429]);
    }));

    test('memory: offers and answers within a byte budget', () => withBroker({ maxStored: 1000 }, async ({ client, broker }) => {
        const { room, hostKey } = ids();
        await client.openRoom(room, hostKey);
        const blob = Pairing.offerBlob('x'.repeat(380)),
              first = Pairing.randomId(), second = Pairing.randomId();
        await client.postOffer(room, first, blob);
        await client.postOffer(room, second, blob);
        assert.ok(broker.stored > 800 && broker.stored <= 1000);
        await assert.rejects(client.postOffer(room, Pairing.randomId(), blob), { code: 'http', status: 503 }, 'full');
        await client.postOffer(room, first, blob);
        assert.ok(broker.stored <= 1000, 'posting again replaces, it does not add');
        await client.closeRoom(room, hostKey);
        assert.equal(broker.stored, 0, 'a closed room gives its bytes back');
        await client.openRoom(room, hostKey);
        await client.postOffer(room, first, blob);
    }));

    test('memory: expired blobs give their bytes back', () => withBroker({}, async ({ client, broker, advance }) => {
        const { room, hostKey, guest } = ids();
        await client.openRoom(room, hostKey);
        await client.postOffer(room, guest, Pairing.offerBlob('v=0'));
        await client.putAnswer(room, guest, hostKey, Pairing.answerBlob('v=0'));
        assert.ok(broker.stored > 0);
        advance(61000);
        await client.listOffers(room, hostKey, 0);
        assert.equal(broker.stored, 0);
        await client.postOffer(room, guest, Pairing.offerBlob('v=0'));
        advance(121000);
        await client.ice();
        assert.equal(broker.rooms.size, 0, 'an expired room is swept');
        assert.equal(broker.stored, 0);
    }));

    test('memory: answers per room are capped', () => withBroker({ maxAnswers: 2 }, async ({ client }) => {
        const { room, hostKey } = ids();
        await client.openRoom(room, hostKey);
        const first = Pairing.randomId();
        await client.putAnswer(room, first, hostKey, Pairing.answerBlob('a'));
        await client.putAnswer(room, Pairing.randomId(), hostKey, Pairing.answerBlob('b'));
        await assert.rejects(client.putAnswer(room, Pairing.randomId(), hostKey, Pairing.answerBlob('c')), { code: 'rateLimited' });
        await client.putAnswer(room, first, hostKey, Pairing.answerBlob('a again'));
    }));

    test('the log holds no address, no blob, no whole id, no secret', () => withBroker({
        logLevel: 'all', trustedProxies: ['127.0.0.1'], turn: ['turn:turn.example.org:3478'], turnSecret: 'TURN-SECRET'
    }, async ({ base, client, lines }) => {
        const { room, hostKey, guest } = ids(),
              forwarded = { 'X-Forwarded-For': '203.0.113.77' };
        await client.ice();
        await client.openRoom(room, hostKey);
        await fetch(base + 'rooms/' + room + '/offers/' + guest, { method: 'POST', body: JSON.stringify(Pairing.offerBlob('v=0 a=candidate 198.51.100.23 PRIVATE-SDP')), headers: forwarded });
        await client.listOffers(room, hostKey, 0);
        await client.putAnswer(room, guest, hostKey, Pairing.answerBlob('v=0 a=candidate 192.0.2.99 PRIVATE-SDP'));
        await fetch(base + 'rooms/' + room + '/answers/' + guest, { headers: forwarded });
        await client.closeRoom(room, hostKey);
        const log = lines.join('\n');
        assert.ok(lines.length >= 7, 'every request at "all"');
        for (const secret of [room, guest, hostKey, '203.0.113.77', '127.0.0.1', '198.51.100.23', '192.0.2.99', 'PRIVATE-SDP', 'TURN-SECRET']) {
            assert.ok(!log.includes(secret), 'not in the log: ' + secret);
        }
        assert.ok(log.includes('PUT /rooms/' + room.slice(0, 4) + '… 204'), 'ids shortened');
        assert.match(lines[0], /^GET \/ice 200 \d+ms$/);
    }));

    test('log levels: info leaves out the routine polls, warn keeps only failures', async () => {
        const course = async ({ client }) => {
            const { room, hostKey, guest } = ids();
            await client.openRoom(room, hostKey);
            await client.listOffers(room, hostKey, 0);
            await client.getAnswer(room, guest);
            await client.postOffer(room, guest, Pairing.offerBlob('v=0'));
            await assert.rejects(client.listOffers(room, Pairing.randomId(), 0), { code: 'forbidden' });
        };
        await withBroker({ logLevel: 'info' }, async (target) => {
            await course(target);
            assert.deepStrictEqual(target.lines.map((line) => line.replace(/^(\S+ \S+?)\/[A-Za-z0-9_-]{4}….*? (\d{3}) \d+ms$/, '$1 $2')), [
                'PUT /rooms 204', 'POST /rooms 204', 'GET /rooms 403'
            ]);
        });
        await withBroker({ logLevel: 'warn' }, async (target) => {
            await course(target);
            assert.equal(target.lines.length, 1);
            assert.match(target.lines[0], / 403 /);
        });
        await withBroker({ logLevel: 'off' }, async (target) => {
            await course(target);
            assert.deepStrictEqual(target.lines, []);
        });
    });

    test('a summary line every 10 minutes, when something happened', () => withBroker({}, async ({ client, lines, advance }) => {
        const { room, hostKey, guest } = ids();
        await client.openRoom(room, hostKey);
        await client.postOffer(room, guest, Pairing.offerBlob('v=0'));
        advance(600000);
        await client.ice();
        const summary = lines.find((line) => line.startsWith('summary'));
        assert.equal(summary, 'summary of the last 10 min: requests 2, offers 1, answers 0, rate limited 0; rooms open now 0', 'the room expired meanwhile');
        lines.length = 0;
        advance(300000);
        await client.ice();
        assert.ok(!lines.some((line) => line.startsWith('summary')), 'not before the next 10 minutes are over');
        advance(300000);
        await client.ice();
        assert.ok(lines.some((line) => line.startsWith('summary of the last 10 min: requests 2,')), 'then with what happened since');
    }));

    test('paths outside the contract: 404, and the broker keeps running', () => withBroker({}, async ({ base }) => {
        assert.equal((await fetch(base)).status, 404);
        assert.equal((await fetch(base + 'rooms/' + 'x'.repeat(200))).status, 404);
        assert.equal((await fetch(base + 'ice', { method: 'POST' })).status, 404);
        assert.equal((await fetch(base + 'ice')).status, 200);
    }));

});
