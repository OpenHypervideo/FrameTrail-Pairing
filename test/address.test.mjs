/*
 * The client address behind a proxy, and the key the rate limit counts by.
 */

import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { clientAddress, plainAddress, rateKey, trustedProxies } from '../src/address.mjs';
import { ids, withBroker } from './helpers.mjs';

// What clientAddress reads of a request.
const request = (peer, headers = {}) => ({ socket: { remoteAddress: peer }, headers });

describe('client address', () => {

    test('trusted proxies: addresses and CIDR ranges, IPv4 and IPv6', () => {
        const trusted = trustedProxies(['127.0.0.1', '::1', '10.0.0.0/8', 'fd00::/8']);
        assert.ok(trusted.has('127.0.0.1'));
        assert.ok(trusted.has('::ffff:127.0.0.1'), 'IPv4-mapped');
        assert.ok(trusted.has('::1'));
        assert.ok(trusted.has('10.20.30.40'));
        assert.ok(trusted.has('fd12:3456::1'));
        assert.ok(!trusted.has('127.0.0.2'));
        assert.ok(!trusted.has('11.0.0.1'));
        assert.ok(!trusted.has('fe80::1'));
        assert.ok(!trusted.has('not an address'));
        assert.ok(!trustedProxies([]).has('127.0.0.1'), 'none: nobody');
        for (const wrong of ['localhost', '10.0.0.0/33', '::1/129', '10.0.0.0/8/1', '1.2.3', '10.0.0.0/x']) {
            assert.throws(() => trustedProxies([wrong]), /not an IP address or CIDR range/, wrong);
        }
    });

    test('plain addresses', () => {
        assert.equal(plainAddress('::ffff:192.0.2.1'), '192.0.2.1');
        assert.equal(plainAddress(' 192.0.2.1 '), '192.0.2.1');
        assert.equal(plainAddress('2001:db8::1'), '2001:db8::1');
        assert.equal(plainAddress(undefined), '');
    });

    test('from an untrusted peer, headers do not count', () => {
        const trusted = trustedProxies(['127.0.0.1']);
        assert.equal(clientAddress(request('198.51.100.7', { 'x-forwarded-for': '203.0.113.9', 'x-real-ip': '203.0.113.9' }), trusted), '198.51.100.7');
        assert.equal(clientAddress(request('::ffff:198.51.100.7', { 'x-forwarded-for': '203.0.113.9' }), null), '198.51.100.7', 'no trusted proxies at all');
    });

    test('from a trusted proxy: the client it names', () => {
        const trusted = trustedProxies(['127.0.0.1', '::1', '10.0.0.0/8']);
        assert.equal(clientAddress(request('127.0.0.1', { 'x-forwarded-for': '203.0.113.9' }), trusted), '203.0.113.9', 'one proxy');
        assert.equal(clientAddress(request('::ffff:127.0.0.1', { 'x-forwarded-for': '2001:db8::5' }), trusted), '2001:db8::5');
        assert.equal(clientAddress(request('127.0.0.1', { 'x-forwarded-for': '6.6.6.6, 203.0.113.9' }), trusted), '203.0.113.9', 'the client cannot put itself in front');
        assert.equal(clientAddress(request('127.0.0.1', { 'x-forwarded-for': '6.6.6.6, 203.0.113.9, 10.1.1.1' }), trusted), '203.0.113.9', 'trusted hops are skipped');
        assert.equal(clientAddress(request('127.0.0.1', { 'x-forwarded-for': '10.2.2.2, 10.1.1.1' }), trusted), '10.2.2.2', 'all trusted: the farthest');
        assert.equal(clientAddress(request('127.0.0.1', { 'x-forwarded-for': 'unknown, 10.1.1.1' }), trusted), '10.1.1.1', 'an entry that is no address ends the walk');
        assert.equal(clientAddress(request('127.0.0.1', { 'x-forwarded-for': 'garbage' }), trusted), '127.0.0.1');
        assert.equal(clientAddress(request('127.0.0.1', { 'x-real-ip': '203.0.113.9' }), trusted), '203.0.113.9', 'X-Real-IP without X-Forwarded-For');
        assert.equal(clientAddress(request('127.0.0.1', { 'x-real-ip': 'nonsense' }), trusted), '127.0.0.1');
        assert.equal(clientAddress(request('127.0.0.1'), trusted), '127.0.0.1', 'no headers: the proxy itself');
    });

    test('the rate key: IPv4 as it is, IPv6 by its /64', () => {
        assert.equal(rateKey('203.0.113.9'), '203.0.113.9');
        assert.equal(rateKey('2001:db8:1:2:aaaa:bbbb:cccc:dddd'), '2001:db8:1:2::/64');
        assert.equal(rateKey('2001:db8:1:2::1'), '2001:db8:1:2::/64', 'one device, many addresses');
        assert.equal(rateKey('2001:db8::1'), '2001:db8:0:0::/64');
        assert.equal(rateKey('::1'), '0:0:0:0::/64');
        assert.equal(rateKey('::'), '0:0:0:0::/64');
        assert.equal(rateKey('64:ff9b::192.0.2.1'), '64:ff9b:0:0::/64');
        assert.equal(rateKey('fe80::1%eth0'), 'fe80:0:0:0::/64');
        assert.notEqual(rateKey('2001:db8:1:2::1'), rateKey('2001:db8:1:3::1'));
    });

    test('behind a trusted proxy, every client has its own allowance', () => withBroker({ rateLimit: 4, rateBurst: 2, trustedProxies: ['127.0.0.1'] }, async ({ base }) => {
        const { room, guest } = ids(),
              poll = (headers) => fetch(base + 'rooms/' + room + '/answers/' + guest, { headers }).then((r) => r.status);
        const a = { 'X-Forwarded-For': '203.0.113.1' }, b = { 'X-Forwarded-For': '203.0.113.2' };
        assert.deepStrictEqual([await poll(a), await poll(a), await poll(a)], [404, 404, 429]);
        assert.equal(await poll(b), 404, 'another client is not limited');
        const sameNet = { 'X-Forwarded-For': '2001:db8:1:2::1' }, sameNet2 = { 'X-Forwarded-For': '2001:db8:1:2::ffff' };
        assert.deepStrictEqual([await poll(sameNet), await poll(sameNet2), await poll(sameNet)], [404, 404, 429], 'one /64, one allowance');
    }));

    test('without trusting the proxy, everyone behind it shares one allowance', () => withBroker({ rateLimit: 4, rateBurst: 2 }, async ({ base }) => {
        const { room, guest } = ids(),
              poll = (headers) => fetch(base + 'rooms/' + room + '/answers/' + guest, { headers }).then((r) => r.status);
        assert.deepStrictEqual([
            await poll({ 'X-Forwarded-For': '203.0.113.1' }),
            await poll({ 'X-Forwarded-For': '203.0.113.2' }),
            await poll({ 'X-Forwarded-For': '203.0.113.3' })
        ], [404, 404, 429]);
    }));

});
