/*
 * The usage guard of the Cloudflare provider: anyone can fetch TURN credentials from /ice and relay through them at the operator's expense, so once the TURN key has relayed the month's limit, the broker hands out no more TURN and revokes what it issued. Cloudflare is a stand-in here.
 */

import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { CLOUDFLARE_GRAPHQL, cloudflareProvider } from '../src/ice.mjs';
import { withBroker } from './helpers.mjs';

const ORIGIN = 'https://www.example.org';
// The tests' own requests to a broker (inside a test, fetch is Cloudflare's stand-in).
const fetch_ = globalThis.fetch;
const ACCOUNT = 'a'.repeat(32);

// A stand-in for Cloudflare: credentials (a new username each time), the analytics (the bytes the test sets), revocations.
function cloudflare() {
    const state = { egress: 0, minted: 0, revoked: [], queries: [], analytics: 'ok', hold: null };
    const json = (body, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
    const fetch = async (url, init) => {
        if (url.endsWith('/credentials/generate-ice-servers')) {
            const username = 'user-' + (++state.minted);
            if (state.hold) { await state.hold; }
            return json({ iceServers: [{ urls: ['stun:stun.cloudflare.com:3478'] }, { urls: ['turns:turn.cloudflare.com:443?transport=tcp'], username, credential: 'c' }] }, 201);
        }
        if (url.endsWith('/revoke')) {
            state.revoked.push(decodeURIComponent(url.split('/credentials/')[1].slice(0, -'/revoke'.length)));
            return new Response(null, { status: 204 });
        }
        if (url === CLOUDFLARE_GRAPHQL) {
            state.queries.push({ headers: init.headers, query: JSON.parse(init.body).query });
            if (state.analytics === 'down') { throw new TypeError('fetch failed'); }
            if (state.analytics === 'refused') { return json({ data: null, errors: [{ message: 'not authorized for that account' }] }); }
            return json({ data: { viewer: { accounts: [{ callsTurnUsageAdaptiveGroups: [{ sum: { egressBytes: state.egress } }] }] } }, errors: null });
        }
        throw new Error('not Cloudflare: ' + url);
    };
    return { state, fetch };
}

function guarded(fetch) {
    let t = Date.UTC(2026, 9, 15, 12);
    const lines = [];
    const p = cloudflareProvider({
        keyId: 'key-id', token: 'TURN-TOKEN', ttl: 86400, now: () => t, fetch, log: (level, line) => lines.push(level + ' ' + line),
        guard: { accountId: ACCOUNT, token: 'ANALYTICS-TOKEN', limit: 500e9 }
    });
    return { p, lines, advance: (ms) => { t += ms; }, now: () => t };
}

const username = (servers) => (servers.find((server) => server.username) || {}).username;

describe('Cloudflare usage guard', () => {

    test('asks the analytics for what the key relayed this month, then mints', async () => {
        const { state, fetch } = cloudflare(),
              { p, lines } = guarded(fetch);
        await p.start();
        p.stop();
        assert.equal(state.queries.length, 1);
        assert.equal(state.queries[0].headers['Authorization'], 'Bearer ANALYTICS-TOKEN');
        const query = state.queries[0].query;
        assert.match(query, /callsTurnUsageAdaptiveGroups/);
        assert.match(query, new RegExp('accountTag: "' + ACCOUNT + '"'));
        assert.match(query, /keyId: "key-id"/);
        assert.match(query, /date_geq: "2026-10-01"/, 'from the 1st of the month');
        assert.match(query, /date_leq: "2026-10-15"/, 'to today');
        assert.match(query, /sum \{ egressBytes \}/, 'what Cloudflare bills: bytes to the clients');
        assert.equal(state.minted, 1);
        assert.deepStrictEqual(lines, ['info Cloudflare TURN usage this month: 0.0 GB of the limit of 500.0 GB']);
    });

    test('warns at 80 %, once a month', async () => {
        const { state, fetch } = cloudflare(),
              { p, lines, now } = guarded(fetch);
        await p.start();
        p.stop();
        state.egress = 400e9;
        await p.checkUsage();
        await p.checkUsage();
        assert.deepStrictEqual(lines.slice(1), ['warn Cloudflare TURN usage this month: 400.0 GB, 80 % of the limit of 500.0 GB']);
        assert.equal(username(await p.servers(now())), 'user-1', 'TURN still');
    });

    test('at the limit: no TURN until next month, and every set not expired is revoked', async () => {
        const { state, fetch } = cloudflare(),
              { p, lines, advance, now } = guarded(fetch);
        await p.start();
        p.stop();
        advance(3600001);
        p.servers(now());
        await p.warm();                                     // user-2, an hour later
        advance(23 * 3600000);
        p.servers(now());
        await p.warm();                                     // user-3; user-1 has expired by now
        assert.equal(state.minted, 3);
        state.egress = 500e9;
        await p.checkUsage();
        assert.deepStrictEqual(state.revoked.sort(), ['user-2', 'user-3']);
        assert.equal(lines.at(-1), 'warn Cloudflare TURN usage this month: 500.0 GB, the limit of 500.0 GB is reached. No TURN until next month; revoked 2 of 2 credential sets.');
        assert.deepStrictEqual(await p.servers(now()), []);
        await p.warm();
        assert.equal(state.minted, 3, 'and none minted');
        state.egress = 0;
        await p.checkUsage();
        assert.deepStrictEqual(await p.servers(now()), [], 'the same month stays off');
        assert.equal(p.blocked, '2026-10');
    });

    test('a new month: TURN again', async () => {
        const { state, fetch } = cloudflare(),
              { p, lines, advance, now } = guarded(fetch);
        await p.start();
        p.stop();
        state.egress = 600e9;
        await p.checkUsage();
        advance(17 * 86400000);                             // November 1st
        state.egress = 1e9;
        await p.checkUsage();
        assert.equal(p.blocked, null);
        assert.equal(lines.at(-1), 'info Cloudflare TURN on again for a new month (1.0 GB of 500.0 GB)');
        assert.match(state.queries.at(-1).query, /date_geq: "2026-11-01"/);
        assert.equal(username(await p.servers(now())), 'user-2', 'freshly minted');
    });

    test('when the analytics cannot be read, TURN stays as it is, and the log says so once', async () => {
        const { state, fetch } = cloudflare(),
              { p, lines, now } = guarded(fetch);
        state.analytics = 'down';
        await p.start();
        p.stop();
        state.analytics = 'refused';
        await p.checkUsage();
        assert.deepStrictEqual(lines, ['warn Cloudflare TURN usage guard: fetch failed (TURN stays on)']);
        assert.equal(username(await p.servers(now())), 'user-1');
        state.analytics = 'ok';
        await p.checkUsage();
        assert.equal(lines.at(-1), 'info Cloudflare TURN usage this month: 0.0 GB of the limit of 500.0 GB', 'and when it works again');
        assert.ok(!lines.join('\n').includes('TOKEN'), 'no token in the log');
    });

    test('a set minted while the limit is reached goes back at once', async () => {
        const { state, fetch } = cloudflare(),
              { p, now } = guarded(fetch);
        let release;
        state.hold = new Promise((resolve) => { release = resolve; });
        const servers = p.servers(now());                   // minting, held
        state.egress = 500e9;
        await p.checkUsage();
        release();
        assert.deepStrictEqual(await servers, []);
        assert.deepStrictEqual(state.revoked, ['user-1']);
    });

    test('through the broker: STUN stays, TURN goes', () => {
        const { state, fetch } = cloudflare();
        return withBroker({
            stun: ['stun:stun.cloudflare.com:3478'], cfTurnKeyId: 'key-id', cfTurnToken: 'TURN-TOKEN', allowedOrigins: [ORIGIN],
            cfAccountId: ACCOUNT, cfAnalyticsToken: 'ANALYTICS-TOKEN', turnMonthlyLimitGB: 500, fetch, logLevel: 'all'
        }, async ({ base, broker, lines }) => {
            await broker.warm();
            broker.stop();
            const ice = async () => (await (await fetch_(base + 'ice', { headers: { 'Origin': ORIGIN } })).json()).iceServers;
            assert.ok((await ice()).some((server) => server.credential));
            state.egress = 501e9;
            await broker.ice.providers.find((provider) => provider.checkUsage).checkUsage();
            assert.deepStrictEqual(await ice(), [{ urls: ['stun:stun.cloudflare.com:3478'] }]);
            assert.deepStrictEqual(state.revoked, ['user-1']);
            assert.ok(lines.some((line) => /limit of 500\.0 GB is reached/.test(line)));
            assert.ok(!lines.join('\n').includes('TOKEN'));
        });
    });

});
