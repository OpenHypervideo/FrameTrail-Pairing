/*
 * Options from the environment and the command line.
 */

import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { readConfig, usage } from '../src/config.mjs';

describe('configuration', () => {

    test('defaults', () => {
        const { options, help } = readConfig([], {});
        assert.equal(help, false);
        assert.equal(options.host, 'localhost');
        assert.equal(options.port, 8787);
        assert.equal(options.turnTTL, 86400);
        assert.equal(options.rateLimit, 1200);
        assert.equal(options.logLevel, 'info');
        assert.deepStrictEqual([options.stun, options.turn, options.allowedOrigins, options.trustedProxies], [[], [], [], []]);
    });

    test('every flag of the stub', () => {
        const { options } = readConfig(['--port', '9000', '--host', '0.0.0.0', '--stun', 'stun:a.example:3478', '--stun', 'stun:b.example:3478',
            '--turn', 'turn:t.example:3478', '--turn-secret', 's', '--turn-ttl', '600', '--cert', 'c.pem', '--key', 'k.pem', '--quiet'], {});
        assert.equal(options.port, 9000);
        assert.equal(options.host, '0.0.0.0');
        assert.deepStrictEqual(options.stun, ['stun:a.example:3478', 'stun:b.example:3478']);
        assert.deepStrictEqual(options.turn, ['turn:t.example:3478']);
        assert.equal(options.turnSecret, 's');
        assert.equal(options.turnTTL, 600);
        assert.equal(options.cert, 'c.pem');
        assert.equal(options.key, 'k.pem');
        assert.equal(options.logLevel, 'off');
        assert.equal(readConfig(['--help'], {}).help, true);
        assert.match(usage(), /--turn-secret/);
    });

    test('the environment, as a systemd unit sets it', () => {
        const { options } = readConfig([], {
            HOST: '127.0.0.1', PORT: '8787', STUN_URLS: 'stun:stun.cloudflare.com:3478', CF_TURN_KEY_ID: 'key', CF_TURN_API_TOKEN: 'token',
            TURN_TTL: '86400', ALLOWED_ORIGINS: 'https://www.example.org/, https://example.net', TRUSTED_PROXIES: '127.0.0.1 ::1',
            RATE_LIMIT: '600', RATE_BURST: '300', LOG_LEVEL: 'warn', UNRELATED: 'x'
        });
        assert.equal(options.host, '127.0.0.1');
        assert.deepStrictEqual(options.stun, ['stun:stun.cloudflare.com:3478']);
        assert.equal(options.cfTurnKeyId, 'key');
        assert.equal(options.cfTurnToken, 'token');
        assert.deepStrictEqual(options.allowedOrigins, ['https://www.example.org', 'https://example.net'], 'commas or spaces; origins normalized');
        assert.deepStrictEqual(options.trustedProxies, ['127.0.0.1', '::1']);
        assert.equal(options.rateLimit, 600);
        assert.equal(options.rateBurst, 300);
        assert.equal(options.logLevel, 'warn');
        assert.equal(readConfig([], { STUN_URLS: '' }).options.stun.length, 0, 'empty: unset');
    });

    test('the command line wins', () => {
        const { options } = readConfig(['--port', '9001', '--stun', 'stun:cli.example:3478', '--log', 'all'], { PORT: '8000', STUN_URLS: 'stun:env.example:3478', LOG_LEVEL: 'warn' });
        assert.equal(options.port, 9001);
        assert.deepStrictEqual(options.stun, ['stun:cli.example:3478'], 'a list on the command line replaces the environment\'s');
        assert.equal(options.logLevel, 'all');
    });

    test('secrets from files', () => {
        const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pairing-config-'));
        try {
            fs.writeFileSync(path.join(dir, 'token'), 'cf-token\n');
            fs.writeFileSync(path.join(dir, 'secret'), 'coturn-secret\n');
            const { options } = readConfig([], {
                CF_TURN_KEY_ID: 'key', CF_TURN_API_TOKEN_FILE: path.join(dir, 'token'),
                TURN_URLS: 'turn:t.example:3478', TURN_SECRET_FILE: path.join(dir, 'secret')
            });
            assert.equal(options.cfTurnToken, 'cf-token');
            assert.equal(options.turnSecret, 'coturn-secret');
            assert.ok(!('cfTurnTokenFile' in options) && !('turnSecretFile' in options));
            assert.throws(() => readConfig([], { TURN_URLS: 'turn:t.example', TURN_SECRET_FILE: path.join(dir, 'missing') }), /Cannot read .*missing \(ENOENT\)/);
        } finally {
            fs.rmSync(dir, { recursive: true });
        }
    });

    test('what is refused, with a message that says why', () => {
        const refused = [
            [['--turn', 'turn:t.example:3478'], {}, /--turn needs --turn-secret/],
            [[], { CF_TURN_KEY_ID: 'key' }, /both the key id .* and its API token/],
            [[], { CF_TURN_API_TOKEN: 'token' }, /both the key id/],
            [['--cert', 'c.pem'], {}, /both --cert and --key/],
            [['--stun', 'turn:t.example:3478'], {}, /not a STUN URL/],
            [['--turn', 'stun:s.example', '--turn-secret', 's'], {}, /not a TURN URL/],
            [['--allowed-origin', 'https://example.org/path'], {}, /not an origin/],
            [['--trusted-proxy', 'localhost'], {}, /not an IP address or CIDR range/],
            [['--port', '70000'], {}, /--port must be a port number/],
            [[], { RATE_LIMIT: '0' }, /RATE_LIMIT must be a positive whole number/],
            [['--rate-limit', '10', '--rate-burst', '20'], {}, /cannot be larger than the rate limit/],
            [['--turn-ttl', '200000'], {}, /between 60 and 172800/],
            [[], { LOG_LEVEL: 'debug' }, /LOG_LEVEL must be one of all, info, warn, off/],
            [['--bogus'], {}, /Unknown option --bogus/],
            [['--port'], {}, /--port needs a value/]
        ];
        for (const [argv, env, message] of refused) {
            assert.throws(() => readConfig(argv, env), message, JSON.stringify([argv, env]));
        }
    });

});
