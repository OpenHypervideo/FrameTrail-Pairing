/*
 * The broker's options, from environment variables (for the systemd unit) and the command line (the stub's flags, and more). The command line wins: a list given there replaces the environment's.
 */

import fs from 'node:fs';
import { trustedProxies } from './address.mjs';
import { normalizeOrigin } from './ice.mjs';

const MAX_TURN_TTL = 172800;    // s; Cloudflare's limit (48 h)

// [option, flag, environment variable, kind, argument, description]
const OPTIONS = [
    ['host',            '--host',               'HOST',                     'string', '<address>', 'Address to listen on (default localhost; 127.0.0.1 behind a proxy, 0.0.0.0 for a LAN)'],
    ['port',            '--port',               'PORT',                     'port',   '<port>',    'Port to listen on (default 8787)'],
    ['stun',            '--stun',               'STUN_URLS',                'list',   '<url>',     'STUN server for every page, e.g. stun:stun.cloudflare.com:3478 (repeatable)'],
    ['cfTurnKeyId',     '--cf-turn-key-id',     'CF_TURN_KEY_ID',           'string', '<id>',      'Cloudflare Realtime TURN key id'],
    ['cfTurnToken',     '--cf-turn-token',      'CF_TURN_API_TOKEN',        'secret', '<token>',   'Its API token'],
    ['cfTurnTokenFile', '--cf-turn-token-file', 'CF_TURN_API_TOKEN_FILE',   'string', '<file>',    'A file holding the API token'],
    ['turnMonthlyLimitGB', '--turn-monthly-limit', 'TURN_MONTHLY_LIMIT_GB', 'gb',     '<GB>',      'Usage guard: no Cloudflare TURN for the rest of the month once the key relayed this much'],
    ['cfAccountId',     '--cf-account-id',      'CF_ACCOUNT_ID',            'string', '<id>',      'Usage guard: the Cloudflare account id'],
    ['cfAnalyticsToken', '--cf-analytics-token', 'CF_ANALYTICS_TOKEN',      'secret', '<token>',   'Usage guard: an API token with Account Analytics: Read'],
    ['cfAnalyticsTokenFile', '--cf-analytics-token-file', 'CF_ANALYTICS_TOKEN_FILE', 'string', '<file>', 'A file holding that token'],
    ['turn',            '--turn',               'TURN_URLS',                'list',   '<url>',     'coturn TURN server with use-auth-secret, e.g. turn:turn.example.org:3478 (repeatable)'],
    ['turnSecret',      '--turn-secret',        'TURN_SECRET',              'secret', '<secret>',  'coturn\'s static-auth-secret'],
    ['turnSecretFile',  '--turn-secret-file',   'TURN_SECRET_FILE',         'string', '<file>',    'A file holding the secret'],
    ['turnTTL',         '--turn-ttl',           'TURN_TTL',                 'ttl',    '<seconds>', 'Lifetime of TURN credentials (default 86400, at most 172800)'],
    ['allowedOrigins',  '--allowed-origin',     'ALLOWED_ORIGINS',          'list',   '<origin>',  'Only pages of this origin get TURN credentials; STUN goes to all. https://*.example.org stands for one label (repeatable; default: every origin)'],
    ['trustedProxies',  '--trusted-proxy',      'TRUSTED_PROXIES',          'list',   '<ip|cidr>', 'Proxy whose X-Forwarded-For / X-Real-IP name the client (repeatable; default none)'],
    ['rateLimit',       '--rate-limit',         'RATE_LIMIT',               'count',  '<n>',       'Requests per client and minute, sustained (default 1200)'],
    ['rateBurst',       '--rate-burst',         'RATE_BURST',               'count',  '<n>',       'Requests per client at once (default half the rate limit)'],
    ['logLevel',        '--log',                'LOG_LEVEL',                'level',  '<level>',   'all, info (all but the routine polls; default), warn or off'],
    ['cert',            '--cert',               'TLS_CERT',                 'string', '<file>',    'Certificate for https (with --key)'],
    ['key',             '--key',                'TLS_KEY',                  'string', '<file>',    'Its private key']
];

const LOG_LEVELS = ['all', 'info', 'warn', 'off'];

function list(text) {
    return String(text).split(/[\s,]+/).filter(Boolean);
}

function readSecretFile(file) {
    try {
        return fs.readFileSync(file, 'utf8').trim();
    } catch (error) {
        throw new Error('Cannot read ' + file + ' (' + error.code + ')');
    }
}

function value(kind, text, name) {
    const number = Number(text);
    switch (kind) {
        case 'port':
            if (!/^\d+$/.test(text) || number > 65535) { throw new Error(name + ' must be a port number, not ' + text); }
            return number;
        case 'count':
            if (!/^\d+$/.test(text) || number < 1) { throw new Error(name + ' must be a positive whole number, not ' + text); }
            return number;
        case 'ttl':
            if (!/^\d+$/.test(text) || number < 60 || number > MAX_TURN_TTL) { throw new Error(name + ' must be between 60 and ' + MAX_TURN_TTL + ' seconds, not ' + text); }
            return number;
        case 'gb':
            if (!/^\d+(\.\d+)?$/.test(text) || !(number > 0)) { throw new Error(name + ' must be a number of gigabytes, not ' + text); }
            return number;
        case 'level':
            if (!LOG_LEVELS.includes(text)) { throw new Error(name + ' must be one of ' + LOG_LEVELS.join(', ') + ', not ' + text); }
            return text;
        default:
            return text;
    }
}

/**
 * The options for createBroker/startBroker from argv (without node and the script) and env. Returns { options, help }; throws an Error whose message says what is wrong.
 */
export function readConfig(argv = [], env = {}) {

    const fromEnv = {}, fromArgs = {};

    for (const [option, , variable, kind] of OPTIONS) {
        if (env[variable] === undefined || env[variable] === '') { continue; }
        fromEnv[option] = (kind === 'list') ? list(env[variable]) : value(kind, String(env[variable]).trim(), variable);
    }

    let help = false;
    for (let i = 0; i < argv.length; i++) {
        const arg = argv[i];
        if (arg === '--help' || arg === '-h') { help = true; continue; }
        if (arg === '--quiet') { fromArgs.logLevel = 'off'; continue; }
        const spec = OPTIONS.find((o) => o[1] === arg);
        if (!spec) { throw new Error('Unknown option ' + arg); }
        const [option, flag, , kind] = spec, next = argv[++i];
        if (next === undefined) { throw new Error(flag + ' needs a value'); }
        if (kind === 'list') {
            (fromArgs[option] = fromArgs[option] || []).push(...list(next));
        } else {
            fromArgs[option] = value(kind, next, flag);
        }
    }

    const o = Object.assign({
        host: 'localhost', port: 8787, stun: [], turn: [], allowedOrigins: [], trustedProxies: [],
        turnTTL: 86400, rateLimit: 1200, logLevel: 'info'
    }, fromEnv, fromArgs);

    if (o.turnSecretFile && !o.turnSecret) { o.turnSecret = readSecretFile(o.turnSecretFile); }
    if (o.cfTurnTokenFile && !o.cfTurnToken) { o.cfTurnToken = readSecretFile(o.cfTurnTokenFile); }
    if (o.cfAnalyticsTokenFile && !o.cfAnalyticsToken) { o.cfAnalyticsToken = readSecretFile(o.cfAnalyticsTokenFile); }
    delete o.turnSecretFile;
    delete o.cfTurnTokenFile;
    delete o.cfAnalyticsTokenFile;

    if (!help) {
        if (o.turn.length && !o.turnSecret) {
            throw new Error('--turn needs --turn-secret (coturn: use-auth-secret, static-auth-secret)');
        }
        if (Boolean(o.cfTurnKeyId) !== Boolean(o.cfTurnToken)) {
            throw new Error('Cloudflare TURN needs both the key id (CF_TURN_KEY_ID) and its API token (CF_TURN_API_TOKEN)');
        }
        const guard = [o.cfAccountId, o.cfAnalyticsToken, o.turnMonthlyLimitGB].filter(Boolean).length;
        if (guard && guard < 3) {
            throw new Error('The usage guard needs CF_ACCOUNT_ID, CF_ANALYTICS_TOKEN and TURN_MONTHLY_LIMIT_GB together');
        }
        if (guard && !o.cfTurnKeyId) {
            throw new Error('The usage guard watches Cloudflare TURN, which needs CF_TURN_KEY_ID and CF_TURN_API_TOKEN');
        }
        if (o.cfAccountId && !/^[0-9a-f]{32}$/i.test(o.cfAccountId)) {
            throw new Error('CF_ACCOUNT_ID must be the 32 hexadecimal characters of the account id, not ' + o.cfAccountId);
        }
        if (Boolean(o.cert) !== Boolean(o.key)) {
            throw new Error('https needs both --cert and --key');
        }
        for (const url of o.stun) {
            if (!/^stuns?:/.test(url)) { throw new Error('not a STUN URL: ' + url); }
        }
        for (const url of o.turn) {
            if (!/^turns?:/.test(url)) { throw new Error('not a TURN URL: ' + url); }
        }
        o.allowedOrigins = o.allowedOrigins.map(normalizeOrigin);
        trustedProxies(o.trustedProxies);
        if (o.rateBurst && o.rateBurst > o.rateLimit) {
            throw new Error('the burst (' + o.rateBurst + ') cannot be larger than the rate limit (' + o.rateLimit + ')');
        }
    }

    return { options: o, help };

}

export function usage() {
    const rows = OPTIONS.map(([, flag, variable, , arg, text]) => '  ' + (flag + ' ' + arg).padEnd(28) + variable.padEnd(24) + text);
    return [
        'FrameTrail pairing broker (contract v1)',
        '',
        'Usage: node src/pairing-broker.mjs [options]',
        '',
        'Every option can also be set by its environment variable; the command line wins.',
        'Lists in a variable are separated by commas or spaces.',
        '',
        '  ' + 'Option'.padEnd(28) + 'Variable'.padEnd(24) + 'Meaning',
        ...rows,
        '  ' + '--quiet'.padEnd(28) + ''.padEnd(24) + 'No log (--log off)',
        '  ' + '--help'.padEnd(28) + ''.padEnd(24) + 'This text',
        '',
        'Examples:',
        '  node src/pairing-broker.mjs                                   # http://localhost:8787, LAN only',
        '  node src/pairing-broker.mjs --host 0.0.0.0 --stun stun:stun.cloudflare.com:3478',
        '  node src/pairing-broker.mjs --turn turn:turn.example.org:3478 --turn-secret <secret>',
        '  node src/pairing-broker.mjs --cert cert.pem --key key.pem     # https, for phones on an https page'
    ].join('\n');
}
