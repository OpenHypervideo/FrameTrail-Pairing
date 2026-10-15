/*
 * What the tests share: FrameTrail's own pairing client (FrameTrailPairing.js, from FRAMETRAIL_SRC, default ../frametrail/src), so the broker is tested against the code that will talk to it; a broker on a free port with a clock the test moves; and the remote mode, in which BROKER_URL names a deployed broker to run the clock-independent tests against.
 */

import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { createBroker } from '../src/pairing-broker.mjs';

const require = createRequire(import.meta.url);

export const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

export const FRAMETRAIL_SRC = path.resolve(ROOT, process.env.FRAMETRAIL_SRC || '../frametrail/src');

const CLIENT = path.join(FRAMETRAIL_SRC, '_shared/frametrail-core/pairing/FrameTrailPairing.js');

if (!fs.existsSync(CLIENT)) {
    throw new Error('FrameTrail\'s pairing client is not at ' + CLIENT + '. Check out FrameTrail beside this repository, or set FRAMETRAIL_SRC to its src folder.');
}

export const Pairing = require(CLIENT);

// A deployed broker to test, e.g. https://pair.example.org/ (with a slash at the end, as pairingBrokerURL).
export const REMOTE = process.env.BROKER_URL ? Pairing.brokerBase(process.env.BROKER_URL) : null;

// An origin the deployed broker gives TURN credentials to, e.g. https://www.example.org.
export const REMOTE_ORIGIN = process.env.BROKER_ORIGIN || null;

export const ids = () => ({ room: Pairing.randomId(), hostKey: Pairing.randomId(), guest: Pairing.randomId() });

/**
 * A broker on a free port of 127.0.0.1, with a clock the test moves:
 * run({ base, client, advance(ms), broker, lines }); lines collects the log.
 */
export async function withBroker(options, run) {
    let now = 1000000;
    const lines = [],
          broker = createBroker(Object.assign({ now: () => now, log: (line) => lines.push(line) }, options)),
          server = http.createServer(broker.handle);
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    const base = 'http://127.0.0.1:' + server.address().port + '/';
    try {
        await run({ base, client: Pairing.brokerClient(base), advance: (ms) => { now += ms; }, broker, lines });
    } finally {
        await new Promise((resolve) => server.close(resolve));
    }
}

/**
 * The broker under test: the deployed one when BROKER_URL is set (options do not apply there), otherwise one in-process.
 */
export async function withTarget(options, run) {
    if (REMOTE) {
        return run({ base: REMOTE, client: Pairing.brokerClient(REMOTE), advance: null, broker: null, lines: [] });
    }
    return withBroker(options, run);
}
