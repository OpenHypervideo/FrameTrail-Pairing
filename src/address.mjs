/*
 * Who is asking: the client address of a request, and the key the rate limit counts it under.
 *
 * Behind a reverse proxy (Apache or nginx in Plesk) every request comes from the proxy, which names the client in X-Forwarded-For and X-Real-IP. Anyone can send those headers, so they count only when the socket peer is a trusted proxy.
 */

import net from 'node:net';


/**
 * An address as Node reports it, without the IPv4-mapped IPv6 prefix ("::ffff:127.0.0.1" → "127.0.0.1").
 */
export function plainAddress(address) {
    const text = String(address || '').trim();
    const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(text);
    return mapped ? mapped[1] : text;
}

function family(address) {
    const version = net.isIP(address);
    return version === 4 ? 'ipv4' : (version === 6 ? 'ipv6' : null);
}


/**
 * I make the set of trusted proxies from a list of addresses and CIDR ranges ("127.0.0.1", "::1", "10.0.0.0/8"). Throws on an entry that is neither.
 */
export function trustedProxies(list = []) {

    const blockList = new net.BlockList();

    for (const entry of list) {
        const [address, prefix, extra] = String(entry).trim().split('/'),
              kind = family(address);
        if (!kind || extra !== undefined) {
            throw new Error('not an IP address or CIDR range: ' + entry);
        }
        if (prefix === undefined) {
            blockList.addAddress(address, kind);
            continue;
        }
        const bits = Number(prefix);
        if (!/^\d+$/.test(prefix) || bits > (kind === 'ipv4' ? 32 : 128)) {
            throw new Error('not an IP address or CIDR range: ' + entry);
        }
        blockList.addSubnet(address, bits, kind);
    }

    return {
        size: list.length,
        has(address) {
            const plain = plainAddress(address), kind = family(plain);
            return Boolean(kind) && blockList.check(plain, kind);
        }
    };

}


/**
 * The client's address. Only when the socket peer is a trusted proxy, I read X-Forwarded-For from the right, skipping trusted hops, and take the first one that is not trusted (a client cannot forge the entries a trusted proxy appended or wrote); without that header, X-Real-IP. An entry that is not an address ends the walk.
 */
export function clientAddress(req, trusted) {

    const peer = plainAddress(req.socket && req.socket.remoteAddress);

    if (!trusted || !trusted.has(peer)) { return peer; }

    const forwarded = String(req.headers['x-forwarded-for'] || '').split(',').map(plainAddress).filter(Boolean);

    if (forwarded.length) {
        let client = peer;
        for (let i = forwarded.length - 1; i >= 0; i--) {
            if (!net.isIP(forwarded[i])) { break; }
            client = forwarded[i];
            if (!trusted.has(client)) { break; }
        }
        return client;
    }

    const real = plainAddress(req.headers['x-real-ip']);
    return net.isIP(real) ? real : peer;

}


// The eight 16-bit groups of an IPv6 address.
export function ipv6Groups(address) {
    let text = address.split('%')[0];
    const v4 = /(\d+)\.(\d+)\.(\d+)\.(\d+)$/.exec(text);
    if (v4) {
        const [a, b, c, d] = v4.slice(1).map(Number);
        text = text.slice(0, v4.index) + ((a << 8) | b).toString(16) + ':' + ((c << 8) | d).toString(16);
    }
    const double = text.indexOf('::'),
          head   = (double < 0 ? text : text.slice(0, double)).split(':').filter(Boolean),
          tail   = (double < 0 ? '' : text.slice(double + 2)).split(':').filter(Boolean),
          fill   = (double < 0) ? [] : new Array(8 - head.length - tail.length).fill('0');
    return head.concat(fill, tail).map((group) => parseInt(group, 16));
}

/**
 * What the rate limit counts a client under: an IPv4 address as it is, an IPv6 address by its /64. A single device usually has a whole /64 to pick addresses from, just as a class behind one IPv4 address shares it.
 */
export function rateKey(address) {
    if (net.isIP(address) !== 6) { return address; }
    return ipv6Groups(address).slice(0, 4).map((group) => group.toString(16)).join(':') + '::/64';
}
