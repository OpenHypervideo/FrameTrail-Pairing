# FrameTrail-Pairing

The pairing broker for [FrameTrail](https://github.com/OpenHypervideo/FrameTrail): the small HTTP service through which a FrameTrail player and the phones that scan its QR code exchange their WebRTC offers and answers, and which tells both sides which STUN and TURN servers to use. Everything else, the hypervideo and the playback, goes directly between player and phone over an encrypted WebRTC DataChannel.

It implements broker contract v1 as FrameTrail ≥ 1.4.2 describes it in [docs/PAIRING.md](https://github.com/OpenHypervideo/FrameTrail/blob/main/docs/PAIRING.md) and grew from the stub FrameTrail ships for development (`scripts/pairing-broker.mjs`). Node 20 or later, no dependencies, one process, everything in memory. On top of the stub it has:

- a rate limit per client that works behind a reverse proxy: it reads `X-Forwarded-For` / `X-Real-IP`, but only from proxies it trusts; IPv6 clients count by their /64;
- TURN credentials from [Cloudflare Realtime TURN](https://developers.cloudflare.com/realtime/turn/) or from a [coturn](https://github.com/coturn/coturn) server of your own, optionally only for the pages of listed origins (STUN goes to every page);
- configuration by environment variables (for systemd) as well as the stub's command line;
- bounded memory, timeouts, and a log without addresses, offers, answers or whole ids.

The setup described here runs the broker on a server with Plesk and takes TURN from Cloudflare; `deploy/coturn/` holds a setup for running TURN on the same server instead.

```
 player (browser)                         pairing broker                          phone (companion page)
 ───────────────                          ──────────────                          ──────────────────────
 GET  /ice                       ───────▶  STUN, TURN credentials  ◀───────        GET  /ice
 PUT  /rooms/{room}  (host key)  ───────▶  room                    ◀───────        POST /rooms/{room}/offers/{phone}
 GET  /rooms/{room}/offers       ───────▶  offer                   
 PUT  /rooms/{room}/answers/…    ───────▶  answer                  ◀───────        GET  /rooms/{room}/answers/{phone}

        └──────────── WebRTC DataChannel (DTLS): directly, or through a TURN relay ────────────┘
```

## Running it locally

```bash
npm test                                  # needs FrameTrail beside this repository (or FRAMETRAIL_SRC, see Tests)
npm start                                 # http://localhost:8787, LAN only: GET /ice answers no servers
node src/pairing-broker.mjs --help        # every option
node src/pairing-broker.mjs --host 0.0.0.0 --stun stun:stun.cloudflare.com:3478 --cert cert.pem --key key.pem
```

For a phone on the LAN, FrameTrail's own `scripts/pairing-lan.mjs` serves FrameTrail and the stub on one https origin; this broker accepts the same options as the stub.

## Configuration

Every option can be given as an environment variable or on the command line; the command line wins (a list given there replaces the variable's). Lists in a variable are separated by commas or spaces.

| Variable | Option | Default | Meaning |
|---|---|---|---|
| `HOST` | `--host` | `localhost` | Address to listen on: `127.0.0.1` behind a proxy, `0.0.0.0` on a LAN |
| `PORT` | `--port` | `8787` | |
| `STUN_URLS` | `--stun` | none | STUN servers for every page |
| `CF_TURN_KEY_ID` | `--cf-turn-key-id` | none | Cloudflare Realtime TURN key id |
| `CF_TURN_API_TOKEN` / `CF_TURN_API_TOKEN_FILE` | `--cf-turn-token` / `--cf-turn-token-file` | none | Its API token, or a file holding it |
| `TURN_MONTHLY_LIMIT_GB` | `--turn-monthly-limit` | none | Usage guard: no Cloudflare TURN for the rest of the month once the key has relayed this many GB |
| `CF_ACCOUNT_ID` | `--cf-account-id` | none | Usage guard: the Cloudflare account id |
| `CF_ANALYTICS_TOKEN` / `CF_ANALYTICS_TOKEN_FILE` | `--cf-analytics-token` / `--cf-analytics-token-file` | none | Usage guard: an API token with Account Analytics: Read, or a file holding it |
| `TURN_URLS` | `--turn` | none | coturn TURN server(s) with `use-auth-secret` |
| `TURN_SECRET` / `TURN_SECRET_FILE` | `--turn-secret` / `--turn-secret-file` | none | coturn's `static-auth-secret`, or a file holding it |
| `TURN_TTL` | `--turn-ttl` | `86400` | Lifetime of TURN credentials in seconds (at most 172800) |
| `ALLOWED_ORIGINS` | `--allowed-origin` | none: every origin | Only pages of these origins get TURN credentials; `https://*.example.org` stands for every origin one label under example.org |
| `TRUSTED_PROXIES` | `--trusted-proxy` | none | Proxies (addresses or CIDR ranges) whose `X-Forwarded-For` / `X-Real-IP` name the client |
| `RATE_LIMIT` | `--rate-limit` | `1200` | Requests per client and minute, sustained |
| `RATE_BURST` | `--rate-burst` | half the rate limit | Requests per client at once |
| `LOG_LEVEL` | `--log`, `--quiet` | `info` | `all`, `info` (all but the routine polls), `warn` or `off` |
| `TLS_CERT` / `TLS_KEY` | `--cert` / `--key` | none | https without a proxy |

Why these values:

- **TURN credentials live 24 hours.** The player fetches `/ice` once, when pairing starts, and opens relays with those credentials for every phone that joins while its QR code is up, which in a classroom can be a whole school day. Cloudflare ends a relayed session shortly after its credentials expire, so a shorter lifetime would cut the player's relays in the middle of a lesson, which matters most on networks that only let TLS on port 443 out. (coturn keeps a running relay after its credentials expired; there the lifetime only limits when new relays can be opened.) Phones fetch `/ice` on every connect. Cloudflare's credentials are minted once and handed out for an hour, so every client gets between 23 and 24 hours; if Cloudflare cannot be reached, the last set is handed out while at least 12 hours are left, then none.
- **TURN only for listed origins.** `ALLOWED_ORIGINS` keeps other websites from using the relay through their visitors' browsers. It is no authentication: a script can send any `Origin` (see Security). A companion page on another origin than the player (`pairingCompanionURL`) has to be listed as well. A host that runs a FrameTrail instance per subdomain lists them all at once with a wildcard: `https://*.example.org` covers `https://yourproject.example.org`, not `https://example.org` itself, not `https://a.b.example.org`, and only on the scheme and port it names. The `*` must be the whole leftmost label of a domain with at least two more labels.
- **A usage guard for Cloudflare.** Anyone can fetch credentials from `/ice` and relay through Cloudflare at the operator's expense, and Cloudflare offers no spending cap. With `TURN_MONTHLY_LIMIT_GB` (and the account id and an analytics token) the broker asks Cloudflare's analytics every 5 minutes how much the TURN key has relayed to clients since the 1st of the month (UTC), which is what Cloudflare bills. At 80 % it logs a warning; at the limit it hands out no TURN until the next month and revokes every credential set it issued that has not expired, which ends the relays made with them. STUN stays, so pairing on one network keeps working. When the analytics cannot be read, TURN stays on and the log says so. The limit counts this key only; 1,000 GB a month are free, so a limit well below that, such as 500, keeps the bill at zero even if someone relays a lot within the 5 minutes between two looks.
- **1200 requests a minute per client, 600 at once.** A whole class pairs from behind one public address: each phone makes about seven requests while it pairs, each player polls once a second, and a school may run several players behind the same address. The limit is a token bucket, so a client that hits it waits about a second, not a minute. IPv6 clients count by their /64, since a single device can pick addresses from a whole /64.
- **Fixed limits** (in `DEFAULTS`, `src/pairing-broker.mjs`): rooms live 120 s after the player's last request, offers and answers 60 s, blobs up to 64 KB, 64 waiting offers and 128 answers per room, 10,000 rooms, 64 MB of offers and answers in all.

## Setup on a Plesk server

The examples call the broker `pair.example.org`, a subdomain of `example.org`, which is a subscription in Plesk, and `https://www.example.org` the origin of the pages that pair (the player and its companion page): replace them with your own.

The broker runs as a systemd service on `127.0.0.1:8787`; Plesk's web server serves `https://pair.example.org/` with a Let's Encrypt certificate and passes the broker's paths on: Plesk's nginx where its nginx component is installed, otherwise Apache (step 1 tells which). STUN and TURN come from Cloudflare, so the server needs no ports beyond 80 and 443. All commands run as root on the server, in this order.

### 1. What the server has

```bash
. /etc/os-release && echo "$PRETTY_NAME"; systemctl --version | head -1; plesk version | head -3
command -v node && node -v; ls /opt/plesk/node 2>/dev/null
ip -brief address show scope global
ss -ltnp | grep -w 8787 || echo "port 8787 is free"
curl -sS -o /dev/null -w 'Cloudflare API reachable: HTTP %{http_code}\n' https://rtc.live.cloudflare.com/
dig +short NS example.org
plesk sbin nginxmng --status; apache2ctl -M 2>/dev/null | grep -E 'proxy_module|proxy_http_module'
```

The broker needs Node 20 or later (step 4), the public IPv4 (and IPv6, if any) address for the DNS records (step 3), port 8787 free, and outbound https to Cloudflare. The last line tells which web server passes requests on (step 6): Plesk's nginx when `nginxmng` says it is enabled, otherwise Apache, which then needs its `proxy` and `proxy_http` modules.

### 2. A TURN key at Cloudflare

In the Cloudflare dashboard, open the **Realtime** section (once called Calls) and its TURN server page, and create a TURN key (name it, say, `frametrail-pairing`). Note its **key id** and **API token**; the token is shown only once and goes only into the broker's configuration on the server (step 5). Usage up to 1,000 GB a month is free, then $0.05 per GB; pairing needs a tiny fraction of that (see Operating).

For the usage guard (see Configuration) the broker also needs:

- the **account id**: in the dashboard's account overview ("Account ID", 32 hexadecimal characters; it is also the part of the dashboard's address after `dash.cloudflare.com/`);
- an **API token that can read the account's analytics**: **My Profile → API Tokens → Create Token → Create Custom Token**, permission **Account → Account Analytics → Read**, account resources **Include → your account**. It can read usage figures and nothing else.

### 3. DNS

At whoever serves example.org's DNS (the name servers from step 1; Plesk's own DNS settings count only if those are Plesk's), add:

| Name | Type | Value |
|---|---|---|
| `pair` | A | the server's public IPv4 address |
| `pair` | AAAA | its IPv6 address, **only** if Plesk serves example.org over IPv6 (Tools & Settings → IP Addresses) |

Let's Encrypt validates over IPv6 when there is an AAAA record, so an AAAA record the server does not answer on can make the certificate fail. If a wildcard record (`*`) already points `pair` at the server, nothing needs adding; a record of its own takes precedence over the wildcard. Check from the server against the domain's own name servers (from step 1):

```bash
dig +short pair.example.org A @<a name server from step 1>
dig +short pair.example.org AAAA @<a name server from step 1>
```

### 4. The subdomain in Plesk, and Node

1. **Websites & Domains → example.org → Add Subdomain**: `pair`, document root as proposed.
2. **pair.example.org → SSL/TLS Certificates → Let's Encrypt**: a certificate for `pair.example.org` (no `www`); then **Hosting Settings**: "Permanent SEO-safe 301 redirect from HTTP to HTTPS" on. PHP and web statistics can be switched off. Under **Logs → Log Rotation**, rotate daily and keep 7 files: the web server logs every request with the client's address.
3. **Node:** the unit runs `/opt/plesk/node/24/bin/node`, Plesk's Node.js 24 (an LTS version; `ls /opt/plesk/node` in step 1 lists what Plesk has). Without it, install Node in Plesk (**Extensions → Node.js**, then the newest LTS version under **Tools & Settings → Node.js**) and put its path into `ExecStart`; any Node 20 or later works.

### 5. The broker

```bash
git clone https://github.com/OpenHypervideo/FrameTrail-Pairing.git /opt/frametrail-pairing

install -d -m 700 /etc/frametrail-pairing
install -m 600 /opt/frametrail-pairing/deploy/broker.env.example /etc/frametrail-pairing/broker.env
nano /etc/frametrail-pairing/broker.env           # CF_TURN_KEY_ID and CF_TURN_API_TOKEN from step 2

cp /opt/frametrail-pairing/deploy/frametrail-pairing.service /etc/systemd/system/
grep ExecStart /etc/systemd/system/frametrail-pairing.service   # the node path from step 4
systemctl daemon-reload
systemctl enable --now frametrail-pairing

systemctl status frametrail-pairing --no-pager
journalctl -u frametrail-pairing -n 20 --no-pager
curl -s http://127.0.0.1:8787/ice; echo
curl -s -H 'Origin: https://www.example.org' http://127.0.0.1:8787/ice; echo
```

The first line of the log says what the broker hands out ("ICE servers: STUN + Cloudflare TURN; TURN credentials for 24 h, to https://www.example.org"). A warning about Cloudflare means the key id or the token is wrong. The first `curl` lists only STUN, the second STUN and TURN with a `username` and `credential`.

The service runs as a throwaway user that systemd creates for each start, cannot write anywhere, holds no capabilities and gets at most 256 MB (`deploy/frametrail-pairing.service`).

### 6. Passing the broker's paths on

**Plesk with Apache alone** (no nginx component): Apache needs its `proxy` and `proxy_http` modules (step 1). If one is missing: **Tools & Settings → Apache Web Server**, tick `proxy` and `proxy_http`, OK.

**Websites & Domains → pair.example.org → Hosting & DNS → Apache & nginx Settings → Additional directives for HTTPS**: paste the contents of [`deploy/apache-directives.conf`](deploy/apache-directives.conf), then OK (the box for HTTP stays empty: http redirects to https). Apache then passes `/ice` and `/rooms/…` to the broker; the broker itself refuses offers and answers over 64 KB (Apache does not apply `LimitRequestBody` to proxied requests). Apache appends the client's address to `X-Forwarded-For`; the broker takes the rightmost address that is not a trusted proxy, so whatever a client writes into that header itself does not count. Everything else stays with Plesk, including `/.well-known/acme-challenge/`, which certificate renewals need. After a broker restart Apache tries again at once (`retry=0`), and it opens a new connection for every request, so it never sends one into a connection Node is closing.

**Plesk with its nginx component:** paste [`deploy/nginx-directives.conf`](deploy/nginx-directives.conf) into **Additional nginx directives** instead; nginx can also keep the broker's paths out of its access log.

```bash
curl -s https://pair.example.org/ice; echo
```

### 7. Check it

From a computer with this repository and FrameTrail beside it:

```bash
BROKER_URL=https://pair.example.org/ npm test
BROKER_URL=https://pair.example.org/ BROKER_ORIGIN=https://www.example.org npm test
curl -s -H 'Origin: https://www.example.org' https://pair.example.org/ice; echo     # STUN and TURN
curl -s https://pair.example.org/ice; echo                                                   # STUN only
```

The first runs the contract tests that do not need a test clock against the deployed broker. The second also checks the origin gating and then opens a relay at Cloudflare over every TURN URL it got (UDP, TCP, TLS on 5349 and 443), with the client in `src/turn-client.mjs`.

Then in a browser: open the [Trickle ICE](https://webrtc.github.io/samples/src/content/peerconnection/trickle-ice/) sample, add the `turns:…:443` URL with the `username` and `credential` from the `curl` output, and press "Gather candidates": rows of type `relay` mean the relay works. Finally pair a real phone with a FrameTrail page whose `pairingBrokerURL` is `https://pair.example.org/`, once on the same WiFi and once on cellular; on cellular, the pairing dialog shows the connection as relayed.

## Updating

```bash
cd /opt/frametrail-pairing && git pull --ff-only && systemctl restart frametrail-pairing
```

Best outside lessons: a restart empties the broker's memory. Players open their rooms again within a second (FrameTrail does that on its own), connected phones are not affected (they talk to the player directly), but a phone in the middle of pairing may have to scan the code again. Cloudflare's relays do not notice.

## Operating

- **Log:** `journalctl -u frametrail-pairing`. At `info`, one line per request except the polls that find nothing new, and every 10 minutes a summary (requests, offers, answers, rate-limited requests, open rooms). No addresses, no offers or answers, ids cut to four characters.
- **Cloudflare usage:** the dashboard's Realtime section shows the TURN traffic; Cloudflare also offers it through its GraphQL analytics API. Pairing traffic is small: a few hundred bytes a second per phone plus the hypervideo once, and only for phones that need a relay. Cloudflare documents no spending cap and no usage alert; the usage guard (see Configuration) is this broker's own. The log shows its first look after every start ("Cloudflare TURN usage this month: …"), its warning at 80 % and when it turns TURN off.
- **When credentials are abused:** revoke the set the broker hands out (the `username` from `/ice`):
  ```bash
  curl -X POST -H "Authorization: Bearer $CF_TURN_API_TOKEN" https://rtc.live.cloudflare.com/v1/turn/keys/$CF_TURN_KEY_ID/credentials/<username>/revoke
  ```
  then restart the broker for a new set. The usage guard revokes everything the broker issued on its own once the month's limit is reached. Deleting the TURN key at Cloudflare ends all of them; removing the `CF_` lines from `broker.env` and restarting turns TURN off (STUN stays).
- **Classrooms:** FrameTrail takes up to 50 phones per player; a room holds 64 waiting offers; a class behind one address stays far below the rate limit. School WiFi that keeps devices apart (client isolation) needs TURN for every phone.

## Self-hosting TURN with coturn

Without Cloudflare, TURN runs on the same server: nobody else sees who pairs, at the price of operating an open relay. `deploy/coturn/` holds a hardened configuration. It has not run on a server yet: before using it, check it with `deploy/coturn/test-local.sh`, which runs it in a coturn container (try `coturn/coturn:4.6.2`, about what Ubuntu 24.04 and Debian 12 ship, and the current release) and runs the TURN checks against it. What changes:

| | Cloudflare (as deployed) | coturn on the VPS |
|---|---|---|
| Who sees the addresses of everyone who pairs | Cloudflare | only you |
| TURN over TLS on port 443 (networks that allow nothing else) | yes | no: the web server holds 443 (see below) |
| Ports to open | none | 3478 UDP+TCP, 5349 TCP, 50000–50999 UDP |
| To look after | the API token | coturn's updates, the certificate job, the firewall, abuse |
| Running relays when credentials expire | ended | kept |

Setup, after the broker runs (steps 1 to 7 above):

```bash
apt install coturn
SECRET=$(openssl rand -base64 48); echo "$SECRET"       # for turnserver.conf and broker.env

install -m 640 -o root -g turnserver /opt/frametrail-pairing/deploy/coturn/turnserver.conf /etc/turnserver.conf
nano /etc/turnserver.conf             # <DOMAIN>, <PUBLIC_IPV4> (and IPv6), <SECRET>, bps-capacity for the server's bandwidth

install -m 755 /opt/frametrail-pairing/deploy/coturn/coturn-cert.sh /usr/local/sbin/
cp /opt/frametrail-pairing/deploy/coturn/coturn-cert.{service,timer} /etc/systemd/system/
nano /etc/systemd/system/coturn-cert.service   # ExecStart: the broker's domain
cp '/opt/frametrail-pairing/deploy/coturn/journald@pairing.conf' /etc/systemd/
install -D -m 644 /opt/frametrail-pairing/deploy/coturn/coturn-override.conf /etc/systemd/system/coturn.service.d/frametrail.conf
systemctl daemon-reload
systemctl start coturn-cert.service && ls -l /etc/coturn/certs
systemctl enable --now coturn-cert.timer
systemctl restart coturn
journalctl --namespace=pairing -u coturn -n 50 --no-pager
systemd-analyze security coturn | tail -1
```

- **Certificate:** `coturn-cert.sh` reads the paths of pair.example.org's certificate and chain from the web server configuration Plesk generates (nginx's where Plesk runs it, otherwise Apache's; Plesk renames the files on every renewal), writes key and full chain to `/etc/coturn/certs` after checking them, and tells coturn to reload them (SIGUSR2, no relay drops). It runs daily and before coturn starts.
- **Firewall:** in Plesk, **Tools & Settings → Firewall → Add custom rule**: allow incoming 3478/udp, 3478/tcp, 5349/tcp and 50000-50999/udp from anywhere; apply and confirm. If the hosting provider puts a firewall in front of the server, open the same ports there.
- **broker.env:** remove the `CF_` lines and add `STUN_URLS=stun:pair.example.org:3478`, `TURN_URLS=turn:pair.example.org:3478?transport=udp,turn:pair.example.org:3478?transport=tcp,turns:pair.example.org:5349?transport=tcp` and `TURN_SECRET=<the same secret>`; restart the broker.
- **Check:** `BROKER_URL=https://pair.example.org/ BROKER_ORIGIN=https://www.example.org TURN_EXPECT_DENIED=1 npm test` also makes sure the relay refuses private, loopback and link-local peers.
- **The server's own address:** the relay may send to it (two clients that both relay through this server reach each other that way), so any UDP service listening on the public address can be reached through the relay from the server itself. Look with `ss -lunp`; Plesk's DNS server (BIND) answers recursive queries from the server's own addresses. If the server does not serve DNS for its domains itself, set **Tools & Settings → DNS Template → DNS Recursion** to deny, unless `/etc/resolv.conf` points at `127.0.0.1`.
- **Port 443:** Plesk's web server listens on port 443, and coturn cannot share it. TURN on 443 needs a second IPv4 address on which the web server does not listen (which takes changing how Plesk binds it), with `listening-ip=<second address>` and `tls-listening-port=443` for coturn, or a TURN service elsewhere as a second provider (`src/ice.mjs`). Note that browsers gather from every TURN server they get, so a second provider sees every pairing too, not only the ones that need it.
- **Ubuntu:** coturn is in Ubuntu's *universe* component, whose security updates are best effort unless Ubuntu Pro is enabled; Debian ships it in *main*.
- **Logs:** coturn logs the addresses of clients and peers; the drop-in puts them into their own journal namespace, kept 7 days (`journalctl --namespace=pairing -u coturn`).

## Security

- **Neither the broker nor a relay can impersonate the player or read along.** The QR code carries the fingerprint of the player's certificate and the phone refuses an answer with another one; the channel is DTLS-encrypted end to end (FrameTrail's docs/PAIRING.md, "Security Model").
- **Only the player answers its phones:** the first request for a room sets its host key; the broker keeps only a hash.
- **`ALLOWED_ORIGINS` is no authentication.** It keeps other websites from handing our TURN to their visitors' browsers; a script can send any `Origin` header and get credentials, and relay traffic at the operator's expense. The usage guard keeps the cost below a monthly limit, Cloudflare's usage shows what happened, and credentials can be revoked (see Operating). The contract has no way for the broker to tie credentials to a room, since `GET /ice` comes before the room. A wildcard origin also covers pages whose authors you do not vet, such as every customer's instance on a hosting platform; it changes nothing about who *can* get credentials, only about which pages get them without trying.
- **After a restart** a room is gone until its player opens it again, within a second. Someone who saw the projected QR code could open it first with another key; the player is then refused (FrameTrail reports the broker as unreachable) and pairing for that code stops until it is stopped and started again. Phones still check the fingerprint, so nobody can take the player's place.
- The broker listens on 127.0.0.1 only and runs sandboxed by systemd; the web server in front handles TLS.

## Privacy (GDPR)

What is processed, where, and for how long:

| | What | Kept |
|---|---|---|
| **Broker** (your server) | The client's IP address (rate limit), the page's `Origin`, and the offers and answers: they contain the IP addresses and ports of both sides as seen from the internet (local addresses are hidden behind mDNS names by browsers) and a device label such as "iPhone" | In memory only: offers and answers 60 s, a room 120 s after the player's last request, the rate-limit entry about a minute. Nothing on disk. |
| **Broker log** (journal on the server) | Method, path with ids cut to four characters, status, duration; summaries | As the server's journal keeps it; holds no personal data |
| **Web server** (Plesk) | Access log: every request with the client's address, path (with room and phone ids) and status, as for every site on the server. Error log: the client's address on errors | Plesk's log rotation: 7 days for pair.example.org (step 4) |
| **Cloudflare** (STUN and TURN) | IP addresses and ports of everyone who pairs (browsers contact the TURN server while they gather candidates, even when the connection ends up direct), timing and traffic volume. The relayed content is end-to-end encrypted; Cloudflare cannot read it | Per Cloudflare's terms |
| **coturn** (instead of Cloudflare, if self-hosted) | The same as Cloudflare, on your server | 7 days in the journal |

There are no cookies, accounts or tracking; TURN usernames are random. The legal basis is legitimate interest (Art. 6(1)(f) GDPR) in connecting the devices the user asks to connect and in keeping the service from being abused. Processors: the hosting provider (conclude a data processing agreement with it) and Cloudflare (STUN/TURN; Cloudflare's data processing addendum is part of its terms, and Cloudflare is certified under the EU-US Data Privacy Framework; check both in the dashboard). Cloudflare's network is global: the relay a client uses is the nearest Cloudflare location.

A page that uses this broker can say in its privacy notice, for example:

> **Pairing with phones.** When you pair a phone with the player, both devices exchange connection details through a pairing service at [broker domain] (operated by [operator], hosted by [hosting provider] in [country]). These details include the devices' IP addresses; the service keeps them in memory for at most two minutes and stores nothing. To connect through firewalls, the devices use STUN and TURN servers of Cloudflare, Inc., which see their IP addresses and relay the connection when a direct one is not possible; the content stays end-to-end encrypted. The video and its content go directly from the player to the phone. Legal basis: Art. 6(1)(f) GDPR.

## Tests

```bash
npm test
```

runs everything in-process with Node's test runner: the contract tests of FrameTrail's stub (ported from `tests/run-js.mjs`) through FrameTrail's own client `FrameTrailPairing.js`, the proxy address handling, the origin gating and the Cloudflare provider (with its API mocked), the rate limit, memory bounds and log, the configuration, and the STUN/TURN client against the test vectors of RFC 5769.

| Variable | Meaning |
|---|---|
| `FRAMETRAIL_SRC` | FrameTrail's `src` folder (default `../frametrail/src`) |
| `BROKER_URL` | Run the contract tests that do not need a test clock against this deployed broker instead |
| `BROKER_ORIGIN` | With `BROKER_URL`: an origin that gets TURN credentials; checks the gating and opens a relay over every TURN URL |
| `TURN_EXPECT_DENIED=1` | The relay must refuse private, loopback and link-local peers (a coturn of your own) |
| `TURN_CA` | A CA certificate to trust for `turns:` (a self-signed one in `deploy/coturn/test-local.sh`) |

## License

MIT, like FrameTrail; see [LICENSE](LICENSE).
