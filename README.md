<p align="center">
  <img src="brand/uwusync-app-icon.svg" width="112" alt="UwUSync logo" />
</p>

# UwUSync Server

The sync server behind [UwUSSH](https://github.com/MinifyX/UwUSSH-Client) and
[UwURDP](https://github.com/MinifyX/UwURDP-Client): your hosts, keys and
passwords on all your devices, on a machine that belongs to you. It was called
UwUSSH Server until it started carrying more than SSH.

It is a **dumb, encrypted mailbox**. It hands out sequence numbers, keeps the
newest version of every record, pages through them from a cursor, and refuses a
write whose version is not the one it holds. It cannot read a single field of
what it stores — not a hostname, not an address, not a password — because
everything is sealed with a key it never sees.

One Rust binary. One SQLite file. No account with us, no telemetry, no
subscription.

## Install

On a Linux machine — a NAS, a Raspberry Pi, a small VPS, amd64 or arm64:

```bash
curl -fsSLO https://github.com/MinifyX/UwUSync-Server/releases/latest/download/install.sh
sudo bash install.sh
```

It installs Docker when it is missing, asks one thing — how your devices reach
this machine — sets up `/opt/uwusync`, starts the server and shows a **setup
code**: one string carrying the address, the certificate's fingerprint and an
invite. Paste it into UwUSSH or UwURDP under Settings → Sync, type your master password
once, and that device is in. Every other device joins from the first one, with
three words it shows you.

```
  UwUSync Server is running (=^･ω･^=)

  Setup code    uwu1_eyJ1IjoiaHR0cHM6Ly8xOTIuMTY4LjEuMjA6ODQ0MyIsImki…
  Address       https://192.168.1.20:8443
  Fingerprint   SHA256:ulfTn6S7NU3WLo3YpGCLPYmpbGfwIQbmvTJDOH421Ok
```

Without questions: `sudo bash install.sh --public nas.lan --yes`. Another code
for another account: `docker compose exec uwusync uwusync-server invite` in
`/opt/uwusync`. `--help` lists every flag, and
[docs/deployment.md](docs/deployment.md) has the whole way: by hand, behind a
reverse proxy, backups and restoring them, moving to another machine.

Without Docker: `cargo build --release`, then run `uwusync-server`. It needs a
folder (`UWUSYNC_DATA`, `./data` by default) and nothing else.

## Update

```bash
cd /opt/uwusync && sudo bash update.sh
```

It takes a newer copy of itself first, then a backup, then the new image — and
waits for the server's health check. If the new version does not come up, the
one from before goes back in. `UWUSYNC_VERSION` in `.env` says what the
machine follows: `latest` for stable releases, `beta` for every release,
`edge` for every commit on `main` that passed CI, or one exact version.

Set up while it was UwUSSH Server? `cd /opt/uwussh && sudo bash update.sh`
moves it over, with its data, its key and its devices:
[docs/deployment.md](docs/deployment.md#from-uwussh-server).

Once a day the server asks GitHub whether there is something newer on that
channel and says so in its log. It is the only connection it ever opens on its
own; `UWUSYNC_UPDATE_CHECK=off` stops it. Nothing installs itself: a sync
server that could replace itself from the network would be one more way in.

## Adding a second device

Not by typing an address and a password on the new device. The device that is
already in shows a short code; the new one types it; the two run SPAKE2 — a
handshake where a spoken code turns into a strong shared key — and agree on
something this server cannot derive. Through that channel the first device
passes what the second needs: the certificate fingerprint to pin, the account
key, and a one-time enrolment token. The new device then proves it knows the
master password, and only then does the server hand over the wrapped vault key.

This server is the post box for that handshake and nothing more. It carries
opaque messages between the two sides — at most a handful, at most a few
kilobytes each, for ten minutes — and never learns the code. Somebody who
guesses a session id still has to guess the code, and SPAKE2 gives them exactly
one attempt at it. They do not even get to speak: one side is the device that
opened the session, signed in as itself, and the other holds its side with a
secret it made up when it first spoke.

Two secrets, and neither is enough on its own: an intercepted code is worth
nothing without the password, and the password is worth nothing without a
device that approved the join.

## What it can and cannot see

| It sees                                    | It does not see                                     |
| ------------------------------------------ | --------------------------------------------------- |
| How many records there are, and of what kind | Host names, addresses, users                         |
| When they changed, and from which device    | Passwords, private keys, passphrases, snippet bodies |
| How many devices an account has             | Which servers you have, or that you have any         |

The header of every record — which record, what kind, whose vault, when, and
whether it is deleted — is sealed **along with** the payload. So this server
cannot mark a record deleted (which would remove it from every device, since a
delete beats a concurrent edit), cannot hand an old version back as the newest
one, and cannot move a blob to another record. A device drops such an envelope
instead of applying it.

What a hostile server could still do is stay silent: withhold records, or show
a brand-new device an older but consistent state. That is the limit of every
zero-knowledge sync, and a device that already knows a record notices the step
backwards.

Since it also stores the wrapped vault key, the client mixes an **account key**
into the key derivation — 128 random bits that live only on paired devices and
in the recovery kit. Whoever takes a copy of this database cannot even start
guessing the master password against it.

The server never sees that key and could not tell whether one is in use, so the
client says: a vault header carries `needsAccountKey`, and the server hands
that on to the next device that joins. Otherwise a device without the kit would
be told its password was wrong, and would go looking in the wrong place.

## Configuration

| Variable                 | Default            | What it does                                                      |
| ------------------------ | ------------------ | ----------------------------------------------------------------- |
| `UWUSYNC_DATA`            | `./data`           | Database, certificate key, and backups under `backups/`            |
| `UWUSYNC_LISTEN`          | `0.0.0.0:8443`     | Address to listen on                                              |
| `UWUSYNC_PUBLIC`          | the listen address | How devices reach this server; goes into the setup code           |
| `UWUSYNC_TLS`             | `auto`             | `auto` for its own certificate, `off` when a proxy does the TLS    |
| `UWUSYNC_REGISTRATION`    | `invite`           | `open`, `invite` or `closed`                                      |
| `UWUSYNC_TRUST_FORWARDED` | `off`              | Believe the last `X-Forwarded-For` address — only behind a proxy  |
| `UWUSYNC_SESSION_SECS`    | `3600`             | How long a device's token lasts before it signs a challenge again |
| `UWUSYNC_UPDATE_CHECK`    | `on`               | Ask GitHub once a day whether there is a newer release            |
| `UWUSYNC_MAX_ACCOUNTS`    | `100`              | How many accounts the server takes, whoever asks                  |
| `UWUSYNC_ACCOUNT_MAX_RECORDS` | `100000`       | What one account may hold, in records…                            |
| `UWUSYNC_ACCOUNT_MAX_MB`  | `256`              | …and in megabytes                                                 |
| `UWUSYNC_SERVER_MAX_MB`   | `2048`             | What all accounts and teams together may hold, in megabytes       |
| `UWUSYNC_TEAMS`           | `on`               | Teams: vaults several accounts share. `off` for none              |
| `UWUSYNC_TEAM_CREATION`   | `all`              | Who may create a team: `all` accounts or `none`                   |
| `UWUSYNC_MAX_TEAMS_PER_ACCOUNT` | `10`         | How many teams one account may be in                              |
| `UWUSYNC_MAX_TEAM_MEMBERS` | `50`              | Members of one team; a team may hold what one account may         |
| `UWUSYNC_MAX_CONNECTIONS` | `512`              | Connections open at once, from everybody                          |
| `UWUSYNC_MAX_CONNECTIONS_PER_IP` | `32`       | …and from one address (an IPv6 /64); `0` for no limit. Not applied behind a proxy |

With Docker these come from `.env` next to `compose.yaml`, which install.sh
writes; `UWUSYNC_BIND` there says where the container is published and
`UWUSYNC_VERSION` which image it runs.

## The commands

```
uwusync-server                  serve (the default)
uwusync-server invite           a code for one new account, good for a week
uwusync-server fingerprint      what a device pins, to compare by eye
uwusync-server accounts         what is on this server, and how many devices each has
uwusync-server devices <id>     the devices of an account
uwusync-server revoke <id>      shut a device out
uwusync-server teams            the teams on this server: members, records, since when
uwusync-server team-delete <id> delete a team with everything in it
uwusync-server team-owner <team> <account>   make a member an owner, for a team without one
uwusync-server backup           a consistent copy, right now
uwusync-server restore [name]   list the backups, or put one back (server stopped)
uwusync-server health           the container's health check
uwusync-server new-key          a new certificate key, when the old one is lost for good
```

In Docker: `docker compose exec uwusync uwusync-server <command>`, from
`/opt/uwusync`.

Backups run by themselves too: one a night, and one more before every update,
seven kept in all — written with `VACUUM INTO`, because copying a live SQLite
file gives you the database without its write-ahead log, which is a backup that
looks fine until you need it. A backup that would leave the disk with less than
a twentieth free (and at least 256 MiB) is skipped with a warning instead.
`restore` checks a backup before it trusts it, refuses while the server runs,
and keeps the database it replaces.

**How much disk it takes.** A vault of hosts, keys and snippets is a few
megabytes, so a household server stays in megabytes. The ceiling is set by
`UWUSYNC_SERVER_MAX_MB`: at the default 2 GiB, the database and seven backups
of it come to about 16 GiB — 18 while a new backup is written and the oldest
has not gone yet — plus a write-ahead log and thirty megabytes of container
log. Lower it on a small disk.

## The protocol

The whole surface. The types come from
[`uwussh-proto`](https://github.com/MinifyX/UwUSSH-Client/tree/main/crates/uwussh-proto),
the same crate the client uses, so a schema change is one edit in one place.

| Endpoint                                     | What it is for                                        |
| -------------------------------------------- | ----------------------------------------------------- |
| `POST /v1/accounts`                          | Create an account from an invite                      |
| `POST /v1/session/challenge`, `POST /v1/session` | A device signs a challenge and gets a token        |
| `GET /v1/vault`, `POST /v1/vault/params`     | The vault header; the parameters a joining device needs |
| `PUT /v1/vault/key`                          | A new master password: rewrap, no record touched      |
| `GET /v1/records`, `POST /v1/records`        | Pull from a cursor, push with a version               |
| `GET /v1/events`                             | "There is something new from N", or in a team (server-sent events) |
| `/v1/teams/…`                                | Teams: shared vaults, their members, invites, keys and records — [docs/teams.md](docs/teams.md) |
| `GET /v1/devices`, `POST /v1/devices/invite`, `POST /v1/devices/enrol`, `POST /v1/devices/{id}/revoke` | Devices: list, let one in, shut one out — another one only with the master password |
| `POST /v1/pair`, `GET`/`POST`/`DELETE /v1/pair/{id}` | The post box two devices pair through           |
| `GET /healthz`                               | Alive, and what schema it speaks                      |

Limits it enforces without a key: 500 records or 8 MiB per request and per
page, 256 KiB per record, what one account may hold and what all of them
together may, a handful of small messages per pairing, 64 KiB for every other
request, two minutes for any of them — and rate limits per address where
guessing would pay, per device for signing in, and per account where one
account could wear the server down for everybody else, four pulls and four
pushes at once among them. Where it can, a limit is counted before the body of
a request is read. Before a request is even read: fifteen seconds for its headers, fifteen
for a connection with nothing to answer (HTTP/1.1 and HTTP/2 alike), eight
requests at once on one HTTP/2 connection, 512 connections at once and 32
from one address. An event stream that is being answered is none of those,
and stays open.

A vault header has to ask for a key derivation that costs at least 19 MiB and
two passes of Argon2id, or the account is not made — the client uses 64 MiB
and three.

## TLS

The server makes its own certificate on first start and says what its
fingerprint is. The setup code carries it, the client pins it, and every device
that pairs later is told it through the handshake — the same thing an SSH
client does with a host key, for the same reason. No domain, no Let's Encrypt,
works over a Tailscale address:

```bash
docker compose exec uwusync uwusync-server fingerprint
# SHA256:ulfTn6S7NU3WLo3YpGCLPYmpbGfwIQbmvTJDOH421Ok
```

**What is pinned is the key, not the certificate.** The fingerprint is a
SHA-256 of the public key, so the certificate itself is made fresh at every
start — new dates, new names, same fingerprint — and nothing a device pinned
ever expires out from under it. Only the private key is kept, in
`tls/key.pem`, readable by nobody else.

That key is also why **moving the server means moving the whole volume**, not
just the database: a server with a new key is, to every device, a stranger.
The health check says so too — it only calls the server healthy when the other
end of its handshake holds the key in `tls/key.pem`.

Already have a real certificate? `sudo bash install.sh --behind-proxy
https://sync.example.com` sets `UWUSYNC_TLS=off`, listens on `127.0.0.1` only,
and believes the last `X-Forwarded-For` address, which is the one your proxy
adds — so the rate limits count devices, not the proxy. Caddy and nginx
examples are in [docs/deployment.md](docs/deployment.md#behind-a-reverse-proxy).

## Building on it

```bash
cargo test            # unit tests, the API over real HTTP, and the real client
cargo clippy --all-targets -- -D warnings
docker build -f docker/Dockerfile -t uwusync-server .   # the image, from source
```

CI does more than that on every push: it cross-builds the binaries for amd64
and arm64, packs them into an image, and runs `install.sh` and `update.sh`
against it on a real Docker — install, check that the setup code, the
fingerprint and the certificate on the wire agree, stop it (quickly), update
it, check the key survived, update to a version that never comes up and watch
the old one come back, restore a backup. Only then is the image scanned and
pushed. A `v…` tag makes a release of it: see
[docs/deployment.md](docs/deployment.md#releases).

`tests/api.rs` drives the server the way a device does, by hand: create an
account, sign a challenge, push, pull, join a second device, revoke it, pair.
That proves the server does what it says — but not that the client agrees.

`tests/client.rs` closes that gap. It pulls the actual crates from the client
repository — its store, its vault, its sync engine, its transport — and runs a
host with a password in the vault from one device to a second one that joined
the account, over HTTP, through this server. The two repositories therefore
cannot drift apart quietly: the shared types come from `uwussh-proto`, and one
test fails the moment either half stops speaking the same protocol.

It runs the pairing too, the whole way: one device shows a code, the other one
is given only those three words, and it comes out with the account, the vault
and a password that opens — while a device that heard the wrong words gets
nothing at all, and the account still has one device afterwards.

And it checks the thing the whole design rests on, from the outside: with the
records on the server in front of it, none of them contains the hostname, the
address, the group or the password that went in.

## Licence

GPL-3.0-only, like UwUSSH and UwURDP. If you hand on a changed version, hand
on the source too.
