# Deployment

Everything about running UwUSync Server on a machine of your own: installing it,
the address your devices use, a reverse proxy, updates, backups, moving it, and
taking it away again. The short version is in the [README](../README.md).

## What you need

- A Linux machine that your devices can reach: a NAS, a Raspberry Pi, a small
  VPS, a box on your tailnet. amd64 or arm64. The server is small: a few
  megabytes of memory while idle, and one SQLite file.
- One TCP port (8443 unless you choose another).
- Docker with Compose v2 — `install.sh` installs it when it is missing.

No domain, no certificate, no port 80: the server brings its own certificate,
and your devices pin its key the way an SSH client pins a host key.

## Install

```bash
curl -fsSLO https://github.com/MinifyX/UwUSync-Server/releases/latest/download/install.sh
sudo bash install.sh
```

What it does, in order:

1. Installs Docker with [Docker's own script](https://get.docker.com) when it is
   not there (after asking), or the Compose plugin when only that is missing,
   and starts the Docker service.
2. Looks whether port 8443 is free, and asks for another one when it is not.
3. Asks how your devices reach this machine. It suggests the address this
   machine talks to the world from; a name like `nas.lan`, a Tailscale name or
   address, or a public name all work. The port is added for you.
4. Writes `/opt/uwusync`: `compose.yaml`, `.env` (only root can read it),
   `update.sh`, and `.env.example` for reference. Each file comes from the
   release of the version it installs, together with its `sha256`, and is only
   used when the two agree.
5. Pulls the image, starts it, waits for its health check, and shows the setup
   code, the address and the fingerprint. When the first start does not work,
   the container goes again and your answers move to `.env.failed`, so running
   `install.sh` once more starts from the beginning.

Every answer is a flag too:

| Flag | |
| --- | --- |
| `--public ADDRESS` | how your devices reach this machine |
| `--bind X` | where the server listens here: a port, or `address:port` (default `8443`) |
| `--behind-proxy URL` | a reverse proxy in front does TLS, see [below](#behind-a-reverse-proxy) |
| `--registration MODE` | `invite` (default), `open` or `closed`, see [accounts](#accounts) |
| `--version TAG` | `latest` (default), `beta`, `edge` or an exact version |
| `--dir DIR` | somewhere other than `/opt/uwusync` |
| `--no-update-check` | the server never asks GitHub about newer releases |
| `--no-docker-install` | stop instead of installing Docker |
| `--from-checkout` | take the files from the repository the script sits in, not from a release |
| `--yes` | ask nothing; what is not passed keeps its default |

```bash
sudo bash install.sh --public nas.lan --yes
```

### By hand

The same three files, without the script:

```bash
mkdir uwusync && cd uwusync
curl -fsSLO https://github.com/MinifyX/UwUSync-Server/releases/latest/download/compose.yaml
curl -fsSL -o .env https://github.com/MinifyX/UwUSync-Server/releases/latest/download/env.example
# in .env: UWUSYNC_PUBLIC=nas.lan:8443
docker compose up -d
docker compose logs uwusync | grep uwu1_
```

`compose.yaml` takes everything that differs from one machine to the next from
`.env`, so `update.sh` can replace it with the next version's. Change `.env`,
not `compose.yaml`; the comments in it say what each line does.

## The setup code

The first start writes a setup code to the log:

```
uwu1_eyJ1IjoiaHR0cHM6Ly9uYXMubGFuOjg0NDMiLCJpIjoiQUJDREUtRkdISkstTU5QUVIiLCJmIjoiU0hBMjU2Oi4uLiJ9
```

It carries three things: the address from `UWUSYNC_PUBLIC`, the fingerprint of
the server's key, and an invite. Paste it into UwUSSH or UwURDP under Settings → Sync and
type your master password; that makes the account and signs the device in.

Only the first device of an account needs a code. The others join from a device
that is in already: it shows three words, the new device types them, and the two
run a handshake through the server that the server cannot read. The account key,
the fingerprint and a one-time token pass through it; the new device then proves
it knows the master password.

A code makes one account and is good for a week. Another one:

```bash
cd /opt/uwusync && sudo docker compose exec uwusync uwusync-server invite
```

### Accounts

`UWUSYNC_REGISTRATION` says who may make one:

- `invite` (the default): only with a code from `uwusync-server invite`.
- `open`: anyone who can reach the server. Fine on a tailnet or a home network
  where everyone who can reach it is family.
- `closed`: nobody new. For a server whose accounts are all made.

Devices are listed and shut out from the app, or here:

```bash
sudo docker compose exec uwusync uwusync-server accounts
sudo docker compose exec uwusync uwusync-server devices <account>
sudo docker compose exec uwusync uwusync-server revoke <device>
```

A revoked device stops syncing at once. What it already has, it keeps: rotate
the keys and passwords it held.

### Teams

A team is a vault that several accounts on this server share: its members
invite each other, and each record is sealed with a key only they have. The
server stores a team the way it stores an account's vault — it cannot read a
record. What it does keep in plain text is a team's name, the name each member
goes by in it, and who is in it in which role. Teams need a client that knows
them; older ones carry on as before.

Four settings, all in `.env`:

| Variable                        | Default | What it does                                              |
| ------------------------------- | ------- | --------------------------------------------------------- |
| `UWUSYNC_TEAMS`                 | `on`    | `off`: no teams on this server. What there is stays in the database, out of reach, until it is `on` again |
| `UWUSYNC_TEAM_CREATION`         | `all`   | `all`: every account may create teams. `none`: nobody may; the teams there are go on working, invites included |
| `UWUSYNC_MAX_TEAMS_PER_ACCOUNT` | `10`    | How many teams one account may be in, created or joined   |
| `UWUSYNC_MAX_TEAM_MEMBERS`      | `50`    | Members of one team, 1 to 1000                            |

A team may hold what one account may hold (`UWUSYNC_ACCOUNT_MAX_RECORDS`,
`UWUSYNC_ACCOUNT_MAX_MB`), each team for itself and beside its members' own
vaults. So an account's ceiling is its own vault plus that of every team it
creates; what keeps the disk safe is `UWUSYNC_SERVER_MAX_MB`, which counts
accounts and teams together. On a server for more than friends, lower
`UWUSYNC_MAX_TEAMS_PER_ACCOUNT` or set `UWUSYNC_TEAM_CREATION=none` once the
teams you want exist.

Lowering a limit takes nothing away: a team with more members than the new
limit keeps them and takes no new ones.

Teams are run from the app. From here you can look, and settle what the app
cannot:

```bash
sudo docker compose exec uwusync uwusync-server teams
sudo docker compose exec uwusync uwusync-server team-delete <team>
sudo docker compose exec uwusync uwusync-server team-owner <team> <account>
```

- `teams` lists them: id, name, members, records, and the day it was made.
- `team-delete` deletes one with everything in it. Its members keep their
  accounts and their own vaults, and their devices drop the team at their next
  sync. There is no way back but a backup.
- `team-owner` makes a member an owner. It is for a team left without one —
  `teams` marks those — and only takes a member who has the team's key: the
  server has no key to give. Ids of accounts are in `uwusync-server accounts`.

A team key is the members' alone. If every member has lost it, the server
cannot help; `team-delete` is what is left.

Restoring a backup takes teams back with everything else: members removed
since are members again, and a key rotated since is the old one again. After a
restore, whoever runs a team should check its members and rotate its key in the
app.

## The address

`UWUSYNC_PUBLIC` is how a device dials this server, and it goes into every setup
code. The server cannot find it out by itself — it listens on every address,
behind whatever your network does — so it is told.

It has to work from every device that syncs. `192.168.1.20:8443` works at home
and nowhere else; a Tailscale address works wherever the device is on the
tailnet; a public name works everywhere, once a port is forwarded to it. The
certificate's names follow it, but the devices do not care about names: they
check the key.

Changing it later is one line in `.env` and `docker compose up -d`. Devices
that are in already keep the address they were given, so change it in the app
on each of them as well.

### IPv6 and Docker

The stock `compose.yaml` publishes the port on the machine's IPv4 and IPv6
addresses, but the network Compose makes for the container has no IPv6. So
Docker's own proxy takes every IPv6 connection and passes it on from the
network's gateway: to the server, **all IPv6 clients look like one address**.
They then share what one address may do — 32 connections, and the counts for
making an account, joining and pairing. Signing in is counted per device, so
that is not shared. IPv4 clients keep their own address.

On a home network or a tailnet that hardly matters. On a server anybody can
reach over IPv6, one stranger can use up what all your IPv6 devices share.
Two ways out:

- **Publish on IPv4 only**, when your devices reach the machine over IPv4
  anyway: `UWUSYNC_BIND=0.0.0.0:8443` in `.env` (or `--bind 0.0.0.0:8443` when
  installing), then `docker compose up -d`. A client that finds the IPv6
  address closed tries the IPv4 one.
- **Give Docker IPv6**, so the addresses stay real: an IPv6 network for the
  project, with Docker's `ip6tables` on — or `"userland-proxy": false` in
  Docker's `daemon.json`, which on a machine without IPv6 networks stops
  publishing on IPv6 at all. Both are Docker's configuration, not this
  server's. `compose.yaml` does not ask for IPv6 itself: on a Docker without
  IPv6 address pools such a network does not come up, and an existing one
  would have to be made anew — an update must not stop a running server.

## Behind a reverse proxy

When you already have Caddy, nginx or Traefik with a real certificate for a
name, the server can sit behind it:

```bash
sudo bash install.sh --behind-proxy https://sync.example.com
```

That sets `UWUSYNC_TLS=off` (plain HTTP), publishes the port on `127.0.0.1`
only — `--bind` may choose another port, not another address — and sets
`UWUSYNC_TRUST_FORWARDED=on`. There is no fingerprint to pin then: the devices
trust the certificate the usual way.

`UWUSYNC_TRUST_FORWARDED=on` makes the rate limits count the address in
`X-Forwarded-For` rather than the proxy's, and it takes the **last** one there,
which is the one your proxy adds. Never switch it on for a server that is
reachable without the proxy: anyone could then choose the address they are
counted under. It also switches off the limit on connections from one address
(`UWUSYNC_MAX_CONNECTIONS_PER_IP`), since every connection comes from the proxy;
the total, `UWUSYNC_MAX_CONNECTIONS`, still holds, and the proxy is the place to
limit per client.

The proxy has to pass on the event stream (`/v1/events`) without buffering it,
and hold a request for at least half a minute: pairing waits up to 20 seconds
for the other side.

**Caddy** does all of that by itself:

```
sync.example.com {
    reverse_proxy 127.0.0.1:8443
}
```

**nginx**:

```nginx
server {
    listen 443 ssl;
    server_name sync.example.com;
    # ssl_certificate ...

    client_max_body_size 16m;

    location / {
        proxy_pass http://127.0.0.1:8443;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_http_version 1.1;
        proxy_buffering off;
        proxy_read_timeout 1h;
    }
}
```

## Updates

```bash
cd /opt/uwusync && sudo bash update.sh
```

`UWUSYNC_VERSION` in `.env` picks what the server follows:

| Tag | |
| --- | --- |
| `latest` | stable releases |
| `beta` | every release, stable or beta |
| `edge` | every commit on `main` that passed CI |
| `0.1.0` | exactly this version |

`sudo bash update.sh --version beta` switches.

What `update.sh` does, in order:

1. Fetches `update.sh` from the newest release of its channel, checks its
   `sha256`, and if it differs from itself, replaces itself and hands over to
   the new one.
2. Fetches `compose.yaml` from the release it is updating to — that version's
   own for a pinned one, the newest of any kind for `beta`. When the one here
   is the one it put there, it is replaced. When it was edited, what it
   understands moves into `.env` — a pinned image tag, another port, a setting
   written straight into the file — and anything else stops the update with a
   diff. `--force` takes the new file and keeps yours as `compose.yaml.bak`;
   `--keep-compose` leaves yours alone, from now on.
3. Has the running server write a backup (`--no-backup` skips it).
4. `docker compose pull` and `up -d`, then waits up to two minutes for the
   server's health check — which only passes when the server answers over TLS
   with its own key.
5. If it does not pass, `compose.yaml` and `.env` go back to what they were,
   `UWUSYNC_VERSION` to the exact version that ran before, and the container
   is made from that again.
6. If that one does not come up either — the new version changed the
   database, and a server will not run on a database newer than itself — the
   backup from step 3 goes back in, and the old version starts on it. What the
   new version had made of the database stays in the volume, beside it.
7. Removes the image the update replaced.

The way back pins the exact version in `.env`: a server that followed
`latest` follows `0.1.0` afterwards. Take that line back to `latest` once the
trouble is understood.

`update.sh` works on the directory it sits in, `/opt/uwusync`, or `--dir` —
never on the directory the shell happens to be in — and only on one whose
`compose.yaml` runs UwUSync Server. What is in that directory runs as root, so
it also has to be safe to trust: the directory, `compose.yaml`, `.env` and
`.uwusync-update` belong to root (or to the admin who ran `sudo`), nobody else
may write to them or to a directory above them, and none of the files is a
link. A `.env` that sets `COMPOSE_…` or `DOCKER_…` variables — which would
steer Compose to another file or project — is refused too. `install.sh` sets
everything up that way; `update.sh` stops and says what to change when
something is not.

### From UwUSSH Server

Until 0.2 this server was called UwUSSH Server. A machine set up back then
lives in `/opt/uwussh`, and its `update.sh` brings it over like any other
update:

```bash
cd /opt/uwussh && sudo bash update.sh
```

It fetches the new `update.sh` first, and that one sees the old names and
moves the server over. It takes a backup, then puts the new `compose.yaml` in
place. It renames the settings in `.env` from `UWUSSH_…` to `UWUSYNC_…` and
writes `UWUSYNC_VOLUME=uwussh_uwussh-data` there, so the new server uses the
volume the old one had. It stops the old container only once the new image is
on the machine. The directory stays `/opt/uwussh`, and the database keeps its
name inside the volume. The certificate key and every account and device stay
as they were, so nothing needs to be done on the devices. If the new version
does not come up, the old container, the old `.env` and the old
`compose.yaml` go back.

Afterwards the commands have the new name:
`docker compose exec uwusync uwusync-server invite`. The image still answers to
`uwussh-server` too. A `compose.yaml` kept by hand (`--keep-compose`) keeps
working. The server still reads the `UWUSSH_…` settings, and the image is
published under both names, `ghcr.io/minifyx/uwusync-server` and
`ghcr.io/minifyx/uwussh-server`.

### What you trust when you update

The `sha256` next to every file keeps a broken download out. It does not keep
out a release somebody replaced: it comes from the same place as the file. So
updating means trusting the GitHub releases of this repository — just as
running the image means trusting what is published under
`ghcr.io/minifyx/uwusync-server`. The scripts run as root, which makes that
trust count for more than the image's, since the container runs with no rights
at all. Read `update.sh` before you put it in a cron job, or pin
`UWUSYNC_VERSION` and update when you have read what changed.

Once a day the server asks GitHub what is newer on its channel (for `edge`: how
many commits `main` is ahead) and says so in its log:

```bash
sudo docker compose logs uwusync | grep "is out"
```

`UWUSYNC_UPDATE_CHECK=off` in `.env` stops that; it is the only connection the
server ever opens on its own.

## Backups

The server writes a backup of its database every night, and one before every
update, all under `backups/` in its volume; the newest seven are kept. They are
written with `VACUUM INTO`, which gives a consistent copy of a live database —
copying the file itself would miss what is still in the write-ahead log.

Each backup is a whole copy, so they take seven times the database. A backup
that would leave less than a twentieth of the disk free (and at least 256 MiB)
is not written: the log says `no backup tonight`, and `uwusync-server backup`
refuses the same way. What the database can grow to is capped by
`UWUSYNC_SERVER_MAX_MB` — 2 GiB by default, for all accounts together — which
puts the ceiling at about 16 GiB for the database and its backups (18 for the
moment a new one is written before the oldest goes). A household server with a
few vaults uses megabytes.

A backup holds only what the server holds: sealed records it cannot read, and
vault headers that are useless without the master password **and** the account
key. That makes it safe to keep somewhere else, and you should — a backup in
the same volume as the database does not survive the disk.

```bash
cd /opt/uwusync
sudo docker compose exec uwusync uwusync-server backup        # one more, now
sudo docker compose cp uwusync:/data/backups ./backups       # all of them, out of the volume
```

### Restoring one

```bash
cd /opt/uwusync
sudo docker compose exec uwusync uwusync-server restore       # which ones there are
sudo docker compose stop
sudo docker compose run --rm uwusync restore uwusync-2026-09-21-031000.db
sudo docker compose up -d
```

`restore` checks the backup before it trusts it (an intact database, of this
server, not from a newer version), refuses while the server still runs, and
keeps the database it replaces as `uwusync.db.before-restore-…`. A backup from
outside goes into the volume first, while the server is stopped:

```bash
sudo docker compose cp ./uwusync-2026-09-21-031000.db uwusync:/data/backups/
```

A restore takes the server back to the backup, and the devices keep what they
have. The server numbers everything that comes after it past what any device
has already read, so new changes reach every device as before. What changed
between the backup and the restore lives only on the devices that have it: it
reaches the server again the next time it is edited there, and a host deleted in
that time can come back on a device that joins later.

## When the certificate key is gone

The server never makes itself a new key while it has accounts: every device
pinned the old one, and a new one would lock them all out without a word. It
stops instead, and says why. Put `tls/key.pem` back from a copy of the volume.
If it is lost for good:

```bash
cd /opt/uwusync && sudo docker compose run --rm uwusync new-key
sudo docker compose up -d
```

and set every device up again, with a new setup code.

## Moving to another machine

The server's key lives next to its database, in the same volume, and the key is
what every device pinned. So move the **whole volume**, not just a backup: a
server with a new key is a stranger to every device, and they will refuse it.

```bash
# on the old machine
cd /opt/uwusync && sudo docker compose stop
sudo docker run --rm -v uwusync_uwusync-data:/data -v "$PWD":/out debian:stable-slim \
  tar -czf /out/uwusync-data.tar.gz -C /data .

# on the new one, after install.sh
cd /opt/uwusync && sudo docker compose stop
sudo docker run --rm -v uwusync_uwusync-data:/data -v "$PWD":/in debian:stable-slim \
  sh -c 'rm -rf /data/* && tar -xzf /in/uwusync-data.tar.gz -C /data && chown -R 10001:10001 /data'
sudo docker compose up -d
```

If the new machine has another address, change `UWUSYNC_PUBLIC` there and the
server address in the app on each device.

## Taking it away

```bash
cd /opt/uwusync && sudo docker compose down --rmi all -v
sudo rm -rf /opt/uwusync
```

`-v` deletes the volume, and with it every record, backup and the key. Copy the
backups out first if you might want them.

## Releases

A release is a tag. I add a section for the version to `CHANGELOG.md`, set the
version in `Cargo.toml`, and push the tag `v0.1.0` (or `v0.2.0-beta.1`). CI then:

1. runs the tests, clippy, `shellcheck`, and `cargo audit`;
2. cross-builds the binary for amd64 and arm64;
3. runs `install.sh` and `update.sh` against an image of those binaries, on a
   real Docker, including an update that fails and the way back;
4. scans the image with Trivy and pushes it to `ghcr.io/minifyx/uwusync-server`
   with its tags: `0.1.0`, `0.1`, `beta`, `latest` (stable only), `sha-…`;
5. checks the tag against the version in `Cargo.toml`, and publishes a GitHub
   release with the changelog section as notes, and `install.sh`, `update.sh`,
   `compose.yaml` and `env.example`, each with a `.sha256`.

A tag with a dash (`v0.2.0-beta.1`) is a pre-release: it gets `beta` but not
`latest`, and `releases/latest` keeps pointing at the last stable one.

Every push to `main` goes through the same steps and publishes the image as
`edge`.
