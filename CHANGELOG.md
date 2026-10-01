# Changelog

Each release gets a section here before its tag is pushed; CI copies the section into the GitHub
release. Versions follow semver; `-beta.N` versions are pre-releases.

## 0.2.2

**The command assistant's records, for UwUSSH 0.3.** UwUSSH 0.3 syncs the settings of its command
assistant and its cache of answers as two new kinds of record (`assist_config` and
`assist_cache`). The server stores them like any other record. Before, it refused a push that held
a kind it did not know.

- **Old clients are not sent them.** UwUSSH 0.2 cannot read a page that holds a kind it has never
  heard of, so the assistant's records only go to clients that ask for them (`assist=1`). The
  others are passed over, and the cursor still moves past them, so an older client keeps syncing
  everything else and never gets stuck in front of them.
- **New kinds need no new server.** A record's kind is now any short lowercase name, kept as it
  came. Kinds the server does not know yet go to the same clients as the assistant's: those skip a
  kind they cannot read instead of failing the page.
- A conflict hands a record back under its own kind. Before, a kind the server could not name came
  back as a host.

## 0.2.1

**Security fixes.** A third look, this time at 0.2.0, found four more ways to wear the server down
— none that let anybody read a record, sign in as someone else or reach another account. All four
are fixed, each with a test. The whole round is in
[docs/security-review-2026-09.md](docs/security-review-2026-09.md).

- **Idle connections close, HTTP/2 ones too.** A connection with nothing to answer for fifteen
  seconds is closed, whichever HTTP it speaks. Before, an HTTP/2 connection that answered the
  pings stayed open for good, so a handful of addresses could take every connection slot. One
  HTTP/2 connection now carries 8 requests at a time instead of 64. An event stream being
  answered still counts as busy.
- **Limits are counted before a body is read.** Creating an account, joining, pairing and pushing
  are counted first, so a request that is over its limit no longer gets its body buffered.
- **One account has at most four pulls and four pushes going at once**, each counted until its
  answer has been sent, not just until it was started. The apps sync one request at a time and
  never get near that.
- **Signing in is counted per device**, and only loosely per address. Behind Docker's proxy every
  IPv6 client shows up as one address, and one of them could lock all the others out.
  [docs/deployment.md](docs/deployment.md) now explains how to give IPv6 clients their own
  address.
- **The limiter tables cannot be filled to lock others out.** Every limit has a table of its own;
  when one is full, a newcomer is counted under its network instead of being refused, and signing
  in is never refused for want of room. With registration closed, creating an account is refused
  before anything is counted.

`.env` is kept out of git and out of the image build, and the README says what the connection
limits really cover.

## 0.2.0

**UwUSSH Server is UwUSync Server now.** It syncs UwURDP as well as UwUSSH, so the old name had
become too narrow. The new names:

- Repository: MinifyX/UwUSync-Server. The old address forwards.
- Image: `ghcr.io/minifyx/uwusync-server`.
- Command: `uwusync-server`.
- Settings: `UWUSYNC_…`.
- New installations: `/opt/uwusync`.
- A new icon.

Nothing changes for the devices: the protocol, the setup codes and the pinned keys stay the same.

- **`update.sh` moves a server from before over by itself**, in the directory it is in. It takes a
  backup first. The settings in `.env` get their new names, the data volume stays the same one,
  and the old container stops only once the new image is on the machine. If the new version does
  not come up, everything from before goes back. CI tests this against a real 0.1.1 installation.
- **The old names keep working.**
  - The server still reads `UWUSSH_…` settings, and its log says which ones still have the old
    name.
  - A database called `uwussh.db` keeps that name, so a rollback still finds it.
  - Backups called `uwussh-….db` are listed, restored and pruned like new ones.
  - The image answers to `uwussh-server` as well. It is also published under its old name,
    `ghcr.io/minifyx/uwussh-server`, for a `compose.yaml` kept by hand.
- **`install.sh` stops on a machine that already has UwUSSH Server** in `/opt/uwussh`, and says
  how to bring that one over. It no longer sets up a second server next to it.

## 0.1.1

**Security fixes.** A second look at 0.1.0 found ways to wear the server down, fill its disk, or
— from a directory someone else could write to — turn `update.sh` against its own machine.
Nothing that let anybody read a record or reach another account. Every one is fixed, most with a
test.

- **Connections have deadlines and a ceiling.** A client that opened a connection and then said
  nothing, or sent its headers a byte at a time, or sat idle after its last request, held a socket
  for as long as it liked; a few thousand of those were a server nobody else could reach. Now the
  headers of a request get fifteen seconds, an idle connection fifteen more, HTTP/2 connections are
  pinged and dropped when nobody answers, and the server takes 512 connections at once and 32 from
  one address (`UWUSSH_MAX_CONNECTIONS`, `UWUSSH_MAX_CONNECTIONS_PER_IP`; behind a proxy only the
  total counts). An event stream being answered is left alone. On Linux the server also raises its
  own open-file limit as far as the system allows.
  *Correction, September 2026:* the fifteen seconds for an idle connection held for HTTP/1.1
  only. An HTTP/2 connection that answered the pings stayed open for as long as it liked, up to
  and including 0.2.0. 0.2.1 closes both kinds.
- **The disk cannot be filled through the backups.** The quota was per account, and fourteen
  nightly backups each copied all of it. Now all accounts together hold at most
  `UWUSSH_SERVER_MAX_MB` (2 GiB by default), seven backups are kept instead of fourteen, and a
  backup that would leave the disk without room to spare is skipped with a warning. At the
  defaults, the database and its backups top out around 16 GiB.
- **`update.sh` only trusts what only root can change.** It looked for the server in the directory
  the shell was in, and ran whatever `compose.yaml` and `.env` it found there. Now it looks beside
  itself, in `/opt/uwussh` or where `--dir` says; refuses a directory, `compose.yaml`, `.env` or
  `.uwussh-update` that anybody but root (or the admin running `sudo`) could write to, or that sits
  under a directory someone else could; and refuses a `.env` that sets `COMPOSE_…` or `DOCKER_…`
  variables.
- **A device holds at most eight session tokens.** Signing in again and again piled up tokens in
  memory without end; now the oldest goes, and expired ones are swept every few minutes.
- **A vault must be expensive to guess against.** The server took a vault header asking for
  Argon2id at 1 KiB and one pass. It now wants at least 19 MiB and two passes for a new account or
  a new master password; the client uses 64 MiB and three. Vaults already on the server are not
  touched.

**Manifests, for UwUSSH 0.1.1.** The client now has each device publish a sealed list of what it
holds, so a device can tell when a server serves it old versions or holds records back. The server
stores them like any other record; it hands them only to clients that ask (`manifests=1`), so an
older client keeps syncing, and it drops a device's manifest when the device is revoked. UwUSSH
0.1.1 and this server belong together: update both.

## 0.1.0

**The first release.** A sync server for [UwUSSH](https://github.com/MinifyX/UwUSSH-Client): your
hosts, keys and passwords on all your devices, through a machine that belongs to you and cannot
read a single field of what it keeps.

**Setting it up is one command.** `install.sh` installs Docker when it is missing, asks how your
devices reach the machine, starts the server and shows a setup code to paste into UwUSSH. No
domain, no certificate to get: the server makes its own and your devices pin its key, the way an
SSH client pins a host key. It runs just as well behind Caddy or nginx.

**Updating is one command too.** `update.sh` takes a newer copy of itself, backs up, pulls the new
image and waits for the server's health check — and if the new version does not come up, the one
from before goes back in. Once a day the server looks whether there is something newer and says so
in its log. Images for amd64 and arm64, as `latest`, `beta` and `edge`.

What is in it:

- **Zero knowledge.** Every record is sealed on the device, header and all, so the server cannot
  read it, move it to another record, mark it deleted or hand an old version back as new. It hands
  out sequence numbers, keeps the newest version of each record, and refuses a write based on a
  version it no longer holds.
- **An account key** next to the master password, so a copy of the server's database is not even
  a place to start guessing the password.
- **Devices sign in** with a key of their own, by signing a challenge. A new device joins from one
  that is already in, with three spoken words: the two run SPAKE2 through the server, which carries
  the messages and understands none of them.
- **Limits** where guessing or hammering would pay, and on what one account may hold.
- **Backups** every night and before every update, and `uwussh-server restore` to put one back.
- **A distroless image** that runs as an unprivileged user on a read-only file system, with no
  capability at all.

Reviewed before release by someone who had not written it: nothing critical, and nothing that let
one account near another's data; every finding is fixed, each with a test. The details are in
[docs/security-review-2026-09.md](docs/security-review-2026-09.md).

The app's side — Settings → Sync — comes with the next UwUSSH beta.
