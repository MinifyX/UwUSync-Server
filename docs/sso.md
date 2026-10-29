# Signing in with UwUAuth

From 0.4 on, a UwUSync server can be paired with [UwUAuth](https://github.com/MinifyX/UwUAuth-Server),
the suite's identity provider. People then make an account, and add a device to one, by signing in
there instead of with an invite or an enrolment token. Invites, enrolment tokens and open
registration keep working beside it.

What does not change: **the master password and the account key still open the vault, and only the
devices know them.** UwUAuth says who somebody is. It never learns, derives or resets what opens
their vault, and neither does this server. Signing in with UwUAuth replaces the proof that you may
come in, not the unlock. Somebody who forgets their master password has lost their vault, with
UwUAuth as without it.

## Pairing

In UwUAuth, make a pairing code for a new app (Apps → Pair). Then, on the server:

```bash
cd /opt/uwusync
sudo docker compose exec uwusync uwusync-server uwuauth pair https://auth.example.com ABCD-EFGH
# or with the code as UwUAuth's QR code carries it
sudo docker compose exec uwusync uwusync-server uwuauth pair 'https://auth.example.com/#pair=ABCD-EFGH'
```

The server asks UwUAuth at `/uwu/v1/server` whether it pairs, sends the code with its own address
(`UWUSYNC_PUBLIC`), its loopback redirect `http://127.0.0.1/uwusync/callback` and where its SCIM
endpoint is, and gets back an OpenID Connect client and a SCIM token. Before it keeps anything it
fetches UwUAuth's discovery document, so a pairing that could not work is not saved.

Kept in the database: UwUAuth's address and issuer, the client id and secret, and a SHA-256 hash of
the SCIM token (the token itself is never stored). The running server reads the pairing on every
request, so a pairing counts at once, without a restart.

```bash
sudo docker compose exec uwusync uwusync-server uwuauth status   # what it is paired with, how many people
sudo docker compose exec uwusync uwusync-server uwuauth unpair   # forget the client and the token
```

Unpairing stops signing in with UwUAuth and makes every ticket handed out before useless. Accounts
made that way stay, and the devices that have them keep syncing. Remove the app in UwUAuth as well.
Pairing again, with the same or another UwUAuth, replaces the old pairing. Logins in progress and
tickets are bound to the pairing they were made under (its client id and when it was made), so a
running server refuses them on the next request after `pair` or `unpair`, without a restart.

### What pairing needs

- `UWUSYNC_PUBLIC` set to an **https** address. UwUAuth sends SCIM requests there.
- A certificate there that UwUAuth trusts. The server's own certificate (`UWUSYNC_TLS=auto`) is
  self-signed and pinned by the devices, which UwUAuth cannot do. So a server that pairs runs
  [behind a reverse proxy](deployment.md#behind-a-reverse-proxy) with a certificate from a CA.
- This server must reach UwUAuth over https with a certificate it trusts: the public web roots,
  plus whatever `UWUSYNC_UWUAUTH_CA` names (a PEM file of one or more root certificates) for a
  UwUAuth behind a private CA. Mount the file into the container and set the variable to its path.
  Outbound requests follow no redirects and time out after a few seconds.

## Signing in

```
device                          UwUSync server                      UwUAuth
  │ POST /v1/sso/authorize        │                                    │
  │  redirectUri=127.0.0.1:<p>    │                                    │
  │  codeChallenge (device PKCE)  │                                    │
  │ ─────────────────────────────▶│  state, nonce, server PKCE         │
  │ ◀──── url, state ─────────────│                                    │
  │ system browser ──────────────────────────────────────────────────▶ │ sign in
  │ ◀────────── 127.0.0.1:<p>/uwusync/callback?code&state&iss ──────── │
  │ POST /v1/sso/token            │                                    │
  │  code, state, codeVerifier    │ ── code + secret + verifier ─────▶ │
  │                               │ ◀─────────── ID token ──────────── │
  │ ◀──── ticket ─────────────────│  checks the ID token               │
  │ POST /v1/accounts or /v1/devices/enrol with the ticket             │
```

- The device listens on `127.0.0.1` on a port of its choosing (RFC 8252). The server accepts only
  `http://127.0.0.1:<port>/uwusync/callback` as the redirect, never `localhost`, which a hosts file
  can point elsewhere.
- **Two PKCE pairs.** The device's, between it and this server: only the device that started a
  login can finish it. And the server's own towards UwUAuth, as any confidential client.
- `state` is checked by the device against what it got, and by the server, which answers each state
  once and forgets it after ten minutes. The device's PKCE verifier is checked before the state is
  used up: somebody who saw the state but not the verifier cannot spend the device's login. A callback that names an issuer (RFC 9207) has to name
  the paired one.
- The ID token is checked by the server: signature against UwUAuth's keys (fetched again once when
  a key is unknown), issuer, audience, expiry and the nonce.
- What the device gets is a **ticket**: for five minutes and one use, "this is UwUAuth's person
  so-and-so", plus whether they have an account here already and whether it needs the account key.
- The person's `userName` here is the ID token's `email` only when `email_verified` is true;
  otherwise `preferred_username`, then `sub`. It is a label: who somebody is stays issuer and `sub`.

With the ticket the device either

- **makes an account** (`POST /v1/accounts` with `ssoTicket`): a new master password and, on the
  device, a new emergency kit, exactly as with an invite; or
- **joins the account** the person already has (`POST /v1/devices/enrol` with `ssoTicket`): with the master
  password, and the account key if the vault has one, exactly as with an enrolment token.

A ticket survives five wrong master passwords, then it is gone and the person signs in again.
It is used up only once the account is made or the device is in: a create that fails leaves it
good for another try. Joins with a ticket are also counted per account: ten an hour, wrong master
passwords included, so somebody who took over a person's UwUAuth login gets a handful of guesses
an hour however many tickets they fetch. Each join with a ticket is logged with the account,
device and person ("a device joined with a UwUAuth sign-in"). Telling the account's other devices
about such a join is not done yet; it is planned.
Logins in progress and tickets live in memory only; a restart costs a person one more sign-in and
nothing else.

Signing in with UwUAuth gets past `UWUSYNC_REGISTRATION=invite`: UwUAuth decided who may come in.
`closed` refuses it as it refuses everybody, and `UWUSYNC_MAX_ACCOUNTS` counts these accounts too.
An account made with an invite cannot be taken over by signing in with UwUAuth: a person is tied
to the account they made by signing in, and to no other.

## SCIM

When UwUAuth handed out a SCIM token, it pushes who may sign in to `<UWUSYNC_PUBLIC>/scim/v2`:

| Endpoint | What it does |
| --- | --- |
| `GET /scim/v2/ServiceProviderConfig`, `/ResourceTypes` | what this endpoint can do: patch, filter, no bulk, no sort, no ETags |
| `GET /scim/v2/Users` | the people, paged (`startIndex`, `count` up to 200), filter `userName eq "…"` or `externalId eq "…"` only |
| `POST /scim/v2/Users` | a new person; `externalId` (UwUAuth's `sub`) is required. A person already known by that `externalId` (signed in before being pushed, or pushed twice) is updated and answered with 200 and their existing id |
| `GET`, `PUT`, `PATCH`, `DELETE /scim/v2/Users/{id}` | one person |
| `/scim/v2/Groups` | accepted and ignored: this server has no groups |

- A person is who UwUAuth's issuer and `externalId` say, never their `userName`: an address can
  change hands, a subject does not. Changing `externalId` of somebody who has an account here is
  refused (400, `mutability`).
- **Pending.** Somebody pushed but not yet signed in is a person without an account. Signing in
  ties them to the account they make.
- **`active: false`** revokes every device of their account at once, ends its sessions, drops their
  tickets and any device pairing in progress. Their data stays. Signing in is refused while they
  are inactive.
- **`active: true`** lets them back in: they sign in with UwUAuth and join their account with their
  master password, as on a new device.
- **DELETE** deletes their account and everything in it. Teams they were in carry on: where they
  were the only owner, the longest-serving admin becomes owner. Where a team has other members and
  no admin to take over, the delete is **refused with 409** and the account stays: make another
  member an owner or admin in the app first, or deactivate the person instead. A team only they are
  in goes with them.

The bearer token is checked first, in constant time against the stored hash; the right token is
always let in. Only refused requests are counted: ten from one address in ten minutes, and further
wrong tokens from there get 429 until the window passes.
Bodies are capped, texts are at most 256 characters without control characters, a PATCH has at
most 64 operations.

## What the server says about itself

- `GET /uwu/v1/server`: `product`, `version`, `url`, `schema`, and whether `sso` and `scim` are on.
- `GET /.well-known/uwusuite`: the suite's discovery document: this server and, when paired, the
  UwUAuth it signs in with.

Both are public and carry nothing secret: the client id and secret never leave the server.

## Security notes

- The client secret is kept in the database in the clear: the server needs it to redeem codes. The
  database file is readable by the server's user only; treat a backup like the database.
- A stolen ticket is worth little: it is bound to nothing secret, but it is good for five minutes
  and one use, and joining an existing account still takes the master password. Making an account
  with it makes an account for the person it names, which is what they asked UwUAuth for.
- UwUAuth deciding who comes in means an attacker who controls UwUAuth can make accounts here and
  shut people out. They cannot open anybody's vault.
