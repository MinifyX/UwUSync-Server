# Teams

A team is a vault that several accounts share. This is the protocol, for whoever writes a client:
every route, every field, every answer. What an operator sets is in
[deployment.md](deployment.md#teams).

Since 0.3.0. A server from before answers `404` to `GET /v1/teams/policy`.

## What the server knows, and what it does not

The server stores a team's records sealed, exactly as it stores an account's own. It never has a
team key. What it keeps, and can read:

- a team's **name**, and each member's **display name** — plain text, so the members and the
  operator's command line can show them;
- who is in which team, in which role, and since when;
- each member's **public key** (X25519, 32 bytes), and its private half sealed by the client
  (`sealed_private`, which the server cannot open);
- for each member, the team key wrapped to that member's public key (`wrapped_key`, opaque here);
- the team's **epoch**: the number of the team key in use, 1 at first, one more with each rotation.

The server enforces who may do what. It cannot enforce what a client does with a key it holds:
taking a member out stops them reading from the server at once, and the records they already
have stay readable to them until the key is rotated. That is what `needs_rotation` is for.

## Conventions

- Every route takes the device's token, `Authorization: Bearer <token>`, as the rest of the API
  does, and acts for the token's **account**. There is nothing here without one: `401`
  `unauthorized`.
- Bodies and answers are JSON. Ids are UUIDs as lowercase text. Times are milliseconds since
  1970 (`…_ms`).
- `public_key`, `sealed_private` and `wrapped_key` are **base64, URL-safe, without padding**.
  The `nonce` and `blob` of a record are what they are in `/v1/records`: standard base64 with
  padding.
- A role is one of `"owner"`, `"admin"`, `"editor"`, `"reader"`. A state is `"pending"` or
  `"active"`.
- A refusal is `{"error": "<code>", "message": "<for a person>"}` with the status given below.
  Decide by `error`, show `message`. `stale-epoch` carries one more field, `epoch`: the team's
  current one.

### Sizes

| What                         | Bound                                         |
| ---------------------------- | --------------------------------------------- |
| team `name`                  | 1 to 80 characters after trimming, no control characters |
| `display_name`               | 1 to 60 characters after trimming, no control characters |
| `public_key`                 | exactly 32 bytes                              |
| `sealed_private`             | 1 to 1024 bytes                               |
| `wrapped_key`                | 1 to 512 bytes                                |
| invite `code`                | 64 characters at most as sent                 |
| a request body               | 64 KiB; `rotate` 1 MiB; a push 16 MiB         |
| a push                       | as `/v1/records`: 500 envelopes, 8 MiB of blobs, 256 KiB a blob |
| open invites of one team     | 20                                            |

A value outside its bound is `400` `invalid`.

### Answers every route can give

| Status | `error`              | When                                                              |
| ------ | -------------------- | ----------------------------------------------------------------- |
| 401    | `unauthorized`       | No token, or one that is not good (any more).                     |
| 429    | `rate-limited`       | Too many requests from this account. See [Limits](#limits).       |
| 403    | `teams-disabled`     | The operator switched teams off. Every route but the policy.      |
| 404    | `not-found`          | No such team — **or this account is not in it.** The two look the same on purpose. Also an id in the path that is not a UUID. |
| 403    | `membership-pending` | This account is in the team and has not been confirmed (again).   |
| 403    | `forbidden`          | This account's role does not allow that.                          |
| 400    | `invalid`            | A field outside its bounds, or not base64.                        |
| 400, 415, 422, 413 | `invalid` | A body that is not the JSON the route takes: not JSON (400), sent without `Content-Type: application/json` (415), a missing field, a wrong type or an unknown role (422), too large (413). |

They are checked in this order: rate limit, `teams-disabled`, the id in the path, then the body,
then membership (`not-found`, `membership-pending`), the role (`forbidden`), and last what the
route itself looks at. `rotate` and a push look at membership and role *before* they read the
body.

## Policy

### `GET /v1/teams/policy`

What this server allows. Answers also when teams are switched off.

```json
{ "enabled": true, "may_create": true, "max_teams_per_account": 10, "max_members_per_team": 50 }
```

- `enabled`: `false` and every other route here answers `403` `teams-disabled`.
- `may_create`: whether `POST /v1/teams` is open. `false` when teams are off or the operator
  lets nobody create one; joining with an invite works all the same.
- `max_teams_per_account`: how many teams one account may be in, created or joined, waiting
  included.
- `max_members_per_team`: members of one team, those who wait included.

## The member key

Every account that is to be in a team has one key pair, made by its client. The server holds the
public key, and the private key sealed under something only the account's devices have.

### `GET /v1/teams/identity`

```json
{ "public_key": "<base64url, 32 bytes>", "sealed_private": "<base64url>", "updated_ms": 1790000000000 }
```

`404` `not-found` when this account has none yet. Only the account's own: there is no route that
hands out another account's sealed key.

### `PUT /v1/teams/identity`

```json
{
  "public_key": "<base64url, 32 bytes>",
  "sealed_private": "<base64url>",
  "replace": false,
  "current_auth_key": "<base64url, 32 bytes>"
}
```

`replace` may be left out and is then `false`. `current_auth_key` is left out too, except in the
one case below that asks for it. Answers `200` with the stored identity, in the shape of the
`GET`.

| The account has…                     | `replace: false`                 | `replace: true`                          |
| ------------------------------------ | -------------------------------- | ---------------------------------------- |
| no identity                          | stored                           | stored                                   |
| exactly this pair                    | `200`, nothing changes           | `200`, nothing changes                   |
| this `public_key`, another `sealed_private` | `409` `identity-exists`   | `sealed_private` is replaced; nothing else changes |
| another `public_key`                 | `409` `identity-exists`          | replaced, with `current_auth_key` — **see below** |

The first write wins, so two devices of one account that both make a pair end with one: the
loser gets `identity-exists`, reads the identity with `GET` and uses that.

Sending the same `public_key` with `replace: true` is how a client seals the private key anew —
after a new master password, say. No team notices.

**Replacing the public key** means the account has a new key pair. Every team key the server
holds for it was wrapped to the old one, so in the same step, for every team the account is in:
its `wrapped_key` is dropped and its `state` becomes `pending`. Its role stays. It reads and
writes nothing in those teams until an owner or admin who has checked the new key confirms it
again (`confirm`, below). The members of those teams get a `team` event. A sole owner who does
this, in a team without an admin, can let nobody in again — itself included; what is left to
them is to delete the team.

Because of that, a device's token is not enough for it. A request with `replace: true` and a
`public_key` other than the stored one must prove the master password in `current_auth_key`: the
account's current login key, the same value and encoding (URL-safe base64 without padding, 32
bytes) that a device revocation sends as `currentAuthKey` — here in snake case, like every field
of this API. The field is ignored in every other case of the table (first write, the same pair,
the same `public_key` sealed anew), so a client need not send it there.

| Status | `error`          | When                                                                 |
| ------ | ---------------- | -------------------------------------------------------------------- |
| 403    | `wrong-password` | `current_auth_key` is missing, or is not the account's login key. Nothing changed. |
| 400    | `invalid`        | `current_auth_key` is not base64url of 32 bytes.                     |
| 429    | `rate-limited`   | Too many wrong proofs from this device (10 an hour, shared with password change and device revocation; a right one clears the count). |

## Teams

A team, as the asking account sees it:

```json
{
  "id": "0199c1d4-…",
  "name": "Ops",
  "role": "owner",
  "state": "active",
  "epoch": 1,
  "wrapped_key": "<base64url>",
  "needs_rotation": false,
  "members": 3,
  "created_ms": 1790000000000
}
```

- `role`, `state`: this account's own.
- `epoch`: the number of the team key in use.
- `wrapped_key`: the team key of that epoch, wrapped to this account's public key. `null` while
  `state` is `pending`.
- `needs_rotation`: somebody who had the key is no longer in the team. Whoever manages the team
  should rotate.
- `members`: everybody in the team, those who wait included.

### `GET /v1/teams`

A bare array of the teams this account is in — active or pending — oldest first. `[]` when none.

### `POST /v1/teams`

```json
{ "name": "Ops", "display_name": "Olive", "wrapped_key": "<base64url>" }
```

Makes a team. The account becomes its only member: `owner`, `active`, at `epoch` 1.
`display_name` is what the other members will see this account as; `wrapped_key` is the new team
key wrapped to the account's own public key. Answers `200` with the team.

| Status | `error`                | When                                                    |
| ------ | ---------------------- | ------------------------------------------------------- |
| 403    | `team-creation-closed` | The operator lets nobody create teams. Checked before the body. |
| 409    | `no-identity`          | The account has no member key yet.                      |
| 403    | `team-limit`           | The account is in as many teams as one account may be.  |

### `PATCH /v1/teams/{id}`

```json
{ "name": "Operations" }
```

Renames it. Owner or admin. Answers `200` with the team.

### `DELETE /v1/teams/{id}`

Deletes the team with its records, members and invites. **Owner only** — also an owner who is
`pending`. `204`. An admin, editor or reader gets `403` `forbidden`.

## Invites

An invite is a code that lets one account ask to be let in. It is good for seven days and for one
redemption. The server keeps a hash of it; the code is in the answer that made it and nowhere
after.

### `POST /v1/teams/{id}/invites`

```json
{ "role": "editor" }
```

Owner or admin. `role` is `admin`, `editor` or `reader`; `owner` is `400` `invalid` (an owner is
made from a member, with `PATCH …/members/{account_id}`). `200`:

```json
{ "id": "0199c1d5-…", "code": "K7QWM-2HXPA-9RTDE", "role": "editor", "expires_ms": 1790604800000 }
```

`403` `too-many-invites` when the team has 20 open ones; revoke one, or wait for one to run out.

An invite lasts only as long as the member who made it may invite: when that member is removed,
leaves, or is made an editor or reader, the open invites they made are deleted in the same step
and their codes answer `invalid-invite`. A member who waits again after replacing their key
keeps theirs.

### `GET /v1/teams/{id}/invites`

Owner or admin. The open invites — not used, not run out — oldest first. No codes.

```json
[ { "id": "0199c1d5-…", "role": "editor", "created_by": "<account id>",
    "created_ms": 1790000000000, "expires_ms": 1790604800000 } ]
```

### `DELETE /v1/teams/{id}/invites/{invite_id}`

Owner or admin. `204`. `404` `not-found` when the team has no such open invite — an invite of
another team included.

### `POST /v1/teams/join`

```json
{ "code": "K7QWM-2HXPA-9RTDE", "display_name": "Nia" }
```

Redeems an invite. Case, dashes and spaces in the code do not matter. `200`:

```json
{ "team_id": "0199c1d4-…", "name": "Ops", "role": "editor", "state": "pending" }
```

The account is now a member who **waits**: the team is in its `GET /v1/teams` with `state`
`pending` and `wrapped_key` `null`, and that is all it sees of it. It cannot read the team's
records, nor its members. The team's members get a `team` event; an owner or admin compares the
newcomer's public key with the newcomer, out of band, and confirms.

| Status | `error`          | When                                                                |
| ------ | ---------------- | ------------------------------------------------------------------- |
| 409    | `no-identity`    | The account has no member key yet. Checked first.                   |
| 403    | `invalid-invite` | No such code, or used, or revoked, or run out. All four look the same. |
| 409    | `already-member` | The account is in that team already. The code is not used up.       |
| 403    | `team-limit`     | The account is in as many teams as one account may be. The code is not used up. |
| 403    | `team-full`      | The team has as many members as a team may have. The code is not used up. |
| 429    | `rate-limited`   | Ten tries that did not work within ten minutes. See [Limits](#limits). |

## Members

### `GET /v1/teams/{id}/members`

Any **active** member, whatever its role. Everybody in the team, those who wait included, in the
order they joined:

```json
[
  { "account_id": "0199c1d0-…", "display_name": "Olive", "role": "owner", "state": "active",
    "public_key": "<base64url, 32 bytes>", "joined_ms": 1790000000000 },
  { "account_id": "0199c1d3-…", "display_name": "Nia", "role": "editor", "state": "pending",
    "public_key": "<base64url, 32 bytes>", "joined_ms": 1790000360000 }
]
```

`public_key` is the member's current one. A member who waits gets `403` `membership-pending`.

### `POST /v1/teams/{id}/members/{account_id}/confirm`

```json
{ "epoch": 1, "public_key": "<base64url, 32 bytes>", "wrapped_key": "<base64url>" }
```

Owner or admin lets a waiting member in: `wrapped_key` is the team key of `epoch`, wrapped to
`public_key` — the member's key as the confirming client saw and checked it. `204`; the member is
`active`, and gets a `team` event.

| Status | `error`            | When                                                                |
| ------ | ------------------ | ------------------------------------------------------------------- |
| 404    | `not-found`        | That account is not in the team.                                    |
| 409    | `stale-epoch`      | `epoch` is not the team's current one. The answer carries it as `epoch`: fetch the team, wrap the current key, try again. |
| 409    | `not-pending`      | That member is active already.                                      |
| 409    | `identity-changed` | `public_key` is not the member's current one: they replaced it after this client read it. Read the members again, check the new key, wrap to it. |

### `PATCH /v1/teams/{id}/members/{account_id}`

```json
{ "role": "admin" }
```

Changes a member's role. `204`, also when the member has that role already.

- An **owner** may give any member any role.
- An **admin** may change between `admin`, `editor` and `reader`, for anybody who is not an
  owner — itself included. Whenever the member is an owner, or `role` is `owner`: `403`
  `forbidden`.
- `409` `not-active`: only an active member becomes an owner.
- `409` `last-owner`: the team's only owner cannot be made something else — an owner who waits
  does not count beside one who has the key. Make another owner first.
- `404` `not-found`: that account is not in the team.

### `DELETE /v1/teams/{id}/members/{account_id}`

Takes a member out — or, with the account's own id, leaves. `204`.

- Anybody may leave, whatever their role, also while pending.
- An **owner** removes anybody. An **admin** removes anybody who is not an owner (`403`
  `forbidden` for an owner).
- `409` `last-owner`: the team's only owner neither leaves nor is removed (as above). Make
  another owner first, or delete the team.
- `404` `not-found`: that account is not in the team.

From this request on the team does not exist for that account: every route answers `404`. The
team's members and the removed account get a `team` event. If the member ever had the team key
of the current epoch, `needs_rotation` becomes `true`; a member who only ever waited leaves it as
it was.

### `POST /v1/teams/{id}/rotate`

```json
{
  "epoch": 2,
  "keys": [
    { "account_id": "0199c1d0-…", "wrapped_key": "<base64url>" },
    { "account_id": "0199c1d3-…", "wrapped_key": "<base64url>" }
  ],
  "cursor": 42
}
```

Owner or admin gives the team a new key. In one step the server sets the epoch to `epoch`,
replaces every active member's `wrapped_key`, **deletes all of the team's records** — they were
sealed under the old key — and clears `needs_rotation`. Answers `200` with the team as it is now.

- `epoch` must be the current epoch plus one. Anything else: `409` `stale-epoch`, with the
  current one as `epoch`. So two clients that rotate at once end with one rotation.
- `keys` must name **exactly the active members**, the caller included, each once. One missing,
  one too many, one twice, a pending member, a removed one, more than 1000: `409`
  `members-mismatch`. Read the members again and wrap for those.
- `cursor` is optional: the team's cursor as this client last saw it. When it is sent and is not
  the team's current one — somebody pushed since — the answer is `409` `stale-cursor` and nothing
  has changed. Pull, then rotate again. Without it, records the client never saw are deleted
  unseen; send it.
- A member who waits stays waiting and is confirmed with the new epoch's key.
- The team's sequence numbers go on counting. They are never reset.

The client that rotates holds every record and pushes them again, sealed under the new key, each
with `base_seq` 0 (see [What a client does](#what-a-client-does)).

## Records

A team's records are a second mailbox beside the account's own, with its own sequence numbers and
its own cursor, starting at 0. The envelope, the conflict rule and the paging are those of
`/v1/records`. Three things differ: every push names its epoch, an envelope's `vault_id` is the
**team's id**, and a pull hands out every kind of record without being asked (`manifests=1` and
`assist=1` mean nothing here; skip a kind you do not know).

### `GET /v1/teams/{id}/records?cursor=<n>&limit=<n>`

Any active member. `cursor` is where to go on from, 0 or left out for everything (`since` is
taken as another name for it). `limit` is 500 at most, and 500 when left out.

```json
{
  "envelopes": [ { "id": "…", "vault_id": "<team id>", "kind": "host", "updated_at": { … },
                   "base_seq": 0, "deleted": false, "nonce": "…", "blob": "…", "seq": 43 } ],
  "cursor": 43,
  "has_more": false,
  "epoch": 2,
  "role": "editor",
  "needs_rotation": false
}
```

`envelopes`, `cursor` and `has_more` are those of `/v1/records`. `epoch`, `role` and
`needs_rotation` are the team's and this account's as of this pull, so a client notices a
rotation or a changed role without asking for either.

### `POST /v1/teams/{id}/records`

```json
{ "schema": 2, "epoch": 2, "envelopes": [ … ] }
```

Owner, admin or editor. `epoch` is the epoch whose key sealed these envelopes. Answers `200` with
what `/v1/records` answers:

```json
{ "accepted": [ { "id": "…", "seq": 44 } ], "conflicts": [ … ], "cursor": 44 }
```

An envelope is accepted when its `base_seq` is the `seq` the server has for that record (0 for a
new one); otherwise the server's version comes back in `conflicts`.

| Status | `error`       | When                                                                     |
| ------ | ------------- | ------------------------------------------------------------------------ |
| 403    | `forbidden`   | A reader. Refused before the body is read.                               |
| 400    | `schema`      | `schema` is not the one the server speaks (see `/healthz`).              |
| 409    | `stale-epoch` | `epoch` is not the team's current one; nothing was stored. The answer carries the current one as `epoch`. |
| 400    | `invalid`     | An envelope `/v1/records` would refuse too — and one whose `vault_id` is not this team's id. |
| 413    | `too-large`   | The team is full (see [Limits](#limits)), or the server is.              |

A record marked `deleted` stays as a marker so that every device learns of the deletion. The
server remembers, per device, the cursor of its last pull of the team, and once a night forgets
the markers that are older than 90 days and that every device which ever pulled the team has
pulled past — the devices of current members, not revoked ones. A device that never pulled the
team holds no copy and keeps no marker alive; a device that is away keeps them all until it
returns or is revoked. A rotation deletes the markers with everything else.

## Events

`GET /v1/events` is the account's stream as before. Beside

```
event: records
data: 17
```

for the account's own vault, a device now also gets

```
event: team
data: 0199c1d4-…
```

where `data` is a team id. It means: something about that team changed — look again. It is sent
to every device of every member (those who wait included) after: records accepted by a push, a
rotation, a rename, a redeemed invite, a confirmation, a changed role, a member's replaced public
key, a removal (also to the removed account) and the deletion of the team (to those who were in
it). The event does not say which; on one, a client fetches `GET /v1/teams` and, for a team it is
active in, pulls. A team that is not in the list any more is gone for this account.

A stream holds 16 undelivered events. One that falls further behind loses the oldest of them,
and is told so:

```
event: team
data: *
```

`data` is the single character `*` in place of a team id. It means: events were missed, and
which is unknown — fetch `GET /v1/teams`, pull every team the account is active in, and pull the
account's own vault too (a `records` event may be among the lost). Events still held follow it as
usual. A client must check for `*` before reading `data` as an id.

Beyond that, treat the stream as a hint and sync on connecting. A team deleted from the
operator's command line sends no event; members notice at their next request (`404`).

## Limits

- Every route here counts against one budget of **300 requests a minute for each account**. The
  two record routes instead count against the budgets of `/v1/records`, which they share: 600
  pulls and 120 pushes a minute, and four of each at once.
- `POST /v1/teams/join` also has its own: **ten tries in ten minutes** for each account. A try
  that lets the account in is taken off the count again; every other one stays on it, a malformed
  one too.
- A team holds what one account's vault may hold: the operator's `UWUSYNC_ACCOUNT_MAX_RECORDS`
  and `UWUSYNC_ACCOUNT_MAX_MB`, counted for each team on its own and beside its members' own
  vaults. Everything on the server together — accounts and teams — stays under
  `UWUSYNC_SERVER_MAX_MB`. Over either: `413` `too-large`.

## Every error code here

| `error`                | Status | Meaning                                                        |
| ---------------------- | ------ | -------------------------------------------------------------- |
| `teams-disabled`       | 403    | Teams are switched off on this server.                         |
| `team-creation-closed` | 403    | Nobody may create teams on this server.                        |
| `forbidden`            | 403    | The account's role does not allow it.                          |
| `membership-pending`   | 403    | The account waits to be confirmed in that team.                |
| `invalid-invite`       | 403    | The code lets nobody in.                                       |
| `team-limit`           | 403    | The account is in as many teams as it may be.                  |
| `team-full`            | 403    | The team has as many members as it may have.                   |
| `too-many-invites`     | 403    | The team has 20 open invites.                                  |
| `no-identity`          | 409    | The account has no member key yet: `PUT /v1/teams/identity`.   |
| `identity-exists`      | 409    | The account has a member key, and `replace` was not set.       |
| `identity-changed`     | 409    | The member's public key is not the one the key was wrapped to. |
| `wrong-password`       | 403    | Replacing the member's public key without `current_auth_key`, or with a wrong one. |
| `already-member`       | 409    | The account is in that team already.                           |
| `not-pending`          | 409    | That member is active already.                                 |
| `not-active`           | 409    | Only an active member becomes an owner.                        |
| `last-owner`           | 409    | The team would be left without an owner who has its key.       |
| `members-mismatch`     | 409    | A rotation did not name exactly the active members.            |
| `stale-epoch`          | 409    | Not the team's current epoch (or, rotating, not the next). Body carries `epoch`. |
| `stale-cursor`         | 409    | Records were pushed since the cursor a rotation named.         |
| `not-found`            | 404    | No such team, member, invite or identity — or not this account's to see. |
| `invalid`, `schema`, `too-large`, `rate-limited`, `unauthorized` | | As everywhere in the API. |

## Who may do what

| | owner | admin | editor | reader | pending |
| --- | --- | --- | --- | --- | --- |
| See the team in `GET /v1/teams` | yes | yes | yes | yes | yes, without key |
| Leave | yes, unless the last owner | yes | yes | yes | yes |
| List members | yes | yes | yes | yes | no |
| Pull records | yes | yes | yes | yes | no |
| Push records | yes | yes | yes | no | no |
| Rename; invites; confirm; rotate | yes | yes | no | no | no |
| Remove a member, change a role | yes | not an owner's, not to owner | no | no | no |
| Delete the team | yes | no | no | no | only an owner |

## What a client does

Not enforced by the server, and what the rules above were made for.

- **Trust the confirmation, not the server.** The server hands out public keys; a server that
  lied about one would be handed the team key. The confirming person compares the newcomer's key
  (a fingerprint of `public_key`) with the newcomer before `confirm`, and again after
  `identity-changed`.
- **On a changed epoch** — in a pull's `epoch`, a `stale-epoch`, or `GET /v1/teams` — fetch the
  team for the new `wrapped_key`, forget every `seq` remembered for that team's records, set the
  team's cursor back to 0 and pull everything. What the server then holds is the team's whole
  content under the new key.
- **Rotating**: pull to the end first; note durably that a rotation is under way and which
  records must go back; `rotate` with `cursor`; then push every record again, sealed under the
  new key, with `base_seq` 0. A client that stops between the two steps finishes the pushing
  when it next starts: until it has, the team is empty on the server.
- **A push refused with `stale-epoch`** stored nothing. After picking the new key up, seal the
  local changes under it and push them with the `base_seq` the new pull gave.
- **`needs_rotation`** is a request to whoever manages the team. Until somebody rotates, a
  removed member's devices can still open the records they already fetched.
- **The server's epoch is the truth.** A server restored from a backup may come back with an
  older epoch and older wrapped keys than a client remembers. Follow the server (rotate again if
  a removal was lost with it); do not push under a key the server no longer hands out.
