//! Records: the mailbox itself.
//!
//! Two operations and one rule. **Pull** hands out everything after a cursor,
//! in sequence order. **Push** takes a record if the version it was based on is
//! the version stored, and reports a conflict with the current one if it is
//! not. That check is the whole of conflict detection here, and it is all the
//! server can do: it cannot read a record, so it cannot merge one either.
//!
//! Only the newest version of each record is kept. A device that needs an older
//! one has it locally or not at all — and the client is built for that, since a
//! record it has not seen is simply new to it.

use crate::db::accounts::Account;
use crate::wire::{Envelope, Kind, PullResponse, PushResponse, Reader};
use crate::{now_ms, ApiError, Result};
use rusqlite::{params, Connection, OptionalExtension};
use uuid::Uuid;
use uwussh_proto::{Accepted, SyncCursor, MAX_BATCH, MAX_BATCH_BYTES, MAX_BLOB_BYTES};

/// What one account may hold. A vault of hosts, keys and snippets is a few
/// megabytes; this is room for a hundred times that, and still means one
/// account cannot fill the disk of a machine that others sync to as well.
///
/// And what every account together may hold, because a hundred accounts at
/// their quota are 25 GiB — and every nightly backup is another copy of all of
/// it. The server-wide cap is what the disk really has to have room for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Quota {
    pub records: u64,
    pub bytes: u64,
    /// Sealed bytes of every account on this server together.
    pub server_bytes: u64,
}

impl Default for Quota {
    fn default() -> Self {
        Self {
            records: 100_000,
            bytes: 256 * 1024 * 1024,
            server_bytes: 2 * 1024 * 1024 * 1024,
        }
    }
}

/// An XChaCha20-Poly1305 nonce, as every envelope carries.
const NONCE_BYTES: usize = 24;

/// Everything about an envelope the server can check without a key: that it
/// belongs to this account's vault, that it is shaped like an envelope, and
/// that it is not big enough to be a problem.
fn check(account: &Account, envelope: &Envelope) -> Result<()> {
    if envelope.vault_id != account.vault_id {
        return Err(ApiError::Invalid(
            "a record from another vault than this account's".into(),
        ));
    }
    if envelope.nonce.len() != NONCE_BYTES {
        return Err(ApiError::Invalid("a record without a proper nonce".into()));
    }
    if envelope.blob.is_empty() {
        return Err(ApiError::Invalid(
            "a record with nothing sealed in it".into(),
        ));
    }
    if envelope.blob.len() > MAX_BLOB_BYTES {
        return Err(ApiError::TooLarge(format!(
            "a record of {} bytes, at most {MAX_BLOB_BYTES} are allowed",
            envelope.blob.len()
        )));
    }
    Ok(())
}

/// Offer records. Each one is taken and numbered, or reported as a conflict
/// with the version the server holds.
///
/// The whole batch is one transaction: a push either happens or does not, so a
/// device never has to wonder which half of it landed.
#[cfg(test)]
pub fn push(
    conn: &mut Connection,
    account: &Account,
    device: Uuid,
    envelopes: &[Envelope],
) -> Result<PushResponse> {
    push_within(conn, account, device, envelopes, Quota::default())
}

/// [`push`], held to what the account may hold and what the server holds in
/// all. A push that would take either past that is refused whole; one that
/// makes the account smaller — a delete, say — always goes through, even for
/// an account that is over, or on a server that is full.
pub fn push_within(
    conn: &mut Connection,
    account: &Account,
    device: Uuid,
    envelopes: &[Envelope],
    quota: Quota,
) -> Result<PushResponse> {
    if envelopes.len() > MAX_BATCH {
        return Err(ApiError::TooLarge(format!(
            "{} records in one request, at most {MAX_BATCH} are allowed",
            envelopes.len()
        )));
    }
    let sealed: usize = envelopes.iter().map(|envelope| envelope.blob.len()).sum();
    if envelopes.len() > 1 && sealed > MAX_BATCH_BYTES {
        return Err(ApiError::TooLarge(format!(
            "{sealed} sealed bytes in one request, at most {MAX_BATCH_BYTES} are allowed"
        )));
    }
    for envelope in envelopes {
        check(account, envelope)?;
    }

    let tx = conn.transaction()?;
    let (mut seq, held_records, held_bytes): (i64, i64, i64) = tx.query_row(
        "SELECT seq, record_count, record_bytes FROM accounts WHERE id = ?1",
        [account.id.to_string()],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    let (mut records, mut bytes) = (held_records, held_bytes);
    let mut response = PushResponse::default();

    for envelope in envelopes {
        let current: Option<(i64, i64)> = tx
            .query_row(
                "SELECT seq, length(blob) FROM records WHERE account_id = ?1 AND id = ?2",
                params![account.id.to_string(), envelope.id.to_string()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;

        // A record the server does not have is new, whatever the device
        // thought it was based on: there is nothing here to conflict with.
        if let Some((current, _)) = current {
            if current as u64 != envelope.base_seq {
                if let Some(held) = get(&tx, account, envelope.id)? {
                    response.conflicts.push(held);
                }
                continue;
            }
        }
        match current {
            Some((_, before)) => bytes += envelope.blob.len() as i64 - before,
            None => {
                records += 1;
                bytes += envelope.blob.len() as i64;
            }
        }

        seq += 1;
        tx.execute(
            "INSERT INTO records
                (account_id, id, kind, seq, hlc_wall_ms, hlc_counter, hlc_device,
                 deleted, nonce, blob, device_id, updated_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
             ON CONFLICT (account_id, id) DO UPDATE SET
                kind = excluded.kind, seq = excluded.seq,
                hlc_wall_ms = excluded.hlc_wall_ms, hlc_counter = excluded.hlc_counter,
                hlc_device = excluded.hlc_device, deleted = excluded.deleted,
                nonce = excluded.nonce, blob = excluded.blob,
                device_id = excluded.device_id, updated_ms = excluded.updated_ms",
            params![
                account.id.to_string(),
                envelope.id.to_string(),
                envelope.kind.as_str(),
                seq,
                envelope.updated_at.wall_ms as i64,
                envelope.updated_at.counter,
                envelope.updated_at.device,
                envelope.deleted,
                envelope.nonce,
                envelope.blob,
                device.to_string(),
                now_ms() as i64,
            ],
        )?;
        response.accepted.push(Accepted {
            id: envelope.id,
            seq: seq as u64,
        });
    }

    if (records > held_records && records as u64 > quota.records)
        || (bytes > held_bytes && bytes as u64 > quota.bytes)
    {
        // Dropping the transaction takes back everything above.
        return Err(ApiError::TooLarge(format!(
            "this account holds as much as this server allows ({} records, {} MiB)",
            quota.records,
            quota.bytes / (1024 * 1024)
        )));
    }
    if bytes > held_bytes {
        // Every account but this one as it was, and this one as it would be.
        // Read inside the transaction, so two accounts pushing at once cannot
        // both squeeze under the line.
        let everyone: i64 = tx.query_row(
            "SELECT coalesce(sum(record_bytes), 0) FROM accounts",
            [],
            |row| row.get(0),
        )?;
        if (everyone - held_bytes + bytes).max(0) as u64 > quota.server_bytes {
            tracing::warn!(
                limit_mib = quota.server_bytes / (1024 * 1024),
                "the server holds as much as it is allowed to; pushes that add are refused"
            );
            return Err(ApiError::TooLarge(format!(
                "this server holds as much as it allows ({} MiB for all accounts together)",
                quota.server_bytes / (1024 * 1024)
            )));
        }
    }
    tx.execute(
        "UPDATE accounts SET seq = ?2, record_count = ?3, record_bytes = ?4 WHERE id = ?1",
        params![account.id.to_string(), seq, records, bytes],
    )?;
    tx.commit()?;

    response.cursor = SyncCursor(seq as u64);
    Ok(response)
}

/// Everything after a cursor, oldest first. `has_more` is honest: a device
/// that stops at the first page would otherwise believe it had everything.
///
/// A page ends at `limit` records or at [`MAX_BATCH_BYTES`] of sealed bytes,
/// whichever comes first, and always holds one. Rows are read one at a time
/// and the reading stops there: five hundred records at the largest size
/// would be 128 MiB in memory for one request, and a few of those at once
/// take down a small machine.
///
/// `reader` says which kinds the device can read (see [`Kind::readable_by`]).
/// The others are passed over without counting towards the page, and the
/// cursor still moves past them — also when that leaves the page empty — so
/// a device that stores the cursor never asks for them again, and one that
/// does not is only handed the same empty page until something it reads
/// comes along.
pub fn pull(
    conn: &Connection,
    account: &Account,
    since: u64,
    limit: usize,
    reader: Reader,
) -> Result<PullResponse> {
    let limit = limit.clamp(1, MAX_BATCH);
    // No LIMIT in SQL: rows passed over don't count towards the page, and the
    // loop stops reading once the page is full.
    let mut stmt = conn.prepare(
        "SELECT id, kind, seq, hlc_wall_ms, hlc_counter, hlc_device, deleted, nonce, blob
           FROM records
          WHERE account_id = ?1 AND seq > ?2
          ORDER BY seq",
    )?;
    let rows = stmt.query_map(params![account.id.to_string(), since as i64], |row| {
        row_to_envelope(account, row)
    })?;
    let mut envelopes = Vec::new();
    let mut bytes = 0;
    let mut has_more = false;
    let mut cursor = since;
    for row in rows {
        let envelope = row?;
        if !envelope.kind.readable_by(reader) {
            cursor = envelope.seq.unwrap_or(cursor).max(cursor);
            continue;
        }
        if envelopes.len() == limit
            || (!envelopes.is_empty() && bytes + envelope.blob.len() > MAX_BATCH_BYTES)
        {
            has_more = true;
            break;
        }
        bytes += envelope.blob.len();
        cursor = envelope.seq.unwrap_or(cursor).max(cursor);
        envelopes.push(envelope);
    }

    Ok(PullResponse {
        envelopes,
        cursor: SyncCursor(cursor),
        has_more,
    })
}

/// One record as the server holds it.
pub fn get(conn: &Connection, account: &Account, id: Uuid) -> Result<Option<Envelope>> {
    Ok(conn
        .query_row(
            "SELECT id, kind, seq, hlc_wall_ms, hlc_counter, hlc_device, deleted, nonce, blob
               FROM records WHERE account_id = ?1 AND id = ?2",
            params![account.id.to_string(), id.to_string()],
            |row| row_to_envelope(account, row),
        )
        .optional()?)
}

fn row_to_envelope(account: &Account, row: &rusqlite::Row<'_>) -> rusqlite::Result<Envelope> {
    let id: String = row.get(0)?;
    let kind = Kind::stored(row.get(1)?);
    let seq: i64 = row.get(2)?;
    let wall: i64 = row.get(3)?;
    let counter: i64 = row.get(4)?;
    let device: i64 = row.get(5)?;
    Ok(Envelope {
        id: Uuid::parse_str(&id).unwrap_or(Uuid::nil()),
        vault_id: account.vault_id,
        kind,
        updated_at: uwussh_proto::Hlc::new(wall as u64, counter as u32, device as u32),
        base_seq: seq as u64,
        deleted: row.get(6)?,
        nonce: row.get(7)?,
        blob: row.get(8)?,
        seq: Some(seq as u64),
    })
}

#[cfg(test)]
pub fn count(conn: &Connection, account: &Account) -> rusqlite::Result<i64> {
    conn.query_row(
        "SELECT count(*) FROM records WHERE account_id = ?1",
        [account.id.to_string()],
        |row| row.get(0),
    )
}

/// Forget tombstones every device has read and that are older than a season.
///
/// Both conditions matter. A tombstone is what stops a device that was offline
/// during a delete from bringing the record back, so one may only go once
/// every device has seen it — and a device that has been away for months gets
/// a fresh start instead, which is why `below_seq` comes from the devices that
/// still read.
pub fn purge_tombstones(
    conn: &Connection,
    account: &Account,
    before_ms: u64,
    below_seq: u64,
) -> rusqlite::Result<usize> {
    let tx = conn.unchecked_transaction()?;
    let which = params![account.id.to_string(), before_ms as i64, below_seq as i64];
    let (count, bytes): (i64, i64) = tx.query_row(
        "SELECT count(*), coalesce(sum(length(blob)), 0) FROM records
          WHERE account_id = ?1 AND deleted = 1 AND updated_ms < ?2 AND seq <= ?3",
        which,
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let removed = tx.execute(
        "DELETE FROM records
          WHERE account_id = ?1 AND deleted = 1 AND updated_ms < ?2 AND seq <= ?3",
        which,
    )?;
    tx.execute(
        "UPDATE accounts
            SET record_count = max(record_count - ?2, 0), record_bytes = max(record_bytes - ?3, 0)
          WHERE id = ?1",
        params![account.id.to_string(), count, bytes],
    )?;
    tx.commit()?;
    Ok(removed)
}

/// Forget the manifests a device published. Once it is revoked, nothing it
/// said is kept up to date any more: after old tombstones are purged, its last
/// manifest would name records a newly joined device can never receive, and
/// that device would take the gap for a server holding them back.
pub fn drop_manifests_of(
    conn: &Connection,
    account_id: Uuid,
    device_id: Uuid,
) -> rusqlite::Result<usize> {
    let tx = conn.unchecked_transaction()?;
    let which = params![
        account_id.to_string(),
        device_id.to_string(),
        Kind::MANIFEST
    ];
    let (count, bytes): (i64, i64) = tx.query_row(
        "SELECT count(*), coalesce(sum(length(blob)), 0) FROM records
          WHERE account_id = ?1 AND device_id = ?2 AND kind = ?3",
        which,
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let removed = tx.execute(
        "DELETE FROM records WHERE account_id = ?1 AND device_id = ?2 AND kind = ?3",
        which,
    )?;
    tx.execute(
        "UPDATE accounts
            SET record_count = max(record_count - ?2, 0), record_bytes = max(record_bytes - ?3, 0)
          WHERE id = ?1",
        params![account_id.to_string(), count, bytes],
    )?;
    tx.commit()?;
    Ok(removed)
}

/// How many records an account holds, and how many sealed bytes.
pub fn usage(conn: &Connection, account: &Account) -> rusqlite::Result<(u64, u64)> {
    conn.query_row(
        "SELECT record_count, record_bytes FROM accounts WHERE id = ?1",
        [account.id.to_string()],
        |row| Ok((row.get::<_, i64>(0)? as u64, row.get::<_, i64>(1)? as u64)),
    )
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::db::{accounts, Db};
    use uwussh_proto::{EntityKind, Hlc};

    fn account(conn: &Connection) -> Account {
        accounts::create(conn, &accounts::tests::header(), b"key").unwrap()
    }

    /// One new record, for tests elsewhere that only need the numbers to move.
    pub(crate) fn push_one(conn: &mut Connection, account: &Account) {
        push(
            conn,
            account,
            Uuid::now_v7(),
            &[envelope(account, Uuid::now_v7(), 0)],
        )
        .unwrap();
    }

    fn sized(account: &Account, bytes: usize) -> Envelope {
        Envelope {
            blob: vec![9; bytes],
            ..envelope(account, Uuid::now_v7(), 0)
        }
    }

    #[test]
    fn a_page_stops_at_the_byte_budget_and_says_there_is_more() {
        let db = Db::open_in_memory().unwrap();
        let mut conn = db.lock();
        let account = account(&conn);
        let device = Uuid::now_v7();
        // Forty records of 256 KiB: ten MiB, more than one page may carry.
        for _ in 0..4 {
            let batch: Vec<Envelope> = (0..10).map(|_| sized(&account, MAX_BLOB_BYTES)).collect();
            push_within(&mut conn, &account, device, &batch[..5], Quota::default()).unwrap();
            push_within(&mut conn, &account, device, &batch[5..], Quota::default()).unwrap();
        }

        let first = pull(&conn, &account, 0, MAX_BATCH, Reader::ALL).unwrap();
        let bytes: usize = first.envelopes.iter().map(|env| env.blob.len()).sum();
        assert!(bytes <= MAX_BATCH_BYTES, "{bytes}");
        assert_eq!(first.envelopes.len(), MAX_BATCH_BYTES / MAX_BLOB_BYTES);
        assert!(first.has_more);

        let second = pull(&conn, &account, first.cursor.0, MAX_BATCH, Reader::ALL).unwrap();
        assert_eq!(first.envelopes.len() + second.envelopes.len(), 40);
        assert!(!second.has_more);
    }

    #[test]
    fn one_request_carries_at_most_the_byte_budget() {
        let db = Db::open_in_memory().unwrap();
        let mut conn = db.lock();
        let account = account(&conn);
        let too_much: Vec<Envelope> = (0..MAX_BATCH_BYTES / MAX_BLOB_BYTES + 1)
            .map(|_| sized(&account, MAX_BLOB_BYTES))
            .collect();
        assert!(matches!(
            push(&mut conn, &account, Uuid::now_v7(), &too_much),
            Err(ApiError::TooLarge(_))
        ));
    }

    #[test]
    fn a_full_account_takes_nothing_more_but_may_still_shrink() {
        let db = Db::open_in_memory().unwrap();
        let mut conn = db.lock();
        let account = account(&conn);
        let device = Uuid::now_v7();
        let quota = Quota {
            records: 2,
            bytes: 1024,
            ..Quota::default()
        };
        let one = sized(&account, 400);
        let two = sized(&account, 400);
        push_within(&mut conn, &account, device, &[one.clone(), two], quota).unwrap();
        assert_eq!(usage(&conn, &account).unwrap(), (2, 800));

        // A third record is one too many, and so is a bigger version of one.
        let three = sized(&account, 10);
        assert!(matches!(
            push_within(&mut conn, &account, device, &[three], quota),
            Err(ApiError::TooLarge(_))
        ));
        let bigger = Envelope {
            blob: vec![1; 700],
            base_seq: 1,
            ..one.clone()
        };
        assert!(push_within(&mut conn, &account, device, &[bigger], quota).is_err());
        assert_eq!(
            usage(&conn, &account).unwrap(),
            (2, 800),
            "nothing of it stayed"
        );

        // Deleting makes room, even for an account that is full.
        let deleted = Envelope {
            blob: vec![1; 16],
            base_seq: 1,
            deleted: true,
            ..one
        };
        push_within(&mut conn, &account, device, &[deleted], quota).unwrap();
        assert_eq!(usage(&conn, &account).unwrap(), (2, 416));
    }

    #[test]
    fn all_accounts_together_hold_no_more_than_the_server_allows() {
        let db = Db::open_in_memory().unwrap();
        let mut conn = db.lock();
        let mine = account(&conn);
        let theirs = accounts::create(&conn, &accounts::tests::header(), b"other").unwrap();
        let device = Uuid::now_v7();
        let quota = Quota {
            server_bytes: 1000,
            ..Quota::default()
        };
        let first = sized(&mine, 600);
        push_within(
            &mut conn,
            &mine,
            device,
            std::slice::from_ref(&first),
            quota,
        )
        .unwrap();

        // Well inside its own quota, and still one too many for the server.
        assert!(matches!(
            push_within(&mut conn, &theirs, device, &[sized(&theirs, 500)], quota),
            Err(ApiError::TooLarge(message)) if message.contains("all accounts")
        ));
        assert_eq!(
            usage(&conn, &theirs).unwrap(),
            (0, 0),
            "nothing of it stayed"
        );
        push_within(&mut conn, &theirs, device, &[sized(&theirs, 400)], quota).unwrap();

        // Full now. Growing is refused, shrinking is not, and what shrinking
        // freed is there for the other account.
        let bigger = Envelope {
            blob: vec![1; 601],
            base_seq: 1,
            ..first.clone()
        };
        assert!(push_within(&mut conn, &mine, device, &[bigger], quota).is_err());
        let smaller = Envelope {
            blob: vec![1; 100],
            base_seq: 1,
            deleted: true,
            ..first
        };
        push_within(&mut conn, &mine, device, &[smaller], quota).unwrap();
        push_within(&mut conn, &theirs, device, &[sized(&theirs, 500)], quota).unwrap();
    }

    fn envelope(account: &Account, id: Uuid, base_seq: u64) -> Envelope {
        Envelope {
            id,
            vault_id: account.vault_id,
            kind: EntityKind::Host.into(),
            updated_at: Hlc::new(1_700_000_000_000, 0, 1),
            base_seq,
            deleted: false,
            nonce: vec![7; NONCE_BYTES],
            blob: vec![1, 2, 3, 4],
            seq: None,
        }
    }

    #[test]
    fn a_pushed_record_gets_the_next_number_and_comes_back_on_a_pull() {
        let db = Db::open_in_memory().unwrap();
        let mut conn = db.lock();
        let account = account(&conn);
        let device = Uuid::now_v7();
        let id = Uuid::now_v7();

        let response = push(&mut conn, &account, device, &[envelope(&account, id, 0)]).unwrap();
        assert_eq!(response.accepted.len(), 1);
        assert_eq!(response.accepted[0].seq, 1);
        assert!(response.conflicts.is_empty());
        assert_eq!(response.cursor, SyncCursor(1));

        let page = pull(&conn, &account, 0, 10, Reader::ALL).unwrap();
        assert_eq!(page.envelopes.len(), 1);
        assert_eq!(page.envelopes[0].id, id);
        assert_eq!(page.envelopes[0].seq, Some(1));
        assert_eq!(page.envelopes[0].vault_id, account.vault_id);
        assert_eq!(page.envelopes[0].blob, vec![1, 2, 3, 4]);
        assert!(!page.has_more);
        assert_eq!(page.cursor, SyncCursor(1));

        // And nothing comes twice.
        let again = pull(&conn, &account, 1, 10, Reader::ALL).unwrap();
        assert!(again.envelopes.is_empty());
        assert_eq!(again.cursor, SyncCursor(1));
    }

    #[test]
    fn a_push_based_on_an_older_version_is_a_conflict_with_the_current_one() {
        let db = Db::open_in_memory().unwrap();
        let mut conn = db.lock();
        let account = account(&conn);
        let id = Uuid::now_v7();
        let first = Uuid::now_v7();
        let second = Uuid::now_v7();

        push(&mut conn, &account, first, &[envelope(&account, id, 0)]).unwrap();
        let mut newer = envelope(&account, id, 1);
        newer.blob = vec![9, 9, 9];
        push(&mut conn, &account, first, &[newer]).unwrap();

        // The second device still thinks version 1 is current.
        let mut stale = envelope(&account, id, 1);
        stale.blob = vec![5, 5, 5];
        let response = push(&mut conn, &account, second, &[stale]).unwrap();
        assert!(response.accepted.is_empty());
        assert_eq!(response.conflicts.len(), 1);
        assert_eq!(
            response.conflicts[0].blob,
            vec![9, 9, 9],
            "the conflict carries what the server holds"
        );
        assert_eq!(response.conflicts[0].seq, Some(2));
        assert_eq!(
            response.conflicts[0].base_seq, 2,
            "so the next attempt is based on it"
        );

        // Based on what it holds, the same record is taken.
        let mut retried = envelope(&account, id, 2);
        retried.blob = vec![5, 5, 5];
        let response = push(&mut conn, &account, second, &[retried]).unwrap();
        assert_eq!(response.accepted.len(), 1);
        assert_eq!(response.accepted[0].seq, 3);
    }

    #[test]
    fn one_conflict_does_not_stop_the_rest_of_the_batch() {
        let db = Db::open_in_memory().unwrap();
        let mut conn = db.lock();
        let account = account(&conn);
        let device = Uuid::now_v7();
        let taken = Uuid::now_v7();
        push(&mut conn, &account, device, &[envelope(&account, taken, 0)]).unwrap();

        let response = push(
            &mut conn,
            &account,
            device,
            &[
                envelope(&account, taken, 0), // conflicts: it is at 1 now
                envelope(&account, Uuid::now_v7(), 0),
                envelope(&account, Uuid::now_v7(), 0),
            ],
        )
        .unwrap();
        assert_eq!(response.accepted.len(), 2);
        assert_eq!(response.conflicts.len(), 1);
        assert_eq!(count(&conn, &account).unwrap(), 3);
    }

    #[test]
    fn a_page_says_when_there_is_another_one() {
        let db = Db::open_in_memory().unwrap();
        let mut conn = db.lock();
        let account = account(&conn);
        let device = Uuid::now_v7();
        for _ in 0..5 {
            push(
                &mut conn,
                &account,
                device,
                &[envelope(&account, Uuid::now_v7(), 0)],
            )
            .unwrap();
        }

        let page = pull(&conn, &account, 0, 2, Reader::ALL).unwrap();
        assert_eq!(page.envelopes.len(), 2);
        assert!(page.has_more);
        assert_eq!(page.cursor, SyncCursor(2));

        let page = pull(&conn, &account, page.cursor.0, 2, Reader::ALL).unwrap();
        assert_eq!(page.envelopes.len(), 2);
        assert!(page.has_more);

        let page = pull(&conn, &account, page.cursor.0, 2, Reader::ALL).unwrap();
        assert_eq!(page.envelopes.len(), 1);
        assert!(!page.has_more, "the last page says so");
    }

    #[test]
    fn nothing_of_another_account_is_ever_in_the_answer() {
        let db = Db::open_in_memory().unwrap();
        let mut conn = db.lock();
        let mine = account(&conn);
        let theirs = account(&conn);
        let device = Uuid::now_v7();
        push(
            &mut conn,
            &theirs,
            device,
            &[envelope(&theirs, Uuid::now_v7(), 0)],
        )
        .unwrap();

        assert!(pull(&conn, &mine, 0, 10, Reader::ALL)
            .unwrap()
            .envelopes
            .is_empty());
        assert_eq!(count(&conn, &mine).unwrap(), 0);
        assert_eq!(count(&conn, &theirs).unwrap(), 1);
    }

    #[test]
    fn what_the_server_can_check_without_a_key_it_does_check() {
        let db = Db::open_in_memory().unwrap();
        let mut conn = db.lock();
        let account = account(&conn);
        let device = Uuid::now_v7();
        let id = Uuid::now_v7();

        let mut stranger = envelope(&account, id, 0);
        stranger.vault_id = Uuid::now_v7();
        assert!(matches!(
            push(&mut conn, &account, device, &[stranger]),
            Err(ApiError::Invalid(_))
        ));

        let mut short_nonce = envelope(&account, id, 0);
        short_nonce.nonce = vec![1, 2, 3];
        assert!(matches!(
            push(&mut conn, &account, device, &[short_nonce]),
            Err(ApiError::Invalid(_))
        ));

        let mut empty = envelope(&account, id, 0);
        empty.blob.clear();
        assert!(matches!(
            push(&mut conn, &account, device, &[empty]),
            Err(ApiError::Invalid(_))
        ));

        let mut huge = envelope(&account, id, 0);
        huge.blob = vec![0; MAX_BLOB_BYTES + 1];
        assert!(matches!(
            push(&mut conn, &account, device, &[huge]),
            Err(ApiError::TooLarge(_))
        ));

        let batch: Vec<Envelope> = (0..MAX_BATCH + 1)
            .map(|_| envelope(&account, Uuid::now_v7(), 0))
            .collect();
        assert!(matches!(
            push(&mut conn, &account, device, &batch),
            Err(ApiError::TooLarge(_))
        ));

        assert_eq!(count(&conn, &account).unwrap(), 0, "and nothing was stored");
    }

    #[test]
    fn a_refused_batch_leaves_nothing_behind() {
        let db = Db::open_in_memory().unwrap();
        let mut conn = db.lock();
        let account = account(&conn);
        let device = Uuid::now_v7();
        let mut bad = envelope(&account, Uuid::now_v7(), 0);
        bad.nonce.clear();

        assert!(push(
            &mut conn,
            &account,
            device,
            &[envelope(&account, Uuid::now_v7(), 0), bad]
        )
        .is_err());
        assert_eq!(count(&conn, &account).unwrap(), 0);
        assert_eq!(
            accounts::get(&conn, account.id).unwrap().unwrap().seq,
            0,
            "and did not use up a sequence number"
        );
    }

    #[test]
    fn a_tombstone_goes_only_once_everyone_has_read_it_and_time_has_passed() {
        let db = Db::open_in_memory().unwrap();
        let mut conn = db.lock();
        let account = account(&conn);
        let device = Uuid::now_v7();
        let id = Uuid::now_v7();
        let mut gone = envelope(&account, id, 0);
        gone.deleted = true;
        push(&mut conn, &account, device, &[gone]).unwrap();

        let ancient = now_ms() + 1;
        assert_eq!(
            purge_tombstones(&conn, &account, ancient, 0).unwrap(),
            0,
            "nobody has read it yet"
        );
        assert_eq!(
            purge_tombstones(&conn, &account, 0, 99).unwrap(),
            0,
            "and it is not old yet"
        );
        assert_eq!(purge_tombstones(&conn, &account, ancient, 99).unwrap(), 1);
        assert_eq!(count(&conn, &account).unwrap(), 0);
    }

    fn manifest(account: &Account) -> Envelope {
        Envelope {
            kind: EntityKind::Manifest.into(),
            ..envelope(account, Uuid::now_v7(), 0)
        }
    }

    #[test]
    fn a_client_from_before_manifests_never_sees_one_and_still_gets_past_them() {
        let db = Db::open_in_memory().unwrap();
        let mut conn = db.lock();
        let account = account(&conn);
        let device = Uuid::now_v7();
        let host = envelope(&account, Uuid::now_v7(), 0);
        push(
            &mut conn,
            &account,
            device,
            &[manifest(&account), host.clone(), manifest(&account)],
        )
        .unwrap();

        let old = pull(&conn, &account, 0, 10, Reader::default()).unwrap();
        assert_eq!(old.envelopes.len(), 1);
        assert_eq!(old.envelopes[0].id, host.id);
        assert_eq!(old.cursor.0, 3, "the cursor moves past the manifests too");
        assert!(!old.has_more);

        let new = pull(&conn, &account, 0, 10, Reader::ALL).unwrap();
        assert_eq!(new.envelopes.len(), 3);

        // A page of nothing but manifests is an empty page for the old one.
        let rest = pull(&conn, &account, 2, 10, Reader::default()).unwrap();
        assert!(rest.envelopes.is_empty());
    }

    #[test]
    fn manifests_passed_over_do_not_fill_the_page() {
        let db = Db::open_in_memory().unwrap();
        let mut conn = db.lock();
        let account = account(&conn);
        let device = Uuid::now_v7();
        let mut batch: Vec<Envelope> = (0..5).map(|_| manifest(&account)).collect();
        batch.push(envelope(&account, Uuid::now_v7(), 0));
        batch.push(envelope(&account, Uuid::now_v7(), 0));
        push(&mut conn, &account, device, &batch).unwrap();

        let page = pull(&conn, &account, 0, 1, Reader::default()).unwrap();
        assert_eq!(page.envelopes.len(), 1);
        assert!(page.has_more);
        let page = pull(&conn, &account, page.cursor.0, 1, Reader::default()).unwrap();
        assert_eq!(page.envelopes.len(), 1);
        assert!(!page.has_more);
    }

    #[test]
    fn a_revoked_device_takes_its_manifest_along_and_nothing_else() {
        let db = Db::open_in_memory().unwrap();
        let mut conn = db.lock();
        let account = account(&conn);
        let gone = Uuid::now_v7();
        let stays = Uuid::now_v7();
        push(
            &mut conn,
            &account,
            gone,
            &[manifest(&account), envelope(&account, Uuid::now_v7(), 0)],
        )
        .unwrap();
        push(&mut conn, &account, stays, &[manifest(&account)]).unwrap();

        assert_eq!(drop_manifests_of(&conn, account.id, gone).unwrap(), 1);
        let left = pull(&conn, &account, 0, 10, Reader::ALL).unwrap();
        assert_eq!(
            left.envelopes.len(),
            2,
            "its host and the other device's manifest"
        );
        assert_eq!(usage(&conn, &account).unwrap().0, 2);
    }

    fn of_kind(account: &Account, kind: &str) -> Envelope {
        Envelope {
            kind: Kind::parse(kind).unwrap(),
            ..envelope(account, Uuid::now_v7(), 0)
        }
    }

    /// What UwUSSH 0.2 asks with: manifests, and no assistant.
    const OLD: Reader = Reader {
        manifests: true,
        assist: false,
    };

    fn kinds(page: &PullResponse) -> Vec<&str> {
        page.envelopes.iter().map(|env| env.kind.as_str()).collect()
    }

    #[test]
    fn the_assistants_records_are_kept_and_go_only_to_clients_that_ask() {
        let db = Db::open_in_memory().unwrap();
        let mut conn = db.lock();
        let account = account(&conn);
        let device = Uuid::now_v7();
        let batch = [
            of_kind(&account, "host"),
            of_kind(&account, Kind::ASSIST_CONFIG),
            of_kind(&account, Kind::ASSIST_CACHE),
            of_kind(&account, "manifest"),
            of_kind(&account, Kind::ASSIST_CACHE),
            of_kind(&account, "key"),
        ];
        let pushed = push(&mut conn, &account, device, &batch).unwrap();
        assert_eq!(pushed.accepted.len(), 6);
        assert_eq!(count(&conn, &account).unwrap(), 6);

        let old = pull(&conn, &account, 0, 10, OLD).unwrap();
        assert_eq!(kinds(&old), ["host", "manifest", "key"]);
        assert_eq!(old.cursor.0, 6);
        assert!(!old.has_more);

        let new = pull(&conn, &account, 0, 10, Reader::ALL).unwrap();
        assert_eq!(
            kinds(&new),
            batch
                .iter()
                .map(|env| env.kind.as_str())
                .collect::<Vec<_>>()
        );
        assert_eq!(new.envelopes[1], {
            let mut stored = batch[1].clone();
            stored.seq = Some(2);
            stored.base_seq = 2;
            stored
        });
        assert_eq!(new.cursor.0, 6);
    }

    #[test]
    fn a_page_of_nothing_an_old_client_reads_still_moves_its_cursor() {
        let db = Db::open_in_memory().unwrap();
        let mut conn = db.lock();
        let account = account(&conn);
        let device = Uuid::now_v7();
        let host = of_kind(&account, "host");
        push(&mut conn, &account, device, std::slice::from_ref(&host)).unwrap();
        let cache: Vec<Envelope> = (0..4)
            .map(|_| of_kind(&account, Kind::ASSIST_CACHE))
            .collect();
        push(&mut conn, &account, device, &cache).unwrap();

        // Rows passed over are passed over even behind a full page: the
        // cursor goes past them right away.
        let first = pull(&conn, &account, 0, 1, OLD).unwrap();
        assert_eq!(kinds(&first), ["host"]);
        assert_eq!(first.cursor.0, 5);
        assert!(!first.has_more);

        // A device that had the host before the slots came: an empty page,
        // a cursor at the end, and nothing more — not the same page again
        // and again.
        let second = pull(&conn, &account, 1, 1, OLD).unwrap();
        assert!(second.envelopes.is_empty());
        assert_eq!(second.cursor.0, 5);
        assert!(!second.has_more);
        let third = pull(&conn, &account, second.cursor.0, 1, OLD).unwrap();
        assert!(third.envelopes.is_empty());
        assert_eq!(third.cursor.0, 5);

        // With one more host behind the slots, the full page says so, and
        // the next one starts after the slots.
        let later = of_kind(&account, "snippet");
        push(&mut conn, &account, device, std::slice::from_ref(&later)).unwrap();
        let full = pull(&conn, &account, 0, 1, OLD).unwrap();
        assert_eq!(kinds(&full), ["host"]);
        assert!(full.has_more);
        assert_eq!(full.cursor.0, 5);
        let next = pull(&conn, &account, full.cursor.0, 1, OLD).unwrap();
        assert_eq!(kinds(&next), ["snippet"]);
        assert!(!next.has_more);

        // UwUSSH 0.2 does not store the cursor of an empty page. It asks from
        // 1 again, and the next host still reaches it, past the slots.
        let again = pull(&conn, &account, first.cursor.0, 1, OLD).unwrap();
        assert_eq!(kinds(&again), ["snippet"]);
        assert_eq!(again.cursor.0, 6);
        assert!(!again.has_more);

        // A new client pages through every one of them.
        let mut cursor = 0;
        let mut seen = Vec::new();
        loop {
            let page = pull(&conn, &account, cursor, 2, Reader::ALL).unwrap();
            assert!(page.cursor.0 > cursor || page.envelopes.is_empty());
            cursor = page.cursor.0;
            seen.extend(page.envelopes.into_iter().map(|env| env.id));
            if !page.has_more {
                break;
            }
        }
        assert_eq!(seen.len(), 6);
        assert_eq!(cursor, 6);
    }

    #[test]
    fn a_kind_nobody_has_heard_of_yet_is_stored_as_it_came() {
        let db = Db::open_in_memory().unwrap();
        let mut conn = db.lock();
        let account = account(&conn);
        let device = Uuid::now_v7();
        let future = of_kind(&account, "hologram");
        push(&mut conn, &account, device, std::slice::from_ref(&future)).unwrap();

        assert!(pull(&conn, &account, 0, 10, OLD)
            .unwrap()
            .envelopes
            .is_empty());
        let page = pull(&conn, &account, 0, 10, Reader::ALL).unwrap();
        assert_eq!(kinds(&page), ["hologram"]);

        // A conflict hands it back under its own kind too.
        let stale = Envelope {
            blob: vec![5; 8],
            ..future.clone()
        };
        let response = push(&mut conn, &account, device, &[stale]).unwrap();
        assert_eq!(response.conflicts.len(), 1);
        assert_eq!(response.conflicts[0].kind.as_str(), "hologram");
    }
}
