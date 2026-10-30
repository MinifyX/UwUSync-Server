# UwUSync-Server

Sync-Server für UwUSSH/UwURDP: verschlüsselter "dummer" Mailbox-Server (axum 0.8, SQLite eingebettet), ein Crate `uwusync-server`, kein Frontend.

## Layout
- `src/api/` HTTP-Handler (accounts, devices, records, pairing, sso, scim, teams); `src/db/` SQLite-Zugriff, `migrate()` in `src/db/mod.rs` (per `user_version`).
- `src/auth.rs`, `pairing.rs`, `oidc.rs`, `sso.rs`, `uwuauth.rs`, `limits.rs`, `tls.rs`, `wire.rs`: Auth, Pairing, UwUAuth-SSO, Rate-Limits, TLS, Wire-Format.
- `tests/`: `api.rs`, `client.rs`, `connections.rs`, `health.rs` (je eigene Binary); `docker/`, `compose.yaml`, `install.sh`, `update.sh` für den Betrieb.

## Befehle
- Gezielt: `cargo test --test api <filter>`, `cargo test --lib <filter>`; voller Lauf wie CI: `cargo fmt --all --check` · `cargo clippy --all-targets --locked -- -D warnings` · `cargo test --all-targets --locked` (Einzelcrate, kein `--workspace` nötig).
- CI prüft zusätzlich `cargo audit` und die Shell-Skripte (`install.sh`/`update.sh`, Job "Scripts"/"Install and update" in `.github/workflows/ci.yml`).

## Fallen
- `uwussh-proto` (und dev-deps `uwussh-store/-sync/-vault`) hängen per Commit-`rev` an `MinifyX/UwUSSH-Client`; alle vier `rev` in `Cargo.toml` gemeinsam anheben, danach bewusst `cargo update -p uwussh-proto`. Protokolländerungen zuerst im Client.
- Schema nur über neue Schritte in `migrate()` ändern, nie bestehende Schritte umschreiben.
- Offen (Abweichung von ~/Projects/CLAUDE.md): vier Test-Binaries statt einer, kein `[profile.dev]` in `Cargo.toml`. Neue Tests trotzdem in die passende vorhandene Datei, keine fünfte Binary anlegen.
- `target/` und `wt/` nicht durchsuchen.

## Plan/Stand
- Kein Plan-Dokument: Einstieg `CHANGELOG.md` (neuester Abschnitt oben), dann `docs/` (`deployment.md`, `sso.md`, `teams.md`) und `README.md` abschnittsweise.

## Release
- Versionsbump in `Cargo.toml`, `## <version>` in `CHANGELOG.md` (CI erzwingt beides und kopiert den Abschnitt ins GitHub-Release), Tag `vX` auf dem Merge-Commit; der Tag-Lauf baut Image und linux amd64/arm64-Binaries samt `install.sh`/`update.sh`.

## Security
- Sicherheitskritisch: `src/auth.rs`, `pairing.rs`, `oidc.rs`, `sso.rs`, `uwuauth.rs`, `limits.rs`, `tls.rs`, `src/api/`, `install.sh`/`update.sh` (laufen als root).
- Vor jedem Feature-Release den globalen Subagent `security-reviewer` über den Bereich seit dem letzten Tag laufen lassen; Ergebnis nach `docs/security-review-<version>.md` (bisher `docs/security-review-2026-09.md`; Format: Ort, Ursache, Fix, keine Payloads).
