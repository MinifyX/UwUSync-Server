#!/usr/bin/env bash
# Brings UwUSync Server to the newest version, where it runs.
#
#   cd /opt/uwusync && sudo bash update.sh
#
# It updates itself first, then looks at compose.yaml, makes a backup, fetches the new image and
# watches the server come back. If it does not come back, the old version does.
#
#   --dir DIR          where UwUSync Server lives (default: where this script is, then /opt/uwusync,
#                      then /opt/uwussh)
#   --version TAG      switch to another tag: latest, beta, edge, or an exact version like 0.1.0
#   --no-backup        do not back up first
#   --force            take the new compose.yaml even when this one was changed by hand
#   --keep-compose     leave compose.yaml alone, now and from now on
#   --no-self-update   do not fetch a newer update.sh first
#   --from-checkout    take compose.yaml from the repository this script is in (for trying a build)
#   --no-pull          start the image already on this machine (for trying a build)
#   --yes              ask nothing; every answer takes its default
#   --help
#
# A server set up while it was called UwUSSH Server moves over by itself: same directory, same
# data volume, the settings in .env under their new names, and the old container only goes once
# the new image is here. What it never touches: your data, and a compose.yaml you edited yourself
# unless you say --force. Of the .env it only ever changes what it says it changes.
# The whole story: docs/deployment.md.
set -uo pipefail

repo=MinifyX/UwUSync-Server
releases="https://github.com/$repo/releases"
image=ghcr.io/minifyx/uwusync-server
service=uwusync
sync_service=$service
# The same server under the name it had before: UwUSSH Server.
legacy_image=ghcr.io/minifyx/uwussh-server
legacy_service=uwussh
# Where this script is — when it is a file at all. Piped into bash, $0 is "bash", and "here"
# would be wherever the shell happened to be.
here=""
[ -f "$0" ] && here="$(cd "$(dirname "$0")" && pwd -P)"

# What we were called with, for the copy that takes over after a self-update.
called_with=("$@")

dir=""
version=""
backup=true
force=false
keep_compose=false
self_update=true
from_checkout=false
pull=true
ask=true

die() {
  printf '\n  (>_<) %s\n' "$1" >&2
  exit 1
}
step() { printf '  %s\n' "$1"; }
warn() { printf '  (>_<) %s\n' "$1" >&2; }

while [ $# -gt 0 ]; do
  case "$1" in
    --dir) dir="${2:?--dir needs a directory}"; shift 2 ;;
    --version) version="${2:?--version needs a tag}"; shift 2 ;;
    --no-backup) backup=false; shift ;;
    --force) force=true; shift ;;
    --keep-compose) keep_compose=true; shift ;;
    --no-self-update) self_update=false; shift ;;
    --from-checkout) from_checkout=true; shift ;;
    --no-pull) pull=false; shift ;;
    --yes | -y) ask=false; shift ;;
    -h | --help)
      sed -n '2,26p' "$0" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *) die "unknown option: $1" ;;
  esac
done

[ "$(id -u)" -eq 0 ] || die "please run this as root: sudo bash update.sh"
command -v docker >/dev/null 2>&1 || die "Docker is missing"
docker compose version >/dev/null 2>&1 || die "Docker Compose v2 is missing"

# ── small helpers ─────────────────────────────────────────────────────────────────────────────
# Whether there is a terminal to ask on: after an exec there may be none, whatever /dev/tty
# looks like in the file system.
have_tty() { { : </dev/tty; } 2>/dev/null; }

yesno() {
  local prompt="$1" fallback="$2" answer=""
  if ! $ask || ! have_tty; then
    [ "$fallback" = y ] && return 0 || return 1
  fi
  read -r -p "  $prompt [$([ "$fallback" = y ] && echo 'Y/n' || echo 'y/N')]: " answer </dev/tty
  answer="${answer:-$fallback}"
  case "$answer" in [yYjJ]*) return 0 ;; *) return 1 ;; esac
}

fetch() {
  local url="$1" target="$2"
  if command -v curl >/dev/null 2>&1; then
    curl -fsL --proto '=https' --tlsv1.2 -o "$target" "$url"
  elif command -v wget >/dev/null 2>&1; then
    wget -q --https-only -O "$target" "$url"
  else
    return 1
  fi
}

# The newest release of any kind, beta included: GitHub's "latest" only knows stable ones.
newest_tag() {
  local list tag
  list=$(mktemp) || return 1
  if fetch "https://api.github.com/repos/$repo/releases?per_page=10" "$list"; then
    tag=$(grep -oE '"tag_name": *"v[0-9][A-Za-z0-9.-]*"' "$list" | head -1 |
      sed -E 's/.*"(v[^"]+)"$/\1/')
  fi
  rm -f "$list"
  printf '%s' "${tag:-}"
}

# Where the files for a tag are: that version's own release, the newest one of any kind for beta,
# and the newest stable one for everything else.
release_base() {
  local tag
  case "$1" in
    [0-9]*) printf '%s/download/v%s' "$releases" "$1" ;;
    beta)
      tag=$(newest_tag)
      if [ -n "$tag" ]; then printf '%s/download/%s' "$releases" "$tag"; else
        printf '%s/latest/download' "$releases"
      fi
      ;;
    *) printf '%s/latest/download' "$releases" ;;
  esac
}

# A release file and the checksum next to it; nothing is used unless the two agree. That keeps a
# broken download out. It does not keep out a release somebody replaced: the checksum comes from
# the same place, and trusting it is trusting the release, as with the image itself.
fetch_checked() {
  local name="$1" target="$2" base="$3" sums want have
  fetch "$base/$name" "$target" || return 1
  sums=$(mktemp) || return 1
  if ! fetch "$base/$name.sha256" "$sums"; then
    rm -f "$sums"
    return 1
  fi
  want=$(cut -d' ' -f1 <"$sums")
  have=$(sha256sum "$target" | cut -d' ' -f1)
  rm -f "$sums"
  [ -n "$want" ] && [ "$want" = "$have" ]
}

hash_of() { sha256sum "$1" | cut -d' ' -f1; }
looks_like_version() { case "${1:-}" in [0-9]*) return 0 ;; *) return 1 ;; esac; }

# A value on its way into the .env has to be one line of plain characters, wherever it came from:
# a flag, or a compose.yaml somebody wrote by hand.
plain_value() { case "${1:-}" in "" | *[!a-zA-Z0-9.:_/+\[\]-]*) return 1 ;; *) return 0 ;; esac; }

# ── where UwUSync Server lives ─────────────────────────────────────────────────────────────────
# Next to this script, or /opt/uwusync, or /opt/uwussh from before the new name, or what --dir
# says — never wherever the shell happens to be. "sudo bash /opt/uwusync/update.sh" from somewhere
# else means that one. And only a directory whose compose.yaml runs this server under either of
# its names — never another project's.
ours() { [ -f "$1/compose.yaml" ] && [ -f "$1/.env" ] && grep -qE "uwu(sync|ssh)-server" "$1/compose.yaml"; }
if [ -z "$dir" ]; then
  for candidate in "$here" /opt/uwusync /opt/uwussh; do
    if [ -n "$candidate" ] && ours "$candidate"; then
      dir="$candidate"
      break
    fi
  done
  [ -n "$dir" ] || die "no UwUSync Server here. Pass --dir with the directory it runs from."
fi
dir="$(cd "$dir" 2>/dev/null && pwd -P)" || die "there is no directory $dir"
ours "$dir" || die "$dir holds no compose.yaml for UwUSync Server with an .env next to it"

# What is in that directory runs as root: Compose starts whatever compose.yaml and .env say, and
# .uwusync-update decides whether compose.yaml is replaced. So all of it has to belong to root, or
# to the admin who ran sudo, and nobody else may write to it — nor to a directory above it, where
# somebody could swap it out. A directory anybody may write to is fine above it only with the
# sticky bit, which keeps them from renaming what is not theirs (/tmp, say).
admin_uid="${SUDO_UID:-0}"
owned_right() {
  local owner mode
  owner=$(stat -c %u "$1" 2>/dev/null) && mode=$(stat -c %a "$1" 2>/dev/null) || return 1
  { [ "$owner" = 0 ] || [ "$owner" = "$admin_uid" ]; } || return 1
  if [ $((8#$mode & 8#022)) -ne 0 ]; then
    [ "${2:-}" = above ] || return 1
    [ $((8#$mode & 8#1000)) -ne 0 ] || return 1
  fi
}
untrusted() {
  die "$1 may be changed by someone other than root$([ "$admin_uid" != 0 ] && printf ' and you'), and what is in $dir runs as root. $2"
}
owned_right "$dir" || untrusted "$dir" "Make it root's and writable only by root: sudo chown root: $dir && sudo chmod go-w $dir"
# Compose lays an override file next to compose.yaml over it by itself, so it runs as root too.
override_names="compose.override.yaml compose.override.yml docker-compose.override.yaml docker-compose.override.yml"
overrides=()
for name in $override_names; do
  [ -e "$dir/$name" ] && overrides+=("$name")
done
for name in compose.yaml .env .uwusync-update .uwussh-update $override_names; do
  [ -e "$dir/$name" ] || [ -L "$dir/$name" ] || continue
  [ -L "$dir/$name" ] && untrusted "$dir/$name" "It is a link; put the file itself there."
  owned_right "$dir/$name" || untrusted "$dir/$name" "sudo chown root: $dir/$name && sudo chmod go-w $dir/$name"
done
above="$dir"
while [ "$above" != / ]; do
  above=$(dirname "$above")
  owned_right "$above" above || untrusted "$above" "Update from a directory that only root may change, like /opt/uwusync."
done

# Compose reads settings of its own from .env: COMPOSE_FILE would run another file than this
# compose.yaml, COMPOSE_PROJECT_NAME another project. None of that belongs in this .env.
if grep -qE '^[[:space:]]*(export[[:space:]]+)?(COMPOSE_|DOCKER_)' "$dir/.env"; then
  die "$dir/.env sets COMPOSE_ or DOCKER_ variables, which steer Compose itself rather than UwUSync Server. Take them out, then run this again."
fi

if $from_checkout; then
  [ -n "$here" ] && [ -f "$here/compose.yaml" ] || die "--from-checkout, but there is no compose.yaml next to this script"
  [ -z "$(find "$here" -maxdepth 0 -perm -0002 2>/dev/null)" ] ||
    die "--from-checkout, but anybody may write to $here; nothing from there is used as root"
fi

cd "$dir" || die "cannot go into $dir"
state="$dir/.uwusync-update"
# What install.sh and update.sh wrote down while the server was UwUSSH Server counts as well.
if [ ! -f "$state" ] && [ -f "$dir/.uwussh-update" ]; then
  cp -p "$dir/.uwussh-update" "$state"
fi

# Which of its two names the compose.yaml here runs the server under, and so what its service and
# container are called.
service_of() { if grep -q "$legacy_image" "$1"; then printf '%s' "$legacy_service"; else printf '%s' "$sync_service"; fi; }
old_service=$(service_of "$dir/compose.yaml")
new_service=$sync_service
service=$old_service

# Reads one value out of the .env, without sourcing a file we did not write.
env_value() {
  local line
  line=$(grep -m1 "^$1=" "$dir/.env" 2>/dev/null) || return 1
  printf '%s' "${line#*=}"
}

# Writes one line of the .env, whether it is in there already, commented out, or missing. The
# copy is made with the rights of the file it replaces, not whatever the umask happens to be.
set_env() {
  local key="$1" value="$2" file="$dir/.env" line found=false tmp="$dir/.env.tmp"
  plain_value "$value" || die "$key would become something odd, so nothing was written: $value"
  install -m 0600 /dev/null "$tmp"
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in
      "$key="* | "#$key="*)
        if $found; then continue; fi
        printf '%s=%s\n' "$key" "$value" >>"$tmp"
        found=true
        ;;
      *) printf '%s\n' "$line" >>"$tmp" ;;
    esac
  done <"$file"
  $found || printf '%s=%s\n' "$key" "$value" >>"$tmp"
  cat "$tmp" >"$file"
  rm -f "$tmp"
}

# Waits for the server's own health check: up to two minutes, less when it keeps falling over.
wait_healthy() {
  printf '  waiting for the server'
  for _ in $(seq 1 60); do
    printf '.'
    sleep 2
    case "$(docker inspect --format '{{.State.Health.Status}}' "$service" 2>/dev/null)" in
      healthy)
        printf '\n'
        return 0
        ;;
      unhealthy) break ;;
    esac
    [ "$(docker inspect --format '{{.RestartCount}}' "$service" 2>/dev/null)" = 0 ] || break
  done
  printf '\n'
  return 1
}

if [ -n "$version" ]; then
  plain_value "$version" || die "a version is letters, digits, dots, dashes and underscores"
fi
# What this machine follows after this run, and so where its files come from.
target="${version:-$(env_value UWUSYNC_VERSION || env_value UWUSSH_VERSION || printf latest)}"
plain_value "$target" || target=latest

printf '\n  UwUSync Server, update\n  ~~~~~~~~~~~~~~~~~~~~~\n\n'

# ── a newer updater first ─────────────────────────────────────────────────────────────────────
# From the newest release of the channel — for a pinned version too, since a newer update.sh
# knows how to handle an older server. Reading the script and replacing the file are two
# different things: bash holds the old file open, so swapping it out under us is safe, and the
# new one takes over with exec right after. The directory goes last, so a relative --dir the
# first run resolved is not resolved again from here.
if $self_update; then
  fresh=$(mktemp)
  scripts_from=$(release_base "$([ "$target" = beta ] && echo beta || echo latest)")
  if fetch_checked update.sh "$fresh" "$scripts_from" &&
    [ "$(hash_of "$fresh")" != "$(hash_of "$0")" ]; then
    step "there is a newer update.sh; taking that one"
    install -m 0755 "$fresh" "$dir/update.sh"
    rm -f "$fresh"
    exec bash "$dir/update.sh" "${called_with[@]}" --no-self-update --dir "$dir"
  fi
  rm -f "$fresh"
fi

# What the .env and compose.yaml were before this run, so a way back puts them back too. Made
# only now, after the self-update: an exec takes no trap along to clean up after it.
saved=$(mktemp -d) || die "no room for a temporary directory"
trap 'rm -f "$dir/.env.tmp"; rm -rf "$saved"' EXIT INT TERM
cp -p "$dir/.env" "$saved/env"
cp -p "$dir/compose.yaml" "$saved/compose.yaml"
for name in "${overrides[@]}"; do cp -p "$dir/$name" "$saved/$name"; done
put_back() {
  local name
  cp -p "$saved/env" "$dir/.env"
  cp -p "$saved/compose.yaml" "$dir/compose.yaml"
  for name in "${overrides[@]}"; do cp -p "$saved/$name" "$dir/$name"; done
}

# ── what is running now ───────────────────────────────────────────────────────────────────────
running_version=$(docker inspect "$service" \
  --format '{{index .Config.Labels "org.opencontainers.image.version"}}' 2>/dev/null)
running_image=$(docker inspect "$service" --format '{{.Image}}' 2>/dev/null)
[ -n "$running_version" ] && step "running now: $running_version"

# ── the compose file ──────────────────────────────────────────────────────────────────────────
# The settings the stock file takes from .env. Written by hand into compose.yaml instead, they
# move into .env; anything else somebody changed stops the update. A compose.yaml from before the
# new name has them as UWUSSH_…, and they move in under their new names.
lifted="UWUSYNC_PUBLIC UWUSYNC_REGISTRATION UWUSYNC_TLS UWUSYNC_TRUST_FORWARDED UWUSYNC_UPDATE_CHECK"
lifted="$lifted UWUSYNC_TRUSTED_PROXIES"
lifted="$lifted UWUSYNC_MAX_ACCOUNTS UWUSYNC_ACCOUNT_MAX_RECORDS UWUSYNC_ACCOUNT_MAX_MB"
lifted="$lifted UWUSYNC_SERVER_MAX_MB UWUSYNC_MAX_CONNECTIONS UWUSYNC_MAX_CONNECTIONS_PER_IP"

# shellcheck disable=SC2016  # the ${...} here are strings to compare against, not expansions
lift_into_env() {
  local file="$1" value key
  value=$(grep -oE "image: ($image|$legacy_image):[^ ]+" "$file" | head -1 | cut -d: -f3)
  case "$value" in
    "" | '${UWUSYNC_VERSION'* | '${UWUSSH_VERSION'*) ;;
    *)
      step "moving the image tag $value into .env"
      set_env UWUSYNC_VERSION "$value"
      ;;
  esac
  value=$(grep -oE '^ *- "[^"]+:8443"' "$file" | head -1 | sed -E 's/.*"(.*):8443"/\1/')
  case "$value" in
    "" | '${UWUSYNC_BIND'* | '${UWUSSH_BIND'*) ;;
    *)
      step "moving the port, which is $value here, into .env"
      set_env UWUSYNC_BIND "$value"
      ;;
  esac
  for key in $lifted; do
    value=$(grep -E "^ +(UWUSYNC|UWUSSH)_${key#UWUSYNC_}: " "$file" | head -1 |
      sed -E "s/^ +[A-Z_]+: *//; s/[[:space:]]+#.*//; s/^[\"']//; s/[\"']\$//")
    case "$value" in
      "" | '${'*) ;;
      *)
        step "moving $key into .env"
        set_env "$key" "$value"
        ;;
    esac
  done
}

# The same file with every value we understand blanked out. What is left over after that is a
# change nobody can translate, and then we stop. The last line takes the width of the comment
# column out of it as well: a port written by hand shifts the comment behind it, and that is not
# a change worth stopping for.
normalized() {
  local expressions=(
    -e "s#(image: $image:).*#\1@#"
    -e 's#^( *- ")[^"]+(:8443".*)#\1@\2#'
    -e 's|[[:space:]]+#| #|'
  )
  local key
  for key in $lifted; do
    expressions+=(-e "s#^( +$key: ).*#\1@#")
  done
  sed -E "${expressions[@]}" "$1" | sha256sum | cut -d' ' -f1
}

# True when this compose.yaml is one we put here: either we wrote down its checksum, or it is
# exactly the file that came with the version running now.
compose_is_ours() {
  local mine theirs
  mine=$(hash_of "$dir/compose.yaml")
  [ -f "$state" ] && grep -qxF "compose $mine" "$state" && return 0
  looks_like_version "$running_version" || return 1
  theirs=$(mktemp)
  if fetch_checked compose.yaml "$theirs" "$releases/download/v$running_version" &&
    [ "$(hash_of "$theirs")" = "$mine" ]; then
    rm -f "$theirs"
    return 0
  fi
  rm -f "$theirs"
  return 1
}

if ! $keep_compose && [ -f "$state" ] && grep -qx "compose keep" "$state"; then
  keep_compose=true
  step "compose.yaml is yours; leaving it alone"
fi

# The compose.yaml this version ships: from its release, or from this checkout when asked.
stock_compose() {
  if $from_checkout; then
    install -m 0644 "$here/compose.yaml" "$1"
  else
    fetch_checked compose.yaml "$1" "$(release_base "$target")"
  fi
}

stock=$(mktemp)
compose_known=false
if $keep_compose; then
  :
elif stock_compose "$stock"; then
  if [ "$(hash_of "$stock")" = "$(hash_of "$dir/compose.yaml")" ]; then
    step "compose.yaml is the current one"
    compose_known=true
  elif compose_is_ours; then
    install -m 0644 "$stock" "$dir/compose.yaml"
    step "compose.yaml brought up to date"
    compose_known=true
  elif [ "$(normalized "$dir/compose.yaml")" = "$(normalized "$stock")" ]; then
    lift_into_env "$dir/compose.yaml"
    install -m 0644 "$stock" "$dir/compose.yaml"
    step "compose.yaml brought up to date, your changes live in .env now"
    compose_known=true
  elif $force; then
    cp -p "$dir/compose.yaml" "$dir/compose.yaml.bak"
    lift_into_env "$dir/compose.yaml.bak"
    install -m 0644 "$stock" "$dir/compose.yaml"
    warn "compose.yaml replaced as asked; the old one is next to it as compose.yaml.bak"
    compose_known=true
  else
    printf '\n'
    warn "your compose.yaml is not the one this version ships, and not everything in it fits"
    warn "into .env. Nothing was changed. This is what differs:"
    printf '\n'
    diff -u "$dir/compose.yaml" "$stock" | sed -n '3,40p'
    cat <<-CHOICE

	  Your file on purpose, say so once and it stops asking:  sudo bash update.sh --keep-compose
	  Take the new one, yours stays as compose.yaml.bak:      sudo bash update.sh --force

	CHOICE
    rm -f "$stock"
    exit 1
  fi
else
  warn "could not fetch the current compose.yaml; going on with the one that is here"
fi
rm -f "$stock"
compose_hash=$(hash_of "$dir/compose.yaml")

# ── from UwUSSH Server to UwUSync Server ──────────────────────────────────────────────────────
# The compose.yaml here now runs the server under its new name, and the one before ran it under
# the old one: the settings in .env take their new names, and the data volume stays the one it
# was — its name goes into .env, so the new compose.yaml finds it. The old container keeps running
# until the new image is here; the files from before are in $saved for the way back.
new_service=$(service_of "$dir/compose.yaml")
migrating=false
if [ "$old_service" = "$legacy_service" ] && [ "$new_service" != "$legacy_service" ]; then
  migrating=true
  step "UwUSSH Server is called UwUSync Server now; moving this one over"
  # Every UWUSSH_ line takes the new name, unless that one is in there already (a setting moved
  # out of compose.yaml a moment ago, say); then the old line stays, and counts for nothing.
  install -m 0600 /dev/null "$dir/.env.tmp"
  awk '
    function key(line) { sub(/^#/, "", line); sub(/=.*/, "", line); return line }
    NR == FNR { if ($0 ~ /^#?UWUSYNC_[A-Z0-9_]*=/) have[key($0)] = 1; next }
    $0 ~ /^#?UWUSSH_[A-Z0-9_]*=/ {
      renamed = key($0)
      sub(/^UWUSSH_/, "UWUSYNC_", renamed)
      if (!(renamed in have)) sub(/UWUSSH_/, "UWUSYNC_")
    }
    { print }
  ' "$dir/.env" "$dir/.env" >"$dir/.env.tmp"
  cat "$dir/.env.tmp" >"$dir/.env"
  rm -f "$dir/.env.tmp"
  step "  the settings in .env are called UWUSYNC_… now"
  volume=$(docker inspect "$legacy_service" \
    --format '{{range .Mounts}}{{if eq .Destination "/data"}}{{.Name}}{{end}}{{end}}' 2>/dev/null)
  if [ -z "$volume" ] && docker volume inspect uwussh_uwussh-data >/dev/null 2>&1; then
    volume=uwussh_uwussh-data
  fi
  if [ -n "$volume" ]; then
    set_env UWUSYNC_VOLUME "$volume"
    step "  the data stays where it is, in the volume $volume"
  else
    warn "no data volume from UwUSSH Server found; the server starts with an empty one"
  fi
  # An override file still speaks of the service by its old name, and Compose would take that for
  # a second service without an image. The service, its container, its volume and its settings
  # take the new names there as well; everything else in it stays as it is.
  for name in "${overrides[@]}"; do
    install -m 0600 /dev/null "$dir/.env.tmp"
    awk '
      /^[^[:space:]#]/ { in_services = ($0 ~ /^services:[[:space:]]*(#.*)?$/); indent = "" }
      in_services && match($0, /^[[:space:]]+[^[:space:]#-]/) {
        if (indent == "") indent = substr($0, 1, RLENGTH - 1)
        if (substr($0, 1, RLENGTH - 1) == indent && $0 ~ "^" indent "[\"'\'']?uwussh[\"'\'']?[[:space:]]*:")
          sub(/uwussh/, "uwusync")
      }
      /^[[:space:]]+container_name:[[:space:]]*["'\'']?uwussh["'\'']?[[:space:]]*(#.*)?$/ { sub(/uwussh/, "uwusync") }
      /^[[:space:]]+-[[:space:]]*["'\'']?uwussh-data:/ { sub(/uwussh-data/, "uwusync-data") }
      { gsub(/UWUSSH_/, "UWUSYNC_"); print }
    ' "$dir/$name" >"$dir/.env.tmp"
    if ! cmp -s "$dir/.env.tmp" "$dir/$name"; then
      cat "$dir/.env.tmp" >"$dir/$name"
      step "  $name speaks of uwusync now as well"
    fi
    rm -f "$dir/.env.tmp"
  done
elif [ "$old_service" = "$legacy_service" ]; then
  step "compose.yaml still runs UwUSSH Server by its old name, as you keep it; that works"
fi

if [ -n "$version" ]; then
  if [ "$new_service" = "$legacy_service" ] && ! grep -qE '^#?UWUSYNC_VERSION=' "$dir/.env"; then
    set_env UWUSSH_VERSION "$version"
  else
    set_env UWUSYNC_VERSION "$version"
  fi
  step "switching to the $version tag"
fi

# Whether Compose makes sense of all of it — compose.yaml, .env and an override file — before
# anything is backed up, fetched or stopped.
if ! problem=$(docker compose config --quiet 2>&1 </dev/null); then
  put_back
  printf '%s\n' "$problem" >&2
  if [ ${#overrides[@]} -gt 0 ]; then
    warn "Compose does not accept compose.yaml together with ${overrides[*]}."
    warn "Look at ${overrides[*]} in $dir, then run this again."
  fi
  die "nothing was changed"
fi

# ── a backup first ────────────────────────────────────────────────────────────────────────────
# It stays in the volume next to the nightly ones, under backups/. The server writes it itself,
# consistently, while it runs — and it is the way back if the new version changes the database
# and then does not come up.
backup_name=""
# The container that runs now, under whichever name — before a move, that is the old one.
running() { [ "$(docker inspect --format '{{.State.Running}}' "$1" 2>/dev/null)" = true ]; }
# exec does not go through the image entrypoint, so the binary is named here: by its new name, or
# by the one it had in an image from before.
server_exec() {
  local container="$1" binary=uwusync-server
  shift
  docker exec "$container" "$binary" --version >/dev/null 2>&1 || binary=uwussh-server
  docker exec "$container" "$binary" "$@" </dev/null
}
if $backup; then
  if running "$old_service"; then
    step "backing up first"
    if written=$(server_exec "$old_service" backup); then
      backup_name=$(printf '%s' "$written" | grep -oE 'uwu(sync|ssh)-[0-9-]+\.db' | tail -1)
      step "  ${backup_name:-written}"
    else
      warn "no backup was made"
      yesno "Update anyway?" n || {
        put_back
        die "stopped, nothing was changed"
      }
    fi
  else
    warn "UwUSync Server is not running, so nothing was backed up"
  fi
fi

# ── the new version ───────────────────────────────────────────────────────────────────────────
if $pull; then
  step "fetching the image"
  docker compose pull --quiet </dev/null || {
    put_back
    die "the image could not be fetched; nothing was changed"
  }
fi

if $migrating; then
  # Now that the new image is here: the old container makes room, for the port and the volume.
  step "stopping UwUSSH Server"
  docker stop "$legacy_service" >/dev/null 2>&1
  docker rm "$legacy_service" >/dev/null 2>&1
  docker network rm "${legacy_service}_default" >/dev/null 2>&1 || true
fi
service=$new_service

step "starting the new version"
if ! docker compose up -d </dev/null; then
  warn "the new version did not start"
  healthy=false
elif wait_healthy; then
  healthy=true
else
  healthy=false
fi

# ── back to the old one, when the new one does not come up ────────────────────────────────────
if ! $healthy; then
  warn "the new version did not come up healthy; putting the one from before back"
  if $migrating; then
    # Back to UwUSSH Server: the new container goes, and the old compose.yaml brings the old one
    # back on the same volume.
    docker compose down </dev/null >/dev/null 2>&1
    rm -f "$state"
    [ -f "$dir/.uwussh-update" ] && cp -p "$dir/.uwussh-update" "$state"
  fi
  put_back
  service=$old_service
  if [ "$service" = "$legacy_service" ] && ! grep -qE '^#?UWUSYNC_VERSION=' "$dir/.env"; then
    version_key=UWUSSH_VERSION
    back_image=$legacy_image
  else
    version_key=UWUSYNC_VERSION
    back_image=$image
  fi
  if looks_like_version "$running_version"; then
    set_env "$version_key" "$running_version"
  elif [ -n "$running_image" ]; then
    docker tag "$running_image" "$back_image:rollback" >/dev/null 2>&1 && set_env "$version_key" rollback
  fi
  docker compose up -d </dev/null >/dev/null 2>&1
  if wait_healthy; then
    warn "UwUSync Server runs on the version from before, and .env says which one that is."
  elif [ -n "$backup_name" ]; then
    # The old version does not come up either: the new one changed the database, and the old
    # one will not run on a database newer than itself. The backup from a minute ago will do.
    warn "the version from before does not come up on the database the new one left behind;"
    warn "putting the backup from just before the update back ($backup_name)"
    docker compose stop </dev/null >/dev/null 2>&1
    if docker compose run --rm -T "$service" restore "$backup_name" </dev/null >/dev/null &&
      docker compose up -d </dev/null >/dev/null 2>&1 && wait_healthy; then
      warn "UwUSync Server runs on the version from before, with the database from just before"
      warn "the update. What the new version had made of it is kept next to it in the volume."
    else
      warn "that did not bring it back either."
    fi
  else
    warn "the version from before does not come up either."
  fi
  warn "What went wrong: cd $dir && docker compose logs $service"
  exit 1
fi

{
  printf '# Written by install.sh and update.sh: what they put here, so they know what they may replace.\n'
  if $keep_compose; then
    printf 'compose keep\n'
  elif $compose_known; then
    printf 'compose %s\n' "$compose_hash"
  fi
} >"$state"
chmod 0644 "$state"
# Its name from before is not needed any more once the move went through.
$migrating && rm -f "$dir/.uwussh-update"

# The image from before has no name any more; only ours, and only those, go.
docker image prune -f --filter "label=org.opencontainers.image.source=https://github.com/$repo" \
  >/dev/null 2>&1 || true
# After a move the old image still has its old name, so it goes by what it is instead.
if $migrating && [ -n "$running_image" ]; then
  docker image rm "$running_image" >/dev/null 2>&1 || true
fi

new_version=$(docker inspect "$service" \
  --format '{{index .Config.Labels "org.opencontainers.image.version"}}' 2>/dev/null)
printf '\n'
if [ -n "$new_version" ] && [ "$new_version" != "$running_version" ]; then
  printf '  UwUSync Server is on %s now (=^･ω･^=)\n\n' "$new_version"
else
  printf '  UwUSync Server is up to date (=^･ω･^=)\n\n'
fi
if $migrating; then
  cat <<MOVED
  It was UwUSSH Server until now. It stays in $dir, with the same data, the same key and the
  same devices. What changed is the name you type:

    cd $dir && sudo docker compose exec $service uwusync-server invite

MOVED
fi
printf '  What is new: %s/latest\n\n' "$releases"
