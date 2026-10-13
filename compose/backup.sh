#!/usr/bin/env bash
set -euo pipefail

compose_dir="$(cd "$(dirname "$0")" && pwd)"
compose=(docker compose --project-directory "$compose_dir" -f "$compose_dir/docker-compose.yml")
service="cautem-gateway"
backup_arg="${1:-}"

if [[ -z "$backup_arg" ]]; then
	echo "usage: $0 BACKUP.tar.gz" >&2
	exit 2
fi

mkdir -p "$(dirname "$backup_arg")"
backup_file="$(cd "$(dirname "$backup_arg")" && pwd)/$(basename "$backup_arg")"
if [[ -e "$backup_file" || -L "$backup_file" ]]; then
	echo "refusing to overwrite existing backup: $backup_file" >&2
	exit 1
fi
container_id="$("${compose[@]}" ps --all -q "$service")"
if [[ -z "$container_id" ]]; then
	echo "gateway container does not exist; start the Compose stack before backup" >&2
	exit 1
fi

was_running="$(docker inspect --format '{{.State.Running}}' "$container_id")"
configured_db_url="$("${compose[@]}" config --format json | python3 -c 'import json,sys; print(json.load(sys.stdin)["services"]["cautem-gateway"].get("environment", {}).get("OPENSHELL_DB_URL", ""))')"
running_db_url="$(docker inspect --format '{{range .Config.Env}}{{println .}}{{end}}' "$container_id" | python3 -c 'import sys; print(next((line.rstrip("\n").split("=", 1)[1] for line in sys.stdin if line.startswith("OPENSHELL_DB_URL=")), ""))')"
if [[ "$configured_db_url" != "$running_db_url" ]]; then
	echo "Compose OPENSHELL_DB_URL does not match the Gateway container; use the active database configuration before backup" >&2
	exit 1
fi
database_mode="none"
if [[ -n "$configured_db_url" ]]; then
	database_mode="postgres"
fi
temporary_dir="$(mktemp -d "${backup_file}.tmpdir.XXXXXX")"
temporary_file="$(mktemp "${backup_file}.tmp.XXXXXX")"
chmod 700 "$temporary_dir"
restart_needed=0
restart_gateway() {
	if [[ "$was_running" == "true" && "$restart_needed" == "1" ]]; then
		"${compose[@]}" start "$service" >/dev/null
		restart_needed=0
	fi
}
cleanup() {
	status=$?
	trap - EXIT
	rm -f "$temporary_file"
	rm -rf "$temporary_dir"
	restart_gateway
	exit "$status"
}
trap cleanup EXIT

if [[ "$was_running" == "true" ]]; then
	"${compose[@]}" stop "$service" >/dev/null
	restart_needed=1
fi
"${compose[@]}" run --rm --no-deps -T --entrypoint tar "$service" \
	czf - -C /var/lib/cautem-gateway . >"$temporary_dir/data-volume.tar.gz"
test -s "$temporary_dir/data-volume.tar.gz"
if [[ "$database_mode" == "postgres" ]]; then
	"${compose[@]}" run --rm --no-deps -T --volume "$temporary_dir:/backup" postgres-tools dump /backup/postgres.dump
	test -s "$temporary_dir/postgres.dump"
fi
printf 'format_version=1\ndatabase=%s\n' "$database_mode" >"$temporary_dir/manifest"
BACKUP_DIR="$temporary_dir" BACKUP_FILE="$temporary_file" python3 - <<'PY'
import os
import pathlib
import tarfile

directory = pathlib.Path(os.environ["BACKUP_DIR"])
with tarfile.open(os.environ["BACKUP_FILE"], "w:gz") as archive:
    for name in ("manifest", "data-volume.tar.gz", "postgres.dump"):
        source = directory / name
        if source.is_file():
            archive.add(source, arcname=name, recursive=False)
PY
test -s "$temporary_file"
chmod 600 "$temporary_file"
if ! ln "$temporary_file" "$backup_file"; then
	echo "could not publish backup without overwriting: $backup_file" >&2
	exit 1
fi
rm -f "$temporary_file"
restart_gateway
trap - EXIT
rm -rf "$temporary_dir"
echo "gateway state backed up to $backup_file (database: $database_mode)"
