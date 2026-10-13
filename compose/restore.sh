#!/usr/bin/env bash
set -euo pipefail

compose_dir="$(cd "$(dirname "$0")" && pwd)"
compose=(docker compose --project-directory "$compose_dir" -f "$compose_dir/docker-compose.yml")
service="cautem-gateway"
backup_arg="${1:-}"

if [[ -z "$backup_arg" || ! -f "$backup_arg" ]]; then
	echo "usage: $0 BACKUP.tar.gz" >&2
	exit 2
fi
backup_file="$(cd "$(dirname "$backup_arg")" && pwd)/$(basename "$backup_arg")"

container_id="$("${compose[@]}" ps --all -q "$service")"
if [[ -z "$container_id" ]]; then
	echo "gateway container does not exist; start the Compose stack before restore" >&2
	exit 1
fi
was_running="$(docker inspect --format '{{.State.Running}}' "$container_id")"
configured_db_url="$("${compose[@]}" config --format json | python3 -c 'import json,sys; print(json.load(sys.stdin)["services"]["cautem-gateway"].get("environment", {}).get("OPENSHELL_DB_URL", ""))')"
running_db_url="$(docker inspect --format '{{range .Config.Env}}{{println .}}{{end}}' "$container_id" | python3 -c 'import sys; print(next((line.rstrip("\n").split("=", 1)[1] for line in sys.stdin if line.startswith("OPENSHELL_DB_URL=")), ""))')"
if [[ "$configured_db_url" != "$running_db_url" ]]; then
	echo "Compose OPENSHELL_DB_URL does not match the Gateway container; use the active database configuration before restore" >&2
	exit 1
fi

CONFIGURED_DB_URL="$configured_db_url" BACKUP_FILE="$backup_file" python3 - <<'PY'
import os
import pathlib
import tarfile
import sys

archive_path = pathlib.Path(os.environ["BACKUP_FILE"])
try:
    with tarfile.open(archive_path, "r:gz") as archive:
        files = {}
        allowed = {"manifest", "data-volume.tar.gz", "postgres.dump"}
        for member in archive.getmembers():
            name = member.name
            parts = [part for part in pathlib.PurePosixPath(name).parts if part not in ("", ".")]
            if name.startswith("/") or ".." in parts:
                raise ValueError(f"unsafe path in archive: {name!r}")
            if member.issym() or member.islnk() or member.isdev() or member.isfifo():
                raise ValueError(f"unsupported link or special file in archive: {name!r}")
            if not (member.isfile() or member.isdir()):
                raise ValueError(f"unsupported archive entry: {name!r}")
            if member.isfile():
                if len(parts) != 1 or parts[0] not in allowed:
                    raise ValueError(f"unexpected backup file: {name!r}")
                if parts[0] in files:
                    raise ValueError(f"duplicate backup file: {parts[0]!r}")
                files[parts[0]] = member
        if "manifest" not in files or "data-volume.tar.gz" not in files:
            raise ValueError("archive is missing manifest or data-volume.tar.gz")
        manifest_file = archive.extractfile(files["manifest"])
        if manifest_file is None:
            raise ValueError("archive manifest cannot be read")
        manifest = {}
        for line in manifest_file.read().decode("utf-8").splitlines():
            if "=" not in line:
                raise ValueError("archive manifest is invalid")
            key, value = line.split("=", 1)
            if key in manifest:
                raise ValueError("archive manifest has duplicate fields")
            manifest[key] = value
        if manifest.get("format_version") != "1" or manifest.get("database") not in ("none", "postgres"):
            raise ValueError("unsupported backup manifest")
        if ("postgres.dump" in files) != (manifest["database"] == "postgres"):
            raise ValueError("backup manifest and PostgreSQL dump do not match")
        if (manifest["database"] == "postgres") != bool(os.environ.get("CONFIGURED_DB_URL")):
            raise ValueError("backup database mode does not match the active Gateway configuration")
        volume_archive = archive.extractfile(files["data-volume.tar.gz"])
        if volume_archive is None:
            raise ValueError("data volume archive cannot be read")
        with tarfile.open(fileobj=volume_archive, mode="r:gz") as volume:
            has_state = False
            for member in volume.getmembers():
                name = member.name
                parts = [part for part in pathlib.PurePosixPath(name).parts if part not in ("", ".")]
                if name.startswith("/") or ".." in parts:
                    raise ValueError(f"unsafe path in data volume archive: {name!r}")
                if member.issym() or member.islnk() or member.isdev() or member.isfifo():
                    raise ValueError(f"unsupported link or special file in data volume archive: {name!r}")
                if not (member.isfile() or member.isdir()):
                    raise ValueError(f"unsupported data volume entry: {name!r}")
                if parts == ["state.json"] and member.isfile():
                    has_state = True
            if manifest["database"] == "none" and not has_state:
                raise ValueError("file-backed backup does not contain state.json")
except (OSError, tarfile.TarError, UnicodeError, ValueError) as error:
    print(f"invalid gateway backup: {error}", file=sys.stderr)
    sys.exit(1)
PY

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
pre_restore_backup="${backup_file}.before-restore-${timestamp}"
"$(dirname "$0")/backup.sh" "$pre_restore_backup"

restore_dir="$(mktemp -d "${backup_file}.restore.XXXXXX")"
chmod 700 "$restore_dir"
restore_succeeded=0
mutation_started=0
restart_gateway() {
	if [[ "$was_running" == "true" ]]; then
		if [[ "$restore_succeeded" == "1" || "$mutation_started" == "0" ]]; then
			"${compose[@]}" start "$service" >/dev/null
		else
			echo "restore failed after mutation; Gateway remains stopped. Recovery snapshot: $pre_restore_backup" >&2
		fi
	fi
}
cleanup_restore() {
	status=$?
	trap - EXIT
	if [[ -n "${restore_dir:-}" ]]; then
		rm -rf "$restore_dir"
	fi
	restart_gateway
	exit "$status"
}
trap cleanup_restore EXIT
BACKUP_FILE="$backup_file" RESTORE_DIR="$restore_dir" python3 - <<'PY'
import os
import pathlib
import tarfile

with tarfile.open(os.environ["BACKUP_FILE"], "r:gz") as archive:
    for name in ("manifest", "data-volume.tar.gz", "postgres.dump"):
        member = next((item for item in archive.getmembers() if pathlib.PurePosixPath(item.name).name == name), None)
        if member is None:
            continue
        source = archive.extractfile(member)
        if source is not None:
            with pathlib.Path(os.environ["RESTORE_DIR"], name).open("wb") as target:
                target.write(source.read())
PY

if [[ "$was_running" == "true" ]]; then
	"${compose[@]}" stop "$service" >/dev/null
fi
mutation_started=1
"${compose[@]}" run --rm --no-deps -T --volume "$restore_dir:/restore:ro" --entrypoint sh "$service" -ec '
data=/var/lib/cautem-gateway
stage="$(mktemp -d /var/lib/cautem-gateway.restore.XXXXXX)"
trap '\''rm -rf -- "$stage"'\'' EXIT
umask 077
tar --no-same-owner -xzf /restore/data-volume.tar.gz -C "$stage"
find "$stage" -type d -exec chmod 700 {} +
find "$stage" -type f -exec chmod 600 {} +
find "$data" -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +
cp -a "$stage"/. "$data"/
chmod 700 "$data"
rm -rf -- "$stage"
'
if [[ -n "$configured_db_url" ]]; then
	"${compose[@]}" run --rm --no-deps -T --volume "$restore_dir:/backup:ro" postgres-tools restore /backup/postgres.dump
fi
restore_succeeded=1
restart_gateway
trap - EXIT
rm -rf "$restore_dir"
echo "gateway state restored from $backup_file"
echo "pre-restore snapshot saved to $pre_restore_backup"
