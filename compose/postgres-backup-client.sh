#!/bin/sh
set -eu

if [ -z "${OPENSHELL_DB_URL:-}" ]; then
	echo "OPENSHELL_DB_URL is required for PostgreSQL backup operations" >&2
	exit 2
fi

action="${1:-}"
archive="${2:-}"
case "$action" in
	dump)
		[ -n "$archive" ] || { echo "dump archive path is required" >&2; exit 2; }
		pg_dump --format=custom --no-owner --no-acl --dbname="$OPENSHELL_DB_URL" --file="$archive"
		chmod 644 "$archive"
		;;
	restore)
		[ -n "$archive" ] || { echo "restore archive path is required" >&2; exit 2; }
		pg_restore --clean --if-exists --no-owner --no-acl --exit-on-error --dbname="$OPENSHELL_DB_URL" "$archive"
		;;
	*)
		echo "usage: postgres-backup-client.sh dump|restore ARCHIVE" >&2
		exit 2
		;;
esac
