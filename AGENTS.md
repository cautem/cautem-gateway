# Agent instructions

## Scope

This repository contains the gateway control plane, APIs, authentication,
registry, and relay. The browser console is under `ui/`.

## Working rules

- Treat authentication, authorization, credentials, lifecycle mutations, and
  relay streams as security-sensitive. Keep read-only and mutating routes clear.
- Update API schemas, generated clients, and API documentation from their
  source definitions; do not hand-edit generated code.
- Keep REST and gRPC compatibility claims accurate in the README and docs.
- Keep local Go workspace replacements in the parent workspace's `go.work`,
  never in this repository's `go.mod`.

## Checks

- Run `go test ./...` from this checkout for Go changes.
- Run the relevant API or browser checks when changing external behavior; UI
  package commands are defined in `ui/package.json`.
- From the parent workspace, `task check` runs the shared Go gate.
