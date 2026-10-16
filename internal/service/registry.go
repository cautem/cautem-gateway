// Package service contains gateway use-cases.
// Ports (interfaces) are declared here at the use site; storage implements them.
package service

import (
	"context"

	"github.com/cautem/quarshell-gateway/internal/domain"
)

// SandboxRepository persists sandbox registry records.
type SandboxRepository interface {
	List(ctx context.Context) ([]domain.Sandbox, error)
	Get(ctx context.Context, name string) (domain.Sandbox, error)
	Upsert(ctx context.Context, sb domain.Sandbox) error
	Delete(ctx context.Context, name string) error
}

// ProposalRepository persists policy proposals.
type ProposalRepository interface {
	List(ctx context.Context) ([]domain.Proposal, error)
	Get(ctx context.Context, id string) (domain.Proposal, error)
}

// Registry is the gateway registry use-case facade.
type Registry struct {
	Sandboxes SandboxRepository
	Proposals ProposalRepository
}

// ListSandboxes returns registered sandboxes.
func (r *Registry) ListSandboxes(ctx context.Context) ([]domain.Sandbox, error) {
	return r.Sandboxes.List(ctx)
}
