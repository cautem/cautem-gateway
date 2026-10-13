package httpapi

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/cautem/cautem-gateway/internal/storage/store"
	"gopkg.in/yaml.v3"
)

func applyGlobalPolicy(ctx context.Context, st *store.Store, runtime *grpcRuntime, document string, expectedRevision uint64, profileSources []string) (uint64, error) {
	if runtime != nil {
		runtime.globalPolicyMu.Lock()
		defer runtime.globalPolicyMu.Unlock()
	}
	previousDocument, _ := st.GlobalPolicySnapshot()
	sandboxes := st.ListSandboxes()
	if runtime == nil && len(sandboxes) > 0 {
		return 0, errors.New("runtime policy delivery is unavailable")
	}
	policies := make(map[string]store.GlobalSandboxPolicy, len(sandboxes))
	for _, sandbox := range sandboxes {
		effective, err := effectivePolicyWithGlobalPolicy(st, BuiltinProvidersDir(), sandbox.Name, profileSources, document)
		if err != nil {
			return 0, fmt.Errorf("compose global policy for sandbox %q: %w", sandbox.Name, err)
		}
		serialized, err := yaml.Marshal(effective)
		if err != nil {
			return 0, fmt.Errorf("serialize global policy for sandbox %q: %w", sandbox.Name, err)
		}
		policies[sandbox.Name] = store.GlobalSandboxPolicy{
			ResourceVersion: sandbox.ResourceVersion,
			PolicyRevision:  sandbox.PolicyRev,
			YAML:            string(serialized),
		}
	}

	globalRevision, sandboxRevisions, updated, _, err := st.SetGlobalPolicyWithSandboxRevisionsIfRevision(document, expectedRevision, policies)
	if err != nil {
		return 0, err
	}
	if !updated {
		return 0, store.ErrResourceVersionConflict
	}
	if len(sandboxes) == 0 {
		return globalRevision, nil
	}
	rpc := &openShellRPC{options: runtime.opt, runtime: runtime}
	syncFailed := make(map[string]bool)
	var firstErr error
	for _, sandbox := range sandboxes {
		if _, exists := st.GetSandbox(sandbox.Name); !exists {
			continue
		}
		revision := sandboxRevisions[sandbox.Name]
		if err := rpc.syncSandboxRuntimePolicy(ctx, sandbox.Name, revision); err != nil {
			_ = st.ReportPolicyStatus(sandbox.Name, revision, store.PolicyStatusFailed, "global policy delivery failed", time.Now().UTC())
			syncFailed[sandbox.Name] = true
			if firstErr == nil {
				firstErr = fmt.Errorf("global policy delivery failed for sandbox %q: %w", sandbox.Name, err)
			}
		}
	}
	acks := make(chan error, len(sandboxes))
	var waitGroup sync.WaitGroup
	for _, sandbox := range sandboxes {
		if _, exists := st.GetSandbox(sandbox.Name); !exists {
			continue
		}
		if syncFailed[sandbox.Name] {
			continue
		}
		revision := sandboxRevisions[sandbox.Name]
		connected := runtime.relay != nil && runtime.relay.Connected(sandbox.Name)
		restartDelivery, deliveryErr := sandboxUsesRestartedPolicyDelivery(runtime, sandbox)
		if deliveryErr != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("inspect policy delivery for sandbox %q: %w", sandbox.Name, deliveryErr)
			}
			continue
		}
		if policyAckRequired(sandbox.Status) && !connected && !restartDelivery {
			_ = st.ReportPolicyStatus(sandbox.Name, revision, store.PolicyStatusFailed, "running sandbox supervisor is disconnected", time.Now().UTC())
			if firstErr == nil {
				firstErr = fmt.Errorf("global policy acknowledgement unavailable for running sandbox %q", sandbox.Name)
			}
			continue
		}
		waitGroup.Add(1)
		go func(name string, revision int) {
			defer waitGroup.Done()
			if err := rpc.waitSandboxPolicyApplied(ctx, name, revision); err != nil {
				acks <- fmt.Errorf("global policy acknowledgement failed for sandbox %q: %w", name, err)
			}
		}(sandbox.Name, revision)
	}
	waitGroup.Wait()
	close(acks)
	for err := range acks {
		if firstErr == nil {
			firstErr = err
		}
	}
	if firstErr != nil {
		if rollbackErr := rollbackGlobalPolicy(ctx, st, runtime, previousDocument, document, globalRevision, profileSources); rollbackErr != nil {
			return globalRevision, errors.Join(firstErr, fmt.Errorf("restore previous global policy: %w", rollbackErr))
		}
	}
	return globalRevision, firstErr
}

func policyAckRequired(status string) bool {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "running", "ready", "started":
		return true
	default:
		return false
	}
}

// rollbackGlobalPolicy commits the previous desired policy as a new revision
// after delivery/acknowledgement failure. Revisions remain monotonic, and the
// compare-and-swap prevents this compensation from overwriting a newer admin
// update that raced with the failed request.

func rollbackGlobalPolicy(ctx context.Context, st *store.Store, runtime *grpcRuntime, previousDocument, failedDocument string, failedRevision uint64, profileSources []string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	recoveryCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Minute)
	defer cancel()
	currentDocument, currentRevision := st.GlobalPolicySnapshot()
	if currentRevision != failedRevision || currentDocument != failedDocument {
		return store.ErrResourceVersionConflict
	}
	sandboxes := st.ListSandboxes()
	policies := make(map[string]store.GlobalSandboxPolicy, len(sandboxes))
	for _, sandbox := range sandboxes {
		effective, err := effectivePolicyWithGlobalPolicy(st, BuiltinProvidersDir(), sandbox.Name, profileSources, previousDocument)
		if err != nil {
			return fmt.Errorf("compose restored global policy for sandbox %q: %w", sandbox.Name, err)
		}
		serialized, err := yaml.Marshal(effective)
		if err != nil {
			return fmt.Errorf("serialize restored global policy for sandbox %q: %w", sandbox.Name, err)
		}
		policies[sandbox.Name] = store.GlobalSandboxPolicy{
			ResourceVersion: sandbox.ResourceVersion,
			PolicyRevision:  sandbox.PolicyRev,
			YAML:            string(serialized),
		}
	}
	_, revisions, updated, _, err := st.SetGlobalPolicyWithSandboxRevisionsIfRevision(previousDocument, failedRevision, policies)
	if err != nil {
		return err
	}
	if !updated {
		return store.ErrResourceVersionConflict
	}
	if runtime == nil {
		return nil
	}
	rpc := &openShellRPC{options: runtime.opt, runtime: runtime}
	connected := make(map[string]int, len(sandboxes))
	var failures []error
	for _, sandbox := range sandboxes {
		revision, ok := revisions[sandbox.Name]
		if !ok {
			continue
		}
		connectedNow := runtime.relay != nil && runtime.relay.Connected(sandbox.Name)
		restartDelivery, deliveryErr := sandboxUsesRestartedPolicyDelivery(runtime, sandbox)
		if deliveryErr != nil {
			failures = append(failures, fmt.Errorf("inspect policy delivery for sandbox %q during compensation: %w", sandbox.Name, deliveryErr))
			continue
		}
		if !connectedNow && !restartDelivery {
			if policyAckRequired(sandbox.Status) {
				_ = st.ReportPolicyStatus(sandbox.Name, revision, store.PolicyStatusFailed, "running sandbox supervisor is disconnected during compensation", time.Now().UTC())
				failures = append(failures, fmt.Errorf("running sandbox %q could not acknowledge restored policy", sandbox.Name))
			}
			continue
		}
		if err := rpc.syncSandboxRuntimePolicy(recoveryCtx, sandbox.Name, revision); err != nil {
			_ = st.ReportPolicyStatus(sandbox.Name, revision, store.PolicyStatusFailed, "compensating policy delivery failed", time.Now().UTC())
			failures = append(failures, fmt.Errorf("write restored policy for sandbox %q: %w", sandbox.Name, err))
			continue
		}
		if connectedNow || (restartDelivery && policyAckRequired(sandbox.Status)) {
			connected[sandbox.Name] = revision
		}
	}
	acks := make(chan error, len(connected))
	var waitGroup sync.WaitGroup
	for name, revision := range connected {
		waitGroup.Add(1)
		go func(name string, revision int) {
			defer waitGroup.Done()
			if err := rpc.waitSandboxPolicyApplied(recoveryCtx, name, revision); err != nil {
				_ = st.ReportPolicyStatus(name, revision, store.PolicyStatusFailed, "compensating policy was not acknowledged", time.Now().UTC())
				acks <- fmt.Errorf("runtime for sandbox %q did not acknowledge restored policy: %w", name, err)
			}
		}(name, revision)
	}
	waitGroup.Wait()
	close(acks)
	for err := range acks {
		failures = append(failures, err)
	}
	return errors.Join(failures...)
}
