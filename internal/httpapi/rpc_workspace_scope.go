package httpapi

import (
	datamodelv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/datamodelv1"
)

func workspaceScope(name string) *datamodelv1.WorkspaceSelector {
	if name == "" {
		return nil
	}
	return &datamodelv1.WorkspaceSelector{Selection: &datamodelv1.WorkspaceSelector_Workspace{Workspace: name}}
}

func requestWorkspace(scope *datamodelv1.WorkspaceSelector) string {
	if scope == nil {
		return ""
	}
	return scope.GetWorkspace()
}

func scopeAllWorkspaces(scope *datamodelv1.WorkspaceSelector) bool {
	return scope != nil && scope.GetAllWorkspaces() != nil
}

func allWorkspacesScope() *datamodelv1.WorkspaceSelector {
	return &datamodelv1.WorkspaceSelector{Selection: &datamodelv1.WorkspaceSelector_AllWorkspaces{AllWorkspaces: &datamodelv1.AllWorkspaces{}}}
}
