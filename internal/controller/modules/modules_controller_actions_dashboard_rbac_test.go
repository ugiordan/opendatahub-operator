package modules

import (
	"context"
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/opendatahub-io/opendatahub-operator/v2/api/common"
	componentApi "github.com/opendatahub-io/opendatahub-operator/v2/api/components/v1alpha1"
	dscv2 "github.com/opendatahub-io/opendatahub-operator/v2/api/datasciencecluster/v2"
	"github.com/opendatahub-io/opendatahub-operator/v2/pkg/cluster"
	"github.com/opendatahub-io/opendatahub-operator/v2/pkg/controller/types"
	"github.com/opendatahub-io/opendatahub-operator/v2/pkg/utils/test/fakeclient"

	corev1 "k8s.io/api/core/v1"
)

func newDashboardRBACTestRR(t *testing.T, platform common.Platform, objects ...client.Object) *types.ReconciliationRequest {
	t.Helper()

	cli, err := fakeclient.New(fakeclient.WithObjects(objects...))
	if err != nil {
		t.Fatalf("create fake client: %v", err)
	}

	dsc := &dscv2.DataScienceCluster{ObjectMeta: metav1.ObjectMeta{Name: "test-dsc"}}

	return &types.ReconciliationRequest{
		Client:   cli,
		Instance: dsc,
		Release:  common.Release{Name: platform},
	}
}

func enableDashboardInRegistry(t *testing.T) {
	t.Helper()
	withTestRegistry(t)
	DefaultRegistry().Add(&dashboardStub{enabled: true})
}

type dashboardStub struct {
	BaseHandler
	enabled bool
}

func (s *dashboardStub) GetName() string                         { return componentApi.DashboardComponentName }
func (s *dashboardStub) IsEnabled(_ *PlatformContext) bool       { return s.enabled }
func (s *dashboardStub) BuildModuleCR(_ context.Context, _ client.Client, _ *PlatformContext) (*unstructured.Unstructured, error) {
	return nil, nil
}

func TestEnsureDashboardNamespacedRBAC_BothNamespacesExist(t *testing.T) {
	enableDashboardInRegistry(t)

	notebooksNS := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: cluster.DefaultNotebooksNamespaceRHOAI}}
	modelRegNS := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "rhoai-model-registries"}}
	wb := &componentApi.Workbenches{
		ObjectMeta: metav1.ObjectMeta{Name: componentApi.WorkbenchesInstanceName},
	}
	mr := &componentApi.ModelRegistry{
		ObjectMeta: metav1.ObjectMeta{Name: componentApi.ModelRegistryInstanceName},
		Spec: componentApi.ModelRegistrySpec{
			ModelRegistryCommonSpec: componentApi.ModelRegistryCommonSpec{
				RegistriesNamespace: "rhoai-model-registries",
			},
		},
	}

	rr := newDashboardRBACTestRR(t, cluster.SelfManagedRhoai, notebooksNS, modelRegNS, wb, mr)

	if err := ensureDashboardNamespacedRBAC(context.Background(), rr); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(rr.Resources) != 4 {
		t.Fatalf("expected 4 resources (2 Roles + 2 RoleBindings), got %d", len(rr.Resources))
	}

	hasRole := func(name, namespace string) bool {
		for _, res := range rr.Resources {
			if res.GetKind() == "Role" && res.GetName() == name && res.GetNamespace() == namespace {
				return true
			}
		}
		return false
	}
	hasRoleBinding := func(name, namespace string) bool {
		for _, res := range rr.Resources {
			if res.GetKind() == "RoleBinding" && res.GetName() == name && res.GetNamespace() == namespace {
				return true
			}
		}
		return false
	}

	if !hasRole("rhods-dashboard-notebooks", cluster.DefaultNotebooksNamespaceRHOAI) {
		t.Error("missing notebooks Role")
	}
	if !hasRoleBinding("rhods-dashboard-notebooks", cluster.DefaultNotebooksNamespaceRHOAI) {
		t.Error("missing notebooks RoleBinding")
	}
	if !hasRole("rhods-dashboard-model-registries", "rhoai-model-registries") {
		t.Error("missing model-registry Role")
	}
	if !hasRoleBinding("rhods-dashboard-model-registries", "rhoai-model-registries") {
		t.Error("missing model-registry RoleBinding")
	}
}

func TestEnsureDashboardNamespacedRBAC_DashboardDisabled(t *testing.T) {
	withTestRegistry(t)
	DefaultRegistry().Add(&dashboardStub{enabled: false})

	rr := newDashboardRBACTestRR(t, cluster.SelfManagedRhoai)

	if err := ensureDashboardNamespacedRBAC(context.Background(), rr); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(rr.Resources) != 0 {
		t.Fatalf("expected 0 resources when dashboard disabled, got %d", len(rr.Resources))
	}
}

func TestEnsureDashboardNamespacedRBAC_NotebooksMissing(t *testing.T) {
	enableDashboardInRegistry(t)

	modelRegNS := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "rhoai-model-registries"}}
	mr := &componentApi.ModelRegistry{
		ObjectMeta: metav1.ObjectMeta{Name: componentApi.ModelRegistryInstanceName},
		Spec: componentApi.ModelRegistrySpec{
			ModelRegistryCommonSpec: componentApi.ModelRegistryCommonSpec{
				RegistriesNamespace: "rhoai-model-registries",
			},
		},
	}

	rr := newDashboardRBACTestRR(t, cluster.SelfManagedRhoai, modelRegNS, mr)

	if err := ensureDashboardNamespacedRBAC(context.Background(), rr); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(rr.Resources) != 2 {
		t.Fatalf("expected 2 resources (model-registry only), got %d", len(rr.Resources))
	}
}

func TestEnsureDashboardNamespacedRBAC_ModelRegistryMissing(t *testing.T) {
	enableDashboardInRegistry(t)

	notebooksNS := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: cluster.DefaultNotebooksNamespaceRHOAI}}
	wb := &componentApi.Workbenches{
		ObjectMeta: metav1.ObjectMeta{Name: componentApi.WorkbenchesInstanceName},
	}

	rr := newDashboardRBACTestRR(t, cluster.SelfManagedRhoai, notebooksNS, wb)

	if err := ensureDashboardNamespacedRBAC(context.Background(), rr); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(rr.Resources) != 2 {
		t.Fatalf("expected 2 resources (notebooks only), got %d", len(rr.Resources))
	}
}

func TestEnsureDashboardNamespacedRBAC_WorkbenchesCRNotFound(t *testing.T) {
	enableDashboardInRegistry(t)

	rr := newDashboardRBACTestRR(t, cluster.SelfManagedRhoai)

	if err := ensureDashboardNamespacedRBAC(context.Background(), rr); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(rr.Resources) != 0 {
		t.Fatalf("expected 0 resources when no CRs exist, got %d", len(rr.Resources))
	}
}

func TestEnsureDashboardNamespacedRBAC_ODHSAName(t *testing.T) {
	enableDashboardInRegistry(t)

	notebooksNS := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: cluster.DefaultNotebooksNamespaceODH}}
	wb := &componentApi.Workbenches{
		ObjectMeta: metav1.ObjectMeta{Name: componentApi.WorkbenchesInstanceName},
	}

	rr := newDashboardRBACTestRR(t, cluster.OpenDataHub, notebooksNS, wb)

	if err := ensureDashboardNamespacedRBAC(context.Background(), rr); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(rr.Resources) != 2 {
		t.Fatalf("expected 2 resources, got %d", len(rr.Resources))
	}

	for _, res := range rr.Resources {
		if res.GetKind() == "Role" && res.GetName() != "odh-dashboard-notebooks" {
			t.Errorf("expected ODH SA name in role, got %q", res.GetName())
		}
	}
}

func TestDashboardModelRegistryRBACRules_ContainsCreateVerb(t *testing.T) {
	rules := dashboardModelRegistryRBACRules()

	for _, rule := range rules {
		if len(rule.Resources) == 1 && rule.Resources[0] == "secrets" {
			hasCreate := false
			for _, v := range rule.Verbs {
				if v == "create" {
					hasCreate = true
					break
				}
			}
			if !hasCreate {
				t.Error("model-registry secrets rule missing 'create' verb")
			}

			hasGet := false
			for _, v := range rule.Verbs {
				if v == "get" {
					hasGet = true
					break
				}
			}
			if !hasGet {
				t.Error("model-registry secrets rule missing 'get' verb")
			}
			return
		}
	}
	t.Error("no secrets rule found in model-registry RBAC rules")
}

// makeStaleRBACObjects returns a Role and RoleBinding in the given namespace
// that carry the managed label, simulating objects left over from a previous reconcile.
func makeStaleRBACObjects(namespace, name string) (client.Object, client.Object) {
	managedLabels := map[string]string{dashboardManagedRBACLabel: dashboardManagedRBACLabelValue}
	role := &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels:    managedLabels,
		},
	}
	rb := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels:    managedLabels,
		},
	}
	return role, rb
}

// TestEnsureDashboardNamespacedRBAC_DisabledCleansUpStale verifies that disabling
// the dashboard causes pre-existing labeled Roles/RoleBindings to be deleted.
func TestEnsureDashboardNamespacedRBAC_DisabledCleansUpStale(t *testing.T) {
	withTestRegistry(t)
	DefaultRegistry().Add(&dashboardStub{enabled: false})

	staleNS := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: cluster.DefaultNotebooksNamespaceRHOAI}}
	staleRole, staleRB := makeStaleRBACObjects(cluster.DefaultNotebooksNamespaceRHOAI, "rhods-dashboard-notebooks")

	rr := newDashboardRBACTestRR(t, cluster.SelfManagedRhoai, staleNS, staleRole, staleRB)

	if err := ensureDashboardNamespacedRBAC(context.Background(), rr); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	remainingRoles := &rbacv1.RoleList{}
	if err := rr.Client.List(context.Background(), remainingRoles,
		client.MatchingLabels{dashboardManagedRBACLabel: dashboardManagedRBACLabelValue}); err != nil {
		t.Fatalf("list roles: %v", err)
	}
	if len(remainingRoles.Items) != 0 {
		t.Errorf("expected 0 stale Roles after dashboard disable, got %d", len(remainingRoles.Items))
	}

	remainingRBs := &rbacv1.RoleBindingList{}
	if err := rr.Client.List(context.Background(), remainingRBs,
		client.MatchingLabels{dashboardManagedRBACLabel: dashboardManagedRBACLabelValue}); err != nil {
		t.Fatalf("list rolebindings: %v", err)
	}
	if len(remainingRBs.Items) != 0 {
		t.Errorf("expected 0 stale RoleBindings after dashboard disable, got %d", len(remainingRBs.Items))
	}
}

// TestEnsureDashboardNamespacedRBAC_NamespaceChangeCleansUpOld verifies that when
// the notebooks namespace changes, the old namespace's Role/RoleBinding is deleted.
func TestEnsureDashboardNamespacedRBAC_NamespaceChangeCleansUpOld(t *testing.T) {
	enableDashboardInRegistry(t)

	oldNS := "rhods-notebooks-old"
	newNS := cluster.DefaultNotebooksNamespaceRHOAI

	// Pre-seed stale objects from the old namespace
	staleNSObj := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: oldNS}}
	newNSObj := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: newNS}}
	staleRole, staleRB := makeStaleRBACObjects(oldNS, "rhods-dashboard-notebooks")

	// Workbenches CR now points to the new namespace (default, no explicit field)
	wb := &componentApi.Workbenches{
		ObjectMeta: metav1.ObjectMeta{Name: componentApi.WorkbenchesInstanceName},
	}

	rr := newDashboardRBACTestRR(t, cluster.SelfManagedRhoai, staleNSObj, newNSObj, staleRole, staleRB, wb)

	if err := ensureDashboardNamespacedRBAC(context.Background(), rr); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Old namespace objects must be gone
	oldRoles := &rbacv1.RoleList{}
	if err := rr.Client.List(context.Background(), oldRoles,
		client.InNamespace(oldNS),
		client.MatchingLabels{dashboardManagedRBACLabel: dashboardManagedRBACLabelValue}); err != nil {
		t.Fatalf("list roles in old namespace: %v", err)
	}
	if len(oldRoles.Items) != 0 {
		t.Errorf("expected 0 Roles in old namespace %s, got %d", oldNS, len(oldRoles.Items))
	}
}

// TestEnsureDashboardNamespacedRBAC_ModelRegistryRemovedCleansUp verifies that
// removing the ModelRegistry CR causes its namespace's Role/RoleBinding to be deleted.
func TestEnsureDashboardNamespacedRBAC_ModelRegistryRemovedCleansUp(t *testing.T) {
	enableDashboardInRegistry(t)

	mrNS := "rhoai-model-registries"

	// Pre-seed stale model-registry RBAC (ModelRegistry CR is absent)
	staleNSObj := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: mrNS}}
	staleRole, staleRB := makeStaleRBACObjects(mrNS, "rhods-dashboard-model-registries")

	rr := newDashboardRBACTestRR(t, cluster.SelfManagedRhoai, staleNSObj, staleRole, staleRB)

	if err := ensureDashboardNamespacedRBAC(context.Background(), rr); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	remainingRoles := &rbacv1.RoleList{}
	if err := rr.Client.List(context.Background(), remainingRoles,
		client.InNamespace(mrNS),
		client.MatchingLabels{dashboardManagedRBACLabel: dashboardManagedRBACLabelValue}); err != nil {
		t.Fatalf("list roles: %v", err)
	}
	if len(remainingRoles.Items) != 0 {
		t.Errorf("expected 0 Roles after ModelRegistry removed, got %d", len(remainingRoles.Items))
	}

	remainingRBs := &rbacv1.RoleBindingList{}
	if err := rr.Client.List(context.Background(), remainingRBs,
		client.InNamespace(mrNS),
		client.MatchingLabels{dashboardManagedRBACLabel: dashboardManagedRBACLabelValue}); err != nil {
		t.Fatalf("list rolebindings: %v", err)
	}
	if len(remainingRBs.Items) != 0 {
		t.Errorf("expected 0 RoleBindings after ModelRegistry removed, got %d", len(remainingRBs.Items))
	}
}

func TestEnsureDashboardNamespacedRBAC_RoleBindingSubject(t *testing.T) {
	enableDashboardInRegistry(t)

	notebooksNS := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: cluster.DefaultNotebooksNamespaceRHOAI}}
	wb := &componentApi.Workbenches{
		ObjectMeta: metav1.ObjectMeta{Name: componentApi.WorkbenchesInstanceName},
	}

	rr := newDashboardRBACTestRR(t, cluster.SelfManagedRhoai, notebooksNS, wb)

	if err := ensureDashboardNamespacedRBAC(context.Background(), rr); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, res := range rr.Resources {
		if res.GetKind() != "RoleBinding" {
			continue
		}

		subjects, ok, _ := unstructured.NestedSlice(res.Object, "subjects")
		if !ok || len(subjects) != 1 {
			t.Fatalf("expected exactly 1 subject in RoleBinding, got %d", len(subjects))
		}

		subj, ok := subjects[0].(map[string]interface{})
		if !ok {
			t.Fatal("subject is not a map")
		}

		if subj["kind"] != string(rbacv1.ServiceAccountKind) {
			t.Errorf("expected ServiceAccount kind, got %v", subj["kind"])
		}
		if subj["name"] != dashboardSANameRHOAI {
			t.Errorf("expected SA name %q, got %v", dashboardSANameRHOAI, subj["name"])
		}
	}
}
