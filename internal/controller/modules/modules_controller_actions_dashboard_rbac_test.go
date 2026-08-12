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
