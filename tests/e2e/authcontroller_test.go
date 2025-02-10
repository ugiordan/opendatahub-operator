package e2e_test

import (
	"github.com/opendatahub-io/opendatahub-operator/v2/pkg/resources"
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	serviceApi "github.com/opendatahub-io/opendatahub-operator/v2/apis/services/v1alpha1"
	"github.com/opendatahub-io/opendatahub-operator/v2/pkg/cluster"
	"github.com/opendatahub-io/opendatahub-operator/v2/pkg/cluster/gvk"
	"github.com/opendatahub-io/opendatahub-operator/v2/pkg/utils/test/matchers/jq"
	"github.com/opendatahub-io/opendatahub-operator/v2/pkg/utils/test/testf"

	. "github.com/onsi/gomega"
)

type AuthControllerTestCtx struct {
	*TestContext
	testAuthInstance serviceApi.Auth
}

func authControllerTestSuite(t *testing.T) {
	t.Helper()

	// Initialize the test context.
	tc, err := NewTestContext(t)
	require.NoError(t, err, "Failed to initialize test context")

	// Create an instance of test context.
	authCtx := AuthControllerTestCtx{
		TestContext: tc,
	}

	// Define test cases
	testCases := []testCase{
		{"Validate Auth CR creation", authCtx.validateAuthCRCreation},
		{"Validate Auth CR default content", authCtx.validateAuthCRDefaultContent},
		{"Validate Auth Role creation", authCtx.validateAuthCRRoleCreation},
		{"Validate Auth RoleBinding creation", authCtx.validateAuthCRRoleBindingCreation},
		{"Validate addition of RoleBinding when group is added", authCtx.validateAddingGroups},
		{"Validate addition of ClusterRole when group is added", authCtx.validateAuthCRClusterRoleCreation},
		{"Validate addition of ClusterRoleBinding when group is added", authCtx.validateAuthCRClusterRoleBindingCreation},
	}

	// Run the test suite
	authCtx.RunTestCases(t, testCases)
}

// validateAuthCRCreation checks if the Auth CR is created and validates it.
func (tc *AuthControllerTestCtx) validateAuthCRCreation(t *testing.T) {
	t.Helper()

	// Ensure that exactly one Auth CR exists.
	u := tc.EnsureExactlyOneResourceExists(
		gvk.Auth,
		types.NamespacedName{Name: serviceApi.AuthInstanceName},
	)

	// Convert the unstructured resource to the test instance.
	tc.ConvertUnstructuredToResource(u, tc.testAuthInstance)
}

// validateAuthCRDefaultContent validates the default content of the Auth CR.
func (tc *AuthControllerTestCtx) validateAuthCRDefaultContent(t *testing.T) {
	t.Helper()

	// Ensure AdminGroups is not empty.
	tc.EnsureResourceConditionMet(tc.testAuthInstance, true, BeEmpty(), "AdminGroups should not be empty")

	// Validate that the first AdminGroup is as expected based on the Platform.
	adminGroup := tc.testAuthInstance.Spec.AdminGroups[0]
	var expectedAdminGroup string
	if tc.Platform == cluster.SelfManagedRhoai || tc.Platform == cluster.ManagedRhoai {
		expectedAdminGroup = "rhods-admins"
	} else {
		expectedAdminGroup = "odh-admins"
	}

	tc.EnsureResourcesAreEqual(
		adminGroup,
		expectedAdminGroup,
		"Expected '%s' as AdminGroup, but got: %v", expectedAdminGroup, adminGroup,
	)

	// Validate that AllowedGroups has 'system:authenticated'.
	allowedGroup := tc.testAuthInstance.Spec.AllowedGroups[0]
	expectedAllowedGroup := "system:authenticated"
	tc.EnsureResourcesAreEqual(
		allowedGroup,
		expectedAllowedGroup,
		"Expected '%s' as AdminGroup, but got: %v", expectedAdminGroup, adminGroup,
	)
}

// validateAuthCRRoleCreation validates the creation of the roles for the Auth CR.
func (tc *AuthControllerTestCtx) validateAuthCRRoleCreation(t *testing.T) {
	t.Helper()

	// Validate the role for admin and allowed groups.
	roles := []string{"admingroup-role", "allowedgroup-role"}
	for _, roleName := range roles {
		tc.EnsureResourceExists(
			gvk.Role,
			types.NamespacedName{Namespace: tc.ApplicationNamespace, Name: roleName},
			"Expected admin Role %s to be created", roleName,
		)
	}
}

// validateAuthCRClusterRoleCreation validates the creation of the cluster role.
func (tc *AuthControllerTestCtx) validateAuthCRClusterRoleCreation(t *testing.T) {
	t.Helper()

	clusterRole := "admingroupcluster-role"
	tc.EnsureResourceExists(
		gvk.ClusterRole,
		types.NamespacedName{Namespace: tc.ApplicationNamespace, Name: clusterRole},
		"Expected admin ClusterRole %s to be created", clusterRole,
	)
}

// validateAuthCRRoleBindingCreation validates the creation of the role bindings.
func (tc *AuthControllerTestCtx) validateAuthCRRoleBindingCreation(t *testing.T) {
	t.Helper()

	roleBindings := []string{"admingroup-rolebinding", "allowedgroup-rolebinding"}
	for _, roleBinding := range roleBindings {
		tc.EnsureResourceExists(
			gvk.RoleBinding,
			types.NamespacedName{Namespace: tc.ApplicationNamespace, Name: roleBinding},
			"Expected admin RoleBinding %s to be created", roleBinding,
		)
	}
}

// validateAuthCRClusterRoleBindingCreation validates the creation of the cluster role bindings.
func (tc *AuthControllerTestCtx) validateAuthCRClusterRoleBindingCreation(t *testing.T) {
	t.Helper()

	clusterRoleBinding := "admingroupcluster-rolebinding"
	tc.EnsureResourceExists(
		gvk.ClusterRoleBinding,
		types.NamespacedName{Namespace: tc.ApplicationNamespace, Name: clusterRoleBinding},
		"Expected admin ClusterRoleBinding %s to be created", clusterRoleBinding,
	)
}

// validateAddingGroups adds groups and validates.
func (tc *AuthControllerTestCtx) validateAddingGroups(t *testing.T) {
	t.Helper()

	g := tc.NewWithT(t)

	testAdminGroup := "aTestAdminGroup"
	testAllowedGroup := "aTestAllowedGroup"

	tc.EnsureResourceExistsOrCreate(
		gvk.Auth,
		resources.NamespacedNameFromObject(&tc.testAuthInstance),
		testf.Transform(`.spec.adminGroups = %s, .spec.allowedGroups = %s`, testAdminGroup, testAllowedGroup),
	)

	g.Update(
		gvk.Auth,
		client.ObjectKeyFromObject(&tc.testAuthInstance),
		testf.Transform(`.spec.adminGroups = %s, .spec.allowedGroups = %s`, testAdminGroup, testAllowedGroup),
	).Eventually().Should(
		jq.Match(`.spec.adminGroups == %s`, testAdminGroup),
		jq.Match(`.spec.allowedGroups == %s`, testAllowedGroup),
	)

	// tc.testAuthInstance.Spec.AdminGroups = append(tc.testAuthInstance.Spec.AdminGroups, "aTestAdminGroup")
	// tc.testAuthInstance.Spec.AllowedGroups = append(tc.testAuthInstance.Spec.AllowedGroups, "aTestAllowedGroup")
	// err := tc.Client().Update(tc.Context(), &tc.testAuthInstance)
	//require.NoError(t, err, "Error updating Auth instance")

	// Validate added admin RoleBinding
	g.Get(gvk.RoleBinding, types.NamespacedName{Namespace: tc.ApplicationNamespace, Name: "admingroup-rolebinding"}).
		Eventually().Should(
		jq.Match(`.subjects[0].name == "%s"`, testAdminGroup),
	)

	// Validate added admin cluster RoleBinding
	g.Get(gvk.ClusterRoleBinding, types.NamespacedName{Namespace: tc.ApplicationNamespace, Name: "admingroupcluster-rolebinding"}).
		Eventually().Should(
		jq.Match(`.subjects[0].name == "%s"`, testAdminGroup),
	)

	// Validate added allowed RoleBinding
	g.Get(gvk.RoleBinding, types.NamespacedName{Namespace: tc.ApplicationNamespace, Name: "allowedgroup-rolebinding"}).
		Eventually().Should(
		jq.Match(`.subjects[0].name == "%s"`, testAllowedGroup),
	)
}
