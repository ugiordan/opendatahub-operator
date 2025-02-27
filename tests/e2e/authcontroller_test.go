package e2e_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"

	serviceApi "github.com/opendatahub-io/opendatahub-operator/v2/apis/services/v1alpha1"
	"github.com/opendatahub-io/opendatahub-operator/v2/controllers/components/dashboard"
	"github.com/opendatahub-io/opendatahub-operator/v2/pkg/cluster"
	"github.com/opendatahub-io/opendatahub-operator/v2/pkg/cluster/gvk"
	"github.com/opendatahub-io/opendatahub-operator/v2/pkg/resources"
	"github.com/opendatahub-io/opendatahub-operator/v2/pkg/utils/test/matchers/jq"
	"github.com/opendatahub-io/opendatahub-operator/v2/pkg/utils/test/testf"

	. "github.com/onsi/gomega"
)

const (
	// Role and RoleBinding names.
	adminGroupRoleName               = "admingroup-role"
	allowedGroupRoleName             = "allowedgroup-role"
	adminGroupRoleBindingName        = "admingroup-rolebinding"
	allowedGroupRoleBindingName      = "allowedgroup-rolebinding"
	adminGroupClusterRoleName        = "admingroupcluster-role"
	adminGroupClusterRoleBindingName = "admingroupcluster-rolebinding"
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
		{"Validate removal of bindings when a group is removed", authCtx.validateRemovingGroups},
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
	tc.EnsureResourceConditionMet(tc.testAuthInstance, Not(BeEmpty()), "AdminGroups should not be empty")

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
	roles := []string{adminGroupRoleName, allowedGroupRoleName}
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

	tc.EnsureResourceExists(
		gvk.ClusterRole,
		types.NamespacedName{Namespace: tc.ApplicationNamespace, Name: adminGroupClusterRoleName},
		"Expected admin ClusterRole %s to be created", adminGroupClusterRoleName,
	)
}

// validateAuthCRRoleBindingCreation validates the creation of the role bindings.
func (tc *AuthControllerTestCtx) validateAuthCRRoleBindingCreation(t *testing.T) {
	t.Helper()

	roleBindings := []string{adminGroupRoleBindingName, allowedGroupRoleBindingName}
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

	tc.EnsureResourceExists(
		gvk.ClusterRoleBinding,
		types.NamespacedName{Namespace: tc.ApplicationNamespace, Name: adminGroupClusterRoleBindingName},
		"Expected admin ClusterRoleBinding %s to be created", adminGroupClusterRoleBindingName,
	)
}

// validateAddingGroups adds groups and validates.
func (tc *AuthControllerTestCtx) validateAddingGroups(t *testing.T) {
	t.Helper()

	testAdminGroup := "aTestAdminGroup"
	testAllowedGroup := "aTestAllowedGroup"

	tc.EnsureResourceCreatedOrUpdated(
		gvk.Auth,
		resources.NamespacedNameFromObject(&tc.testAuthInstance),
		testf.Transform(
			`.spec.adminGroups |= . + ["%s"] | .spec.allowedGroups |= . + ["%s"]`, testAdminGroup, testAllowedGroup,
		),
	)

	// Helper to validate role bindings and cluster role bindings
	validateBinding := func(bindingType schema.GroupVersionKind, bindingName, groupName string) {
		tc.EnsureResourceExistsAndMatchesCondition(
			bindingType,
			types.NamespacedName{Namespace: tc.ApplicationNamespace, Name: bindingName},
			jq.Match(`.subjects[1].name == "%s"`, groupName),
		)
	}

	// Validate RoleBinding and ClusterRoleBinding for admin and allowed groups
	validateBinding(gvk.RoleBinding, adminGroupRoleBindingName, testAdminGroup)
	validateBinding(gvk.ClusterRoleBinding, adminGroupClusterRoleBindingName, testAdminGroup)
	validateBinding(gvk.RoleBinding, allowedGroupRoleBindingName, testAllowedGroup)
}

func (tc *AuthControllerTestCtx) validateRemovingGroups(t *testing.T) {
	t.Helper()

	expectedGroup := dashboard.GetAdminGroup()

	// Update the Auth resource with the expected admin Group
	tc.EnsureResourceCreatedOrUpdated(
		gvk.Auth,
		types.NamespacedName{Name: serviceApi.AuthInstanceName, Namespace: tc.ApplicationNamespace},
		testf.Transform(`.spec.adminGroups = %s`, expectedGroup),
		"Failed to create or update Auth resource '%s' with admin group '%s'", serviceApi.AuthInstanceName, expectedGroup,
	)

	// Helper to validate the binding conditions
	validateBinding := func(bindingType schema.GroupVersionKind, bindingName string, args ...any) {
		tc.EnsureResourceExistsAndMatchesCondition(
			bindingType,
			types.NamespacedName{Namespace: tc.ApplicationNamespace, Name: bindingName},
			And(
				jq.Match(`.subjects | length == 1`),
				jq.Match(`.subjects[0].name == "%s"`, expectedGroup),
			),
			args...,
		)
	}

	// Validate RoleBinding and ClusterRoleBinding for admin group after removal
	validateBinding(gvk.RoleBinding, adminGroupRoleBindingName,
		"Expected RoleBinding '%s' to have exactly one subject with name '%s'", adminGroupRoleBindingName, expectedGroup)
	validateBinding(gvk.ClusterRoleBinding, adminGroupClusterRoleBindingName,
		"Expected ClusterRoleBinding '%s' to have exactly one subject with name '%s'", adminGroupClusterRoleBindingName, expectedGroup)
}
