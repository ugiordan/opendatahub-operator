package e2e_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/opendatahub-io/opendatahub-operator/v2/pkg/cluster/gvk"
	"github.com/opendatahub-io/opendatahub-operator/v2/pkg/metadata/labels"
	"github.com/opendatahub-io/opendatahub-operator/v2/pkg/upgrade"
	"github.com/opendatahub-io/opendatahub-operator/v2/pkg/utils/test/testf"

	. "github.com/onsi/gomega"
)

// CfgMapDeletionTestCtx holds the context for the config map deletion tests.
type CfgMapDeletionTestCtx struct {
	*TestContext
	configMapNamespacedName types.NamespacedName
}

// cfgMapDeletionTestSuite runs the testing flow for DSC deletion logic via ConfigMap.
func cfgMapDeletionTestSuite(t *testing.T) {
	t.Helper()

	// Initialize the test context.
	tc, err := NewTestContext(t)
	require.NoError(t, err, "Failed to initialize test context")

	// Create an instance of test context.
	cfgMapDeletionTestCtx := &CfgMapDeletionTestCtx{
		TestContext:             tc,
		configMapNamespacedName: types.NamespacedName{Name: deleteConfigMap, Namespace: tc.OperatorNamespace},
	}

	// Ensure ConfigMap cleanup after tests
	defer cfgMapDeletionTestCtx.removeDeletionConfigMap(t)

	// Define test cases
	testCases := []testCase{
		{name: "Validate creation of configmap with deletion disabled", testFn: cfgMapDeletionTestCtx.validateDSCDeletionUsingConfigMap},
		{name: "Validate that owned namespaces are not deleted", testFn: cfgMapDeletionTestCtx.validateOwnedNamespacesAllExist},
	}

	// Run the test suite
	cfgMapDeletionTestCtx.RunTestCases(t, testCases)
}

// validateDSCDeletionUsingConfigMap tests the deletion of DSC based on the config map setting.
func (tc *CfgMapDeletionTestCtx) validateDSCDeletionUsingConfigMap(t *testing.T) {
	t.Helper()

	// Create or update the deletion config map
	enableDeletion := "false"
	tc.g.CreateOrUpdate(
		gvk.ConfigMap,
		tc.configMapNamespacedName,
		testf.Transform(`.metadata.labels[%s] = %s`, upgrade.DeleteConfigMapLabel, enableDeletion)).
		Eventually().ShouldNot(BeNil(), "Failed to create or update deletion config map")

	// Verify the existence of the DSC instance.
	tc.EnsureResourceExists(gvk.DataScienceCluster, types.NamespacedName{Name: tc.DSC.Name})
}

// validateOwnedNamespacesAllExist verifies that the owned namespaces exist.
func (tc *CfgMapDeletionTestCtx) validateOwnedNamespacesAllExist(t *testing.T) {
	t.Helper()

	// Ensure namespaces with the owned namespace label exist
	tc.EnsureResourcesWithLabelsExist(
		gvk.Namespace,
		client.MatchingLabels{labels.ODH.OwnedNamespace: "true"},
		ownedNamespaceNumber,
		"Expected %d owned namespaces with label '%s'. Owned namespaces should not be deleted: %v", ownedNamespaceNumber, labels.ODH.OwnedNamespace,
	)
}

// removeDeletionConfigMap ensures the deletion of the ConfigMap.
func (tc *CfgMapDeletionTestCtx) removeDeletionConfigMap(t *testing.T) {
	t.Helper()

	// Delete the config map
	tc.DeleteResource(
		gvk.ConfigMap,
		tc.configMapNamespacedName,
		client.PropagationPolicy(metav1.DeletePropagationForeground),
	)
}
