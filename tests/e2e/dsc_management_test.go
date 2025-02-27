package e2e_test

import (
	"fmt"
	gomegaTypes "github.com/onsi/gomega/types"
	"github.com/opendatahub-io/opendatahub-operator/v2/pkg/resources"
	"github.com/opendatahub-io/opendatahub-operator/v2/pkg/utils/test/testf"
	"testing"

	operatorv1 "github.com/openshift/api/operator/v1"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	infrav1 "github.com/opendatahub-io/opendatahub-operator/v2/apis/infrastructure/v1"
	modelregistryctrl "github.com/opendatahub-io/opendatahub-operator/v2/controllers/components/modelregistry"
	"github.com/opendatahub-io/opendatahub-operator/v2/pkg/cluster/gvk"
	"github.com/opendatahub-io/opendatahub-operator/v2/pkg/metadata/labels"

	. "github.com/onsi/gomega"
)

const (
	testNamespace             = "test-model-registries"   // Namespace used for model registry testing
	dsciInstanceNameDuplicate = "e2e-test-dsci-duplicate" // Instance name for the duplicate DSCI resource
	dscInstanceNameDuplicate  = "e2e-test-dsc-duplicate"  // Instance name for the duplicate DSC resource
)

// DSCIManagementTestCtx holds the context for the DSCI and DSC management tests.
type DSCTestCtx struct {
	*TestContext
}

func dscManagementTestSuite(t *testing.T) {
	t.Helper()

	// Initialize the test context.
	tc, err := NewTestContext(t)
	require.NoError(t, err, "Failed to initialize test context")

	// Create an instance of test context.
	dscTestCtx := DSCTestCtx{
		TestContext: tc,
	}

	// Define test cases
	testCases := []testCase{
		{"Ensure Service Mesh and Serverless operators are installed", dscTestCtx.validateOperatorsInstallation},
		{"Validate creation of DSCInitialization instance", dscTestCtx.validateDSCICreation},
		{"Validate creation of DataScienceCluster instance", dscTestCtx.validateDSCCreation},
		{"Validate ServiceMeshSpec in DSCInitialization instance", dscTestCtx.validateServiceMeshSpecInDSCI},
		{"Validate Knative resource", dscTestCtx.validateKnativeSpecInDSC},
		{"Validate owned namespaces exist", dscTestCtx.validateOwnedNamespacesAllExist},
	}

	// Append webhook-specific tests
	if dscTestCtx.TestOpts.webhookTest {
		testCases = append(testCases, []testCase{
			{"Validate creation of more than one DSCInitialization instance", dscTestCtx.validateDSCIDuplication},
			{"Validate creation of more than one DataScienceCluster instance", dscTestCtx.validateDSCDuplication},
			{"Validate Model Registry Configuration Changes", dscTestCtx.validateModelRegistryConfig},
		}...)
	}

	// Run the test suite
	dscTestCtx.RunTestCases(t, testCases)
}

// setUp ensures the Service Mesh and Serverless operators  are concurrently installed.
func (tc *DSCTestCtx) validateOperatorsInstallation(t *testing.T) {
	t.Helper()

	// Define operators to be installed.
	operators := []types.NamespacedName{
		{Name: serviceMeshOpName, Namespace: openshiftOperatorsNamespace},
		{Name: serverlessOpName, Namespace: serverlessOperatorNamespace},
	}

	// Create test cases.
	testCases := make([]testCase, len(operators))
	for i, op := range operators {
		testCases[i] = testCase{
			name: fmt.Sprintf("Ensure %s Operator is installed", op.Name),
			testFn: func(t *testing.T) {
				t.Helper()
				tc.EnsureOperatorInstalled(op)
			},
		}
	}

	// Run test cases in parallel.
	tc.RunTestCases(t, testCases, WithParallel())
}

// validateDSCICreation validate the creation of a DSCInitialization.
func (tc *DSCTestCtx) validateDSCICreation(t *testing.T) {
	t.Helper()

	tc.EnsureResourceCreatedOrUpdated(
		gvk.DSCInitialization,
		types.NamespacedName{Namespace: tc.TestDSCI.Namespace, Name: tc.TestDSCI.Name},
		NoOpMutationFn,
		"Failed to create DSCI resource %s", tc.TestDSCI.Name,
	)
}

// validateDSCCreation validate the creation of a DataScienceCluster.
func (tc *DSCTestCtx) validateDSCCreation(t *testing.T) {
	t.Helper()

	tc.EnsureResourceCreatedOrUpdated(
		gvk.DataScienceCluster,
		types.NamespacedName{Namespace: tc.TestDsc.Namespace, Name: tc.TestDsc.Name},
		NoOpMutationFn,
		"Failed to create DSC resource %s", tc.TestDsc.Name,
	)
}

// validateServiceMeshSpecInDSCI validates the ServiceMeshSpec within a DSCI instance.
func (tc *DSCTestCtx) validateServiceMeshSpecInDSCI(t *testing.T) {
	t.Helper()

	// expected ServiceMeshSpec
	expServiceMeshSpec := &infrav1.ServiceMeshSpec{
		ManagementState: operatorv1.Managed,
		ControlPlane: infrav1.ControlPlaneSpec{
			Name:              serviceMeshControlPlane,
			Namespace:         serviceMeshNamespace,
			MetricsCollection: serviceMeshMetricsCollection,
		},
		Auth: infrav1.AuthSpec{
			Audiences: &[]string{"https://kubernetes.default.svc"},
		},
	}

	// actual ServiceMeshSpec
	act := tc.TestDSCI

	// Assert that the actual ServiceMeshSpec matches the expected one using require
	tc.EnsureResourceNotNil(act)
	tc.EnsureResourcesAreEqual(
		act.Spec.ServiceMesh,
		expServiceMeshSpec,
		"Error validating DSCInitialization instance: Service Mesh spec mismatch",
	)
}

// validateKnativeSpecInDSC validates that the Kserve serving spec in the DataScienceCluster matches the expected spec.
func (tc *DSCTestCtx) validateKnativeSpecInDSC(t *testing.T) {
	t.Helper()

	// expected ServingSpec
	expServingSpec := infrav1.ServingSpec{
		ManagementState: operatorv1.Managed,
		Name:            knativeServingNamespace,
		IngressGateway: infrav1.GatewaySpec{
			Certificate: infrav1.CertificateSpec{
				Type: infrav1.OpenshiftDefaultIngress,
			},
		},
	}

	// actual ServingSpec
	act := tc.TestDsc

	// Assert that the actual ServingSpec matches the expected one using require
	tc.EnsureResourceNotNil(act)
	tc.EnsureResourcesAreEqual(
		act.Spec.Components.Kserve.Serving,
		expServingSpec,
		"Error validating DataScienceCluster instance: Kserve serving spec mismatch",
	)
}

// validateOwnedNamespacesAllExist verifies that the owned namespaces exist.
func (tc *DSCTestCtx) validateOwnedNamespacesAllExist(t *testing.T) {
	t.Helper()

	// Ensure namespaces with the owned namespace label exist
	tc.EnsureResourcesWithLabelsExist(
		gvk.Namespace,
		client.MatchingLabels{labels.ODH.OwnedNamespace: "true"},
		ownedNamespaceNumber,
		"Expected %d owned namespaces with label '%s'.", labels.ODH.OwnedNamespace,
	)
}

// validateDSCDuplication ensures that no duplicate DSCInitialization resource can be created.
func (tc *DSCTestCtx) validateDSCIDuplication(t *testing.T) {
	t.Helper()

	dup := CreateDSCI(dsciInstanceNameDuplicate)

	// assert that a duplicate DSCI Initialization cannot be created.
	tc.EnsureResourceIsUnique(dup, "Error validating DSCI duplication")
}

// validateDSCDuplication ensures that no duplicate DataScienceCluster resource can be created.
func (tc *DSCTestCtx) validateDSCDuplication(t *testing.T) {
	t.Helper()

	dup := CreateDSC(dscInstanceNameDuplicate)

	// assert that a duplicate DSC Initialization cannot be created.
	tc.EnsureResourceIsUnique(dup, "Error validating DSC duplication")
}

// validateModelRegistryConfig validates the ModelRegistry configuration changes based on ManagementState.
func (tc *DSCTestCtx) validateModelRegistryConfig(t *testing.T) {
	t.Helper()

	// Check if the ModelRegistry is managed
	if tc.TestDsc.Spec.Components.ModelRegistry.ManagementState == operatorv1.Managed {
		// Ensure changing registriesNamespace is not allowed and expect failure
		tc.UpdateRegistriesNamespace(testNamespace, modelregistryctrl.DefaultModelRegistriesNamespace, true)

		// No further checks if it's managed
		return
	}

	// Ensure setting registriesNamespace to a non-default value is allowed.
	// No error is expected, and we check the value of the patch after it's successful
	tc.UpdateRegistriesNamespace(testNamespace, testNamespace, false)

	// Ensure resetting registriesNamespace to the default value is allowed.
	tc.UpdateRegistriesNamespace(modelregistryctrl.DefaultModelRegistriesNamespace, modelregistryctrl.DefaultModelRegistriesNamespace, false)
}

// UpdateRegistriesNamespace updates the ModelRegistry component's `RegistriesNamespace` field
// in the DSC object and verifies the outcome using Gomega assertions.
//
// It applies a JSON MergePatch to modify the `registriesNamespace` field, ensuring the update
// either succeeds or fails based on the `shouldFail` flag. After patching, it asserts that the
// `RegistriesNamespace` field matches the expected value.
//
// Parameters:
//   - newNamespace (string): The new namespace to set in the ModelRegistry component.
//   - expectedValue (string): The expected value of the `RegistriesNamespace` field after patching.
//   - shouldFail (bool): If true, the function expects an error during patching; otherwise, it expects success.
//
// Example Usage:
//
//	err := tc.UpdateRegistriesNamespace("custom-namespace", "custom-namespace", false)
//	tc.g.Expect(err).ToNot(HaveOccurred())
func (tc *DSCTestCtx) UpdateRegistriesNamespace(newNamespace, expectedValue string, shouldFail bool) {
	// Define the expected condition based on the shouldFail flag
	var condition gomegaTypes.GomegaMatcher
	if shouldFail {
		// If shouldFail is true, we expect the patch to fail
		condition = Not(Succeed())
	} else {
		// If shouldFail is false, we expect the patch to succeed
		condition = Succeed()
	}

	// Update the registriesNamespace field.
	tc.EnsureResourceCreatedOrPatchedWithCondition(
		gvk.Auth,
		resources.NamespacedNameFromObject(tc.TestDsc),
		testf.Transform(`.spec.components[].modelregistry.registriesNamespace |= "%s"`, newNamespace),
		condition,
		"Failed to update RegistriesNamespace to %s, expected %s", newNamespace, expectedValue,
	)

	// If patching succeeded and should not fail, verify the RegistriesNamespace value
	if !shouldFail {
		tc.EnsureResourcesAreEqual(
			tc.TestDsc.Spec.Components.ModelRegistry.RegistriesNamespace,
			expectedValue,
			"Expected RegistriesNamespace to be %s, but got %s", expectedValue, tc.TestDsc.Spec.Components.ModelRegistry.RegistriesNamespace)

	}
}
