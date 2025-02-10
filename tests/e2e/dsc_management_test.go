package e2e_test

import (
	"fmt"
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
		{"Validate ServiceMeshSpec in DSCInitialization instance", dscTestCtx.validateServiceMeshSpecInDSCI},
		{"Validate owned namespaces exist", dscTestCtx.validateOwnedNamespacesAllExist},
		{"Validate creation of DataScienceCluster instance", dscTestCtx.validateDSCCreation},
		{"Validate Knative resource", dscTestCtx.validateKnativeSpecInDSC},
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
		{Name: serverlessOpName, Namespace: openshiftOperatorsNamespace},
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

	tc.EnsureResourceExistsOrCreate(
		gvk.DSCInitialization,
		types.NamespacedName{Namespace: tc.TestDSCI.Namespace, Name: tc.TestDSCI.Name},
		NoOpMutationFn,
		"Failed to create DSCI resource %s", tc.TestDSCI.Name,
	)
}

// validateDSCCreation validate the creation of a DataScienceCluster.
func (tc *DSCTestCtx) validateDSCCreation(t *testing.T) {
	t.Helper()

	tc.EnsureResourceExistsOrCreate(
		gvk.DataScienceCluster,
		types.NamespacedName{Namespace: tc.TestDSCI.Namespace, Name: tc.TestDSCI.Name},
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

	dup := createDSCI(dsciInstanceNameDuplicate)

	// assert that a duplicate DSCI Initialization cannot be created.
	tc.EnsureResourceIsUnique(dup, "Error validating DSCI duplication")
}

// validateDSCDuplication ensures that no duplicate DataScienceCluster resource can be created.
func (tc *DSCTestCtx) validateDSCDuplication(t *testing.T) {
	t.Helper()

	dup := createDSC(dscInstanceNameDuplicate)

	// assert that a duplicate DSC Initialization cannot be created.
	tc.EnsureResourceIsUnique(dup, "Error validating DSC duplication")
}

// validateModelRegistryConfig validates the ModelRegistry configuration changes based on ManagementState.
func (tc *DSCTestCtx) validateModelRegistryConfig(t *testing.T) {
	t.Helper()

	// Skip validation if the ModelRegistry is managed.
	if tc.TestDsc.Spec.Components.ModelRegistry.ManagementState == operatorv1.Managed {
		// Ensure changing registriesNamespace is not allowed.
		tc.g.Expect(
			tc.UpdateRegistriesNamespace(
				testNamespace,
				modelregistryctrl.DefaultModelRegistriesNamespace,
				true,
			),
		).To(HaveOccurred(), "Expected failure when attempting to change registriesNamespace while in Managed state.")

		return
	}

	// Ensure setting registriesNamespace to a non-default value is allowed.
	tc.g.Expect(
		tc.UpdateRegistriesNamespace(
			testNamespace,
			testNamespace,
			false,
		)).
		To(Succeed(), "Failed to set registriesNamespace to a non-default value.")

	// Ensure resetting registriesNamespace to the default value is allowed.
	tc.g.Expect(
		tc.UpdateRegistriesNamespace(
			modelregistryctrl.DefaultModelRegistriesNamespace,
			modelregistryctrl.DefaultModelRegistriesNamespace,
			false),
	).To(Succeed(), "Failed to reset registriesNamespace to the default value.")
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
func (tc *DSCTestCtx) UpdateRegistriesNamespace(newNamespace, expectedValue string, shouldFail bool) error {
	// Construct the JSON patch to update the registriesNamespace field.
	patchData := fmt.Sprintf(`{"spec":{"components":{"modelregistry":{"registriesNamespace":"%s"}}}}`, newNamespace)

	// Apply the patch.
	err := tc.Client().Patch(tc.Context(), tc.TestDsc, client.RawPatch(types.MergePatchType, []byte(patchData)))

	// Validate the patching outcome.
	if shouldFail {
		tc.g.Expect(err).To(HaveOccurred(), "Expected an error while setting RegistriesNamespace in DSC %s to %s, but no error occurred.", tc.TestDsc.Name, newNamespace)
		return err
	}

	tc.g.Expect(err).ToNot(HaveOccurred(), "Unexpected error when setting RegistriesNamespace in DSC %s to %s: %v", tc.TestDsc.Name, newNamespace, err)

	// Verify the `RegistriesNamespace` field matches the expected value.
	tc.g.Expect(tc.TestDsc.Spec.Components.ModelRegistry.RegistriesNamespace).To(Equal(expectedValue),
		"Expected RegistriesNamespace to be %s, but got %s", expectedValue, tc.TestDsc.Spec.Components.ModelRegistry.RegistriesNamespace)

	return nil
}
