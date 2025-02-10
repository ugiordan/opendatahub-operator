package e2e_test

import (
	"fmt"
	gomegaTypes "github.com/onsi/gomega/types"
	"github.com/opendatahub-io/opendatahub-operator/v2/pkg/utils/test/testf"
	"k8s.io/apimachinery/pkg/api/errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/onsi/gomega/gstruct"
	operatorv1 "github.com/openshift/api/operator/v1"
	ofapi "github.com/operator-framework/api/pkg/operators/v1alpha1"
	operatorsv1alpha1 "github.com/operator-framework/api/pkg/operators/v1alpha1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apiextv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/opendatahub-io/opendatahub-operator/v2/apis/common"
	componentApi "github.com/opendatahub-io/opendatahub-operator/v2/apis/components/v1alpha1"
	"github.com/opendatahub-io/opendatahub-operator/v2/apis/components/v1alpha1/datasciencepipelines"
	dscv1 "github.com/opendatahub-io/opendatahub-operator/v2/apis/datasciencecluster/v1"
	dsciv1 "github.com/opendatahub-io/opendatahub-operator/v2/apis/dscinitialization/v1"
	infrav1 "github.com/opendatahub-io/opendatahub-operator/v2/apis/infrastructure/v1"
	serviceApi "github.com/opendatahub-io/opendatahub-operator/v2/apis/services/v1alpha1"
	modelregistryctrl "github.com/opendatahub-io/opendatahub-operator/v2/controllers/components/modelregistry"
	"github.com/opendatahub-io/opendatahub-operator/v2/pkg/cluster/gvk"
	"github.com/opendatahub-io/opendatahub-operator/v2/pkg/metadata/labels"
	"github.com/opendatahub-io/opendatahub-operator/v2/pkg/resources"

	. "github.com/onsi/gomega"
)

var NoOpMutationFn = func(obj *unstructured.Unstructured) error {
	return nil // No operation, just return nil
}

// Namespace and Operator Constants.
const (
	// Namespaces for various components.
	applicationNamespace        = "opendatahub"          // Namespace for the DSCI applications
	knativeServingNamespace     = "knative-serving"      // Namespace for Knative Serving components
	openshiftOperatorsNamespace = "openshift-operators"  // Namespace for OpenShift Operators
	serverlessNamespace         = "openshift-serverless" // Namespace for the Serverless Operator

	// Service Mesh Constants.
	serviceMeshOpName            = "servicemeshoperator" // Name of the Service Mesh Operator
	serverlessOpName             = "serverless-operator" // Name of the Serverless Operator
	serviceMeshControlPlane      = "data-science-smcp"   // Service Mesh control plane name
	serviceMeshNamespace         = "istio-system"        // Namespace for Istio Service Mesh control plane
	serviceMeshMetricsCollection = "Istio"               // Metrics collection for Service Mesh (e.g., Istio)
)

// Timeout & Interval Constants.
const (
	csvWaitTimeout = 5 * time.Minute // Timeout for ClusterServiceVersion readiness

	// General Operation Timeouts and Intervals.
	generalRetryInterval = 10 * time.Second // Retry interval for general operations
	generalWaitTimeout   = 2 * time.Minute  // General timeout for waiting operations

	// Set default timeout for Eventually (default is 1 second).
	defaultEventuallyTimeout = 5 * time.Second
	// Set default timeout for Eventually (default is 1 second).
	defaultEventuallyPollInterval = 100 * time.Millisecond
	// Set default duration for Consistently (default is 2 seconds).
	defaultConsistentlyDuration = 10 * time.Second
	// Set default polling interval for Consistently (default is 50ms).
	defaultConsistentlyPollInterval = 100 * time.Millisecond
)

// Configuration and Miscellaneous Constants.
const (
	ownedNamespaceNumber = 1                       // Number of namespaces owned, adjust to 4 for RHOAI deployment
	deleteConfigMap      = "delete-configmap-name" // ConfigMap name for deletion
	readyStatus          = "Ready"                 // Status indicating a resource is ready

	dsciInstanceName = "e2e-test-dsci" // Instance name for the DSCI
	dscInstanceName  = "e2e-test-dsc"  // Instance name for the DSC
)

// RunTestCases runs a series of test cases, optionally in parallel based on the provided options.
//
// Parameters:
//   - t (*testing.T): The test context passed into the test function.
//   - testCases ([]testCase): A slice of test cases to execute.
//   - opts (...TestCaseOption): Optional configuration options, like enabling parallel execution.
//
// Example usage:
//
//	tc.RunTestCases(t, testCases) // Runs tests sequentially (default)
//	tc.RunTestCases(t, testCases, WithParallel()) // Runs tests in parallel
func (tc *TestContext) RunTestCases(t *testing.T, testCases []testCase, opts ...TestCaseOption) {
	t.Helper()

	// Apply all provided options (e.g., parallel execution) to each test case.
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			// Apply each option to the current test
			for _, opt := range opts {
				opt(t)
			}

			// Run the test function for the current test case
			testCase.testFn(t)
		})
	}
}

// TestCaseOption defines a function type that can be used to modify how individual test cases are executed.
type TestCaseOption func(t *testing.T)

// WithParallel is an option that marks test cases to run in parallel.
func WithParallel() TestCaseOption {
	return func(t *testing.T) {
		t.Helper()

		t.Parallel() // Marks the test case to run in parallel with other tests
	}
}

// EnsureResourceExistsOrNil attempts to retrieve a specific Kubernetes resource from the cluster.
// It retries fetching the resource until the retry window expires. If the resource exists, it returns it.
// If the resource does not exist, it returns nil and does not fail the test, which is useful when subsequent actions
// (such as creating the resource) are intended.
//
// Parameters:
//   - gvk (schema.GroupVersionKind): The GroupVersionKind of the resource being checked.
//   - nn (types.NamespacedName): The namespace and name of the resource.
//   - args (...interface{}): Optional Gomega assertion message arguments. If none are provided, a default message
//     is used for failure when the resource is expected to exist but cannot be found.
//
// Returns:
//   - *unstructured.Unstructured: The resource object if it exists, or nil if not found.
//
// Example Usage:
//
//	resource := tc.EnsureResourceExistsOrNil(gvk, nn)
//
//	if resource == nil {
//	    // Handle case where resource doesn't exist (e.g., create it)
//	} else {
//	    // Resource exists, proceed with further logic
//	}
func (tc *TestContext) EnsureResourceExistsOrNil(
	gvk schema.GroupVersionKind,
	nn types.NamespacedName,
	args ...any,
) *unstructured.Unstructured {
	// Construct a resource identifier.
	resourceID := resources.FormatNamespacedName(nn)

	// Default error message if none is provided
	if len(args) == 0 {
		args = append(args, "Error occurred while fetching the resource '%s' of kind '%s'", resourceID, gvk.Kind)
	}

	// Attempt to get the resource with retries
	var obj *unstructured.Unstructured
	var err error
	tc.g.Eventually(func() error {
		obj, err = tc.g.Get(gvk, nn).Get() // Fetch the resource
		if errors.IsNotFound(err) {
			// Return nil if resource not found
			return nil
		}
		return err // Return any other error
	}).Should(Succeed(), args)

	// Return the resource or nil if it wasn't found
	return obj
}

// EnsureResourceExists verifies whether a specific Kubernetes resource exists by checking its presence in the cluster.
// If the resource doesn't exist, it will fail the test with an error message.
//
// Parameters:
//   - gvk (schema.GroupVersionKind): The GroupVersionKind of the resource being checked.
//   - nn (types.NamespacedName): The namespace and name of the resource.
//   - args (...interface{}): Optional Gomega assertion message arguments. If none are provided, a default message is used.
//
// Returns:
//   - *unstructured.Unstructured: The resource object if it exists.
//
// Example Usage:
//
//	tc.EnsureResourceExists(g, schema.GroupVersionKind{Group: "apps", Version: "v1", Kind: "Deployment"},
//	    types.NamespacedName{Name: "my-deployment", Namespace: "default"})
func (tc *TestContext) EnsureResourceExists(
	gvk schema.GroupVersionKind,
	nn types.NamespacedName,
	args ...any,
) *unstructured.Unstructured {
	return tc.EnsureResourceExistsAndMatchesCondition(gvk, nn, true, BeNil(), args...)
}

// EnsureResourceExistsAndMatchesCondition ensures that the resource exists and matches the given condition.
// It fetches the resource and asserts that it satisfies the specified condition.
//
// Parameters:
//   - gvk (schema.GroupVersionKind): The GroupVersionKind of the resource being checked.
//   - nn (types.NamespacedName): The namespace and name of the resource (used for filtering).
//   - shouldNot (bool): If true, the condition should **not** be satisfied; otherwise, it should.
//   - condition (GomegaMatcher): The Gomega matcher for the condition that the resource should satisfy (e.g., BeNil, BeEmpty, HaveLen).
//   - args (...interface{}): Optional Gomega assertion message arguments. If not provided, a default message is used.
//
// Example Usage:
//
//	tc.EnsureResourceExistsAndMatchesCondition(gvk, nn, BeEmpty(), false, "default/my-deployment", "Deployment")
func (tc *TestContext) EnsureResourceExistsAndMatchesCondition(
	gvk schema.GroupVersionKind,
	nn types.NamespacedName,
	shouldNot bool,
	condition gomegaTypes.GomegaMatcher,
	args ...any,
) *unstructured.Unstructured {
	// Construct a resource identifier.
	resourceID := resources.FormatNamespacedName(nn)

	// Set default error message if none is provided
	if len(args) == 0 {
		args = append(args, "Expected resource '%s' of kind '%s' to exist, but it was not found.", resourceID, gvk.Kind)
	}

	// Ensure the resource exists by using EnsureResourceExistsOrNil
	obj := tc.EnsureResourceExistsOrNil(gvk, nn, args...)

	// Ensure that the resource object is not nil
	tc.g.Expect(obj).ShouldNot(BeNil(), args...)

	// Validate the condition on the resource
	if shouldNot {
		tc.g.Expect(obj).ShouldNot(condition, args...)
	} else {
		tc.g.Expect(obj).Should(condition, args...)
	}

	return obj
}

// EnsureResourcesExist verifies whether a list of specific Kubernetes resources exists in the cluster.
// It waits for the resources to appear and fails the test with a message if any resource is not found within the timeout.
//
// Parameters:
//   - gvk (schema.GroupVersionKind): The GroupVersionKind of the resource being checked.
//   - nn (types.NamespacedName): The namespace and name of the resource.
//   - args (...interface{}): Optional Gomega assertion message arguments. If none are provided, a default message is used.
//
// Returns:
//   - []unstructured.Unstructured: The list of resources if they exist.
//
// Example Usage:
//
//	tc.EnsureResourcesExist(gvk.Deployment, types.NamespacedName{Namespace: "default"})
func (tc *TestContext) EnsureResourcesExist(
	gvk schema.GroupVersionKind,
	nn types.NamespacedName,
	args ...any,
) []unstructured.Unstructured {
	// Construct a resource identifier
	resourceID := resources.FormatNamespacedName(nn)

	// Set default error message if none is provided
	if len(args) == 0 {
		args = append(args, "Expected resource '%s' of kind '%s' to exist, but it was not found.", resourceID, gvk.Kind)
	}

	// Use Eventually to retry getting the resource list until they appear
	var resourcesList []unstructured.Unstructured
	var err error
	tc.g.Eventually(func() error {
		resourcesList, _ = tc.g.List(gvk, &client.ListOptions{Namespace: nn.Namespace}).Get() // Fetch the list of resources
		return err
	}).Should(
		Succeed(),
		"Error occurred while fetching the resources '%s' of kind '%s': %v", resourceID, gvk.Kind, err,
	)

	// Ensure that the resources list is not empty
	tc.g.Expect(resourcesList).ShouldNot(BeEmpty(), args...)

	return resourcesList
}

// EnsureResourceExistsOrCreate ensures that the specified Kubernetes resource exists.
// If the resource is missing, it will attempt to create it; if it already exists, no action is taken.
//
// This function first checks for the resource's existence using its name and namespace. If the resource is not found,
// it will attempt to create it using the provided transformation function, and then verify its presence.
//
// Parameters:
//   - gvk (schema.GroupVersionKind): The GroupVersionKind of the resource being ensured.
//   - nn (types.NamespacedName): The namespace and name of the resource to check or create.
//   - fn (func): A transformation function that will be applied to the resource before creation. It modifies the resource in place (e.g., setting the spec).
//   - args (...any): Optional Gomega assertion message arguments. If none are provided, a default message is used.
//
// Returns:
//   - *unstructured.Unstructured: The resource object if it exists or is successfully created.
//
// Example Usage:
//
//	tc.EnsureResourceExistsOrCreate(
//	    schema.GroupVersionKind{Group: "apps", Version: "v1", Kind: "Deployment"},
//	    types.NamespacedName{Name: "my-deployment", Namespace: "default"},
//	    transformSpecFunction,
//	)
func (tc *TestContext) EnsureResourceExistsOrCreate(
	gvk schema.GroupVersionKind,
	nn types.NamespacedName,
	fn func(obj *unstructured.Unstructured) error,
	args ...any,
) *unstructured.Unstructured {
	// Construct a resource identifier.
	resourceID := resources.FormatNamespacedName(nn)

	// Default error message if no arguments are provided
	if len(args) == 0 {
		args = append(args, "Expected resource '%s' of kind '%s' to exist, but it was not found and could not be created.", resourceID, gvk.Kind)
	}

	// Ensure that the resource exists, retrying if necessary
	existingResource := tc.EnsureResourceExistsOrNil(gvk, nn)

	// If the resource doesn't exist, create it
	if existingResource == nil {
		// Create the resource using CreateOrUpdate
		tc.g.CreateOrUpdate(gvk, nn, fn).
			Eventually().
			Should(Succeed(), "Failed to create resource '%s' of kind '%s'", resourceID, gvk.Kind)

		// Verify the object exists after creation
		return tc.EnsureResourceExists(gvk, nn, args...)
	}

	// Resource exists, return the existing resource
	return existingResource
}

// EnsureResourceExistsOrUpdate ensures that a given Kubernetes resource exists.
// If the resource is missing, it will be created; if it already exists, it will be updated
// using the provided mutation function.
//
// This function internally uses `CreateOrUpdate` to guarantee that the resource is present
// in the cluster with the desired state.
//
// Parameters:
//   - gvk (schema.GroupVersionKind): The GroupVersionKind of the resource being created or updated.
//   - nn (types.NamespacedName): The namespace and name of the resource.
//   - fn (func(*unstructured.Unstructured) error): A function to modify the resource before applying it.
//   - args (...interface{}): Optional Gomega assertion message arguments. If none are provided, a default message is used.
//
// Returns:
//   - *unstructured.Unstructured: The existing or newly created (updated) resource object.
//
// Example Usage:
//
//	tc.EnsureResourceExistsOrUpdate(g, schema.GroupVersionKind{Group: "apps", Version: "v1", Kind: "Deployment"},
//	    types.NamespacedName{Name: "my-deployment", Namespace: "default"},
//	    func(obj *unstructured.Unstructured) error {
//	        obj.SetLabels(map[string]string{"app": "my-app"})
//	        return nil
//	    })
func (tc *TestContext) EnsureResourceExistsOrUpdate(
	gvk schema.GroupVersionKind,
	nn types.NamespacedName,
	fn func(obj *unstructured.Unstructured) error,
	args ...any,
) *unstructured.Unstructured {
	// Construct a resource identifier.
	resourceID := resources.FormatNamespacedName(nn)

	// default error message if no arguments are provided
	if len(args) == 0 {
		args = append(args, "Expected resource '%s' of kind '%s' to exist, but it was not found.", resourceID, gvk.Kind)
	}

	// Use Eventually to retry getting the resource until it appears
	var obj *unstructured.Unstructured
	var err error
	tc.g.Eventually(func() error {
		obj, err = tc.g.CreateOrUpdate(gvk, nn, fn).Get() // Fetch the resource
		return err
	}).Should(
		Succeed(),
		"Error occurred while fetching the resource '%s' of kind '%s': %v", resourceID, gvk.Kind, err,
	)

	// Ensure that the resource object is not nil
	tc.g.Expect(obj).ShouldNot(BeNil(), args...)

	return obj
}

// EnsureExactlyOneResourceExists verifies that exactly one instance of a specific Kubernetes resource
// exists by listing the resources in the cluster. If there are none or more than one, it will fail the test.
//
// Parameters:
//   - gvk (schema.GroupVersionKind): The GroupVersionKind of the resource being checked.
//   - nn (types.NamespacedName): The namespace and name of the resource (in this case, used for filtering).
//   - args (...interface{}): Optional Gomega assertion message arguments. If none are provided, a default message is used.
//
// Returns:
//   - *unstructured.Unstructured: The resource object if exactly one exists.
//
// Example Usage:
//
//	tc.EnsureExactlyOneResourceExists(g, schema.GroupVersionKind{Group: "apps", Version: "v1", Kind: "Deployment"},
//	    types.NamespacedName{Name: "my-deployment", Namespace: "default"})
func (tc *TestContext) EnsureExactlyOneResourceExists(
	gvk schema.GroupVersionKind,
	nn types.NamespacedName,
	args ...any,
) *unstructured.Unstructured {
	// Construct a resource identifier.
	resourceID := resources.FormatNamespacedName(nn)

	// Set default error message if none is provided
	if len(args) == 0 {
		args = append(args, "Expected exactly one resource '%s' of kind '%s', but found a different number.", resourceID, gvk.Kind)
	}

	// Use Eventually to retry getting the resources until they appears
	var objList []unstructured.Unstructured
	var err error
	tc.g.Eventually(func() error {
		objList, err = tc.g.List(gvk).Get() // Fetch the resources
		return err
	}).Should(
		Succeed(),
		"Error occurred while listing resources '%s' of kind '%s': %v", resourceID, gvk.Kind, err,
	)

	// Ensure that the resource list is not nil or empty
	tc.g.Expect(objList).ShouldNot(BeEmpty(), args...)

	// Ensure exactly one resource exists
	tc.g.Expect(objList).
		Should(
			HaveLen(1),
			"Expected exactly one resource '%s' of kind '%s', but found %d.", resourceID, gvk.Kind, len(objList),
		)

	return &objList[0]
}

// EnsureResourcesWithLabelsExist verifies that a specified number of resources with the provided labels exist in the cluster.
//
// Parameters:
//   - gvk (schema.GroupVersionKind): The GroupVersionKind of the resource being checked.
//   - matchingLabels (client.MatchingLabels): A label selector to filter the resources.
//   - minCount (int): The minimum number of resources expected to match the label selector.
//   - args (...interface{}): Optional Gomega assertion message arguments. If none are provided, a default message is used.
//
// Example Usage:
//
//	tc.EnsureResourcesWithLabelsExist(g, schema.GroupVersionKind{Group: "apps", Version: "v1", Kind: "Deployment"},
//	    client.MatchingLabels{"app": "my-app"}, 2)
func (tc *TestContext) EnsureResourcesWithLabelsExist(
	gvk schema.GroupVersionKind,
	matchingLabels client.MatchingLabels,
	minCount int,
	args ...any,
) {
	// Set default error message if none is provided
	if len(args) == 0 {
		args = append(args, "Expected %d resources of kind '%s' with labels '%v' to exist.", minCount, gvk.Kind, matchingLabels)
	}

	// List resources of the specified kind with the given label selector
	tc.g.List(
		gvk,
		matchingLabels,
	).Eventually().Should(
		HaveLen(minCount), args...,
	)
}

// EnsureSubscriptionExistsOrCreate ensures that the specified Subscription exists.
// If the Subscription is missing, it will be created; if it already exists, no action is taken.
// This function reuses the `EnsureResourceExistsOrCreate` logic to guarantee that the Subscription
// exists or is created.
//
// Parameters:
//   - name (string): The name of the Subscription.
//   - ns (string): The namespace where the Subscription is expected to exist.
//
// Returns:
//   - *unstructured.Unstructured: The existing or newly created Subscription object as an unstructured resource.
func (tc *TestContext) EnsureSubscriptionExistsOrCreate(
	nn types.NamespacedName,
) *unstructured.Unstructured {
	// Construct a resource identifier.
	resourceID := resources.FormatNamespacedName(nn)

	// Create the subscription object using the necessary values (adapt as needed)
	sub := createSubscription(nn)

	// Ensure the Subscription exists or create it if missing
	return tc.EnsureResourceExistsOrCreate(
		gvk.Subscription,
		types.NamespacedName{Namespace: sub.Namespace, Name: sub.Name},
		testf.TransformSpecToUnstructured(sub.Spec),
		"Failed to ensure Subscription '%s' exists", resourceID,
	)
}

// EnsureResourcesAreEqual ensures that two resources are identical.
// It compares the resources' data using reflection, allowing flexibility with input types.
//
// Parameters:
//   - actualResource (interface{}): The resource that is compared against the expected resource.
//   - expectedResource (interface{}): The resource that is expected to match the actual resource.
//   - args (...interface{}): Optional Gomega assertion message arguments. If none are provided, a default message is used.
//
// Returns:
//   - None (assertion failure will stop execution).
//
// Example Usage:
//
//	tc.EnsureResourcesAreEqual(actualResource, expectedResource)
func (tc *TestContext) EnsureResourcesAreEqual(
	actualResource, expectedResource interface{},
	args ...any,
) {
	// If no args are provided, use a default error message
	if len(args) == 0 {
		args = append(args, "Expected resource to be equal to the actual resource, but they differ.")
	}

	// If both are of the same concrete type, directly compare them
	if reflect.TypeOf(expectedResource) == reflect.TypeOf(actualResource) {
		tc.g.Expect(expectedResource).Should(
			Equal(actualResource),
			args...,
		)
		return
	}

	// If the types are different, perform deeper checks and give a helpful error
	if reflect.TypeOf(expectedResource) != reflect.TypeOf(actualResource) {
		tc.g.Expect(actualResource).Should(
			Equal(expectedResource),
			append(args, fmt.Sprintf("Resource types don't match. Expected %T, but got %T", expectedResource, actualResource))...,
		)
		return
	}

	// If types match but the content might differ, use reflect.DeepEqual to compare them
	tc.g.Expect(reflect.DeepEqual(expectedResource, actualResource)).Should(
		BeTrue(),
		append(args, "Resources are of the same type, but their content differs.")...,
	)
}

// EnsureResourceNotNil verifies that the given resource is not nil and fails the test if it is.
//
// Parameters:
//   - obj (*unstructured.Unstructured): The resource object to check.
//   - resourceID (string): The identifier of the resource (e.g., "namespace/name").
//   - kind (string): The kind of the resource (e.g., "Deployment").
//   - args (...interface{}): Optional Gomega assertion message arguments.
//
// Example Usage:
//
//	obj := tc.EnsureResourceExists(gvk, nn)
//	tc.EnsureResourceNotNil(obj, "default/my-deployment", "Deployment")
func (tc *TestContext) EnsureResourceNotNil(
	obj any,
	args ...any,
) {
	tc.EnsureResourceConditionMet(obj, true, BeNil(), args...)
}

// EnsureResourceCondition verifies that the given resource satisfies or does not satisfy a specified condition,
// based on the `shouldNot` parameter, and fails the test if the expectation is not met.
//
// Parameters:
//   - obj (any): The resource object to check.
//   - shouldNot (bool): If true, the condition should **not** be satisfied; otherwise, it should.
//   - condition (func(any) GomegaMatcher): A Gomega matcher to check (e.g., BeNil, BeEmpty, HaveLen).
//   - args (...interface{}): Optional Gomega assertion message arguments. If not provided, a default message is used.
//
// Example Usage:
//
//	obj := tc.EnsureResourceExists(gvk, nn)
//	tc.EnsureResourceCondition(obj, false, BeNil()) // Expect BeNil() to be true
//	tc.EnsureResourceCondition(obj, true, BeEmpty()) // Expect BeEmpty() to be false
func (tc *TestContext) EnsureResourceConditionMet(
	obj any,
	shouldNot bool,
	condition gomegaTypes.GomegaMatcher,
	args ...any,
) {
	// Convert the input object to unstructured
	u, err := resources.ToUnstructured(obj)
	tc.g.Expect(err).ShouldNot(HaveOccurred(), err)

	// Construct a meaningful resource identifier
	resourceID := resources.FormatUnstructuredName(u)

	// Set a default error message if none is provided
	if len(args) == 0 {
		args = append(args, "Expected resource '%s' of kind '%s' to satisfy condition '%v' but did not.", resourceID, u.GetKind(), condition)
	}

	// Perform the assertion using the custom condition
	if shouldNot {
		tc.g.Expect(obj).ShouldNot(condition, args...)
	} else {
		tc.g.Expect(obj).Should(condition, args...)
	}
}

// EnsureDeploymentReady ensures that the specified Deployment is ready by checking its status and conditions.
//
// This function performs the following steps:
// 1. Ensures that the deployment resource exists using `EnsureResourceExists`.
// 2. Converts the `Unstructured` resource into a `Deployment` object using Kubernetes' runtime conversion.
// 3. Asserts that the `Deployment` condition `DeploymentAvailable` is `True`.
// 4. Verifies that the number of ready replicas in the deployment matches the expected count.
//
// Parameters:
//   - nn (types.NamespacedName): The namespace and name of the deployment to check.
//   - replicas (int32): The expected number of ready replicas for the deployment.
//
// Example Usage:
//
//	tc.EnsureDeploymentReady(g, types.NamespacedName{Namespace: "default", Name: "my-deployment"}, 3)
func (tc *TestContext) EnsureDeploymentReady(
	nn types.NamespacedName,
	replicas int32,
) {
	// Construct a resource identifier.
	resourceID := resources.FormatNamespacedName(nn)

	// Ensure the deployment exists and retrieve the object.
	u := tc.EnsureResourceExists(
		gvk.Deployment,
		nn,
		"Deployment %s was expected to exist but was not found", resourceID,
	)

	// Convert the Unstructured object to a Deployment object
	deployment := &appsv1.Deployment{}
	tc.ConvertUnstructuredToResource(u, deployment)

	// Assert that the deployment contains the necessary condition (DeploymentAvailable) with status "True"
	tc.g.Expect(deployment.Status.Conditions).Should(ContainElement(
		gstruct.MatchFields(gstruct.IgnoreExtras, gstruct.Fields{
			"Type":   Equal(appsv1.DeploymentAvailable),
			"Status": Equal(corev1.ConditionTrue),
		}),
	), "Expected DeploymentAvailable condition to be True for deployment %s", resourceID)

	// Assert the number of ready replicas matches the expected count
	tc.g.Expect(deployment.Status.ReadyReplicas).Should(Equal(replicas),
		"Expected %d ready replicas for deployment, but got %d",
		replicas, resourceID, deployment.Status.ReadyReplicas)
}

// EnsureCRDEstablished ensures that the specified CustomResourceDefinition is fully established.
//
// This function performs the following steps:
// 1. Ensures that the CRD resource exists using `EnsureResourceExists`.
// 2. Converts the `Unstructured` resource into a `CustomResourceDefinition` object using Kubernetes' runtime conversion.
// 3. Asserts that the CRD condition `Established` is `True`.
//
// Parameters:
//   - name (string): The name of the CRD to check.
//
// Example Usage:
//
//	tc.EnsureCRDEstablished(g, "mycustomresources.example.com")
func (tc *TestContext) EnsureCRDEstablished(
	name string,
) {
	// Ensure the CustomResourceDefinition exists and retrieve the object
	u := tc.EnsureResourceExists(
		gvk.CustomResourceDefinition,
		types.NamespacedName{Name: name}, "CRD %s was expected to exist but was not found", name,
	)

	// Convert the Unstructured object to a CustomResourceDefinition object
	crd := &apiextv1.CustomResourceDefinition{}
	tc.ConvertUnstructuredToResource(u, crd)

	// Assert that the CustomResourceDefinition contains the necessary condition (Established) with status "True"
	tc.g.Expect(crd.Status.Conditions).Should(ContainElement(
		gstruct.MatchFields(gstruct.IgnoreExtras, gstruct.Fields{
			"Type":   Equal(apiextv1.Established),
			"Status": Equal(apiextv1.ConditionTrue),
		}),
	), "Expected CRD condition 'Established' to be True for CRD %s", name)
}

// EnsureResourceIsUnique ensures that creating a second instance of a given resource fails.
//
// This function performs the following steps:
// 1. Converts the provided resource object into an `Unstructured` format using `ToUnstructured`.
// 2. Extracts the `GroupVersionKind` (GVK) from the object.
// 3. Ensures that at least one resource of the same kind already exists in the cluster using `EnsureResourceExists`.
// 4. Attempts to create a duplicate resource using `CreateUnstructured`.
// 5. Asserts that the creation attempt fails, ensuring uniqueness constraints are enforced.
//
// Parameters:
//   - tc (*TestContext): The test context that provides access to Gomega and the Kubernetes client.
//   - obj (any): The resource object to create, which must be convertible to an unstructured format.
//
// Returns:
//   - error: Returns nil if the duplicate creation fails as expected, otherwise returns an error.
//
// Example Usage:
//
//	tc.EnsureCRDEstablished(g, "mycustomresources.example.com")
func (tc *TestContext) EnsureResourceIsUnique(
	obj any,
	args ...any,
) {
	// Convert the input object to unstructured
	u, err := resources.ToUnstructured(obj)
	tc.g.Expect(err).ShouldNot(HaveOccurred(), err)

	// Extract GroupVersionKind from the unstructured object
	groupVersionKind := u.GetObjectKind().GroupVersionKind()

	// Ensure that at least one resource of this kind already exists
	tc.EnsureResourceExists(
		groupVersionKind,
		types.NamespacedName{Namespace: u.GetNamespace()},
		"Failed to verify existence of %s", groupVersionKind.Kind,
	)

	// Set default error message if none is provided
	if len(args) == 0 {
		args = append(args, "Expected creation of duplicate %s to fail, but it succeeded.", groupVersionKind.Kind)
	}

	// Attempt to create the duplicate resource, expecting failure
	tc.g.Create(
		u,
		types.NamespacedName{Namespace: u.GetNamespace(), Name: u.GetName()},
	).Eventually().ShouldNot(Succeed(), args...)
}

// EnsureOperatorInstalled ensures that the specified operator is installed and the associated ClusterServiceVersion (CSV) reaches the 'Succeeded' phase.
//
// This function performs the following tasks:
// 1. Retrieves the InstallPlan for the specified operator, using the provided namespace and name (NN).
// 2. Checks whether the InstallPlan is approved. If not, it approves the plan in environments like CI where it's in Manual mode.
// 3. Verifies that the operator's ClusterServiceVersion (CSV) reaches the 'Succeeded' phase.
//
// If the CSV does not reach the 'Succeeded' phase within the specified timeout, the test will fail.
//
// Parameters:
//   - nn (types.NamespacedName): The namespace and name of the operator being installed.
//
// Example Usage:
//
//	tc.EnsureOperatorInstalled(types.NamespacedName{
//	    Namespace: "openshift-operators",
//	    Name: "my-operator",
//	})
//
// The method internally calls `RetrieveInstallPlan` to fetch the InstallPlan, `ApproveInstallPlan` to approve the InstallPlan in case it's not already approved,
// and `RetrieveClusterServiceVersion` to get the associated CSV and confirm its 'Succeeded' phase.
func (tc *TestContext) EnsureOperatorInstalled(nn types.NamespacedName) {
	// Construct a resource identifier.
	resourceID := resources.FormatNamespacedName(nn)

	// Retrieve the InstallPlan
	plan := tc.RetrieveInstallPlan(nn)

	// in CI InstallPlan is in Manual mode
	if !plan.Spec.Approved {
		tc.ApproveInstallPlan(plan)
	}

	tc.g.Eventually(func() bool {
		csv := tc.RetrieveClusterServiceVersion(nn)
		return csv.Status.Phase == "Succeeded"
	}, csvWaitTimeout, generalRetryInterval).
		Should(BeTrue(), "CSV %s did not reach 'Succeeded' phase", resourceID)
}

// DeleteResource verifies whether a specific Kubernetes resource exists and deletes it if found.
//
// Parameters:
//   - t (*testing.T): The test context used for running the test.
//   - kind (schema.GroupVersionKind): The GroupVersionKind of the resource to be deleted.
//   - name (string): The name of the resource to be deleted.
//   - option (...client.DeleteOption): Optional options for the delete operation, such as cascading or propagation policy.
//
// Example Usage:
//
//	tc.DeleteResource(t, schema.GroupVersionKind{Group: "apps", Version: "v1", Kind: "Deployment"},
//	    "my-deployment", client.DeleteOptions{})
func (tc *TestContext) DeleteResource(kind schema.GroupVersionKind, name string, option ...client.DeleteOption) {
	// Ensure the resource exists before attempting deletion
	tc.g.Get(
		kind,
		types.NamespacedName{Name: name},
	).Eventually().ShouldNot(
		BeNil(), "Expected %s instance %s to exist before attempting deletion", kind.Kind, name,
	)

	// Delete the resource if it exists
	tc.g.Delete(
		kind,
		types.NamespacedName{Name: name},
		option...,
	).Eventually().Should(
		Succeed(), "Failed to delete %s instance %s", kind.Kind, name,
	)
}

// ConvertUnstructuredToResource converts the provided Unstructured object to the specified resource type.
// This function performs the conversion and asserts that no error occurs during the conversion process.
//
// The function utilizes Gomega's Expect method to assert that the conversion is successful.
// If the conversion fails, the test will fail.
//
// Parameters:
//   - u (*unstructured.Unstructured): The Unstructured object to be converted.
//   - obj (T): A pointer to the target resource object to which the Unstructured object will be converted. The object must be a pointer to a struct.
//
// Example Usage:
//
//	// Assuming we have an Unstructured object and a resource object of type Subscription
//	var sub *ofapi.Subscription
//	resources.ConvertUnstructuredToResource(u, &sub)
//
//	// This will assert that the conversion was successful, and if not, the test will fail
func (tc *TestContext) ConvertUnstructuredToResource(u *unstructured.Unstructured, obj any) {
	// Convert Unstructured object to the given resource object
	err := resources.FromUnstructured(u, obj)
	tc.g.Expect(err).ShouldNot(HaveOccurred(), "Failed converting %T from Unstructured.Object: %v", obj, u.Object)
}

// RetrieveInstallPlanName retrieves the name of the InstallPlan associated with a subscription.
// It ensures that the subscription exists (or is created) and then retrieves the InstallPlan name.
// This function does not return an error, it will panic if anything goes wrong (such as a missing InstallPlanRef).
//
// Parameters:
//   - name (string): The name of the Subscription to check.
//   - ns (string): The namespace of the Subscription.
//
// Returns:
//   - string: The name of the InstallPlan associated with the Subscription.
func (tc *TestContext) RetrieveInstallPlanName(nn types.NamespacedName) string {
	// Ensure the subscription exists or is created
	u := tc.EnsureSubscriptionExistsOrCreate(nn)

	// Convert the Unstructured object to Subscription and assert no error
	sub := &ofapi.Subscription{}
	tc.ConvertUnstructuredToResource(u, sub)

	// Ensure InstallPlanRef is not nil
	tc.EnsureResourceNotNil(sub.Status.InstallPlanRef)

	// Return the name of the InstallPlan
	return sub.Status.InstallPlanRef.Name
}

// RetrieveInstallPlan retrieves the InstallPlan associated with a Subscription by its name and namespace.
// It ensures the Subscription exists (or is created) and fetches the InstallPlan object by its name and namespace.
//
// Parameters:
//   - name (string): The name of the Subscription to check.
//   - ns (string): The namespace of the Subscription.
//
// Returns:
//   - *ofapi.InstallPlan: The InstallPlan associated with the Subscription.
func (tc *TestContext) RetrieveInstallPlan(nn types.NamespacedName) *ofapi.InstallPlan {
	// Retrieve the InstallPlan name using getInstallPlanName (ensuring Subscription exists if necessary)
	planName := tc.RetrieveInstallPlanName(nn)

	// Ensure the InstallPlan exists or is created
	u := tc.EnsureResourceExists(
		gvk.InstallPlan,
		types.NamespacedName{Namespace: nn.Namespace, Name: planName},
		"InstallPlan %s was expected to exist but was not found", planName,
	)

	// Convert the Unstructured object to an InstallPlan object
	installPlan := &ofapi.InstallPlan{}
	tc.ConvertUnstructuredToResource(u, installPlan)

	// Return the InstallPlan object
	return installPlan
}

// RetrieveClusterServiceVersion retrieves a ClusterServiceVersion (CSV) for an operator by name and namespace.
// If the CSV does not exist, the function will fail the test using Gomega assertions.
//
// Parameters:
//   - name (string): The name of the ClusterServiceVersion to retrieve.
//   - ns (string): The namespace where the ClusterServiceVersion is expected to be found.
//
// Returns:
//   - *ofapi.ClusterServiceVersion: A pointer to the retrieved ClusterServiceVersion object.
//
// Example Usage:
//
//	csv := tc.RetrieveClusterServiceVersion("my-operator", "openshift-operators")
func (tc *TestContext) RetrieveClusterServiceVersion(nn types.NamespacedName) *ofapi.ClusterServiceVersion {
	// Construct a resource identifier.
	resourceID := resources.FormatNamespacedName(nn)

	// Retrieve the list of CSVs using EnsureResourcesExist
	csvList := tc.EnsureResourcesExist(gvk.ClusterServiceVersion, nn)

	// Check if the CSV list contains the expected CSV by name
	var csv ofapi.ClusterServiceVersion
	for _, item := range csvList {
		if item.GetName() == nn.Name {
			// Convert the Unstructured object to ClusterServiceVersion and assert no error
			tc.ConvertUnstructuredToResource(&item, csv)
			break
		}
	}

	// Assert that we found the CSV
	tc.g.Expect(csv).ShouldNot(BeNil(), "CSV %s not found", resourceID)

	return &csv
}

// ApproveInstallPlan approves the provided InstallPlan by applying a patch to update its approval status.
//
// This function performs the following steps:
// 1. Prepares the InstallPlan object with the necessary changes to approve it.
// 2. Sets up patch options, including force applying the patch with the specified field manager.
// 3. Applies the patch to update the InstallPlan, marking it as approved automatically.
// 4. Asserts that no error occurs during the patch application process.
//
// Parameters:
//   - plan (*ofapi.InstallPlan): The InstallPlan object that needs to be approved.
//
// Example Usage:
//
//	tc.ApproveInstallPlan(plan)
func (tc *TestContext) ApproveInstallPlan(plan *ofapi.InstallPlan) {
	// Prepare the InstallPlan object to be approved
	obj := createInstallPlan(plan.ObjectMeta.Name, plan.ObjectMeta.Namespace, plan.Spec.ClusterServiceVersionNames)

	// Set up patch options
	force := true
	opt := &client.PatchOptions{
		FieldManager: dscInstanceName,
		Force:        &force,
	}

	// Apply the patch to approve the InstallPlan
	err := tc.Client().Patch(tc.Context(), obj, client.Apply, opt)
	tc.g.Expect(err).
		ShouldNot(
			HaveOccurred(),
			"Failed to approve InstallPlan %s in namespace %s: %v", obj.ObjectMeta.Name, obj.ObjectMeta.Namespace, err,
		)
}

// createDSCI creates a DSCInitialization CR.
func createDSCI(name string) *dsciv1.DSCInitialization {
	dsciTest := &dsciv1.DSCInitialization{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: dsciv1.DSCInitializationSpec{
			ApplicationsNamespace: applicationNamespace,
			Monitoring: serviceApi.DSCMonitoring{
				ManagementSpec: common.ManagementSpec{
					ManagementState: operatorv1.Removed, // keep rhoai branch to Managed so we can test it
				},
				MonitoringCommonSpec: serviceApi.MonitoringCommonSpec{
					Namespace: applicationNamespace,
				},
			},
			TrustedCABundle: &dsciv1.TrustedCABundleSpec{
				ManagementState: operatorv1.Managed,
				CustomCABundle:  "",
			},
			ServiceMesh: &infrav1.ServiceMeshSpec{
				ControlPlane: infrav1.ControlPlaneSpec{
					MetricsCollection: "Istio",
					Name:              serviceMeshControlPlane,
					Namespace:         serviceMeshNamespace,
				},
				ManagementState: operatorv1.Managed,
			},
		},
	}
	return dsciTest
}

// createDSC creates a DataScienceCluster CR.
func createDSC(name string) *dscv1.DataScienceCluster {
	dscTest := &dscv1.DataScienceCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: dscv1.DataScienceClusterSpec{
			Components: dscv1.Components{
				// keep dashboard as enabled, because other test is rely on this
				Dashboard: componentApi.DSCDashboard{
					ManagementSpec: common.ManagementSpec{
						ManagementState: operatorv1.Removed,
					},
				},
				Workbenches: componentApi.DSCWorkbenches{
					ManagementSpec: common.ManagementSpec{
						ManagementState: operatorv1.Removed,
					},
				},
				ModelMeshServing: componentApi.DSCModelMeshServing{
					ManagementSpec: common.ManagementSpec{
						ManagementState: operatorv1.Removed,
					},
				},
				DataSciencePipelines: componentApi.DSCDataSciencePipelines{
					ManagementSpec: common.ManagementSpec{
						ManagementState: operatorv1.Removed,
					},
					DataSciencePipelinesCommonSpec: componentApi.DataSciencePipelinesCommonSpec{
						PreloadedPipelines: datasciencepipelines.ManagedPipelinesSpec{
							InstructLab: datasciencepipelines.ManagedPipelineOptions{
								State: operatorv1.Removed,
							},
						},
					},
				},
				Kserve: componentApi.DSCKserve{
					ManagementSpec: common.ManagementSpec{
						ManagementState: operatorv1.Removed,
					},
					KserveCommonSpec: componentApi.KserveCommonSpec{
						DefaultDeploymentMode: componentApi.Serverless,
						Serving: infrav1.ServingSpec{
							ManagementState: operatorv1.Managed,
							Name:            knativeServingNamespace,
							IngressGateway: infrav1.GatewaySpec{
								Certificate: infrav1.CertificateSpec{
									Type: infrav1.OpenshiftDefaultIngress,
								},
							},
						},
					},
				},
				CodeFlare: componentApi.DSCCodeFlare{
					ManagementSpec: common.ManagementSpec{
						ManagementState: operatorv1.Removed,
					},
				},
				Ray: componentApi.DSCRay{
					ManagementSpec: common.ManagementSpec{
						ManagementState: operatorv1.Removed,
					},
				},
				Kueue: componentApi.DSCKueue{
					ManagementSpec: common.ManagementSpec{
						ManagementState: operatorv1.Removed,
					},
				},
				TrustyAI: componentApi.DSCTrustyAI{
					ManagementSpec: common.ManagementSpec{
						ManagementState: operatorv1.Removed,
					},
				},
				ModelRegistry: componentApi.DSCModelRegistry{
					ManagementSpec: common.ManagementSpec{
						ManagementState: operatorv1.Removed,
					},
					ModelRegistryCommonSpec: componentApi.ModelRegistryCommonSpec{
						RegistriesNamespace: modelregistryctrl.DefaultModelRegistriesNamespace,
					},
				},
				TrainingOperator: componentApi.DSCTrainingOperator{
					ManagementSpec: common.ManagementSpec{
						ManagementState: operatorv1.Removed,
					},
				},
				FeastOperator: componentApi.DSCFeastOperator{
					ManagementSpec: common.ManagementSpec{
						ManagementState: operatorv1.Removed,
					},
				},
			},
		},
	}

	return dscTest
}

// createSubscription creates a Subscription object.
func createSubscription(nn types.NamespacedName) *ofapi.Subscription {
	return &ofapi.Subscription{
		TypeMeta: metav1.TypeMeta{
			Kind:       operatorsv1alpha1.SubscriptionKind,
			APIVersion: operatorsv1alpha1.SubscriptionCRDAPIVersion,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      nn.Name,
			Namespace: nn.Namespace,
		},
		Spec: &ofapi.SubscriptionSpec{
			CatalogSource:          "redhat-operators",
			CatalogSourceNamespace: "openshift-marketplace",
			Channel:                "stable",
			Package:                nn.Name,
			InstallPlanApproval:    ofapi.ApprovalAutomatic,
		},
	}
}

// createSubscription creates an InstallPlan object.
func createInstallPlan(name string, ns string, csvNames []string) *ofapi.InstallPlan {
	return &ofapi.InstallPlan{
		TypeMeta: metav1.TypeMeta{
			Kind:       operatorsv1alpha1.InstallPlanKind,
			APIVersion: operatorsv1alpha1.InstallPlanAPIVersion,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: ns,
		},
		Spec: ofapi.InstallPlanSpec{
			Approved:                   true,
			Approval:                   ofapi.ApprovalAutomatic,
			ClusterServiceVersionNames: csvNames,
		},
	}
}

// mockCRDCreation generates a mock CustomResourceDefinition for a given group, version, kind, and component name.
func mockCRDCreation(group, version, kind, componentName string) *apiextv1.CustomResourceDefinition {
	return &apiextv1.CustomResourceDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name: strings.ToLower(fmt.Sprintf("%ss.%s", kind, group)),
			Labels: map[string]string{
				labels.ODH.Component(componentName): labels.True,
			},
		},
		Spec: apiextv1.CustomResourceDefinitionSpec{
			Group: group,
			Names: apiextv1.CustomResourceDefinitionNames{
				Kind:   kind,
				Plural: strings.ToLower(kind) + "s",
			},
			Scope: apiextv1.ClusterScoped,
			Versions: []apiextv1.CustomResourceDefinitionVersion{
				{
					Name:    version,
					Served:  true,
					Storage: true,
					Schema: &apiextv1.CustomResourceValidation{
						OpenAPIV3Schema: &apiextv1.JSONSchemaProps{
							Type: "object",
						},
					},
				},
			},
		},
	}
}
