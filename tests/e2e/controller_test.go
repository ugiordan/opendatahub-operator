package e2e_test

import (
	"flag"
	"fmt"
	"k8s.io/apimachinery/pkg/types"
	"os"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"slices"
	"strings"
	"testing"

	operatorv1 "github.com/openshift/api/operator/v1"
	routev1 "github.com/openshift/api/route/v1"
	ofapiv1 "github.com/operator-framework/api/pkg/operators/v1"
	ofapi "github.com/operator-framework/api/pkg/operators/v1alpha1"
	monitoringv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"
	"golang.org/x/exp/maps"
	autoscalingv1 "k8s.io/api/autoscaling/v1"
	apiextv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	"github.com/opendatahub-io/opendatahub-operator/v2/apis/common"
	componentApi "github.com/opendatahub-io/opendatahub-operator/v2/apis/components/v1alpha1"
	dscv1 "github.com/opendatahub-io/opendatahub-operator/v2/apis/datasciencecluster/v1"
	dsciv1 "github.com/opendatahub-io/opendatahub-operator/v2/apis/dscinitialization/v1"
	featurev1 "github.com/opendatahub-io/opendatahub-operator/v2/apis/features/v1"
	serviceApi "github.com/opendatahub-io/opendatahub-operator/v2/apis/services/v1alpha1"
	"github.com/opendatahub-io/opendatahub-operator/v2/pkg/cluster"
	"github.com/opendatahub-io/opendatahub-operator/v2/pkg/utils/test/testf"
)

type TestFn func(t *testing.T)

var (
	testOpts testContextConfig
	Scheme   = runtime.NewScheme()

	componentsTestSuites = map[string]TestFn{
		// do not add modelcontroller here, due to dependency, test it separately below
		componentApi.DashboardComponentName:            dashboardTestSuite,
		componentApi.RayComponentName:                  rayTestSuite,
		componentApi.ModelRegistryComponentName:        modelRegistryTestSuite,
		componentApi.TrustyAIComponentName:             trustyAITestSuite,
		componentApi.KueueComponentName:                kueueTestSuite,
		componentApi.TrainingOperatorComponentName:     trainingOperatorTestSuite,
		componentApi.DataSciencePipelinesComponentName: dataSciencePipelinesTestSuite,
		componentApi.CodeFlareComponentName:            codeflareTestSuite,
		componentApi.WorkbenchesComponentName:          workbenchesTestSuite,
		componentApi.KserveComponentName:               kserveTestSuite,
		componentApi.ModelMeshServingComponentName:     modelMeshServingTestSuite,
		componentApi.ModelControllerComponentName:      modelControllerTestSuite,
		componentApi.FeastOperatorComponentName:        feastOperatorTestSuite,
	}

	servicesTestSuites = map[string]TestFn{
		serviceApi.MonitoringServiceName: monitoringTestSuite,
		serviceApi.AuthServiceName:       authControllerTestSuite,
	}
)

type arrayFlags []string

// String returns the string representation of the arrayFlags.
func (i *arrayFlags) String() string {
	return fmt.Sprintf("%v", *i)
}

// Set appends a new value to the arrayFlags.
func (i *arrayFlags) Set(value string) error {
	*i = append(*i, value)
	return nil
}

type testCase struct {
	name   string
	testFn func(t *testing.T)
}

type testContextConfig struct {
	operatorNamespace string
	skipDeletion      bool

	operatorControllerTest bool
	webhookTest            bool
	components             arrayFlags
	services               arrayFlags
}

// TestContext holds information specific to individual tests.
type TestContext struct {
	// Embeds the common test context.
	*testf.TestContext

	// Shared Gomega test wrapper.
	g *testf.WithT

	// Namespace of the operator.
	OperatorNamespace string

	// Namespace of the deployed applications.
	ApplicationNamespace string

	// Test DataScienceCluster instance.
	DSC *dscv1.DataScienceCluster

	// Namespaced name of the test DataScienceCluster instance.
	DSCNamespacedName types.NamespacedName

	// Test DSCInitialization CR instance (not created by default in ODH).
	DSCI *dsciv1.DSCInitialization

	// Namespaced name of the test DSCInitialization CR instance.
	DSCINamespacedName types.NamespacedName

	// Test platform.
	Platform common.Platform

	// Test configuration options.
	TestOpts testContextConfig
}

// NewTestContext initializes a new test context.
func NewTestContext(t *testing.T) (*TestContext, error) { //nolint:thelper
	tcf, err := testf.NewTestContext(
		testf.WithTOptions(
			testf.WithEventuallyTimeout(defaultEventuallyTimeout),
			testf.WithEventuallyPollingInterval(defaultEventuallyPollInterval),
			testf.WithConsistentlyDuration(defaultConsistentlyDuration),
			testf.WithConsistentlyPollingInterval(defaultConsistentlyPollInterval),
		),
	)

	if err != nil {
		return nil, err
	}

	release := cluster.GetRelease()

	// setup DSCI and DataScienceCluster CRs since we do not create automatically by operator
	testDSCI := CreateDSCI(dsciInstanceName)
	testDSC := CreateDSC(dscInstanceName)

	return &TestContext{
		TestContext:          tcf,
		g:                    tcf.NewWithT(t),
		OperatorNamespace:    testOpts.operatorNamespace,
		ApplicationNamespace: testDSCI.Spec.ApplicationsNamespace,
		DSC:                  testDSC,
		DSCNamespacedName:    client.ObjectKeyFromObject(testDSCI),
		DSCI:                 testDSCI,
		DSCINamespacedName:   client.ObjectKeyFromObject(testDSCI),
		Platform:             release.Name,
		TestOpts:             testOpts,
	}, nil
}

// TestOdhOperator sets up the testing suite for ODH Operator.
func TestOdhOperator(t *testing.T) {
	registerSchemes()

	log.SetLogger(zap.New(zap.UseDevMode(true)))

	if testOpts.operatorControllerTest {
		// individual test suites after the operator is running
		if !t.Run("ODH Manager E2E Tests", odhOperatorTestSuite) {
			return
		}
	}

	// Run create and delete tests for all the components
	t.Run("DSC/DSCI management E2E Tests", dscManagementTestSuite)

	runTestSuites(t, "Components E2E Tests", testOpts.components, componentsTestSuites)
	runTestSuites(t, "Services E2E Tests", testOpts.services, servicesTestSuites)

	// Run deletion if skipDeletion is not set
	if !testOpts.skipDeletion {
		if testOpts.operatorControllerTest {
			// this is a negative test case, since by using the positive CM('true'), even CSV gets deleted which leaves no operator pod in prow
			t.Run("Deletion ConfigMap E2E Tests", cfgMapDeletionTestSuite)
		}

		t.Run("DSC/DSCI Deletion E2E Tests", deletionTestSuite)
	}
}

func TestMain(m *testing.M) {
	// call flag.Parse() here if TestMain uses flags
	flag.StringVar(&testOpts.operatorNamespace, "operator-namespace", "opendatahub-operator-system", "Namespace where the odh operator is deployed")
	flag.BoolVar(&testOpts.skipDeletion, "skip-deletion", false, "skip deletion of the controllers")

	flag.BoolVar(&testOpts.operatorControllerTest, "test-operator-controller", true, "run operator controller tests")
	flag.BoolVar(&testOpts.webhookTest, "test-webhook", true, "run webhook tests")

	validateSelection(testOpts.components, componentsTestSuites, "test-component")
	validateSelection(testOpts.services, servicesTestSuites, "test-service")

	flag.Parse()
	os.Exit(m.Run())
}

// registerSchemes registers all necessary schemes for testing.
func registerSchemes() {
	schemes := []func(*runtime.Scheme) error{
		clientgoscheme.AddToScheme,
		routev1.AddToScheme,
		apiextv1.AddToScheme,
		autoscalingv1.AddToScheme,
		dsciv1.AddToScheme,
		dscv1.AddToScheme,
		featurev1.AddToScheme,
		monitoringv1.AddToScheme,
		ofapi.AddToScheme,
		operatorv1.AddToScheme,
		componentApi.AddToScheme,
		serviceApi.AddToScheme,
		ofapiv1.AddToScheme,
	}

	for _, schemeFn := range schemes {
		utilruntime.Must(schemeFn(Scheme))
	}
}

// runTestSuites executes test suites for the given category.
func runTestSuites(t *testing.T, category string, selectedTests arrayFlags, testSuites map[string]TestFn) {
	t.Helper()

	t.Run(category, func(t *testing.T) {
		for name, testFn := range testSuites {
			if len(selectedTests) > 0 && !slices.Contains(selectedTests, name) {
				t.Logf("Skipping %s: %s", category, name)
				continue
			}
			t.Run(name, testFn)
		}
	})
}

// validateSelection ensures selected components or services are valid test names.
func validateSelection(selection arrayFlags, validTests map[string]TestFn, flagName string) {
	validNames := strings.Join(maps.Keys(validTests), ", ")
	flag.Var(&selection, flagName, "Run tests for the specified "+flagName+". Valid values are: "+validNames)

	for _, name := range selection {
		if _, ok := validTests[name]; !ok {
			fmt.Printf("%s: unknown value %s, valid values are: %s\n", flagName, name, strings.Join(maps.Keys(validTests), ", "))
			os.Exit(1)
		}
	}
}
