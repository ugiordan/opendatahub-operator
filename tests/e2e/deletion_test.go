package e2e_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/opendatahub-io/opendatahub-operator/v2/pkg/cluster/gvk"
)

type DeletionTestCtx struct {
	*TestContext
}

func deletionTestSuite(t *testing.T) {
	t.Helper()

	// Initialize the test context.
	tc, err := NewTestContext(t)
	require.NoError(t, err, "Failed to initialize test context")

	// Create an instance of test context.
	deletionTestCtx := DeletionTestCtx{
		TestContext: tc,
	}

	// Define the test cases
	testCases := []testCase{
		{"Deletion DSC instance", deletionTestCtx.testDeletionExistDSC},
		{"Deletion DSCI instance", deletionTestCtx.testDeletionExistDSCI},
	}

	// Run the test suite using the helper function.
	deletionTestCtx.RunTestCases(t, testCases)
}

// testDeletionExistDSC deletes the DataScienceCluster instance if it exists.
func (tc *TestContext) testDeletionExistDSC(t *testing.T) {
	t.Helper()

	// Delete the DSC instance
	tc.DeleteResource(gvk.DataScienceCluster, tc.TestDsc.Name)
}

// testDeletionExistDSCI deletes the DSCInitialization instance if it exists.
func (tc *TestContext) testDeletionExistDSCI(t *testing.T) {
	t.Helper()

	// Delete the DSCI instance
	tc.DeleteResource(gvk.DSCInitialization, tc.TestDSCI.Name)
}
