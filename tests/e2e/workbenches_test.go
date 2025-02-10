package e2e_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	componentApi "github.com/opendatahub-io/opendatahub-operator/v2/apis/components/v1alpha1"
)

func workbenchesTestSuite(t *testing.T) {
	t.Helper()

	ct, err := NewComponentTestCtx(&componentApi.Kserve{})
	require.NoError(t, err)

	componentCtx := WorkbenchesTestCtx{
		ComponentTestCtx: ct,
	}

	require.NoError(t, err)

	t.Run("Validate component enabled", componentCtx.ValidateComponentEnabled)
	t.Run("Validate component spec", componentCtx.ValidateOperandsOwnerReferences)
	t.Run("Validate operands have OwnerReferences", componentCtx.ValidateOperandsOwnerReferences)
	t.Run("Validate update operand resources", componentCtx.ValidateUpdateDeploymentsResources)
	t.Run("Validate component releases", componentCtx.ValidateComponentReleases)
	t.Run("Validate component disabled", componentCtx.ValidateComponentDisabled)
}

type WorkbenchesTestCtx struct {
	*ComponentTestCtx
}
