package servicemesh

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/hashicorp/go-multierror"
	corev1 "k8s.io/api/core/v1"
	k8serr "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/util/wait"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/opendatahub-io/opendatahub-operator/v2/pkg/cluster"
	"github.com/opendatahub-io/opendatahub-operator/v2/pkg/cluster/gvk"
	"github.com/opendatahub-io/opendatahub-operator/v2/pkg/feature"
	"github.com/opendatahub-io/opendatahub-operator/v2/pkg/metadata/labels"
)

const (
	interval = 10 * time.Second
	duration = 5 * time.Minute
)

// EnsureAuthNamespaceExists creates a namespace for the Authorization provider and set ownership so it will be garbage collected when the operator is uninstalled.
func EnsureAuthNamespaceExists(ctx context.Context, cli client.Client, f *feature.Feature) error {
	authNs, err := FeatureData.Authorization.Namespace.Extract(f)
	if err != nil {
		return fmt.Errorf("could not get auth from feature: %w", err)
	}

	_, err = cluster.CreateNamespace(ctx, cli, authNs, feature.OwnedBy(f), cluster.WithLabels(labels.ODH.OwnedNamespace, "true"))
	return err
}

func EnsureServiceMeshOperatorInstalled(ctx context.Context, cli client.Client, f *feature.Feature) error {
	if err := feature.EnsureOperatorIsInstalled("servicemeshoperator")(ctx, cli, f); err != nil {
		return fmt.Errorf("failed to find the pre-requisite Service Mesh Operator subscription, please ensure Service Mesh Operator is installed. %w", err)
	}
	// Extra check SMCP CRD is installed and is active.
	if err := cluster.CustomResourceDefinitionExists(ctx, cli, gvk.ServiceMeshControlPlane.GroupKind()); err != nil {
		return fmt.Errorf("failed to find the Service Mesh Control Plane CRD, please ensure Service Mesh Operator is installed. %w", err)
	}
	// Extra check smcp validation service is running.
	validationService := &corev1.Service{}
	if err := cli.Get(ctx, client.ObjectKey{
		Name:      "istio-operator-service",
		Namespace: "openshift-operators",
	}, validationService); err != nil {
		if k8serr.IsNotFound(err) {
			return fmt.Errorf("failed to find the Service Mesh VWC service, please ensure Service Mesh Operator is running. %w", err)
		}
		return fmt.Errorf("failed to find the Service Mesh VWC service. %w", err)
	}

	return nil
}

func EnsureServiceMeshInstalled(ctx context.Context, cli client.Client, f *feature.Feature) error {
	if err := EnsureServiceMeshOperatorInstalled(ctx, cli, f); err != nil {
		return err
	}

	if err := WaitForControlPlaneToBeReady(ctx, cli, f); err != nil {
		controlPlane, errGet := FeatureData.ControlPlane.Extract(f)
		if errGet != nil {
			return fmt.Errorf("failed to get control plane struct: %w", err)
		}

		f.Log.Error(err, "failed waiting for control plane being ready", "control-plane", controlPlane.Name, "namespace", controlPlane.Namespace)

		return multierror.Append(err, errors.New("service mesh control plane is not ready")).ErrorOrNil()
	}

	return nil
}

func WaitForControlPlaneToBeReady(ctx context.Context, cli client.Client, f *feature.Feature) error {
	controlPlane, err := FeatureData.ControlPlane.Extract(f)
	if err != nil {
		return err
	}

	smcp := controlPlane.Name
	smcpNs := controlPlane.Namespace

	f.Log.Info("waiting for control plane components to be ready", "control-plane", smcp, "namespace", smcpNs, "duration (s)", duration.Seconds())

	backoff := wait.Backoff{
		Duration: interval,
		Factor:   2.0,
		Steps:    5,
	}
	// 5 minute timeout
	return wait.ExponentialBackoffWithContext(ctx, backoff, func(ctx context.Context) (bool, error) {
		ready, err := CheckControlPlaneComponentReadiness(ctx, cli, smcp, smcpNs)
		if err != nil {
			return false, err
		}

		if ready {
			f.Log.Info("done waiting for control plane components to be ready", "control-plane", smcp, "namespace", smcpNs)
		}

		return ready, nil
	})
}

func CheckControlPlaneComponentReadiness(ctx context.Context, c client.Client, smcpName, smcpNs string) (bool, error) {
	smcpObj := &unstructured.Unstructured{}
	smcpObj.SetGroupVersionKind(gvk.ServiceMeshControlPlane)
	err := c.Get(ctx, client.ObjectKey{
		Namespace: smcpNs,
		Name:      smcpName,
	}, smcpObj)

	switch {
	case k8serr.IsNotFound(err):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("failed to get Service Mesh Control Plane: %w", err)
	}

	components, found, err := unstructured.NestedMap(smcpObj.Object, "status", "readiness", "components")
	if err != nil {
		return false, fmt.Errorf("status conditions not found or error in parsing of Service Mesh Control Plane: %w", err)
	}
	if !found {
		return false, nil
	}

	readyComponents := len(components["ready"].([]interface{}))     //nolint:forcetypeassert,errcheck
	pendingComponents := len(components["pending"].([]interface{})) //nolint:forcetypeassert,errcheck
	unreadyComponents := len(components["unready"].([]interface{})) //nolint:forcetypeassert,errcheck

	return pendingComponents == 0 && unreadyComponents == 0 && readyComponents > 0, nil
}
