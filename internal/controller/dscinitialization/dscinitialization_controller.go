/*
Copyright 2023.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package dscinitialization contains controller logic of CRD DSCInitialization.
package dscinitialization

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"
	"time"

	operatorv1 "github.com/openshift/api/operator/v1"
	corev1 "k8s.io/api/core/v1"
	k8serr "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/retry"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/opendatahub-io/operator-security-runtime/pkg/rbacscope"

	dscv2 "github.com/opendatahub-io/opendatahub-operator/v2/api/datasciencecluster/v2"
	dsciv2 "github.com/opendatahub-io/opendatahub-operator/v2/api/dscinitialization/v2"
	featuresv1 "github.com/opendatahub-io/opendatahub-operator/v2/api/features/v1"
	infrav1 "github.com/opendatahub-io/opendatahub-operator/v2/api/infrastructure/v1"
	serviceApi "github.com/opendatahub-io/opendatahub-operator/v2/api/services/v1alpha1"
	"github.com/opendatahub-io/opendatahub-operator/v2/internal/controller/services/gateway"
	"github.com/opendatahub-io/opendatahub-operator/v2/internal/controller/status"
	"github.com/opendatahub-io/opendatahub-operator/v2/pkg/cluster"
	"github.com/opendatahub-io/opendatahub-operator/v2/pkg/cluster/gvk"
	rp "github.com/opendatahub-io/opendatahub-operator/v2/pkg/controller/predicates/resources"
	"github.com/opendatahub-io/opendatahub-operator/v2/pkg/deploy"
	"github.com/opendatahub-io/opendatahub-operator/v2/pkg/logger"
	"github.com/opendatahub-io/opendatahub-operator/v2/pkg/resources"
	"github.com/opendatahub-io/opendatahub-operator/v2/pkg/upgrade"
)

const (
	finalizerName = "dscinitialization.opendatahub.io/finalizer"
	fieldManager  = "dscinitialization.opendatahub.io"
)

// DSCInitializationReconciler reconciles a DSCInitialization object.
type DSCInitializationReconciler struct {
	Client       client.Client
	Scheme       *runtime.Scheme
	Recorder     record.EventRecorder
	SecretScoper *rbacscope.RBACScoper

	// provisionedSecretScopes tracks namespaces where scoped secrets access
	// has been successfully provisioned. Cleared per-namespace on drift
	// (via Role/RoleBinding watches) and fully reset on pod restart.
	provisionedSecretScopes sync.Map
}

// Reconcile contains controller logic specific to DSCInitialization instance updates.
func (r *DSCInitializationReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) { //nolint:funlen,gocyclo,maintidx
	log := logf.FromContext(ctx).WithName("DSCInitialization")
	log.Info("Reconciling DSCInitialization.", "DSCInitialization Request.Name", req.Name)

	currentOperatorRelease := cluster.GetRelease()
	// Set platform
	platform := currentOperatorRelease.Name

	instance, err := cluster.GetDSCI(ctx, r.Client)
	switch {
	case k8serr.IsNotFound(err):
		return ctrl.Result{}, nil
	case err != nil:
		log.Error(err, "Failed to retrieve DSCInitialization resource.", "DSCInitialization Request.Name", req.Name)

		ref := &corev1.ObjectReference{Name: req.Name, Namespace: req.Namespace}
		ref.SetGroupVersionKind(gvk.DSCInitialization)

		r.Recorder.Eventf(ref, corev1.EventTypeWarning, "DSCInitializationReconcileError", "Failed to retrieve DSCInitialization instance")

		return ctrl.Result{}, err
	}

	if instance.Spec.DevFlags != nil {
		level := instance.Spec.DevFlags.LogLevel
		log.V(1).Info("Setting log level", "level", level)
		if err := logger.SetLevel(level); err != nil {
			log.Error(err, "Failed to set log level", "level", level)
		}
	}

	if instance.DeletionTimestamp.IsZero() {
		if !controllerutil.ContainsFinalizer(instance, finalizerName) {
			log.Info("Adding finalizer for DSCInitialization", "name", instance.Name, "finalizer", finalizerName)
			controllerutil.AddFinalizer(instance, finalizerName)
			if err := r.Client.Update(ctx, instance); err != nil {
				return ctrl.Result{}, err
			}
		}
	} else {
		log.Info("Finalization DSCInitialization start deleting instance", "name", instance.Name, "finalizer", finalizerName)

		// Clean up dynamically scoped secrets access across all namespaces
		if r.SecretScoper != nil {
			if err := r.SecretScoper.CleanupAllAccess(ctx, instance); err != nil {
				log.Error(err, "Failed to cleanup scoped secrets access")
				return ctrl.Result{}, err
			}
			log.Info("Cleaned up scoped secrets access")
			// Clear in-memory tracking so DSCI recreation re-provisions all namespaces.
			r.provisionedSecretScopes = sync.Map{}
		}

		err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
			newInstance := &dsciv2.DSCInitialization{}
			if err := r.Client.Get(ctx, client.ObjectKeyFromObject(instance), newInstance); err != nil {
				return err
			}
			if controllerutil.ContainsFinalizer(newInstance, finalizerName) {
				controllerutil.RemoveFinalizer(newInstance, finalizerName)
				if err := r.Client.Update(ctx, newInstance); err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			log.Error(err, "Failed to remove finalizer when deleting DSCInitialization instance")
			return ctrl.Result{}, err
		}

		return ctrl.Result{}, nil
	}

	// Start reconciling
	if instance.Status.Conditions == nil {
		reason := status.ReconcileInit
		message := "Initializing DSCInitialization resource"
		instance, err := status.UpdateWithRetry(ctx, r.Client, instance, func(saved *dsciv2.DSCInitialization) {
			status.SetProgressingCondition(&saved.Status.Conditions, reason, message)
			saved.Status.Phase = status.PhaseProgressing
			saved.Status.Release = currentOperatorRelease
		})
		if err != nil {
			log.Error(err, "Failed to add conditions to status of DSCInitialization resource.", "DSCInitialization", req.Namespace, "Request.Name", req.Name)
			r.Recorder.Eventf(instance, corev1.EventTypeWarning, "DSCInitializationReconcileError",
				"%s for instance %s", message, instance.Name)

			return reconcile.Result{}, err
		}
	}

	// upgrade case to update release version in status
	if !instance.Status.Release.Version.Equals(currentOperatorRelease.Version.Version) {
		message := "Updating DSCInitialization status"
		instance, err := status.UpdateWithRetry(ctx, r.Client, instance, func(saved *dsciv2.DSCInitialization) {
			saved.Status.Release = currentOperatorRelease
		})
		if err != nil {
			log.Error(err, "Failed to update release version for DSCInitialization resource.", "DSCInitialization", req.Namespace, "Request.Name", req.Name)
			r.Recorder.Eventf(instance, corev1.EventTypeWarning, "DSCInitializationReconcileError",
				"%s for instance %s", message, instance.Name)
			return reconcile.Result{}, err
		}
	}

	// Deal with application namespace, configmap, networpolicy etc
	if err := r.createOperatorResource(ctx, instance, platform); err != nil {
		if _, err := status.UpdateWithRetry(ctx, r.Client, instance, func(saved *dsciv2.DSCInitialization) {
			status.SetProgressingCondition(&saved.Status.Conditions, status.ReconcileFailed, err.Error())
			saved.Status.Phase = status.PhaseError
		}); err != nil {
			log.Error(err, "Failed to update DSCInitialization conditions", "DSCInitialization", req.Namespace, "Request.Name", req.Name)

			r.Recorder.Eventf(instance, corev1.EventTypeWarning, "DSCInitializationReconcileError",
				"%s for instance %s", err.Error(), instance.Name)
		}

		// no need to log error as it was already logged in createOperatorResource
		r.Recorder.Eventf(instance, corev1.EventTypeWarning, "DSCInitializationReconcileError",
			"failed to create operator resources for instance %s: %s", instance.Name, err.Error())

		return reconcile.Result{}, err
	}

	// Ensure scoped secrets access in all namespaces where the operator needs secrets.
	// Uses CreateOrUpdate internally — only GETs existing resources and writes
	// when something changed (idempotent, no-op when Roles are already correct).
	if err := r.ensureScopedSecretsAccess(ctx, instance); err != nil {
		log.Error(err, "Failed to ensure scoped secrets access")
		return reconcile.Result{}, err
	}

	switch req.Name {
	case "prometheus": // prometheus configmap
		if instance.Spec.Monitoring.ManagementState == operatorv1.Managed && platform == cluster.ManagedRhoai {
			log.Info("Monitoring enabled to restart deployment", "cluster", "Managed Service Mode")
			if err := r.configureManagedMonitoring(ctx, instance, "updates"); err != nil {
				return reconcile.Result{}, err
			}
		}

		return ctrl.Result{}, nil
	case "addon-managed-odh-parameters":
		if instance.Spec.Monitoring.ManagementState == operatorv1.Managed && platform == cluster.ManagedRhoai {
			log.Info("Monitoring enabled when notification updated", "cluster", "Managed Service Mode")
			if err := r.configureManagedMonitoring(ctx, instance, "updates"); err != nil {
				return reconcile.Result{}, err
			}
		}

		return ctrl.Result{}, nil
	case "backup": // revert back to the original prometheus.yml
		if instance.Spec.Monitoring.ManagementState == operatorv1.Managed && platform == cluster.ManagedRhoai {
			log.Info("Monitoring enabled to restore back", "cluster", "Managed Service Mode")
			if err := r.configureManagedMonitoring(ctx, instance, "revertbackup"); err != nil {
				return reconcile.Result{}, err
			}
		}

		return ctrl.Result{}, nil
	default:
		switch platform {
		case cluster.SelfManagedRhoai:
			if instance.Spec.Monitoring.ManagementState == operatorv1.Managed {
				log.Info("Monitoring enabled", "cluster", "Self-Managed Mode")
				if err = r.configureSegmentIO(ctx, instance); err != nil {
					return reconcile.Result{}, err
				}

				if err = r.newMonitoringCR(ctx, instance); err != nil {
					return ctrl.Result{}, err
				}
			} else {
				log.Info("Monitoring disabled", "cluster", "Self-Managed Mode")
				if err := r.deleteMonitoringCR(ctx); err != nil {
					return reconcile.Result{}, err
				}
			}
		case cluster.ManagedRhoai:
			osdConfigsPath := filepath.Join(deploy.DefaultManifestPath, "osd-configs")
			if err = deploy.DeployManifestsFromPath(ctx, r.Client, instance, osdConfigsPath, instance.Spec.ApplicationsNamespace, "osd", true); err != nil {
				log.Error(err, "Failed to apply osd specific configs from manifests", "Manifests path", osdConfigsPath)
				r.Recorder.Eventf(instance, corev1.EventTypeWarning, "DSCInitializationReconcileError", "Failed to apply "+osdConfigsPath)

				return reconcile.Result{}, err
			}
			// TODO: till we allow user to disable Monitoring in Managed cluster
			log.Info("Monitoring enabled in initialization stage", "cluster", "Managed Service Mode")
			if err = r.newMonitoringCR(ctx, instance); err != nil {
				return ctrl.Result{}, err
			}
			if err = r.configureManagedMonitoring(ctx, instance, "init"); err != nil {
				return reconcile.Result{}, err
			}
			if err = r.configureCommonMonitoring(ctx, instance); err != nil {
				return reconcile.Result{}, err
			}
		default: // TODO: see if this can be conbimed with self-managed case
			if instance.Spec.Monitoring.ManagementState == operatorv1.Managed {
				log.Info("Monitoring enabled", "cluster", "ODH Mode")
				if err = r.newMonitoringCR(ctx, instance); err != nil {
					return ctrl.Result{}, err
				}
			} else {
				log.Info("Monitoring disabled", "cluster", "ODH Mode")
				if err := r.deleteMonitoringCR(ctx); err != nil {
					return reconcile.Result{}, err
				}
			}
		}

		// legacy ServiceMesh FeatureTracker cleanup, retained from the remove ServiceMesh controller
		// TODO where exactly to put this logic ?
		ftNames := []string{
			instance.Spec.ApplicationsNamespace + "-mesh-shared-configmap",
			instance.Spec.ApplicationsNamespace + "-mesh-control-plane-creation",
			instance.Spec.ApplicationsNamespace + "-mesh-metrics-collection",
			instance.Spec.ApplicationsNamespace + "-enable-proxy-injection-in-authorino-deployment",
			instance.Spec.ApplicationsNamespace + "-mesh-control-plane-external-authz",
		}
		for _, name := range ftNames {
			ft := featuresv1.FeatureTracker{
				ObjectMeta: metav1.ObjectMeta{
					Name: name,
				},
			}

			err := r.Client.Delete(ctx, &ft, client.PropagationPolicy(metav1.DeletePropagationForeground))
			if k8serr.IsNotFound(err) {
				continue
			} else if err != nil {
				return ctrl.Result{}, fmt.Errorf("failed to delete FeatureTracker %s: %w", ft.GetName(), err)
			}
		}

		// Create Auth
		if err = r.CreateAuth(ctx, platform); err != nil {
			log.Info("failed to create Auth")
			return ctrl.Result{}, err
		}

		// Create GatewayConfig, always have one in the cluster but up to user to config.
		if err = r.CreateGatewayConfig(ctx, instance); err != nil {
			log.Info("failed to create GatewayConfig")
			return ctrl.Result{}, err
		}

		// Create default HWProfile CR
		if err = r.ManageDefaultAndCustomHWProfileCR(ctx, instance, platform); err != nil {
			log.Info("failed to manage default and custom HardwareProfile CR")
			return ctrl.Result{}, err
		}

		// Finish reconciling
		_, err = status.UpdateWithRetry(ctx, r.Client, instance, func(saved *dsciv2.DSCInitialization) {
			status.SetCompleteCondition(&saved.Status.Conditions, status.ReconcileCompleted, status.ReconcileCompletedMessage)
			saved.Status.Phase = status.PhaseReady
		})
		if err != nil {
			log.Error(err, "failed to update DSCInitialization status after successfully completed reconciliation")
			r.Recorder.Eventf(instance, corev1.EventTypeWarning, "DSCInitializationReconcileError", "Failed to update DSCInitialization status")
		}

		return ctrl.Result{}, nil
	}
}

// secretScopeTargetNamespaces returns the namespaces where the operator needs
// scoped secrets access. Matches the cache config (createSecretCacheConfig).
func (r *DSCInitializationReconciler) secretScopeTargetNamespaces(instance *dsciv2.DSCInitialization) []string {
	operatorNs, _ := cluster.GetOperatorNamespace()

	namespaces := make([]string, 0, 4)
	for _, ns := range []string{
		operatorNs,
		instance.Spec.ApplicationsNamespace,
		instance.Spec.Monitoring.Namespace,
		"openshift-ingress", // TLS certificate secrets for gateway
	} {
		if ns != "" {
			namespaces = append(namespaces, ns)
		}
	}
	return namespaces
}

// ensureScopedSecretsAccess creates per-namespace Roles/RoleBindings for secrets
// in namespaces where the operator needs secrets access. Uses in-memory tracking
// to skip namespaces that are already provisioned — only makes API calls for
// namespaces not yet tracked. Drift is handled by Role/RoleBinding watches that
// clear the tracking entry, triggering re-provisioning on the next reconcile.
func (r *DSCInitializationReconciler) ensureScopedSecretsAccess(ctx context.Context, instance *dsciv2.DSCInitialization) error {
	if r.SecretScoper == nil {
		return nil
	}

	log := logf.FromContext(ctx).WithName("ScopedSecretsAccess")

	for _, ns := range r.secretScopeTargetNamespaces(instance) {
		if _, provisioned := r.provisionedSecretScopes.Load(ns); provisioned {
			continue
		}

		if err := r.SecretScoper.EnsureAccessInNamespace(ctx, instance, ns); err != nil {
			return fmt.Errorf("ensuring secrets access in namespace %s: %w", ns, err)
		}
		r.provisionedSecretScopes.Store(ns, true)
		log.Info("Ensured scoped secrets access", "namespace", ns)
	}

	return nil
}

// invalidateSecretScope clears the in-memory tracking for a namespace,
// forcing re-provisioning on the next reconcile.
func (r *DSCInitializationReconciler) invalidateSecretScope(ns string) {
	r.provisionedSecretScopes.Delete(ns)
}

func getObject(gvk schema.GroupVersionKind) client.Object {
	return resources.GvkToUnstructured(gvk)
}

// SetupWithManager sets up the controller with the Manager.
func (r *DSCInitializationReconciler) SetupWithManager(ctx context.Context, mgr ctrl.Manager) error {
	b := ctrl.NewControllerManagedBy(mgr).
		// add predicates prevents meaningless reconciliations from being triggered
		// not use WithEventFilter() because it conflict with secret and configmap predicate
		For(
			getObject(gvk.DSCInitialization),
			builder.WithPredicates(predicate.Or(predicate.GenerationChangedPredicate{}, predicate.LabelChangedPredicate{})),
		).
		Owns(
			getObject(gvk.Namespace),
			builder.WithPredicates(predicate.Or(predicate.GenerationChangedPredicate{}, predicate.LabelChangedPredicate{}))).
		Owns(
			getObject(gvk.Secret),
			builder.WithPredicates(predicate.Or(predicate.GenerationChangedPredicate{}, predicate.LabelChangedPredicate{}))).
		Owns(
			getObject(gvk.ConfigMap),
			builder.WithPredicates(predicate.Or(predicate.GenerationChangedPredicate{}, predicate.LabelChangedPredicate{}))).
		Owns(
			getObject(gvk.NetworkPolicy),
			builder.WithPredicates(predicate.Or(predicate.GenerationChangedPredicate{}, predicate.LabelChangedPredicate{}))).
		Owns(
			getObject(gvk.Role),
			builder.WithPredicates(predicate.Or(predicate.GenerationChangedPredicate{}, predicate.LabelChangedPredicate{}))).
		Owns(
			getObject(gvk.RoleBinding),
			builder.WithPredicates(predicate.Or(predicate.GenerationChangedPredicate{}, predicate.LabelChangedPredicate{}))).
		Owns(
			getObject(gvk.ClusterRole),
			builder.WithPredicates(predicate.Or(predicate.GenerationChangedPredicate{}, predicate.LabelChangedPredicate{}))).
		Owns(
			getObject(gvk.ClusterRoleBinding),
			builder.WithPredicates(predicate.Or(predicate.GenerationChangedPredicate{}, predicate.LabelChangedPredicate{}))).
		Owns(
			getObject(gvk.Deployment),
			builder.WithPredicates(predicate.Or(predicate.GenerationChangedPredicate{}, predicate.LabelChangedPredicate{}))).
		Owns(
			getObject(gvk.ServiceAccount),
			builder.WithPredicates(predicate.Or(predicate.GenerationChangedPredicate{}, predicate.LabelChangedPredicate{}))).
		Owns(
			getObject(gvk.Service),
			builder.WithPredicates(predicate.Or(predicate.GenerationChangedPredicate{}, predicate.LabelChangedPredicate{}))).
		Owns(
			getObject(gvk.Route),
			builder.WithPredicates(predicate.Or(predicate.GenerationChangedPredicate{}, predicate.LabelChangedPredicate{}))).
		Owns(
			getObject(gvk.PersistentVolumeClaim),
			builder.WithPredicates(predicate.Or(predicate.GenerationChangedPredicate{}, predicate.LabelChangedPredicate{}))).
		Owns( // ensure always have default one for AcceleratorProfile/HardwareProfile blocking
			getObject(gvk.ValidatingAdmissionPolicy),
		).
		Owns( // ensure always have default one for AcceleratorProfile/HardwareProfile blocking
			getObject(gvk.ValidatingAdmissionPolicyBinding),
		).
		Owns( // ensure always have one platform's HardwareProfile in the cluster.
			getObject(gvk.HardwareProfile),
			builder.WithPredicates(rp.Deleted())).
		Watches(
			getObject(gvk.DataScienceCluster),
			handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, a client.Object) []reconcile.Request {
				return r.watchDSCResource(ctx)
			}),
			builder.WithPredicates(rp.DSCDeletionPredicate), // TODO: is it needed?
		).
		Watches(
			getObject(gvk.Secret),
			handler.EnqueueRequestsFromMapFunc(r.watchMonitoringSecretResource),
			builder.WithPredicates(rp.SecretContentChangedPredicate),
		).
		Watches(
			getObject(gvk.ConfigMap),
			handler.EnqueueRequestsFromMapFunc(r.watchMonitoringConfigMapResource),
			builder.WithPredicates(rp.CMContentChangedPredicate),
		).
		Watches(
			getObject(gvk.Auth),
			handler.EnqueueRequestsFromMapFunc(r.watchAuthResource),
		).
		Watches(
			getObject(gvk.GatewayConfig),
			handler.EnqueueRequestsFromMapFunc(r.watchGatewayConfigResource),
		).
		Watches( // TODO: this might not be needed after v3.3.
			getObject(gvk.CustomResourceDefinition),
			handler.EnqueueRequestsFromMapFunc(r.watchHWProfileCRDResource),
			builder.WithPredicates(predicate.Or(
				rp.CreatedOrUpdatedName("acceleratorprofiles.dashboard.opendatahub.io"),
				rp.CreatedOrUpdatedName("hardwareprofiles.dashboard.opendatahub.io"),
			)),
		)

	// Watch scoper-managed Roles/RoleBindings for drift recovery.
	// These use annotation-based ownership (not OwnerReferences) since DSCI is
	// cluster-scoped, so the existing Owns() won't detect changes to them.
	if r.SecretScoper != nil {
		b = b.Watches(
			getObject(gvk.Role),
			handler.EnqueueRequestsFromMapFunc(r.watchScopedRBACResource),
			builder.WithPredicates(rp.ScopedRBACPredicate(r.SecretScoper.ManagedLabels())),
		).
			Watches(
				getObject(gvk.RoleBinding),
				handler.EnqueueRequestsFromMapFunc(r.watchScopedRBACResource),
				builder.WithPredicates(rp.ScopedRBACPredicate(r.SecretScoper.ManagedLabels())),
			)
	}

	return b.Complete(r)
}

// watchScopedRBACResource handles changes to scoper-managed Roles/RoleBindings.
// It invalidates the in-memory tracking for the affected namespace and triggers
// a DSCI reconcile to re-provision if needed.
func (r *DSCInitializationReconciler) watchScopedRBACResource(ctx context.Context, obj client.Object) []reconcile.Request {
	log := logf.FromContext(ctx)
	log.Info("Scoped RBAC resource changed, invalidating tracking", "kind", obj.GetObjectKind().GroupVersionKind().Kind, "namespace", obj.GetNamespace(), "name", obj.GetName())

	r.invalidateSecretScope(obj.GetNamespace())

	instanceList := &dsciv2.DSCInitializationList{}
	if err := r.Client.List(ctx, instanceList); err != nil {
		log.Error(err, "Failed to list DSCInitialization instances")
		return nil
	}
	if len(instanceList.Items) == 0 {
		return nil
	}
	return []reconcile.Request{{NamespacedName: types.NamespacedName{Name: instanceList.Items[0].Name}}}
}

func (r *DSCInitializationReconciler) watchMonitoringConfigMapResource(ctx context.Context, a client.Object) []reconcile.Request {
	log := logf.FromContext(ctx)
	if a.GetName() == "prometheus" && a.GetNamespace() == "redhat-ods-monitoring" {
		log.Info("Found monitoring configmap has updated, start reconcile")

		return []reconcile.Request{{NamespacedName: types.NamespacedName{Name: "prometheus", Namespace: "redhat-ods-monitoring"}}}
	}
	return nil
}

func (r *DSCInitializationReconciler) watchMonitoringSecretResource(ctx context.Context, a client.Object) []reconcile.Request {
	log := logf.FromContext(ctx)
	operatorNs, err := cluster.GetOperatorNamespace()
	if err != nil {
		return nil
	}

	if a.GetName() == "addon-managed-odh-parameters" && a.GetNamespace() == operatorNs {
		log.Info("Found monitoring secret has updated, start reconcile")

		return []reconcile.Request{{NamespacedName: types.NamespacedName{Name: "addon-managed-odh-parameters", Namespace: operatorNs}}}
	}
	return nil
}

func (r *DSCInitializationReconciler) watchDSCResource(ctx context.Context) []reconcile.Request {
	log := logf.FromContext(ctx)
	instanceList := &dscv2.DataScienceClusterList{}
	if err := r.Client.List(ctx, instanceList); err != nil {
		// do not handle if cannot get list
		log.Error(err, "Failed to get DataScienceClusterList")
		return nil
	}
	if len(instanceList.Items) == 0 && !upgrade.HasDeleteConfigMap(ctx, r.Client) {
		log.Info("Found no DSC instance in cluster but not in uninstallation process, reset monitoring stack config")

		return []reconcile.Request{{NamespacedName: types.NamespacedName{Name: "backup"}}}
	}
	return nil
}

func (r *DSCInitializationReconciler) watchAuthResource(ctx context.Context, a client.Object) []reconcile.Request {
	log := logf.FromContext(ctx)
	instanceList := &serviceApi.AuthList{}
	if err := r.Client.List(ctx, instanceList); err != nil {
		// do not handle if cannot get list
		log.Error(err, "Failed to get AuthList")
		return nil
	}
	if len(instanceList.Items) == 0 {
		log.Info("Found no Auth instance in cluster, reconciling to recreate")

		return []reconcile.Request{{NamespacedName: types.NamespacedName{Name: "auth"}}}
	}

	return nil
}

func (r *DSCInitializationReconciler) watchGatewayConfigResource(ctx context.Context, a client.Object) []reconcile.Request {
	log := logf.FromContext(ctx)
	instanceList := &serviceApi.GatewayConfigList{}
	if err := r.Client.List(ctx, instanceList); err != nil {
		// do not handle if cannot get list
		log.Error(err, "Failed to get GatewayConfigList")
		return nil
	}
	if len(instanceList.Items) == 0 {
		log.Info("Found no GatewayConfig instance in cluster, reconciling to recreate one")

		return []reconcile.Request{{NamespacedName: types.NamespacedName{Name: serviceApi.GatewayConfigName}}}
	}

	return nil
}

func (r *DSCInitializationReconciler) deleteMonitoringCR(ctx context.Context) error {
	defaultMonitoring := &serviceApi.Monitoring{
		ObjectMeta: metav1.ObjectMeta{
			Name: serviceApi.MonitoringInstanceName,
		},
	}
	err := r.Client.Delete(ctx, defaultMonitoring)
	if err != nil && !k8serr.IsNotFound(err) {
		return err
	}

	return nil
}

func (r *DSCInitializationReconciler) newMonitoringCR(ctx context.Context, dsci *dsciv2.DSCInitialization) error {
	// Create Monitoring CR singleton
	defaultMonitoring := &serviceApi.Monitoring{
		TypeMeta: metav1.TypeMeta{
			Kind:       serviceApi.MonitoringKind,
			APIVersion: serviceApi.GroupVersion.String(),
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: serviceApi.MonitoringInstanceName,
		},
		Spec: serviceApi.MonitoringSpec{
			MonitoringCommonSpec: serviceApi.MonitoringCommonSpec{
				Namespace: dsci.Spec.Monitoring.Namespace,
			},
		},
	}

	metricsEnabled := dsci.Spec.Monitoring.Metrics != nil && dsci.Spec.Monitoring.Metrics.Storage != nil
	tracesEnabled := dsci.Spec.Monitoring.Traces != nil

	if metricsEnabled {
		defaultMonitoring.Spec.Metrics = dsci.Spec.Monitoring.Metrics
	} else {
		defaultMonitoring.Spec.Metrics = nil
	}

	if tracesEnabled {
		defaultMonitoring.Spec.Traces = dsci.Spec.Monitoring.Traces
		// Without this, when TLS.Enabled is false, the TLS struct is not removed from the Monitoring CR and it causes an error.
		if defaultMonitoring.Spec.Traces.TLS != nil && !defaultMonitoring.Spec.Traces.TLS.Enabled {
			defaultMonitoring.Spec.Traces.TLS = nil
		}
	} else {
		defaultMonitoring.Spec.Traces = nil
	}

	defaultMonitoring.Spec.Alerting = dsci.Spec.Monitoring.Alerting

	if metricsEnabled || tracesEnabled {
		if dsci.Spec.Monitoring.CollectorReplicas != 0 {
			defaultMonitoring.Spec.CollectorReplicas = dsci.Spec.Monitoring.CollectorReplicas
		} else {
			isSNO := cluster.IsSingleNodeCluster(ctx, r.Client)
			if isSNO {
				defaultMonitoring.Spec.CollectorReplicas = 1
			} else {
				defaultMonitoring.Spec.CollectorReplicas = 2
			}
		}
	}

	if err := controllerutil.SetOwnerReference(dsci, defaultMonitoring, r.Client.Scheme()); err != nil {
		return err
	}

	err := resources.Apply(
		ctx,
		r.Client,
		defaultMonitoring,
		client.FieldOwner(fieldManager),
		client.ForceOwnership,
	)

	if err != nil && !k8serr.IsAlreadyExists(err) {
		return err
	}
	return nil
}

// CreateGatewayConfig creates a default GatewayConfig if it doesn't exist.
// Parameters:
//   - ctx: context for the operation
//   - instance: DSCInitialization instance
//
// Returns:
//   - error: nil on success, error if GatewayConfig creation fails
func (r *DSCInitializationReconciler) CreateGatewayConfig(ctx context.Context, instance *dsciv2.DSCInitialization) error {
	gatewayConfig := &serviceApi.GatewayConfig{}
	err := r.Client.Get(ctx, client.ObjectKey{Name: serviceApi.GatewayConfigName}, gatewayConfig)
	if err == nil {
		return nil
	}

	if !k8serr.IsNotFound(err) {
		return err
	}

	// GatewayConfig CR not found, create default GatewayConfig CR.
	defaultGateway := &serviceApi.GatewayConfig{
		TypeMeta: metav1.TypeMeta{
			Kind:       serviceApi.GatewayConfigKind,
			APIVersion: serviceApi.GroupVersion.String(),
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: serviceApi.GatewayConfigName,
		},
		Spec: serviceApi.GatewayConfigSpec{
			Certificate: &infrav1.CertificateSpec{
				Type:       infrav1.OpenshiftDefaultIngress,
				SecretName: gateway.DefaultGatewayTLSSecretName,
			},
			Cookie: serviceApi.CookieConfig{
				Expire:  metav1.Duration{Duration: 24 * time.Hour},
				Refresh: metav1.Duration{Duration: 1 * time.Hour},
			},
			AuthProxyTimeout: metav1.Duration{Duration: 5 * time.Second},
		},
	}

	// Set the DSCInitialization instance as the owner of the GatewayConfig
	if err := ctrl.SetControllerReference(instance, defaultGateway, r.Scheme); err != nil {
		return err
	}

	if err := r.Client.Create(ctx, defaultGateway); err != nil && !k8serr.IsAlreadyExists(err) {
		return err
	}
	return nil
}

// watchHWProfileCRDResource triggers DSCI reconciliation when Dashboard AcceleratorProfile/HWProfile CRDs are created.
// This ensures VAP/VAPB resources can be created when Dashboard CRDs become available.
// TODO: this is a temporary solution to ensure VAP/VAPB resources are created when Dashboard CRDs become available, it should be removed in v3.3.
func (r *DSCInitializationReconciler) watchHWProfileCRDResource(ctx context.Context, a client.Object) []reconcile.Request {
	log := logf.FromContext(ctx)

	log.V(1).Info("Dashboard CRD change detected, triggering DSCI reconciliation for VAP/VAPB resources", "CRD", a.GetName())

	instanceList := &dsciv2.DSCInitializationList{}
	if err := r.Client.List(ctx, instanceList); err != nil {
		log.Error(err, "Failed to get DSCInitializationList")
		return []reconcile.Request{{NamespacedName: types.NamespacedName{Name: "default-dsci"}}}
	}

	if len(instanceList.Items) == 0 {
		// No DSCI found, but trigger anyway for default name in case of race conditions
		// If no DSCI actually exists, the reconcile request will be ignored
		log.V(1).Info("No DSCI instances found, triggering default-dsci reconciliation as fallback to create VAP/VAPB")
		return []reconcile.Request{{NamespacedName: types.NamespacedName{Name: "default-dsci"}}}
	}

	return []reconcile.Request{{NamespacedName: types.NamespacedName{Name: instanceList.Items[0].Name}}}
}
