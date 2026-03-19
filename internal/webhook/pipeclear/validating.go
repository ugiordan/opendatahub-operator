//go:build !nowebhook

package pipeclear

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	admissionv1 "k8s.io/api/admission/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	webhookutils "github.com/opendatahub-io/opendatahub-operator/v2/pkg/webhook"
)

// +kubebuilder:webhook:path=/validate-pipeclear,mutating=false,failurePolicy=ignore,sideEffects=None,groups=pipelines.kubeflow.org,resources=pipelineversions,verbs=create,versions=v2beta1,name=pipeclear-validator.opendatahub.io,admissionReviewVersions=v1
//nolint:lll

// PolicyConfig defines the validation rules.
type PolicyConfig struct {
	BlockMutableTags          bool
	AllowedRegistries         []string
	MaxTasksPerPipeline       int
	MaxMemoryRequest          string // e.g. "128Gi"
	MaxCPURequest             string // e.g. "64"
	MaxGPURequest             int
	BlockPrivilegedContainers bool
	BlockHostMounts           bool
}

// DefaultPolicy returns the default validation policy.
func DefaultPolicy() *PolicyConfig {
	return &PolicyConfig{
		BlockMutableTags:          true,
		AllowedRegistries:         nil, // nil means all registries allowed
		MaxTasksPerPipeline:       100,
		MaxMemoryRequest:          "128Gi",
		MaxCPURequest:             "64",
		MaxGPURequest:             8,
		BlockPrivilegedContainers: true,
		BlockHostMounts:           true,
	}
}

// Validator implements webhook.AdmissionHandler for PipeClear pipeline validation.
type Validator struct {
	Client  client.Reader
	Decoder admission.Decoder
	Name    string
	Policy  *PolicyConfig
}

// Assert that Validator implements admission.Handler interface.
var _ admission.Handler = &Validator{}

// SetupWithManager registers the validating webhook with the provided controller-runtime manager.
//
// Parameters:
//   - mgr: The controller-runtime manager to register the webhook with.
//
// Returns:
//   - error: Always nil (for future extensibility).
func (v *Validator) SetupWithManager(mgr ctrl.Manager) error {
	hookServer := mgr.GetWebhookServer()
	hookServer.Register("/validate-pipeclear", &webhook.Admission{
		Handler:        v,
		LogConstructor: webhookutils.NewWebhookLogConstructor(v.Name),
	})

	return nil
}

// Handle processes admission requests for PipelineVersion creation.
//
// Parameters:
//   - ctx: Context for the admission request (logger is extracted from here).
//   - req: The admission.Request containing the operation and object details.
//
// Returns:
//   - admission.Response: The result of the admission check, indicating whether the operation is allowed or denied.
func (v *Validator) Handle(ctx context.Context, req admission.Request) admission.Response {
	log := logf.FromContext(ctx)

	// Check if decoder is properly injected
	if v.Decoder == nil {
		log.Error(nil, "Decoder is nil - webhook not properly initialized")
		return admission.Errored(http.StatusInternalServerError, fmt.Errorf("webhook decoder not initialized"))
	}

	// Only validate CREATE operations
	if req.Operation != admissionv1.Create {
		return admission.Allowed("Operation allowed")
	}

	// Decode the object
	obj := &unstructured.Unstructured{}
	if err := v.Decoder.Decode(req, obj); err != nil {
		log.Error(err, "failed to decode PipelineVersion")
		return admission.Errored(http.StatusBadRequest, fmt.Errorf("failed to decode object: %w", err))
	}

	// Extract the pipeline spec
	spec, found, err := unstructured.NestedMap(obj.Object, "spec", "pipelineSpec")
	if err != nil || !found {
		// No pipeline spec to validate
		return admission.Allowed("No pipeline spec found, skipping validation")
	}

	return v.validatePipelineSpec(ctx, spec)
}

// validatePipelineSpec validates the pipeline IR spec.
//
// Parameters:
//   - ctx: Context for logging.
//   - spec: The pipeline spec as an unstructured map.
//
// Returns:
//   - admission.Response: The result of the validation.
func (v *Validator) validatePipelineSpec(ctx context.Context, spec map[string]interface{}) admission.Response {
	log := logf.FromContext(ctx)
	var warnings []string
	var denials []string

	policy := v.Policy
	if policy == nil {
		policy = DefaultPolicy()
	}

	// Extract executors from deployment spec
	deploymentSpec, _, _ := unstructured.NestedMap(spec, "deploymentSpec")
	if deploymentSpec == nil {
		return admission.Allowed("No deployment spec found")
	}

	executors, _, _ := unstructured.NestedMap(deploymentSpec, "executors")

	// Check max tasks per pipeline
	if policy.MaxTasksPerPipeline > 0 && len(executors) > policy.MaxTasksPerPipeline {
		denials = append(denials, fmt.Sprintf("pipeline has %d tasks, exceeding maximum of %d", len(executors), policy.MaxTasksPerPipeline))
	}

	for executorName, executorRaw := range executors {
		executor, ok := executorRaw.(map[string]interface{})
		if !ok {
			continue
		}

		container, _, _ := unstructured.NestedMap(executor, "container")
		if container == nil {
			continue
		}

		image, _, _ := unstructured.NestedString(container, "image")
		if image == "" {
			denials = append(denials, fmt.Sprintf("executor %q has no container image specified", executorName))
			continue
		}

		// Check for mutable "latest" tag
		if policy.BlockMutableTags {
			if !strings.Contains(image, ":") || strings.HasSuffix(image, ":latest") {
				warnings = append(warnings, fmt.Sprintf("image %q uses mutable tag - consider using a specific version", image))
			}
		}

		// Check allowed registries
		if len(policy.AllowedRegistries) > 0 {
			registry := strings.SplitN(image, "/", 2)[0]
			allowed := false
			for _, r := range policy.AllowedRegistries {
				if registry == r {
					allowed = true
					break
				}
			}
			if !allowed {
				denials = append(denials, fmt.Sprintf("image %q uses registry %q which is not in allowed list: %v", image, registry, policy.AllowedRegistries))
			}
		}
	}

	if len(denials) > 0 {
		msg := fmt.Sprintf("PipeClear validation failed: %s", strings.Join(denials, "; "))
		log.Info("PipeClear denied PipelineVersion", "reasons", denials)
		return admission.Denied(msg)
	}

	resp := admission.Allowed("PipeClear validation passed")
	if len(warnings) > 0 {
		resp.Warnings = warnings
		log.Info("PipeClear allowed PipelineVersion with warnings", "warnings", warnings)
	}

	return resp
}
