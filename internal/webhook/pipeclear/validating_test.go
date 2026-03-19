package pipeclear_test

import (
	"encoding/json"
	"fmt"
	"testing"

	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	pipeclearwebhook "github.com/opendatahub-io/opendatahub-operator/v2/internal/webhook/pipeclear"
	"github.com/opendatahub-io/opendatahub-operator/v2/pkg/utils/test/scheme"

	. "github.com/onsi/gomega"
)

const testNamespace = "test-ns"

// newPipelineVersion creates an unstructured PipelineVersion object for testing.
func newPipelineVersion(name string, executors map[string]interface{}) *unstructured.Unstructured {
	obj := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "pipelines.kubeflow.org/v2beta1",
			"kind":       "PipelineVersion",
			"metadata": map[string]interface{}{
				"name":      name,
				"namespace": testNamespace,
			},
		},
	}

	if executors != nil {
		obj.Object["spec"] = map[string]interface{}{
			"pipelineSpec": map[string]interface{}{
				"deploymentSpec": map[string]interface{}{
					"executors": executors,
				},
			},
		}
	}

	return obj
}

// newAdmissionRequest creates an admission.Request for a PipelineVersion object.
func newAdmissionRequest(t *testing.T, op admissionv1.Operation, obj *unstructured.Unstructured) admission.Request {
	t.Helper()

	raw, err := json.Marshal(obj)
	if err != nil {
		t.Fatalf("failed to marshal object: %v", err)
	}

	return admission.Request{
		AdmissionRequest: admissionv1.AdmissionRequest{
			UID:       "test-uid",
			Operation: op,
			Object:    runtime.RawExtension{Raw: raw},
			Kind: metav1.GroupVersionKind{
				Group:   "pipelines.kubeflow.org",
				Version: "v2beta1",
				Kind:    "PipelineVersion",
			},
			Resource: metav1.GroupVersionResource{
				Group:    "pipelines.kubeflow.org",
				Version:  "v2beta1",
				Resource: "pipelineversions",
			},
			Name:      obj.GetName(),
			Namespace: obj.GetNamespace(),
		},
	}
}

// TestPipeClearWebhook_AllowCleanPipeline tests that a PipelineVersion with a properly tagged
// image from a trusted registry is allowed without warnings.
func TestPipeClearWebhook_AllowCleanPipeline(t *testing.T) {
	t.Parallel()
	g := NewWithT(t)
	ctx := t.Context()
	sch, err := scheme.New()
	g.Expect(err).ToNot(HaveOccurred())

	decoder := admission.NewDecoder(sch)
	validator := &pipeclearwebhook.Validator{
		Name:    "test-validator",
		Decoder: decoder,
	}

	obj := newPipelineVersion("clean-pipeline-v1", map[string]interface{}{
		"exec-train": map[string]interface{}{
			"container": map[string]interface{}{
				"image": "registry.redhat.io/ubi9/python-311:1.0",
			},
		},
	})

	req := newAdmissionRequest(t, admissionv1.Create, obj)
	resp := validator.Handle(ctx, req)

	g.Expect(resp.Allowed).To(BeTrue())
	g.Expect(resp.Warnings).To(BeEmpty())
}

// TestPipeClearWebhook_WarnOnLatestTag tests that a PipelineVersion with an image using the
// "latest" tag is allowed but returns a warning.
func TestPipeClearWebhook_WarnOnLatestTag(t *testing.T) {
	t.Parallel()
	g := NewWithT(t)
	ctx := t.Context()
	sch, err := scheme.New()
	g.Expect(err).ToNot(HaveOccurred())

	decoder := admission.NewDecoder(sch)
	validator := &pipeclearwebhook.Validator{
		Name:    "test-validator",
		Decoder: decoder,
	}

	obj := newPipelineVersion("latest-pipeline-v1", map[string]interface{}{
		"exec-train": map[string]interface{}{
			"container": map[string]interface{}{
				"image": "registry.redhat.io/ubi9/python-311:latest",
			},
		},
	})

	req := newAdmissionRequest(t, admissionv1.Create, obj)
	resp := validator.Handle(ctx, req)

	g.Expect(resp.Allowed).To(BeTrue())
	g.Expect(resp.Warnings).ToNot(BeEmpty())
	g.Expect(resp.Warnings[0]).To(ContainSubstring("mutable tag"))
}

// TestPipeClearWebhook_DenyMissingImage tests that a PipelineVersion with an executor
// missing a container image is denied.
func TestPipeClearWebhook_DenyMissingImage(t *testing.T) {
	t.Parallel()
	g := NewWithT(t)
	ctx := t.Context()
	sch, err := scheme.New()
	g.Expect(err).ToNot(HaveOccurred())

	decoder := admission.NewDecoder(sch)
	validator := &pipeclearwebhook.Validator{
		Name:    "test-validator",
		Decoder: decoder,
	}

	obj := newPipelineVersion("missing-image-v1", map[string]interface{}{
		"exec-train": map[string]interface{}{
			"container": map[string]interface{}{
				"image": "",
			},
		},
	})

	req := newAdmissionRequest(t, admissionv1.Create, obj)
	resp := validator.Handle(ctx, req)

	g.Expect(resp.Allowed).To(BeFalse())
	g.Expect(resp.Result.Message).To(ContainSubstring("no container image specified"))
}

// TestPipeClearWebhook_AllowWhenNoSpec tests that a PipelineVersion without a pipelineSpec
// is allowed (validation is skipped).
func TestPipeClearWebhook_AllowWhenNoSpec(t *testing.T) {
	t.Parallel()
	g := NewWithT(t)
	ctx := t.Context()
	sch, err := scheme.New()
	g.Expect(err).ToNot(HaveOccurred())

	decoder := admission.NewDecoder(sch)
	validator := &pipeclearwebhook.Validator{
		Name:    "test-validator",
		Decoder: decoder,
	}

	// PipelineVersion without any spec
	obj := newPipelineVersion("no-spec-v1", nil)

	req := newAdmissionRequest(t, admissionv1.Create, obj)
	resp := validator.Handle(ctx, req)

	g.Expect(resp.Allowed).To(BeTrue())
}

// TestPipeClearWebhook_DeniesWhenDecoderNotInitialized tests that the webhook returns an error
// when the decoder is nil.
func TestPipeClearWebhook_DeniesWhenDecoderNotInitialized(t *testing.T) {
	t.Parallel()
	g := NewWithT(t)
	ctx := t.Context()

	// Create validator WITHOUT decoder injection
	validator := &pipeclearwebhook.Validator{
		Name: "test-validator",
		// Decoder is intentionally nil to test the nil check
	}

	obj := newPipelineVersion("test-v1", map[string]interface{}{
		"exec-train": map[string]interface{}{
			"container": map[string]interface{}{
				"image": "registry.redhat.io/ubi9/python-311:1.0",
			},
		},
	})

	req := newAdmissionRequest(t, admissionv1.Create, obj)
	resp := validator.Handle(ctx, req)

	g.Expect(resp.Allowed).To(BeFalse())
	g.Expect(resp.Result.Message).To(ContainSubstring("webhook decoder not initialized"))
}

// TestPipeClearWebhook_AllowNonCreateOperations tests that non-CREATE operations are allowed.
func TestPipeClearWebhook_AllowNonCreateOperations(t *testing.T) {
	t.Parallel()
	g := NewWithT(t)
	ctx := t.Context()
	sch, err := scheme.New()
	g.Expect(err).ToNot(HaveOccurred())

	decoder := admission.NewDecoder(sch)
	validator := &pipeclearwebhook.Validator{
		Name:    "test-validator",
		Decoder: decoder,
	}

	obj := newPipelineVersion("update-v1", map[string]interface{}{
		"exec-train": map[string]interface{}{
			"container": map[string]interface{}{
				"image": "",
			},
		},
	})

	// UPDATE should be allowed even with empty image (only CREATE is validated)
	req := newAdmissionRequest(t, admissionv1.Update, obj)
	resp := validator.Handle(ctx, req)

	g.Expect(resp.Allowed).To(BeTrue())
}

// TestPipeClearWebhook_DenyDisallowedRegistry tests that a PipelineVersion with an image from
// a non-allowed registry is denied when AllowedRegistries is set.
func TestPipeClearWebhook_DenyDisallowedRegistry(t *testing.T) {
	t.Parallel()
	g := NewWithT(t)
	ctx := t.Context()
	sch, err := scheme.New()
	g.Expect(err).ToNot(HaveOccurred())

	decoder := admission.NewDecoder(sch)
	validator := &pipeclearwebhook.Validator{
		Name:    "test-validator",
		Decoder: decoder,
		Policy: &pipeclearwebhook.PolicyConfig{
			BlockMutableTags:  true,
			AllowedRegistries: []string{"registry.redhat.io", "quay.io"},
		},
	}

	obj := newPipelineVersion("dockerio-pipeline-v1", map[string]interface{}{
		"exec-train": map[string]interface{}{
			"container": map[string]interface{}{
				"image": "docker.io/library/python:3.11",
			},
		},
	})

	req := newAdmissionRequest(t, admissionv1.Create, obj)
	resp := validator.Handle(ctx, req)

	g.Expect(resp.Allowed).To(BeFalse())
	g.Expect(resp.Result.Message).To(ContainSubstring("not in allowed list"))
}

// TestPipeClearWebhook_AllowWithAllowedRegistry tests that a PipelineVersion with an image from
// an allowed registry is permitted when AllowedRegistries is set.
func TestPipeClearWebhook_AllowWithAllowedRegistry(t *testing.T) {
	t.Parallel()
	g := NewWithT(t)
	ctx := t.Context()
	sch, err := scheme.New()
	g.Expect(err).ToNot(HaveOccurred())

	decoder := admission.NewDecoder(sch)
	validator := &pipeclearwebhook.Validator{
		Name:    "test-validator",
		Decoder: decoder,
		Policy: &pipeclearwebhook.PolicyConfig{
			BlockMutableTags:  true,
			AllowedRegistries: []string{"registry.redhat.io", "quay.io"},
		},
	}

	obj := newPipelineVersion("allowed-registry-v1", map[string]interface{}{
		"exec-train": map[string]interface{}{
			"container": map[string]interface{}{
				"image": "registry.redhat.io/ubi9/python-311:1.0",
			},
		},
	})

	req := newAdmissionRequest(t, admissionv1.Create, obj)
	resp := validator.Handle(ctx, req)

	g.Expect(resp.Allowed).To(BeTrue())
}

// TestPipeClearWebhook_DenyTooManyTasks tests that a PipelineVersion with more executors than
// MaxTasksPerPipeline is denied.
func TestPipeClearWebhook_DenyTooManyTasks(t *testing.T) {
	t.Parallel()
	g := NewWithT(t)
	ctx := t.Context()
	sch, err := scheme.New()
	g.Expect(err).ToNot(HaveOccurred())

	decoder := admission.NewDecoder(sch)
	validator := &pipeclearwebhook.Validator{
		Name:    "test-validator",
		Decoder: decoder,
		Policy: &pipeclearwebhook.PolicyConfig{
			MaxTasksPerPipeline: 3,
		},
	}

	// Create 4 executors to exceed the limit of 3
	executors := map[string]interface{}{}
	for i := 0; i < 4; i++ {
		executors[fmt.Sprintf("exec-%d", i)] = map[string]interface{}{
			"container": map[string]interface{}{
				"image": fmt.Sprintf("registry.redhat.io/ubi9/python-311:%d.0", i),
			},
		}
	}

	obj := newPipelineVersion("too-many-tasks-v1", executors)

	req := newAdmissionRequest(t, admissionv1.Create, obj)
	resp := validator.Handle(ctx, req)

	g.Expect(resp.Allowed).To(BeFalse())
	g.Expect(resp.Result.Message).To(ContainSubstring("exceeding maximum of 3"))
}

// TestPipeClearWebhook_DefaultPolicyUsed tests that when Policy is nil, the DefaultPolicy is used.
func TestPipeClearWebhook_DefaultPolicyUsed(t *testing.T) {
	t.Parallel()
	g := NewWithT(t)
	ctx := t.Context()
	sch, err := scheme.New()
	g.Expect(err).ToNot(HaveOccurred())

	decoder := admission.NewDecoder(sch)
	validator := &pipeclearwebhook.Validator{
		Name:    "test-validator",
		Decoder: decoder,
		// Policy is nil - DefaultPolicy should be used
	}

	// Use an image with :latest tag - default policy has BlockMutableTags=true
	obj := newPipelineVersion("default-policy-v1", map[string]interface{}{
		"exec-train": map[string]interface{}{
			"container": map[string]interface{}{
				"image": "registry.redhat.io/ubi9/python-311:latest",
			},
		},
	})

	req := newAdmissionRequest(t, admissionv1.Create, obj)
	resp := validator.Handle(ctx, req)

	// Should be allowed with a mutable tag warning (default policy warns but doesn't deny)
	g.Expect(resp.Allowed).To(BeTrue())
	g.Expect(resp.Warnings).ToNot(BeEmpty())
	g.Expect(resp.Warnings[0]).To(ContainSubstring("mutable tag"))

	// Verify default policy allows all registries (AllowedRegistries is nil)
	defaultPolicy := pipeclearwebhook.DefaultPolicy()
	g.Expect(defaultPolicy.AllowedRegistries).To(BeNil())
	g.Expect(defaultPolicy.MaxTasksPerPipeline).To(Equal(100))
	g.Expect(defaultPolicy.BlockMutableTags).To(BeTrue())
}
