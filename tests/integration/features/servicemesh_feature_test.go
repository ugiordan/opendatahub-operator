package features_test

import (
	"context"
	"io"
	"os"
	"path"
	"path/filepath"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	dscv1 "github.com/opendatahub-io/opendatahub-operator/v2/apis/dscinitialization/v1"
	"github.com/opendatahub-io/opendatahub-operator/v2/pkg/feature"
	"github.com/opendatahub-io/opendatahub-operator/v2/pkg/feature/servicemesh"
	"github.com/opendatahub-io/opendatahub-operator/v2/pkg/gvr"
	"github.com/opendatahub-io/opendatahub-operator/v2/tests/envtestutil"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Service Mesh feature", func() {
	var testFeature *feature.Feature
	var objectCleaner *envtestutil.Cleaner

	BeforeEach(func() {
		c, err := client.New(envTest.Config, client.Options{})
		Expect(err).ToNot(HaveOccurred())

		objectCleaner = envtestutil.CreateCleaner(c, envTest.Config, timeout, interval)

		testFeatureName := "servicemesh-feature"
		namespace := envtestutil.AppendRandomNameTo(testFeatureName)

		dsciSpec := newDSCInitializationSpec(namespace)
		testFeature, err = feature.CreateFeature(testFeatureName).
			For(dsciSpec).
			UsingConfig(envTest.Config).
			Load()

		Expect(err).ToNot(HaveOccurred())
	})

	Describe("preconditions", func() {

		When("operator is not installed", func() {
			It("operator presence check should return an error", func() {
				Expect(servicemesh.EnsureServiceMeshOperatorInstalled(testFeature)).ToNot(Succeed())
			})
		})

		When("operator is installed", func() {

			It("should faile checking operator presence prerequisite when CRD not installed", func() {
				Expect(servicemesh.EnsureServiceMeshOperatorInstalled(testFeature)).ToNot(Succeed())
			})

			It("should succeed checking operator presence prerequisite when CRD installed", func() {
				// given
				smcpCRD := installServiceMeshControlPlaneCRD()
				defer objectCleaner.DeleteAll(smcpCRD)

				// then
				Expect(servicemesh.EnsureServiceMeshOperatorInstalled(testFeature)).To(Succeed())
			})

			It("should find installed Service Mesh Control Plane", func() {
				// given
				smcpCRD := installServiceMeshControlPlaneCRD()
				defer objectCleaner.DeleteAll(smcpCRD)

				// when
				ns := envtestutil.AppendRandomNameTo(testNamespacePrefix)
				nsResource := createNamespace(ns)
				Expect(envTestClient.Create(context.Background(), nsResource)).To(Succeed())
				defer objectCleaner.DeleteAll(nsResource)

				createServiceMeshControlPlane("test-name", ns)

				// then
				testFeature.Spec.ControlPlane.Namespace = ns
				testFeature.Spec.ControlPlane.Name = "test-name"
				Expect(servicemesh.EnsureServiceMeshInstalled(testFeature)).To(Succeed())
			})

			It("should fail to find Service Mesh Control Plane if not present", func() {
				// given
				smcpCRD := installServiceMeshControlPlaneCRD()
				defer objectCleaner.DeleteAll(smcpCRD)

				// then
				Expect(servicemesh.EnsureServiceMeshInstalled(testFeature)).ToNot(Succeed())
			})
		})
	})

	Describe("control plane configuration", func() {

		var (
			dsciSpec     *dscv1.DSCInitializationSpec
			smcpCRD      *apiextensionsv1.CustomResourceDefinition
			name         = "data-science-smcp"
			appNamespace = "opendatahub"
		)

		BeforeEach(func() {
			dsciSpec = newDSCInitializationSpec(appNamespace)
			smcpCRD = installServiceMeshControlPlaneCRD()
		})

		AfterEach(func() {
			defer objectCleaner.DeleteAll(smcpCRD)
		})

		It("should disable automated network policy by patching existing SMCP", func() {
			// given
			namespace := envtestutil.AppendRandomNameTo(testNamespacePrefix)
			ns := createNamespace(namespace)
			Expect(envTestClient.Create(context.Background(), ns)).To(Succeed())
			defer objectCleaner.DeleteAll(ns)

			createServiceMeshControlPlane(name, namespace)

			dsciSpec.ServiceMesh.ControlPlane.Name = name
			dsciSpec.ServiceMesh.ControlPlane.Namespace = namespace

			controlPlaneWithNetworkPoliciesMgmtDisabled, err := feature.CreateFeature("control-plane-with-disabled-network-policies").
				For(dsciSpec).
				Manifests(fromTestTmpDir(path.Join("templates/servicemesh/base", "control-plane-disable-networkpolicies.patch.tmpl"))).
				UsingConfig(envTest.Config).
				Load()

			Expect(err).ToNot(HaveOccurred())

			// when
			Expect(controlPlaneWithNetworkPoliciesMgmtDisabled.Apply()).To(Succeed())

			// then
			serviceMeshControlPlane, err := getServiceMeshControlPlane(envTest.Config, namespace, name)
			Expect(err).ToNot(HaveOccurred())

			networkPolicyManagement, found, err := unstructured.NestedBool(serviceMeshControlPlane.Object, "spec", "security", "manageNetworkPolicy")
			Expect(err).ToNot(HaveOccurred())
			Expect(found).To(BeTrue())
			Expect(networkPolicyManagement).To(BeFalse())
		})

	})

})

func installServiceMeshControlPlaneCRD() *apiextensionsv1.CustomResourceDefinition {
	// Create SMCP the CRD
	smcpCrdObj := &apiextensionsv1.CustomResourceDefinition{}
	Expect(yaml.Unmarshal([]byte(serviceMeshControlPlaneCRD), smcpCrdObj)).To(Succeed())
	c, err := client.New(envTest.Config, client.Options{})
	Expect(err).ToNot(HaveOccurred())

	Expect(c.Create(context.TODO(), smcpCrdObj)).To(Succeed())

	crdOptions := envtest.CRDInstallOptions{PollInterval: interval, MaxTime: timeout}
	Expect(envtest.WaitForCRDs(envTest.Config, []*apiextensionsv1.CustomResourceDefinition{smcpCrdObj}, crdOptions)).To(Succeed())

	return smcpCrdObj
}

const serviceMeshControlPlaneCRD = `apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  labels:
    maistra-version: 2.4.2
  annotations:
    service.beta.openshift.io/inject-cabundle: "true"
    controller-gen.kubebuilder.io/version: v0.4.1
  name: servicemeshcontrolplanes.maistra.io
spec:
  group: maistra.io
  names:
    categories:
      - maistra-io
    kind: ServiceMeshControlPlane
    listKind: ServiceMeshControlPlaneList
    plural: servicemeshcontrolplanes
    shortNames:
      - smcp
    singular: servicemeshcontrolplane
  scope: Namespaced
  versions:
    - name: v1
      schema:
        openAPIV3Schema:
          type: object
          x-kubernetes-preserve-unknown-fields: true
      served: true
      storage: false
      subresources:
        status: {}
    - name: v2
      schema:
        openAPIV3Schema:
          type: object
          x-kubernetes-preserve-unknown-fields: true
      served: true
      storage: true
      subresources:
        status: {}
`

func createServiceMeshControlPlane(name, namespace string) {
	serviceMeshControlPlane := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "maistra.io/v2",
			"kind":       "ServiceMeshControlPlane",
			"metadata": map[string]interface{}{
				"name":      name,
				"namespace": namespace,
			},
			"spec": map[string]interface{}{},
		},
	}
	Expect(createSMCPInCluster(envTest.Config, serviceMeshControlPlane, namespace)).To(Succeed())
}

// createSMCPInCluster uses dynamic client to create a dummy SMCP resource for testing.
func createSMCPInCluster(cfg *rest.Config, smcpObj *unstructured.Unstructured, namespace string) error {
	dynamicClient, err := dynamic.NewForConfig(cfg)
	if err != nil {
		return err
	}

	result, err := dynamicClient.Resource(gvr.SMCP).Namespace(namespace).Create(context.TODO(), smcpObj, metav1.CreateOptions{})
	if err != nil {
		return err
	}

	statusConditions := []interface{}{
		map[string]interface{}{
			"type":   "Ready",
			"status": "True",
		},
	}

	// Since we don't have actual service mesh operator deployed, we simulate the status
	status := map[string]interface{}{
		"conditions": statusConditions,
		"readiness": map[string]interface{}{
			"components": map[string]interface{}{
				"pending": []interface{}{},
				"ready": []interface{}{
					"istiod",
					"ingress-gateway",
				},
				"unready": []interface{}{},
			},
		},
	}

	if err := unstructured.SetNestedField(result.Object, status, "status"); err != nil {
		return err
	}

	_, err = dynamicClient.Resource(gvr.SMCP).Namespace(namespace).UpdateStatus(context.TODO(), result, metav1.UpdateOptions{})
	if err != nil {
		return err
	}

	return nil
}

func getServiceMeshControlPlane(cfg *rest.Config, namespace, name string) (*unstructured.Unstructured, error) {
	dynamicClient, err := dynamic.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}

	smcp, err := dynamicClient.Resource(gvr.SMCP).Namespace(namespace).Get(context.TODO(), name, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}

	return smcp, nil
}

func fromTestTmpDir(fileName string) string {
	root, err := envtestutil.FindProjectRoot()
	Expect(err).ToNot(HaveOccurred())

	tmpDir := filepath.Join(os.TempDir(), envtestutil.RandomUUIDName(16))
	if err := os.Mkdir(tmpDir, os.ModePerm); err != nil {
		Fail(err.Error())
	}

	src := path.Join(root, "pkg", "feature", fileName)
	dest := path.Join(tmpDir, fileName)
	if err := copyFile(src, dest); err != nil {
		Fail(err.Error())
	}

	return dest
}

func copyFile(src, dst string) error {
	source, err := os.Open(src)
	if err != nil {
		return err
	}
	defer source.Close()

	if err := os.MkdirAll(filepath.Dir(dst), os.ModePerm); err != nil {
		return err
	}

	destination, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destination.Close()

	_, err = io.Copy(destination, source)
	return err
}