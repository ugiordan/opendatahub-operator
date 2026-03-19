//go:build !nowebhook

package pipeclear

import (
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

// RegisterWebhooks registers the PipeClear validating webhook.
//
// Parameters:
//   - mgr: The controller-runtime manager to register webhooks with.
//
// Returns:
//   - error: Any error encountered during webhook registration.
func RegisterWebhooks(mgr ctrl.Manager) error {
	if err := (&Validator{
		Client:  mgr.GetAPIReader(),
		Decoder: admission.NewDecoder(mgr.GetScheme()),
		Name:    "pipeclear-validating",
	}).SetupWithManager(mgr); err != nil {
		return err
	}

	return nil
}
