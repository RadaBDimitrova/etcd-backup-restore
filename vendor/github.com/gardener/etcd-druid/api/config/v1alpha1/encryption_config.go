package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// EncryptionProviderType is a type alias for the encryption provider type string.
type EncryptionProviderType string

const (
	// EncryptionProviderTypeAESCBC is the aescbc encryption provider type.
	EncryptionProviderTypeAESCBC EncryptionProviderType = "aescbc"
	// EncryptionProviderTypeAESGCM is the aesgcm encryption provider type.
	EncryptionProviderTypeAESGCM EncryptionProviderType = "aesgcm"
)

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// EncryptionConfiguration defines the configuration for the backup encryption.
// It is closely inspired from the EncryptionConfiguration of apiserver.config.k8s.io/v1.
type EncryptionConfiguration struct {
	metav1.TypeMeta `json:",inline"`

	// Providers contains a list of possible encryption providers to encrypt backups.
	// Each provider supports multiple keys - the keys are tried in order for decryption,
	// and if the provider is the first provider, the first key is used for encryption.
	// +optional
	Providers []EncryptionProvider `json:"providers,omitempty"`
}

// EncryptionProvider describes the encryption provider to be used. Only one provider type may be specified per entry.
type EncryptionProvider struct {
	// AesGcmProvider provides encryption using AES-GCM.
	// +optional
	AesGcmProvider *EncryptionProviderAesGCM `json:"aesgcm,omitempty"`

	// AesGcmProvider provides encryption using AES-CBC.
	// +optional
	AesCbcProvider *EncryptionProviderAesCbc `json:"aescbc,omitempty"`
}

// EncryptionProviderAesGCM is the encryption provider using AES-GCM.
type EncryptionProviderAesGCM struct {
	// Keys contains the encryption keys for the provider.
	Keys []EncryptionKey `json:"keys"`
}

// EncryptionProviderAesCbc is the encryption provider using AES-CBC.
type EncryptionProviderAesCbc struct {
	// Keys contains the encryption keys for the provider.
	Keys []EncryptionKey `json:"keys"`
}

// EncryptionKey contains the encryption key.
type EncryptionKey struct {
	// Name is the name of the encryption key.
	Name string `json:"name"`
	// Secret is the encryption secret.
	Secret []byte `json:"secret"`
}
