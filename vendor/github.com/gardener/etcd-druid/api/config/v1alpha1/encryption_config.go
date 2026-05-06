package v1alpha1

// EncryptionConfiguration defines the configuration for the backup encryption.
// It is closely inspired from the EncryptionConfiguration of apiserver.config.k8s.io/v1.
type EncryptionConfiguration struct {
	// IdentityProvider can be used in order not to use any encryption.
	// +optional
	IdentityProvider *struct{} `json:"identity,omitempty"`

	// AesGcmProvider provides encryption using AES-GCM.
	// +optional
	AesGcmProvider *EncryptionProviderAesGCM `json:"aesgcm,omitempty"`

	// AesGcmProvider provides encryption using AES-GCM.
	// +optional
	AesCbcProvider *EncryptionProviderAesCbc `json:"aescbc,omitempty"`

	// TODO:
	// secretbox
}

type EncryptionProviderAesGCM struct {
	// Keys contains the encryption keys for the provider.
	Keys []EncryptionKey `json:"keys"`
}

type EncryptionProviderAesCbc struct {
	// Keys contains the encryption keys for the provider.
	Keys []EncryptionKey `json:"keys"`
}

type EncryptionKey struct {
	// Name is the name of the encryption key.
	Name string `json:"name"`
	// Secret is the encryption secret.
	Secret string `json:"secret"`
}
