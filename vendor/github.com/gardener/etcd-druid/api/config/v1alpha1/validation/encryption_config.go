package validation

import (
	"encoding/base64"
	"fmt"

	druidconfigv1alpha1 "github.com/gardener/etcd-druid/api/config/v1alpha1"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

const (
	requiredSecretKeyLength = 32
)

// ValidateEncryptionConfiguration validates the encryption configuration.
func ValidateEncryptionConfiguration(config *druidconfigv1alpha1.EncryptionConfiguration) field.ErrorList {
	allErrs := field.ErrorList{}

	if config == nil {
		return allErrs
	}

	providersFld := field.NewPath("providers")

	for i, provider := range config.Providers {
		var (
			count  int
			idxFld = providersFld.Index(i)
		)

		if provider.AesCbcProvider != nil {
			count++
			allErrs = append(allErrs, validateEncryptionKeys(provider.AesCbcProvider.Keys, idxFld.Child("aescbc"))...)
		}

		if provider.AesGcmProvider != nil {
			count++
			allErrs = append(allErrs, validateEncryptionKeys(provider.AesGcmProvider.Keys, idxFld.Child("aesgcm"))...)
		}

		if count != 1 {
			allErrs = append(allErrs, field.Invalid(idxFld, provider, "exactly one provider type must be specified"))
		}
	}

	return allErrs
}

func validateEncryptionKeys(keys []druidconfigv1alpha1.EncryptionKey, fldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}

	if len(keys) == 0 {
		allErrs = append(allErrs, field.Invalid(fldPath, keys, "at least one key must be provided"))
	}

	names := map[string]bool{}

	for i, key := range keys {
		if _, ok := names[key.Name]; ok {
			allErrs = append(allErrs, field.Duplicate(fldPath.Index(i).Child("name"), key.Name))
		}

		names[key.Name] = true

		bytes, err := base64.RawStdEncoding.DecodeString(string(key.Secret))
		if err != nil {
			allErrs = append(allErrs, field.Invalid(fldPath.Index(i).Child("secret"), key.Secret, fmt.Sprintf("secret cannot be base64 decoded: %s", err.Error())))
			continue
		}

		if count := len(bytes); count != requiredSecretKeyLength {
			allErrs = append(allErrs, field.Invalid(fldPath.Index(i).Child("secret"), key.Secret, fmt.Sprintf("secret must have 32 bytes, but has %d", count)))
		}
	}

	return allErrs
}
