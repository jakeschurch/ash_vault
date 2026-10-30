package retirement

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/openbao/openbao/sdk/v2/helper/keysutil"
	"github.com/openbao/openbao/sdk/v2/logical"
)

const namespacePrefix = "ashvault.v2.export."
const namespaceReadyPrefix = "ashvault/namespaces/"
const namespaceMovedPrefix = "ashvault/export-moved/"

var purposes = []string{"", ".mac", "_lookup"}

// policyProfile validates the identity before any destructive operation. Errors
// deliberately contain no serialized policy, key material or reversible scope name.
func policyProfile(ctx context.Context, s logical.Storage, name string) (*logical.StorageEntry, *bool, error) {
	entry, err := s.Get(ctx, "policy/"+name)
	if err != nil || entry == nil {
		return entry, nil, err
	}
	var profile struct {
		Name       string `json:"name"`
		Exportable *bool  `json:"exportable"`
	}
	if err := entry.DecodeJSON(&profile); err != nil || profile.Name != name || profile.Exportable == nil {
		return nil, nil, errors.New("invalid policy identity")
	}
	var policy keysutil.Policy
	if err := entry.DecodeJSON(&policy); err != nil || policy.StoragePrefix != "" || policy.Derived || policy.ConvergentEncryption || policy.Imported || policy.SoftDeleted || policy.AllowPlaintextBackup || policy.AutoRotatePeriod != 0 {
		return nil, nil, errors.New("unsupported policy profile")
	}
	switch policy.Type {
	case keysutil.KeyType_AES128_GCM96, keysutil.KeyType_AES256_GCM96, keysutil.KeyType_ChaCha20_Poly1305, keysutil.KeyType_XChaCha20_Poly1305:
	default:
		return nil, nil, errors.New("unsupported policy type")
	}
	return entry, profile.Exportable, nil
}

func nativeProfile(ctx context.Context, s logical.Storage, name string) error {
	for _, suffix := range purposes {
		_, profile, err := policyProfile(ctx, s, name+suffix)
		if err != nil {
			return err
		}
		if profile != nil && (*profile || suffix == "_lookup") {
			return errors.New("foreign key profile")
		}
	}
	return nil
}

func namespaceResult(ready, retired bool) (*logical.Response, error) {
	return response(map[string]interface{}{"protocol": Protocol, "namespace": 2, "ready": ready, "retired": retired}), nil
}

// The caller owns a real storage transaction. Copies, deletion, and the migration
// marker commit together; no key bytes ever cross the operator HTTP connection.
func migrateNamespace(ctx context.Context, req *logical.Request, s logical.Storage, name string, legacyRetired, rollback bool) (*logical.Response, error) {
	if !strings.HasPrefix(name, namespacePrefix+"nx_") {
		return invalid("scope does not require namespace migration")
	}
	legacy := "ashvault_" + strings.TrimPrefix(name, namespacePrefix)
	ready, err := marker(ctx, s, namespaceReadyPrefix+name)
	if err != nil {
		return failure(req, 503, "namespace_state_unavailable")
	}
	retired := false
	for _, suffix := range purposes {
		value, err := marker(ctx, s, retiredPrefix+name+suffix)
		if err != nil {
			return failure(req, 503, "namespace_state_unavailable")
		}
		retired = retired || value
	}
	if rollback {
		if retired || legacyRetired {
			return invalid("retired namespace cannot be rolled back")
		}
		for _, suffix := range purposes {
			wasRetired, err := marker(ctx, s, retiredPrefix+legacy+suffix)
			if err != nil {
				return failure(req, 503, "namespace_state_unavailable")
			}
			if wasRetired {
				return invalid("retired legacy namespace cannot be restored")
			}
		}
		if !ready {
			return namespaceResult(false, false)
		}
		if err := movePolicies(ctx, s, name, legacy); err != nil {
			return failure(req, 503, "namespace_rollback_unavailable")
		}
		for _, suffix := range purposes {
			if err := s.Delete(ctx, namespaceMovedPrefix+legacy+suffix); err != nil {
				return failure(req, 503, "namespace_rollback_unavailable")
			}
		}
		if err := s.Delete(ctx, namespaceReadyPrefix+name); err != nil {
			return failure(req, 503, "namespace_rollback_unavailable")
		}
		return namespaceResult(false, false)
	}
	// A retry must not reinterpret a tombstone subsequently written by the native
	// scope that now independently occupies the old physical key name.
	if ready {
		return namespaceResult(true, retired)
	}
	owned, foreign := false, false
	for _, suffix := range purposes {
		_, profile, err := policyProfile(ctx, s, legacy+suffix)
		if err != nil {
			return failure(req, 503, "namespace_state_unavailable")
		}
		if profile != nil {
			owned = owned || *profile
			foreign = foreign || !*profile
		}
		if profile == nil {
			archive, err := s.Get(ctx, "archive/"+legacy+suffix)
			if err != nil || archive != nil {
				return failure(req, 503, "unowned_archive")
			}
		}
		wasRetired, err := marker(ctx, s, retiredPrefix+legacy+suffix)
		if err != nil {
			return failure(req, 503, "namespace_state_unavailable")
		}
		retired = retired || wasRetired
	}
	if owned && foreign {
		return failure(req, 503, "mixed_namespace_ownership")
	}
	retired = retired || legacyRetired
	if owned {
		if retired {
			for _, suffix := range purposes {
				for _, prefix := range []string{"policy/", "archive/"} {
					if err := s.Delete(ctx, prefix+legacy+suffix); err != nil {
						return failure(req, 503, "namespace_migration_unavailable")
					}
				}
			}
		} else if err := movePolicies(ctx, s, legacy, name); err != nil {
			return failure(req, 503, "namespace_migration_unavailable")
		}
	} else {
		// Never overwrite an unclaimed destination, even for a fresh binary scope.
		for _, suffix := range purposes {
			for _, prefix := range []string{"policy/", "archive/"} {
				entry, err := s.Get(ctx, prefix+name+suffix)
				if err != nil || entry != nil {
					return failure(req, 503, "namespace_destination_occupied")
				}
			}
		}
	}
	if retired {
		if err := retire(ctx, s, name); err != nil {
			return failure(req, 503, "namespace_migration_unavailable")
		}
	}
	for _, suffix := range purposes {
		if err := putMarker(ctx, s, namespaceMovedPrefix+legacy+suffix); err != nil {
			return failure(req, 503, "namespace_migration_unavailable")
		}
	}
	if err := putMarker(ctx, s, namespaceReadyPrefix+name); err != nil {
		return failure(req, 503, "namespace_migration_unavailable")
	}
	return namespaceResult(true, retired)
}

func movePolicies(ctx context.Context, s logical.Storage, from, to string) error {
	// Preflight every destination before preparing any writes, including archives.
	for _, suffix := range purposes {
		for _, prefix := range []string{"policy/", "archive/"} {
			entry, err := s.Get(ctx, prefix+to+suffix)
			if err != nil {
				return err
			}
			if entry != nil {
				return errors.New("destination occupied")
			}
		}
	}
	for _, suffix := range purposes {
		policy, profile, err := policyProfile(ctx, s, from+suffix)
		if err != nil {
			return err
		}
		archive, err := s.Get(ctx, "archive/"+from+suffix)
		if err != nil {
			return err
		}
		if policy == nil {
			if archive != nil {
				return errors.New("unowned archive")
			}
			continue
		}
		if profile == nil || !*profile {
			return errors.New("foreign key profile")
		}
		var document map[string]json.RawMessage
		if err := policy.DecodeJSON(&document); err != nil {
			return errors.New("invalid policy")
		}
		document["name"], _ = json.Marshal(to + suffix)
		encoded, err := json.Marshal(document)
		if err != nil {
			return errors.New("invalid policy")
		}
		policy.Key, policy.Value = "policy/"+to+suffix, encoded
		if err := s.Put(ctx, policy); err != nil {
			return err
		}
		if archive != nil {
			archive.Key = "archive/" + to + suffix
			if err := s.Put(ctx, archive); err != nil {
				return err
			}
		}
		for _, prefix := range []string{"policy/", "archive/"} {
			if err := s.Delete(ctx, prefix+from+suffix); err != nil {
				return err
			}
		}
	}
	return nil
}
