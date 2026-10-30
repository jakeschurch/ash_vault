// Package retirement provides the Transit operations AshVault uses, with permanent
// scope retirement in the same storage transaction as every key operation.
package retirement

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/helper/keysutil"
	"github.com/openbao/openbao/sdk/v2/logical"
)

const Protocol = "ashvault-retirement/v1"
const initializedKey = "ashvault/initialized"
const retiredPrefix = "ashvault/retired/"

type backend struct {
	*framework.Backend
	keys *keysutil.LockManager
}

// storageOnly prevents SDK helpers from committing a transaction owned by this backend.
type storageOnly struct{ logical.Storage }

func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	lm, err := keysutil.NewLockManager(false, 0)
	if err != nil {
		return nil, errors.New("cannot initialize key manager")
	}
	b := &backend{keys: lm}
	b.Backend = &framework.Backend{
		BackendType: logical.TypeLogical,
		Help:        "AshVault Transit with transactional, permanent scope retirement",
		PathsSpecial: &logical.Paths{
			Root:            []string{"ashvault/initialize"},
			SealWrapStorage: []string{"policy/", "archive/"},
		},
	}
	// This is deliberately an allowlist. Import/restore, implicit creation, and
	// metadata deletion must not provide a second route around retirement.
	for _, pattern := range []string{
		"ashvault/protocol", "ashvault/initialize", "ashvault/retired/(?P<name>[^/]+)",
		"ashvault/retire/(?P<name>[^/]+)", "keys/(?P<name>[^/]+)",
		"keys/(?P<name>[^/]+)/rotate", "keys/(?P<name>[^/]+)/config",
		"export/(?P<kind>encryption-key|hmac-key)/(?P<name>[^/]+)/(?P<version>[0-9]+)",
		"encrypt/(?P<name>[^/]+)", "decrypt/(?P<name>[^/]+)",
		"hmac/(?P<name>[^/]+)/sha2-256", "verify/(?P<name>[^/]+)/sha2-256",
	} {
		b.Paths = append(b.Paths, &framework.Path{
			Pattern: pattern, Fields: fields(),
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ReadOperation:   b.request,
				logical.UpdateOperation: b.request,
			},
		})
	}
	if err := b.Setup(ctx, conf); err != nil {
		return nil, errors.New("cannot set up backend")
	}
	return b, nil
}

func fields() map[string]*framework.FieldSchema {
	return map[string]*framework.FieldSchema{
		"name": {Type: framework.TypeString}, "kind": {Type: framework.TypeString},
		"version": {Type: framework.TypeString}, "type": {Type: framework.TypeString, Default: "aes256-gcm96"},
		"exportable": {Type: framework.TypeBool}, "allow_plaintext_backup": {Type: framework.TypeBool},
		"derived": {Type: framework.TypeBool}, "convergent_encryption": {Type: framework.TypeBool},
		"deletion_allowed": {Type: framework.TypeBool}, "key_version": {Type: framework.TypeInt},
		"plaintext": {Type: framework.TypeString}, "ciphertext": {Type: framework.TypeString},
		"associated_data": {Type: framework.TypeString}, "input": {Type: framework.TypeString},
		"hmac": {Type: framework.TypeString}, "retired_scopes": {Type: framework.TypeStringSlice},
	}
}

func (b *backend) request(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	if !validFields(req) {
		return invalid("unsupported request field")
	}
	storage, ok := req.Storage.(logical.TransactionalStorage)
	if !ok {
		return failure(req, 503, "transactional_storage_required")
	}
	tx, err := storage.BeginTx(ctx)
	if err != nil {
		return failure(req, 503, "storage_unavailable")
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = tx.Rollback(cleanup)
	}()
	resp, err := b.dispatch(ctx, req, d, storageOnly{tx})
	if err != nil || (resp != nil && resp.IsError()) {
		return resp, err
	}
	if resp != nil {
		if code, ok := resp.Data[logical.HTTPStatusCode].(int); ok && code >= 400 {
			return resp, nil
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return failure(req, 503, "commit_unavailable")
	}
	return resp, nil
}

// Reject options we cannot honor rather than returning a plausible success for
// Transit features this deliberately restricted backend does not implement.
func validFields(req *logical.Request) bool {
	allowed := map[string]bool{"name": true, "kind": true, "version": true}
	var fields []string
	switch {
	case req.Path == "ashvault/initialize":
		fields = []string{"retired_scopes"}
	case strings.HasPrefix(req.Path, "keys/") && strings.HasSuffix(req.Path, "/config"):
		fields = []string{"deletion_allowed"}
	case strings.HasPrefix(req.Path, "keys/") && !strings.HasSuffix(req.Path, "/rotate"):
		fields = []string{"type", "exportable", "allow_plaintext_backup", "derived", "convergent_encryption"}
	case strings.HasPrefix(req.Path, "encrypt/"):
		fields = []string{"plaintext", "associated_data", "key_version"}
	case strings.HasPrefix(req.Path, "decrypt/"):
		fields = []string{"ciphertext", "associated_data"}
	case strings.HasPrefix(req.Path, "hmac/"):
		fields = []string{"input", "key_version"}
	case strings.HasPrefix(req.Path, "verify/"):
		fields = []string{"input", "hmac", "key_version"}
	}
	for _, field := range fields {
		allowed[field] = true
	}
	for field := range req.Data {
		if !allowed[field] {
			return false
		}
	}
	return true
}

func (b *backend) dispatch(ctx context.Context, req *logical.Request, d *framework.FieldData, s logical.Storage) (*logical.Response, error) {
	initialized, err := marker(ctx, s, initializedKey)
	if err != nil {
		return failure(req, 503, "storage_unavailable")
	}
	if req.Path == "ashvault/protocol" && req.Operation == logical.ReadOperation {
		return response(map[string]interface{}{"protocol": Protocol, "transactional": true, "initialized": initialized}), nil
	}
	if req.Path == "ashvault/initialize" && req.Operation == logical.UpdateOperation {
		for _, name := range d.Get("retired_scopes").([]string) {
			if normalized, err := scopeName(name); err != nil || normalized != name {
				return invalid("invalid data key name")
			}
			if err := retire(ctx, s, name); err != nil {
				return failure(req, 503, "retirement_unavailable")
			}
		}
		if err := putMarker(ctx, s, initializedKey); err != nil {
			return failure(req, 503, "initialization_unavailable")
		}
		return response(map[string]interface{}{"protocol": Protocol, "initialized": true}), nil
	}
	name := d.Get("name").(string)
	scope, err := scopeName(name)
	if err != nil {
		return invalid("invalid key name")
	}
	if strings.HasPrefix(req.Path, "ashvault/retire/") && req.Operation == logical.UpdateOperation && name == scope {
		if err := retire(ctx, s, scope); err != nil {
			return failure(req, 503, "retirement_unavailable")
		}
		return response(map[string]interface{}{"protocol": Protocol, "retired": true}), nil
	}
	if !initialized {
		return failure(req, 503, "initialization_required")
	}
	retired, err := marker(ctx, s, retiredPrefix+name)
	if err != nil {
		return failure(req, 503, "storage_unavailable")
	}
	if strings.HasPrefix(req.Path, "ashvault/retired/") && req.Operation == logical.ReadOperation && name == scope {
		return response(map[string]interface{}{"protocol": Protocol, "initialized": true, "retired": retired}), nil
	}

	if retired {
		if req.Operation == logical.ReadOperation && req.Path == "keys/"+name {
			return nil, nil
		}
		return failure(req, 410, "scope_retired")
	}
	return b.keyRequest(ctx, req, d, s, name)
}

func (b *backend) keyRequest(ctx context.Context, req *logical.Request, d *framework.FieldData, s logical.Storage, name string) (*logical.Response, error) {
	create := req.Path == "keys/"+name && req.Operation == logical.UpdateOperation
	if create && (d.Get("allow_plaintext_backup").(bool) || d.Get("derived").(bool) || d.Get("convergent_encryption").(bool)) {
		return invalid("unsupported key profile")
	}
	types := map[string]keysutil.KeyType{
		"aes128-gcm96": keysutil.KeyType_AES128_GCM96, "aes256-gcm96": keysutil.KeyType_AES256_GCM96,
		"chacha20-poly1305":  keysutil.KeyType_ChaCha20_Poly1305,
		"xchacha20-poly1305": keysutil.KeyType_XChaCha20_Poly1305,
	}
	kind, valid := types[d.Get("type").(string)]
	if create && !valid {
		return invalid("unsupported key type")
	}
	p, _, err := b.keys.GetPolicyExclusive(ctx, keysutil.PolicyRequest{
		Storage: s, Name: name, KeyType: kind, Exportable: d.Get("exportable").(bool), Upsert: create,
	}, rand.Reader)
	if err != nil {
		return failure(req, 503, "key_storage_unavailable")
	}
	if p == nil {
		if req.Operation == logical.ReadOperation {
			return nil, nil
		}
		return invalid("no existing key")
	}
	defer p.Unlock()
	if p.Derived || p.ConvergentEncryption || p.Imported || p.SoftDeleted || p.AllowPlaintextBackup || p.AutoRotatePeriod != 0 {
		return invalid("unsupported stored key profile")
	}
	switch p.Type {
	case keysutil.KeyType_AES128_GCM96, keysutil.KeyType_AES256_GCM96, keysutil.KeyType_ChaCha20_Poly1305, keysutil.KeyType_XChaCha20_Poly1305:
	default:
		return invalid("unsupported stored key type")
	}
	if req.Path == "keys/"+name {
		return response(metadata(p)), nil
	}
	if req.Path == "keys/"+name+"/rotate" && req.Operation == logical.UpdateOperation {
		if err := p.Rotate(ctx, s, rand.Reader); err != nil {
			return failure(req, 503, "rotation_unavailable")
		}
		return response(metadata(p)), nil
	}
	if req.Path == "keys/"+name+"/config" && req.Operation == logical.UpdateOperation {
		p.DeletionAllowed = d.Get("deletion_allowed").(bool)
		if err := p.Persist(ctx, s); err != nil {
			return failure(req, 503, "configuration_unavailable")
		}
		return response(metadata(p)), nil
	}
	if strings.HasPrefix(req.Path, "export/") && req.Operation == logical.ReadOperation {
		if !p.Exportable {
			return invalid("key is not exportable")
		}
		version, err := strconv.Atoi(d.Get("version").(string))
		if err != nil || version < 1 || version > p.LatestVersion || version < p.MinDecryptionVersion {
			return invalid("key version does not exist")
		}
		entry, ok := p.Keys[strconv.Itoa(version)]
		if !ok {
			return invalid("key version does not exist")
		}
		key := entry.Key
		if d.Get("kind").(string) == "hmac-key" {
			key = entry.HMACKey
		}
		return response(map[string]interface{}{"keys": map[string]string{strconv.Itoa(version): base64.StdEncoding.EncodeToString(key)}}), nil
	}
	if req.Operation != logical.UpdateOperation {
		return invalid("unsupported operation")
	}
	if req.Path == "encrypt/"+name {
		version := d.Get("key_version").(int)
		if version == 0 {
			version = p.LatestVersion
		}
		ciphertext, err := p.EncryptWithFactory(version, nil, nil, d.Get("plaintext").(string), associatedData(d.Get("associated_data").(string)))
		if err != nil {
			return invalid("encryption input or key version is invalid")
		}
		return response(map[string]interface{}{"ciphertext": ciphertext, "key_version": version}), nil
	}
	if req.Path == "decrypt/"+name {
		plaintext, err := p.DecryptWithFactory(nil, nil, d.Get("ciphertext").(string), associatedData(d.Get("associated_data").(string)))
		if err != nil {
			return invalid("cipher: message authentication failed")
		}
		return response(map[string]interface{}{"plaintext": plaintext}), nil
	}
	if req.Path == "hmac/"+name+"/sha2-256" || req.Path == "verify/"+name+"/sha2-256" {
		return mac(p, d, strings.HasPrefix(req.Path, "verify/"))
	}
	return invalid("unsupported operation")
}

func scopeName(name string) (string, error) {
	if dataKeyName(name) {
		return name, nil
	}
	data := name
	if strings.HasSuffix(name, ".mac") {
		data = strings.TrimSuffix(name, ".mac")
	} else if strings.HasSuffix(name, "_lookup") {
		data = strings.TrimSuffix(name, "_lookup")
	}
	if dataKeyName(data) {
		return data, nil
	}
	return "", errors.New("invalid name")
}

func dataKeyName(data string) bool {
	for _, prefix := range []string{"ashvault_nx_", "ashvault_"} {
		if !strings.HasPrefix(data, prefix) {
			continue
		}
		encoded := strings.TrimPrefix(data, prefix)
		raw, err := base64.RawURLEncoding.DecodeString(encoded)
		if err == nil && base64.RawURLEncoding.EncodeToString(raw) == encoded {
			return true
		}
	}
	return false
}

func retire(ctx context.Context, s logical.Storage, scope string) error {
	names := []string{scope, scope + ".mac", scope + "_lookup"}
	for _, name := range names {
		if err := putMarker(ctx, s, retiredPrefix+name); err != nil {
			return err
		}
		for _, prefix := range []string{"policy/", "archive/"} {
			if err := s.Delete(ctx, prefix+name); err != nil {
				return err
			}
		}
	}
	return nil
}

func putMarker(ctx context.Context, s logical.Storage, name string) error {
	entry, err := logical.StorageEntryJSON(name, map[string]interface{}{"protocol": Protocol, "permanent": true})
	if err != nil {
		return err
	}
	return s.Put(ctx, entry)
}

func marker(ctx context.Context, s logical.Storage, name string) (bool, error) {
	entry, err := s.Get(ctx, name)
	if err != nil || entry == nil {
		return false, err
	}
	var value struct {
		Protocol  string `json:"protocol"`
		Permanent bool   `json:"permanent"`
	}
	if err := entry.DecodeJSON(&value); err != nil || value.Protocol != Protocol || !value.Permanent {
		return false, errors.New("invalid retirement marker")
	}
	return true, nil
}

func metadata(p *keysutil.Policy) map[string]interface{} {
	versions := map[string]int64{}
	for version, entry := range p.Keys {
		versions[version] = entry.CreationTime.Unix()
	}
	return map[string]interface{}{"name": p.Name, "type": p.Type.String(), "exportable": p.Exportable,
		"latest_version": p.LatestVersion, "min_decryption_version": p.MinDecryptionVersion,
		"min_encryption_version": p.MinEncryptionVersion, "deletion_allowed": p.DeletionAllowed, "keys": versions}
}

type associatedData string

func (a associatedData) GetAssociatedData() ([]byte, error) {
	return base64.StdEncoding.DecodeString(string(a))
}

func mac(p *keysutil.Policy, d *framework.FieldData, verify bool) (*logical.Response, error) {
	version := d.Get("key_version").(int)
	var provided []byte
	if verify {
		parts := strings.Split(d.Get("hmac").(string), ":")
		if len(parts) != 3 || parts[0] != "vault" || !strings.HasPrefix(parts[1], "v") {
			return invalid("invalid HMAC")
		}
		var err error
		version, err = strconv.Atoi(strings.TrimPrefix(parts[1], "v"))
		if err != nil || version < 1 {
			return invalid("invalid HMAC version")
		}
		provided, err = base64.StdEncoding.DecodeString(parts[2])
		if err != nil {
			return invalid("invalid HMAC")
		}
	}
	if version == 0 {
		version = p.LatestVersion
	}
	if version < p.MinDecryptionVersion || version > p.LatestVersion {
		return invalid("key version does not exist")
	}
	key, err := p.HMACKey(version)
	if err != nil {
		return invalid("key version does not exist")
	}
	input, err := base64.StdEncoding.DecodeString(d.Get("input").(string))
	if err != nil {
		return invalid("invalid HMAC input")
	}
	hash := hmac.New(sha256.New, key)
	_, _ = hash.Write(input)
	tag := hash.Sum(nil)
	if verify {
		return response(map[string]interface{}{"valid": hmac.Equal(tag, provided)}), nil
	}
	return response(map[string]interface{}{"hmac": fmt.Sprintf("vault:v%d:%s", version, base64.StdEncoding.EncodeToString(tag))}), nil
}

func response(data map[string]interface{}) *logical.Response { return &logical.Response{Data: data} }
func invalid(message string) (*logical.Response, error) {
	return logical.ErrorResponse(message), logical.ErrInvalidRequest
}

func failure(_ *logical.Request, code int, reason string) (*logical.Response, error) {
	body, _ := json.Marshal(map[string]interface{}{"errors": []string{reason}, "ashvault_error": reason, "protocol": Protocol})
	return response(map[string]interface{}{logical.HTTPStatusCode: code, logical.HTTPContentType: "application/json", logical.HTTPRawBody: string(body)}), nil
}
