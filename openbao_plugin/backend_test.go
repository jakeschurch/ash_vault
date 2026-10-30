package retirement

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/sdk/v2/physical/inmem"
)

const testName = "ashvault_dGVuYW50"

func TestCanonicalDataNameEndingInLookup(t *testing.T) {
	// A canonical data name can end in these letters without being a lookup key.
	name := "ashvault_a_lookup"
	s := testStorage(t)
	b := testBackend(t, s)
	initialize(t, b, s)
	create(t, b, s, name, true)
	create(t, b, s, name+"_lookup", true)
	mustCall(t, b, s, logical.UpdateOperation, "ashvault/retire/"+name, nil)
	assertAbsent(t, s, name)
}

func TestUnsupportedFieldsAndPinnedVersion(t *testing.T) {
	s := testStorage(t)
	b := testBackend(t, s)
	initialize(t, b, s)
	create(t, b, s, testName, true)
	mustCall(t, b, s, logical.UpdateOperation, "keys/"+testName+"/rotate", nil)
	r := mustCall(t, b, s, logical.UpdateOperation, "encrypt/"+testName, map[string]interface{}{"plaintext": "c2VjcmV0", "key_version": 1})
	if r.Data["key_version"] != 1 {
		t.Fatal("pinned version response must match ciphertext")
	}
	r, _ = call(b, s, logical.UpdateOperation, "keys/"+testName+"/config", map[string]interface{}{"min_decryption_version": 2})
	if status(r) != 400 {
		t.Fatal("unsupported field was silently ignored")
	}
}

func testStorage(t *testing.T) logical.Storage {
	t.Helper()
	p, err := inmem.NewInmem(nil, hclog.NewNullLogger())
	if err != nil {
		t.Fatal("cannot create test storage")
	}
	return logical.NewLogicalStorage(p)
}

func testBackend(t *testing.T, s logical.Storage) logical.Backend {
	t.Helper()
	b, err := Factory(context.Background(), &logical.BackendConfig{
		StorageView: s, Logger: hclog.NewNullLogger(), System: &logical.StaticSystemView{},
	})
	if err != nil {
		t.Fatal("cannot create backend")
	}
	return b
}

func call(b logical.Backend, s logical.Storage, op logical.Operation, path string, data map[string]interface{}) (*logical.Response, error) {
	return b.HandleRequest(context.Background(), &logical.Request{Storage: s, Operation: op, Path: path, Data: data})
}

func mustCall(t *testing.T, b logical.Backend, s logical.Storage, op logical.Operation, path string, data map[string]interface{}) *logical.Response {
	t.Helper()
	r, err := call(b, s, op, path, data)
	if err != nil || (r != nil && (r.IsError() || status(r) >= 400)) {
		t.Fatalf("request %s failed (error type %T)", path, err)
	}
	return r
}

func status(r *logical.Response) int {
	if r == nil {
		return 404
	}
	if code, ok := r.Data[logical.HTTPStatusCode].(int); ok {
		return code
	}
	if r.IsError() {
		return 400
	}
	return 200
}

func initialize(t *testing.T, b logical.Backend, s logical.Storage) {
	t.Helper()
	mustCall(t, b, s, logical.UpdateOperation, "ashvault/initialize", nil)
}

func create(t *testing.T, b logical.Backend, s logical.Storage, name string, exportable bool) {
	t.Helper()
	mustCall(t, b, s, logical.UpdateOperation, "keys/"+name, map[string]interface{}{"exportable": exportable})
}

func assertAbsent(t *testing.T, s logical.Storage, scope string) {
	t.Helper()
	for _, name := range []string{scope, scope + ".mac", scope + "_lookup"} {
		for _, prefix := range []string{"policy/", "archive/"} {
			entry, err := s.Get(context.Background(), prefix+name)
			if err != nil || entry != nil {
				t.Fatalf("key storage %s remains", prefix+name)
			}
		}
	}
}

func TestInitializationAndTransactionalRequirement(t *testing.T) {
	s := testStorage(t)
	b := testBackend(t, s)
	r := mustCall(t, b, s, logical.ReadOperation, "ashvault/protocol", nil)
	if r.Data["initialized"] != false {
		t.Fatal("fresh plugin must be inactive")
	}
	r, _ = call(b, s, logical.UpdateOperation, "keys/"+testName, nil)
	if status(r) != 503 {
		t.Fatal("uninitialized creation must fail closed")
	}
	assertAbsent(t, s, testName)
	r, _ = call(b, storageOnly{s}, logical.UpdateOperation, "ashvault/initialize", nil)
	if status(r) != 503 {
		t.Fatal("nontransactional storage must fail closed")
	}
	// Import an old tombstone before activating the mount.
	mustCall(t, b, s, logical.UpdateOperation, "ashvault/retire/"+testName, nil)
	initialize(t, b, s)
	r, _ = call(b, s, logical.UpdateOperation, "keys/"+testName, nil)
	if status(r) != 410 {
		t.Fatal("imported retirement was lost")
	}
}

func TestTransitCompatibilityAndPurposeErasure(t *testing.T) {
	s := testStorage(t)
	b := testBackend(t, s)
	initialize(t, b, s)
	create(t, b, s, testName, true)
	create(t, b, s, testName+".mac", true)
	create(t, b, s, testName+"_lookup", true)
	before := mustCall(t, b, s, logical.ReadOperation, "export/encryption-key/"+testName+"/1", nil)
	mustCall(t, b, s, logical.UpdateOperation, "keys/"+testName+"/rotate", nil)
	// Recreate the backend over the same data: no cache may hide stored state.
	b = testBackend(t, s)
	after := mustCall(t, b, s, logical.ReadOperation, "export/encryption-key/"+testName+"/1", nil)
	if before.Data["keys"].(map[string]string)["1"] != after.Data["keys"].(map[string]string)["1"] {
		t.Fatal("historical key changed")
	}
	plain := base64.StdEncoding.EncodeToString([]byte("private-test-plaintext"))
	aad := base64.StdEncoding.EncodeToString([]byte("test-aad"))
	enc := mustCall(t, b, s, logical.UpdateOperation, "encrypt/"+testName, map[string]interface{}{"plaintext": plain, "associated_data": aad, "key_version": 1})
	dec := mustCall(t, b, s, logical.UpdateOperation, "decrypt/"+testName, map[string]interface{}{"ciphertext": enc.Data["ciphertext"], "associated_data": aad})
	if dec.Data["plaintext"] != plain {
		t.Fatal("AEAD round trip failed")
	}
	r, _ := call(b, s, logical.UpdateOperation, "decrypt/"+testName, map[string]interface{}{"ciphertext": enc.Data["ciphertext"], "associated_data": ""})
	if status(r) != 400 {
		t.Fatal("wrong AAD must fail")
	}
	tag := mustCall(t, b, s, logical.UpdateOperation, "hmac/"+testName+".mac/sha2-256", map[string]interface{}{"input": plain, "key_version": 1})
	verified := mustCall(t, b, s, logical.UpdateOperation, "verify/"+testName+".mac/sha2-256", map[string]interface{}{"input": plain, "hmac": tag.Data["hmac"]})
	if verified.Data["valid"] != true {
		t.Fatal("HMAC verification failed")
	}
	mustCall(t, b, s, logical.UpdateOperation, "ashvault/retire/"+testName, nil)
	assertAbsent(t, s, testName)
	b = testBackend(t, s)
	for _, name := range []string{testName, testName + ".mac", testName + "_lookup"} {
		r, _ := call(b, s, logical.UpdateOperation, "keys/"+name, nil)
		if status(r) != 410 {
			t.Fatal("retired purpose could be recreated after restart")
		}
	}
	r, _ = call(b, s, logical.UpdateOperation, "decrypt/"+testName, map[string]interface{}{"ciphertext": enc.Data["ciphertext"], "associated_data": aad})
	if status(r) != 410 {
		t.Fatal("retired ciphertext could be decrypted")
	}
	mustCall(t, b, s, logical.UpdateOperation, "ashvault/retire/"+testName, nil)
	assertAbsent(t, s, testName)
}

// controlledStorage changes timing/failure of the real SDK transaction; it does not
// replace the SDK's commit conflict checks or rollback implementation.
type controlledStorage struct {
	logical.Storage
	beforeCommit     func()
	afterCommitError bool
	deleteError      bool
}
type controlledTx struct {
	logical.Transaction
	owner *controlledStorage
}

func (s *controlledStorage) BeginReadOnlyTx(ctx context.Context) (logical.Transaction, error) {
	return s.BeginTx(ctx)
}
func (s *controlledStorage) BeginTx(ctx context.Context) (logical.Transaction, error) {
	tx, err := s.Storage.(logical.TransactionalStorage).BeginTx(ctx)
	if err != nil {
		return nil, err
	}
	return &controlledTx{Transaction: tx, owner: s}, nil
}
func (tx *controlledTx) Commit(ctx context.Context) error {
	if tx.owner.beforeCommit != nil {
		tx.owner.beforeCommit()
	}
	err := tx.Transaction.Commit(ctx)
	if err == nil && tx.owner.afterCommitError {
		return errors.New("simulated lost commit response")
	}
	return err
}
func (tx *controlledTx) Delete(ctx context.Context, key string) error {
	if tx.owner.deleteError && strings.HasSuffix(key, ".mac") {
		return errors.New("private-storage-error-needle")
	}
	return tx.Transaction.Delete(ctx, key)
}

func TestRetirementFencesAlreadyPreparedCreateAtCommit(t *testing.T) {
	for _, suffix := range []string{"", ".mac", "_lookup"} {
		t.Run("purpose"+suffix, func(t *testing.T) {
			s := testStorage(t)
			b := testBackend(t, s)
			initialize(t, b, s)
			prepared := make(chan struct{})
			resume := make(chan struct{})
			done := make(chan *logical.Response, 1)
			defer close(resume)
			var once sync.Once
			controlled := &controlledStorage{Storage: s, beforeCommit: func() { once.Do(func() { close(prepared) }); <-resume }}
			go func() { r, _ := call(b, controlled, logical.UpdateOperation, "keys/"+testName+suffix, nil); done <- r }()
			<-prepared
			// The creator has generated a key and prepared all writes. Retirement
			// commits while that request is delayed, without any client cleanup.
			mustCall(t, b, s, logical.UpdateOperation, "ashvault/retire/"+testName, nil)
			assertAbsent(t, s, testName)
			resume <- struct{}{}
			if status(<-done) != 503 {
				t.Fatal("stale transaction was allowed to commit")
			}
			assertAbsent(t, s, testName)
		})
	}
}

func TestRetirementFailureRollsBackMarkerAndAllKeyDeletions(t *testing.T) {
	s := testStorage(t)
	b := testBackend(t, s)
	initialize(t, b, s)
	for _, suffix := range []string{"", ".mac", "_lookup"} {
		create(t, b, s, testName+suffix, true)
	}
	r, _ := call(b, &controlledStorage{Storage: s, deleteError: true}, logical.UpdateOperation, "ashvault/retire/"+testName, nil)
	if status(r) != 503 {
		t.Fatal("failed deletion claimed success")
	}
	if strings.Contains(r.Data[logical.HTTPRawBody].(string), "private-storage-error-needle") {
		t.Fatal("storage error leaked")
	}
	for _, suffix := range []string{"", ".mac", "_lookup"} {
		r := mustCall(t, b, s, logical.ReadOperation, "keys/"+testName+suffix, nil)
		if r == nil {
			t.Fatal("rollback lost an active key")
		}
	}
	state := mustCall(t, b, s, logical.ReadOperation, "ashvault/retired/"+testName, nil)
	if state.Data["retired"] != false {
		t.Fatal("rolled back retirement marker remained")
	}
	mustCall(t, b, s, logical.UpdateOperation, "ashvault/retire/"+testName, nil)
	assertAbsent(t, s, testName)
}

func TestLostRetirementResponseAndRestartRemainErased(t *testing.T) {
	s := testStorage(t)
	b := testBackend(t, s)
	initialize(t, b, s)
	create(t, b, s, testName, true)
	r, _ := call(b, &controlledStorage{Storage: s, afterCommitError: true}, logical.UpdateOperation, "ashvault/retire/"+testName, nil)
	if status(r) != 503 {
		t.Fatal("lost commit response must stay unavailable")
	}
	b = testBackend(t, s)
	r, _ = call(b, s, logical.UpdateOperation, "keys/"+testName, nil)
	if status(r) != 410 {
		t.Fatal("restart lost retirement")
	}
	mustCall(t, b, s, logical.UpdateOperation, "ashvault/retire/"+testName, nil)
	assertAbsent(t, s, testName)
}

func TestCorruptMarkersFailClosed(t *testing.T) {
	s := testStorage(t)
	b := testBackend(t, s)
	initialize(t, b, s)
	if err := s.Put(context.Background(), &logical.StorageEntry{Key: retiredPrefix + testName, Value: []byte("private-invalid-marker")}); err != nil {
		t.Fatal("cannot inject corrupt marker")
	}
	r, _ := call(b, s, logical.UpdateOperation, "keys/"+testName, nil)
	if status(r) != 503 {
		t.Fatal("corrupt marker allowed a create")
	}
	if strings.Contains(r.Data[logical.HTTPRawBody].(string), "private-invalid-marker") {
		t.Fatal("marker data leaked")
	}
	assertAbsent(t, s, testName)
}

func TestUnknownOperationsAndNestedPurposeNamesCannotBypassRetirement(t *testing.T) {
	s := testStorage(t)
	b := testBackend(t, s)
	initialize(t, b, s)
	mustCall(t, b, s, logical.UpdateOperation, "ashvault/retire/"+testName, nil)
	for _, path := range []string{"restore/" + testName, "keys/" + testName + "/import", "keys/" + testName + "/soft-delete-restore", "keys/" + testName + ".mac.mac", "keys/" + testName + "_lookup.mac", "keys/" + testName + ".mac_lookup"} {
		r, err := call(b, s, logical.UpdateOperation, path, nil)
		if err == nil && status(r) < 400 {
			t.Fatalf("unsupported path allowed: %s", path)
		}
	}
	r, _ := call(b, s, logical.UpdateOperation, "keys/"+testName, map[string]interface{}{"name": "ashvault_b3RoZXI="})
	if status(r) != 410 {
		t.Fatal("body name overrode retired URL name")
	}
	assertAbsent(t, s, testName)
}

func TestNonExportableKeyRemainsUsableUntilRetirement(t *testing.T) {
	s := testStorage(t)
	b := testBackend(t, s)
	initialize(t, b, s)
	name := "ashvault_nx_dGVuYW50"
	create(t, b, s, name, false)
	r, _ := call(b, s, logical.ReadOperation, "export/encryption-key/"+name+"/1", nil)
	if status(r) != 400 {
		t.Fatal("nonexportable key was exported")
	}
	mustCall(t, b, s, logical.UpdateOperation, "encrypt/"+name, map[string]interface{}{"plaintext": "c2VjcmV0", "associated_data": "YWFk"})
	mustCall(t, b, s, logical.UpdateOperation, "ashvault/retire/"+name, nil)
	assertAbsent(t, s, name)
}
