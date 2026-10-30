package retirement

import (
	"context"
	"strings"
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"
)

const legacyBinary = "ashvault_nx_YWJk"
const escapedBinary = namespacePrefix + "nx_YWJk"

func migrate(t *testing.T, b logical.Backend, s logical.Storage, rollback bool) *logical.Response {
	t.Helper()
	return mustCall(t, b, s, logical.UpdateOperation, "ashvault/namespace/"+escapedBinary, map[string]interface{}{"rollback": rollback})
}

func TestNamespaceMigrationPreservesAllVersionsAndRollback(t *testing.T) {
	s := testStorage(t)
	b := testBackend(t, s)
	initialize(t, b, s)
	before := map[string]interface{}{}
	for _, suffix := range purposes {
		create(t, b, s, legacyBinary+suffix, true)
		before[suffix] = mustCall(t, b, s, logical.ReadOperation, "export/encryption-key/"+legacyBinary+suffix+"/1", nil).Data["keys"]
		mustCall(t, b, s, logical.UpdateOperation, "keys/"+legacyBinary+suffix+"/rotate", nil)
	}
	enc := mustCall(t, b, s, logical.UpdateOperation, "encrypt/"+legacyBinary, map[string]interface{}{"plaintext": "c2VjcmV0", "key_version": 1, "associated_data": "YWFk"})
	r, _ := call(b, s, logical.UpdateOperation, "ashvault/retire/"+legacyBinary, map[string]interface{}{"key_profile": "native"})
	if status(r) != 503 {
		t.Fatal("native retirement erased exportable keys")
	}
	migrate(t, b, s, false)
	assertAbsent(t, s, legacyBinary)
	for _, suffix := range purposes {
		got := mustCall(t, b, s, logical.ReadOperation, "export/encryption-key/"+escapedBinary+suffix+"/1", nil).Data["keys"]
		if before[suffix].(map[string]string)["1"] != got.(map[string]string)["1"] {
			t.Fatal("historical key changed")
		}
		mustCall(t, b, s, logical.ReadOperation, "export/encryption-key/"+escapedBinary+suffix+"/2", nil)
	}
	dec := mustCall(t, b, s, logical.UpdateOperation, "decrypt/"+escapedBinary, map[string]interface{}{"ciphertext": enc.Data["ciphertext"], "associated_data": "YWFk"})
	if dec.Data["plaintext"] != "c2VjcmV0" {
		t.Fatal("ciphertext lost compatibility")
	}
	migrate(t, b, s, false)
	r, _ = call(b, s, logical.UpdateOperation, "keys/"+legacyBinary, map[string]interface{}{"exportable": true})
	if status(r) != 400 {
		t.Fatal("old exporter recreated the migrated namespace")
	}
	migrate(t, b, s, true)
	assertAbsent(t, s, escapedBinary)
	for _, suffix := range purposes {
		got := mustCall(t, b, s, logical.ReadOperation, "export/encryption-key/"+legacyBinary+suffix+"/1", nil).Data["keys"]
		if before[suffix].(map[string]string)["1"] != got.(map[string]string)["1"] {
			t.Fatal("rollback changed key material")
		}
	}
	migrate(t, b, s, true)
	migrate(t, b, s, false)
}

func TestNamespaceIsolationAndOccupiedRollback(t *testing.T) {
	s := testStorage(t)
	b := testBackend(t, s)
	initialize(t, b, s)
	create(t, b, s, legacyBinary, false)
	migrate(t, b, s, false)
	create(t, b, s, escapedBinary, true)
	r, _ := call(b, s, logical.UpdateOperation, "ashvault/namespace/"+escapedBinary, map[string]interface{}{"rollback": true})
	if status(r) != 503 {
		t.Fatal("rollback overwrote native keys")
	}
	mustCall(t, b, s, logical.ReadOperation, "keys/"+legacyBinary, nil)
	mustCall(t, b, s, logical.UpdateOperation, "ashvault/retire/"+legacyBinary, map[string]interface{}{"key_profile": "native"})
	migrate(t, b, s, false) // old retirement after migration must not erase the new scope
	mustCall(t, b, s, logical.ReadOperation, "export/encryption-key/"+escapedBinary+"/1", nil)
	mustCall(t, b, s, logical.UpdateOperation, "ashvault/retire/"+escapedBinary, nil)
	assertAbsent(t, s, escapedBinary)
}

func TestNamespaceMigrationPreservesLegacyErasure(t *testing.T) {
	for _, serverMarker := range []bool{false, true} {
		s := testStorage(t)
		b := testBackend(t, s)
		initialize(t, b, s)
		if serverMarker {
			mustCall(t, b, s, logical.UpdateOperation, "ashvault/retire/"+legacyBinary, nil)
		}
		mustCall(t, b, s, logical.UpdateOperation, "ashvault/namespace/"+escapedBinary, map[string]interface{}{"legacy_retired": !serverMarker})
		b = testBackend(t, s)
		r, _ := call(b, s, logical.UpdateOperation, "keys/"+escapedBinary, map[string]interface{}{"exportable": true})
		if status(r) != 410 {
			t.Fatal("migration resurrected an erased binary scope")
		}
		r, _ = call(b, s, logical.UpdateOperation, "ashvault/namespace/"+escapedBinary, map[string]interface{}{"rollback": true})
		if status(r) != 400 {
			t.Fatal("rollback resurrected erased scope")
		}
	}
}

func TestNamespaceMigrationRollsBackOnFailureAndLostAck(t *testing.T) {
	s := testStorage(t)
	b := testBackend(t, s)
	initialize(t, b, s)
	for _, suffix := range purposes {
		create(t, b, s, legacyBinary+suffix, true)
	}
	controlled := &controlledStorage{Storage: s, deleteError: true}
	r, _ := call(b, controlled, logical.UpdateOperation, "ashvault/namespace/"+escapedBinary, nil)
	if status(r) != 503 {
		t.Fatal("failed deletion reported success")
	}
	assertAbsent(t, s, escapedBinary)
	ready, err := marker(context.Background(), s, namespaceReadyPrefix+escapedBinary)
	if err != nil || ready {
		t.Fatal("failed migration leaked readiness")
	}
	for _, suffix := range purposes {
		mustCall(t, b, s, logical.ReadOperation, "keys/"+legacyBinary+suffix, nil)
	}
	controlled = &controlledStorage{Storage: s, afterCommitError: true}
	r, _ = call(b, controlled, logical.UpdateOperation, "ashvault/namespace/"+escapedBinary, nil)
	if status(r) != 503 {
		t.Fatal("lost ack reported confirmed success")
	}
	b = testBackend(t, s)
	migrate(t, b, s, false)
	assertAbsent(t, s, legacyBinary)
}

func TestNamespaceRejectsMixedOwnershipAndCorruptState(t *testing.T) {
	s := testStorage(t)
	b := testBackend(t, s)
	initialize(t, b, s)
	create(t, b, s, legacyBinary, true)
	create(t, b, s, legacyBinary+".mac", false)
	r, _ := call(b, s, logical.UpdateOperation, "ashvault/namespace/"+escapedBinary, nil)
	if status(r) != 503 {
		t.Fatal("mixed ownership was guessed")
	}
	if err := s.Put(context.Background(), &logical.StorageEntry{Key: namespaceReadyPrefix + escapedBinary, Value: []byte("private-marker")}); err != nil {
		t.Fatal(err)
	}
	r, _ = call(b, s, logical.UpdateOperation, "ashvault/namespace/"+escapedBinary, nil)
	if status(r) != 503 || strings.Contains(r.Data[logical.HTTPRawBody].(string), "private-marker") {
		t.Fatal("corrupt marker did not fail closed")
	}
}
