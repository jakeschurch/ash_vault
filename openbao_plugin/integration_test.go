package retirement

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// This suite owns its Raft server, credentials and plugin processes. It never
// connects to a developer's configured OpenBao instance.
func TestOpenBaoIntegration(t *testing.T) {
	switch os.Getenv("ASHVAULT_BACKEND") {
	case "", "memory":
		t.Skip("set ASHVAULT_BACKEND=openbao; requires bao, curl and go on PATH")
	case "openbao":
	default:
		t.Fatal("ASHVAULT_BACKEND must be memory or openbao")
	}
	dir := t.TempDir()
	plugins := filepath.Join(dir, "plugins")
	if err := os.MkdirAll(plugins, 0700); err != nil {
		t.Fatal("cannot create plugin directory")
	}
	binary := filepath.Join(plugins, "ashvault-transit")
	if output, err := exec.Command("rtk", "go", "build", "-trimpath", "-o", binary, "./cmd/ashvault-transit").CombinedOutput(); err != nil {
		t.Fatalf("plugin build: %s", output)
	}
	freePort := func() int {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal("cannot allocate local port")
		}
		defer l.Close()
		return l.Addr().(*net.TCPAddr).Port
	}
	port, clusterPort := freePort(), freePort()
	address := fmt.Sprintf("http://127.0.0.1:%d", port)
	config := fmt.Sprintf(`api_addr = %q
cluster_addr = "http://127.0.0.1:%d"
plugin_directory = %q
listener "tcp" { address = "127.0.0.1:%d" tls_disable = true }
storage "raft" { path = %q node_id = "retirement-integration" }
`, address, clusterPort, plugins, port, filepath.Join(dir, "raft"))
	if err := os.Mkdir(filepath.Join(dir, "raft"), 0700); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dir, "bao.hcl")
	if err := os.WriteFile(configPath, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	logFile, err := os.Create(filepath.Join(dir, "server.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer logFile.Close()
	var server *exec.Cmd
	start := func() {
		// Start the actual binary, not a shell/proxy whose child might outlive cleanup.
		bao, err := exec.LookPath("bao")
		if err != nil {
			t.Fatal("bao executable is required")
		}
		server = exec.Command(bao, "server", "-config="+configPath)
		server.Stdout, server.Stderr = logFile, logFile
		if err := server.Start(); err != nil {
			t.Fatal("cannot start owned server")
		}
		deadline := time.Now().Add(20 * time.Second)
		for time.Now().Before(deadline) {
			response, err := http.Get(address + "/v1/sys/health")
			if err == nil {
				response.Body.Close()
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
		t.Fatal("owned server failed to start (see temporary server.log)")
	}
	stop := func() {
		if server != nil && server.Process != nil {
			_ = server.Process.Signal(os.Interrupt)
			_ = server.Wait()
			server = nil
		}
	}
	t.Cleanup(stop)
	start()
	client := &http.Client{Timeout: 15 * time.Second}
	token := ""
	request := func(method, path string, body map[string]interface{}) (int, map[string]interface{}) {
		t.Helper()
		encoded, _ := json.Marshal(body)
		req, _ := http.NewRequest(method, address+"/v1/"+path, bytes.NewReader(encoded))
		req.Header.Set("X-Vault-Token", token)
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request %s failed (%T)", path, err)
		}
		defer resp.Body.Close()
		value := map[string]interface{}{}
		_ = json.NewDecoder(resp.Body).Decode(&value)
		return resp.StatusCode, value
	}
	must := func(method, path string, body map[string]interface{}) map[string]interface{} {
		t.Helper()
		status, value := request(method, path, body)
		if status < 200 || status >= 300 {
			t.Fatalf("%s %s returned %d", method, path, status)
		}
		data, _ := value["data"].(map[string]interface{})
		return data
	}
	status, initialized := request("PUT", "sys/init", map[string]interface{}{"secret_shares": 1, "secret_threshold": 1})
	if status != 200 {
		t.Fatal("cannot initialize owned server")
	}
	token = initialized["root_token"].(string)
	unseal := initialized["keys_base64"].([]interface{})[0].(string)
	unsealServer := func() {
		must("PUT", "sys/unseal", map[string]interface{}{"key": unseal})
		deadline := time.Now().Add(20 * time.Second)
		for time.Now().Before(deadline) {
			status, _ := request("GET", "sys/health", nil)
			if status == 200 {
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
		t.Fatal("owned server failed to become active")
	}
	unsealServer()
	file, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(file)
	// Register as transit with a custom version: tuning the existing mount retains
	// its storage, including historical key material created by stock Transit.
	must("POST", "sys/mounts/transit", map[string]interface{}{"type": "transit"})
	builtinVersion, ok := must("GET", "sys/mounts", nil)["transit/"].(map[string]interface{})["running_plugin_version"].(string)
	if !ok || builtinVersion == "" {
		t.Fatal("cannot identify stock Transit version")
	}
	must("PUT", "sys/plugins/catalog/secret/transit", map[string]interface{}{
		"sha256": hex.EncodeToString(hash[:]), "command": "ashvault-transit", "version": "v0.1.0",
	})
	names := []string{testName, testName + ".mac", testName + "_lookup"}
	keys := map[string]interface{}{}
	for _, name := range names {
		must("POST", "transit/keys/"+name, map[string]interface{}{"exportable": true})
		keys[name] = must("GET", "transit/export/encryption-key/"+name+"/1", nil)["keys"]
		must("POST", "transit/keys/"+name+"/rotate", nil)
	}
	binaryKeys := map[string]interface{}{}
	for _, suffix := range purposes {
		name := legacyBinary + suffix
		must("POST", "transit/keys/"+name, map[string]interface{}{"exportable": true})
		binaryKeys[suffix] = must("GET", "transit/export/encryption-key/"+name+"/1", nil)["keys"]
		must("POST", "transit/keys/"+name+"/rotate", nil)
	}
	binaryCiphertext := must("POST", "transit/encrypt/"+legacyBinary, map[string]interface{}{"plaintext": "c2VjcmV0", "associated_data": "YWFk", "key_version": 1})["ciphertext"]
	plaintext := base64.StdEncoding.EncodeToString([]byte("migration secret"))
	input := map[string]interface{}{"plaintext": plaintext, "associated_data": "YWFk", "key_version": 1}
	ciphertext := must("POST", "transit/encrypt/"+testName, input)["ciphertext"]
	hmacInput := map[string]interface{}{"input": "c2lnbmVk", "key_version": 1}
	tag := must("POST", "transit/hmac/"+testName+".mac/sha2-256", hmacInput)["hmac"]
	must("POST", "sys/mounts/transit/tune", map[string]interface{}{"plugin_version": "v0.1.0"})
	must("PUT", "sys/plugins/reload/backend", map[string]interface{}{"plugin": "transit"})
	if status, _ := request("POST", "transit/keys/"+testName, nil); status != 503 {
		t.Fatal("migration must require initialization")
	}
	must("POST", "transit/ashvault/initialize", nil)
	must("PUT", "sys/policies/acl/retirement-test-app", map[string]interface{}{
		"policy": `path "transit/*" { capabilities = ["create", "read", "update", "delete", "list"] }`,
	})
	_, tokenResponse := request("POST", "auth/token/create", map[string]interface{}{
		"policies": []string{"retirement-test-app"}, "no_default_policy": true,
	})
	rootToken := token
	token = tokenResponse["auth"].(map[string]interface{})["client_token"].(string)
	if status, _ := request("POST", "transit/ashvault/initialize", nil); status != 403 {
		t.Fatal("initialization must require sudo, even with ordinary update permission")
	}
	if status, _ := request("POST", "transit/ashvault/namespace/"+escapedBinary, nil); status != 403 {
		t.Fatal("namespace migration must require sudo")
	}
	must("GET", "transit/ashvault/protocol", nil)
	token = rootToken
	must("POST", "transit/ashvault/namespace/"+escapedBinary, nil)
	for _, suffix := range purposes {
		got := must("GET", "transit/export/encryption-key/"+escapedBinary+suffix+"/1", nil)["keys"]
		if fmt.Sprint(got) != fmt.Sprint(binaryKeys[suffix]) {
			t.Fatal("binary migration changed historical keys")
		}
	}
	must("POST", "transit/ashvault/namespace/"+escapedBinary, map[string]interface{}{"rollback": true})
	must("POST", "transit/ashvault/namespace/"+escapedBinary, nil)
	for _, name := range names {
		got := must("GET", "transit/export/encryption-key/"+name+"/1", nil)["keys"]
		if fmt.Sprint(got) != fmt.Sprint(keys[name]) {
			t.Fatal("migration changed historical key material")
		}
	}
	decrypted := must("POST", "transit/decrypt/"+testName, map[string]interface{}{"ciphertext": ciphertext, "associated_data": "YWFk"})
	if decrypted["plaintext"] != plaintext {
		t.Fatal("migration changed ciphertext compatibility")
	}
	if got := must("POST", "transit/hmac/"+testName+".mac/sha2-256", hmacInput)["hmac"]; got != tag {
		t.Fatal("migration changed MAC key material")
	}
	if got := must("POST", "transit/encrypt/"+testName, input)["key_version"]; got != float64(1) {
		t.Fatal("pinned version response is incorrect")
	}
	for _, fields := range []map[string]interface{}{{"min_decryption_version": 2}, {"auto_rotate_period": 60}} {
		if status, _ := request("POST", "transit/keys/"+testName+"/config", fields); status != 400 {
			t.Fatal("unsupported configuration must be rejected")
		}
	}

	// A proxy can retain a request after its caller dies. Release that exact request
	// only after retirement succeeds: there is no client left to perform cleanup.
	for i, suffix := range []string{"", ".mac", "_lookup"} {
		scope := "ashvault_" + base64.RawURLEncoding.EncodeToString([]byte("dead-client-"+strconv.Itoa(i)))
		arrived, release, forwarded := make(chan struct{}), make(chan struct{}), make(chan int, 1)
		proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			close(arrived)
			<-release
			// Deliberately do not inherit the disconnected caller's cancellation.
			upstream, _ := http.NewRequest("POST", address+"/v1/transit/keys/"+scope+suffix, bytes.NewReader(body))
			upstream.Header.Set("X-Vault-Token", token)
			resp, err := client.Do(upstream)
			if err != nil {
				forwarded <- 0
				return
			}
			resp.Body.Close()
			forwarded <- resp.StatusCode
		}))
		// A real disposable client process, terminated while the proxy holds its request.
		curl, err := exec.LookPath("curl")
		if err != nil {
			t.Fatal("curl executable is required")
		}
		child := exec.Command(curl, "--silent", "--request", "POST", "--data", `{}`, proxy.URL)
		if err := child.Start(); err != nil {
			t.Fatal("cannot start disposable client")
		}
		select {
		case <-arrived:
		case <-time.After(10 * time.Second):
			t.Fatal("client did not arrive")
		}
		_ = child.Process.Kill()
		_ = child.Wait()
		must("POST", "transit/ashvault/retire/"+scope, nil)
		close(release)
		if status := <-forwarded; status != 410 {
			t.Fatalf("dead client's delayed create returned %d", status)
		}
		proxy.Close()
		for _, purpose := range []string{"", ".mac", "_lookup"} {
			if status, _ := request("GET", "transit/keys/"+scope+purpose, nil); status != 404 {
				t.Fatal("late key survived retirement")
			}
		}
	}
	must("POST", "transit/ashvault/retire/"+testName, nil)
	// Crash the owned plugin process (not just its client) and verify durable state
	// on reload. Linux /proc matching confines the kill to this test's binary.
	entries, _ := os.ReadDir("/proc")
	killed := false
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		exe, _ := os.Readlink(filepath.Join("/proc", entry.Name(), "exe"))
		if exe == binary {
			process, _ := os.FindProcess(pid)
			_ = process.Kill()
			killed = true
		}
	}
	if !killed {
		t.Fatal("owned plugin process was not found")
	}
	must("PUT", "sys/plugins/reload/backend", map[string]interface{}{"plugin": "transit"})
	stop()
	start()
	unsealServer()
	for _, name := range names {
		if status, _ := request("POST", "transit/keys/"+name, nil); status != 410 {
			t.Fatal("retirement lost across server restart")
		}
		if status, _ := request("GET", "transit/export/encryption-key/"+name+"/1", nil); status != 410 {
			t.Fatal("retired key remains exportable")
		}
	}
	for _, route := range []string{"restore/" + testName, "keys/" + testName + "/import"} {
		if status, _ := request("POST", "transit/"+route, nil); status < 400 {
			t.Fatal("unsupported route bypassed retirement")
		}
	}
	if retired := must("GET", "transit/ashvault/retired/"+testName, nil); retired["retired"] != true {
		t.Fatal("durable marker disappeared")
	}
	// The new names are ordinary Transit names. Keeping the plugin is optional
	// when the application uses stock mode after its maintenance migration.
	must("POST", "sys/mounts/transit/tune", map[string]interface{}{"plugin_version": builtinVersion})
	must("PUT", "sys/plugins/reload/backend", map[string]interface{}{"plugin": "transit"})
	if got := must("POST", "transit/decrypt/"+escapedBinary, map[string]interface{}{"ciphertext": binaryCiphertext, "associated_data": "YWFk"})["plaintext"]; got != "c2VjcmV0" {
		t.Fatal("stock Transit lost migrated ciphertext")
	}
}
