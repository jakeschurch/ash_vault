package main

import (
	"log"
	"os"

	backend "github.com/jakeschurch/ash_vault/openbao_plugin"
	"github.com/openbao/openbao/api/v2"
	"github.com/openbao/openbao/sdk/v2/plugin"
)

func main() {
	meta := &api.PluginAPIClientMeta{}
	if err := meta.FlagSet().Parse(os.Args[1:]); err != nil {
		log.Fatal("invalid plugin arguments")
	}
	tlsConfig := meta.GetTLSConfig()
	if err := plugin.ServeMultiplex(&plugin.ServeOpts{
		BackendFactoryFunc: backend.Factory,
		TLSProviderFunc:    api.VaultPluginTLSProvider(tlsConfig),
	}); err != nil {
		// Never format a backend error that might contain request or key data.
		log.Fatal("plugin stopped")
	}
}
