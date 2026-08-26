// Command f3check validates the real-data ingestion path (fetch -> parse ->
// filter -> dedup) against the user's whitelisted sources. It does NOT ping
// (probing uses the embedded mihomo hub and needs real egress to tunnel through
// a node), so it proves the network/protocol stages handle real subscriptions.
// The live ping + generate step must run on the user's Linux host with egress
// to the node IPs.
package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"vpn-sub-manager/internal/config"
	"vpn-sub-manager/internal/fetch"
	"vpn-sub-manager/internal/filter"
	"vpn-sub-manager/internal/model"
	"vpn-sub-manager/internal/parse"
)

var sources = []string{
	"https://github.com/Au1rxx/free-vpn-subscriptions/raw/main/output/v2ray-base64.txt",
	"https://raw.githubusercontent.com/Epodonios/v2ray-configs/refs/heads/main/All_Configs_base64_Sub.txt",
	"https://raw.githubusercontent.com/kort0881/vpn-vless-configs-russia/refs/heads/main/output/vless.txt",
}

func main() {
	dir, err := os.MkdirTemp("", "f3check-*")
	if err != nil {
		fmt.Println("tempdir:", err)
		os.Exit(1)
	}
	defer os.RemoveAll(dir)

	reg, err := config.New(filepath.Join(dir, "sources.txt"))
	if err != nil {
		fmt.Println("config.New:", err)
		os.Exit(1)
	}
	for _, u := range sources {
		if _, err := reg.AddSource(u); err != nil {
			fmt.Printf("AddSource %s: %v\n", u, err)
			os.Exit(1)
		}
	}

	f := fetch.NewFetcher(reg)
	ctx := context.Background()

	var all []model.Node
	enabled, err := reg.EnabledSources()
	if err != nil {
		fmt.Println("EnabledSources:", err)
		os.Exit(1)
	}
	for _, src := range enabled {
		fetched, ferr := f.Fetch(ctx, src)
		if ferr != nil {
			fmt.Printf("[FAIL] fetch %s: %v\n", src.URL, ferr)
			continue
		}
		for _, fs := range fetched {
			ns, perr := parse.ParseSubscription(fs.Body)
			if perr != nil {
				fmt.Printf("[WARN] parse %s: %v\n", fs.URL, perr)
				continue
			}
			fmt.Printf("  %s: parsed %d nodes\n", fs.URL, len(ns))
			all = append(all, ns...)
		}
	}
	if len(all) == 0 {
		fmt.Println("NODES PARSED = 0 — ingestion failed or sources empty")
		os.Exit(1)
	}

	raw := len(all)
	dedup := filter.Dedup(all)
	noBroken := filter.DropBroken(dedup)
	noUnsupported := filter.DropUnsupported(noBroken)
	noOpen := filter.DropOpen(noUnsupported)
	noInsecure := filter.DropInsecure(noOpen)
	clean := filter.DropMalware(noInsecure)

	fmt.Println("--- ingestion summary ---")
	fmt.Printf("raw parsed      : %d\n", raw)
	fmt.Printf("after dedup     : %d\n", len(dedup))
	fmt.Printf("after broken    : %d\n", len(noBroken))
	fmt.Printf("after unsupported: %d\n", len(noUnsupported))
	fmt.Printf("after open      : %d\n", len(noOpen))
	fmt.Printf("after insecure  : %d\n", len(noInsecure))
	fmt.Printf("after malware   : %d (final, to be pinged/generated on Linux)\n", len(clean))
	fmt.Println("INGESTION OK")
}
