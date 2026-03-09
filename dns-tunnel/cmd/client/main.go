package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"gopkg.in/yaml.v3"

	"dns-tunnel/client"
)

type config struct {
	Listen    string   `yaml:"listen"`
	Domain    string   `yaml:"domain"`
	Resolvers []string `yaml:"resolvers"`
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	cfgPath := flag.String("config", "config/client.yaml", "path to client config file")
	flag.Parse()

	raw, err := os.ReadFile(*cfgPath)
	if err != nil {
		log.Fatalf("read config %s: %v", *cfgPath, err)
	}

	var cfg config
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		log.Fatalf("parse config: %v", err)
	}

	if len(cfg.Resolvers) == 0 {
		log.Fatal("no resolvers configured — edit config/client.yaml")
	}

	pool := client.NewResolverPool(cfg.Resolvers)

	fmt.Printf("DNS Tunnel Client\n")
	fmt.Printf("  SOCKS5 proxy : %s\n", cfg.Listen)
	fmt.Printf("  Tunnel domain: %s\n", cfg.Domain)
	fmt.Printf("  Resolvers    : %d configured\n", len(cfg.Resolvers))
	for _, r := range pool.All() {
		fmt.Printf("    - %s\n", r.Addr)
	}
	fmt.Println()

	socks5 := client.NewSOCKS5Server(cfg.Listen, cfg.Domain, pool)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		log.Printf("received signal %v, shutting down…", sig)
		cancel()
	}()

	if err := socks5.Run(ctx); err != nil {
		log.Fatalf("client: %v", err)
	}
}
