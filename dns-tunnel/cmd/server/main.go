package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"

	"dns-tunnel/server"
)

type config struct {
	Listen      string `yaml:"listen"`
	Domain      string `yaml:"domain"`
	ServerIP    string `yaml:"server_ip"`
	DialTimeout string `yaml:"dial_timeout"`
	SessionTTL  string `yaml:"session_ttl"`
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	cfgPath := flag.String("config", "config/server.yaml", "path to server config file")
	flag.Parse()

	raw, err := os.ReadFile(*cfgPath)
	if err != nil {
		log.Fatalf("read config %s: %v", *cfgPath, err)
	}

	var cfg config
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		log.Fatalf("parse config: %v", err)
	}

	dialTimeout, _ := time.ParseDuration(cfg.DialTimeout)
	if dialTimeout <= 0 {
		dialTimeout = 10 * time.Second
	}
	sessionTTL, _ := time.ParseDuration(cfg.SessionTTL)
	if sessionTTL <= 0 {
		sessionTTL = 5 * time.Minute
	}

	srv := server.New(server.Config{
		ListenAddr:  cfg.Listen,
		BaseDomain:  cfg.Domain,
		ServerIP:    cfg.ServerIP,
		DialTimeout: dialTimeout,
		SessionTTL:  sessionTTL,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		log.Printf("received signal %v, shutting down…", sig)
		cancel()
	}()

	if err := srv.Run(ctx); err != nil {
		log.Fatalf("server: %v", err)
	}
}
