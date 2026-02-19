package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"fj_go_server/internal/api"
	"fj_go_server/internal/config"
	"fj_go_server/internal/db"
	"fj_go_server/internal/runtime"
	"fj_go_server/internal/store"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	conn, err := db.Open(cfg.DatabasePath)
	if err != nil {
		log.Fatalf("open sqlite: %v", err)
	}
	defer conn.Close()

	st := store.New(conn)
	ctx := context.Background()
	if err := st.Init(ctx); err != nil {
		log.Fatalf("initialize schema: %v", err)
	}

	serverID, err := st.EnsureServerID(ctx)
	if err != nil {
		log.Fatalf("ensure server id: %v", err)
	}
	if err := st.SetPairCode(ctx, cfg.PairCode, cfg.PairCodeExpiry()); err != nil {
		log.Fatalf("set pair code: %v", err)
	}

	rt := runtime.NewManager(st)
	srv := api.New(cfg, st, rt)

	printBootInfo(cfg, serverID)
	log.Printf("starting fj relay on %s", cfg.Addr())

	go func() {
		if err := srv.Start(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("server failed: %v", err)
		}
	}()

	waitForShutdown(srv)
}

func waitForShutdown(srv *api.Server) {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	<-signals

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	log.Println("shutting down server...")
	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("graceful shutdown failed: %v", err)
	}
}

func printBootInfo(cfg config.Config, serverID string) {
	pairing := map[string]string{
		"server_url": cfg.ServerURL,
		"server_id":  serverID,
		"pair_code":  cfg.PairCode,
	}

	if pairing["server_url"] == "" {
		pairing["server_url"] = fmt.Sprintf("http://<SERVER_IP>:%s", cfg.Port)
	}

	log.Println("----------------------------------------------------------")
	log.Printf("FJ Mobile IDE Relay is ready")
	log.Printf("Server ID: %s", pairing["server_id"])
	log.Printf("Server URL: %s", pairing["server_url"])
	log.Printf("Pair Code: %s", pairing["pair_code"])
	log.Printf("Pair code expiry (minutes): %d", cfg.PairCodeTTLMinutes)
	log.Println("Use these values in the Flutter app onboarding screen.")
	log.Println("----------------------------------------------------------")
}
