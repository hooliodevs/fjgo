package config

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Host                          string
	Port                          string
	DatabasePath                  string
	WorkspacesRoot                string
	DefaultCursorCommand          string
	PairCode                      string
	PairCodeTTLMinutes            int
	ServerURL                     string
	PrivilegeConfirmationRequired bool
}

func Load() (Config, error) {
	cfg := Config{
		Host:                          env("HOST", "0.0.0.0"),
		Port:                          env("PORT", "8787"),
		DatabasePath:                  env("DATABASE_PATH", "./data/fj_relay.db"),
		WorkspacesRoot:                env("WORKSPACES_ROOT", "./workspaces"),
		DefaultCursorCommand:          env("DEFAULT_CURSOR_COMMAND", "cursor"),
		PairCode:                      strings.TrimSpace(os.Getenv("PAIR_CODE")),
		ServerURL:                     strings.TrimSpace(os.Getenv("SERVER_URL")),
		PrivilegeConfirmationRequired: envBool("PRIVILEGE_CONFIRMATION_REQUIRED", true),
	}

	ttlRaw := env("PAIR_CODE_TTL_MINUTES", "43200")
	ttl, err := strconv.Atoi(ttlRaw)
	if err != nil || ttl <= 0 {
		return Config{}, fmt.Errorf("PAIR_CODE_TTL_MINUTES must be a positive integer")
	}
	cfg.PairCodeTTLMinutes = ttl

	if cfg.PairCode == "" {
		code, genErr := generatePairCode()
		if genErr != nil {
			return Config{}, fmt.Errorf("generate pair code: %w", genErr)
		}
		cfg.PairCode = code
	}

	if err := os.MkdirAll(filepath.Dir(cfg.DatabasePath), 0o755); err != nil {
		return Config{}, fmt.Errorf("create database dir: %w", err)
	}
	if err := os.MkdirAll(cfg.WorkspacesRoot, 0o755); err != nil {
		return Config{}, fmt.Errorf("create workspaces dir: %w", err)
	}

	return cfg, nil
}

func (c Config) Addr() string {
	return c.Host + ":" + c.Port
}

func (c Config) PairCodeExpiry() time.Time {
	return time.Now().UTC().Add(time.Duration(c.PairCodeTTLMinutes) * time.Minute)
}

func env(key, fallback string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	return value
}

func envBool(key string, fallback bool) bool {
	value := strings.TrimSpace(strings.ToLower(os.Getenv(key)))
	if value == "" {
		return fallback
	}
	switch value {
	case "1", "true", "yes", "y", "on":
		return true
	case "0", "false", "no", "n", "off":
		return false
	default:
		return fallback
	}
}

func generatePairCode() (string, error) {
	buf := make([]byte, 3)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	encoded := strings.ToUpper(hex.EncodeToString(buf))
	return encoded[:3] + "-" + encoded[3:], nil
}
