package main

import (
	"context"
	"log"
	"net/http"
	"time"

	"mailclient/internal/api"
	"mailclient/internal/auth"
	"mailclient/internal/config"
	"mailclient/internal/db"
	"mailclient/internal/mail"
	"mailclient/internal/notify"
	"mailclient/internal/service"
	"mailclient/internal/store"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("load config: %v", err)
	}
	sqdb, err := db.OpenSQLite(cfg.DBPath, cfg.DBMaxOpenConns, cfg.DBMaxIdleConns, cfg.DBConnMaxLifetime)
	if err != nil {
		log.Fatalf("open db: %v", err)
	}
	defer sqdb.Close()
	if err := db.ApplyMigrationFile(sqdb, "migrations/001_init.sql"); err != nil {
		log.Fatalf("migration: %v", err)
	}

	st := store.New(sqdb)
	if cfg.BootstrapAdminEmail != "" && cfg.BootstrapAdminPassword != "" {
		hash, err := auth.HashPassword(cfg.BootstrapAdminPassword)
		if err != nil {
			log.Fatalf("bootstrap admin hash: %v", err)
		}
		if err := st.EnsureAdmin(context.Background(), cfg.BootstrapAdminEmail, hash); err != nil {
			log.Fatalf("bootstrap admin create: %v", err)
		}
	}

	mailClient := mail.NewIMAPSMTPClient(cfg)
	provisioner, err := mail.NewProvisioner(cfg)
	if err != nil {
		log.Fatalf("provisioner: %v", err)
	}
	sender := notify.NewSender(cfg)

	svc := service.New(cfg, st, mailClient, provisioner, sender)
	r := api.NewRouter(cfg, svc)

	hsrv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           r,
		ReadTimeout:       time.Duration(cfg.HTTPReadTimeoutSec) * time.Second,
		ReadHeaderTimeout: time.Duration(cfg.HTTPReadHeaderTimeoutSec) * time.Second,
		WriteTimeout:      time.Duration(cfg.HTTPWriteTimeoutSec) * time.Second,
		IdleTimeout:       time.Duration(cfg.HTTPIdleTimeoutSec) * time.Second,
	}

	log.Printf("listening on %s", cfg.ListenAddr)
	if err := hsrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("server: %v", err)
	}
}
