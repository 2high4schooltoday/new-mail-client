package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"time"

	"mailclient/internal/api"
	"mailclient/internal/auth"
	"mailclient/internal/config"
	"mailclient/internal/db"
	"mailclient/internal/mail"
	"mailclient/internal/notify"
	"mailclient/internal/service"
	"mailclient/internal/store"
	"mailclient/internal/update"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("load config: %v", err)
	}
	if len(os.Args) > 1 && os.Args[1] == "update-worker" {
		if err := update.RunWorker(context.Background(), cfg); err != nil {
			log.Fatalf("update worker: %v", err)
		}
		return
	}
	if cfg.CookiePolicyWarning != "" {
		log.Printf("config_warning: %s", cfg.CookiePolicyWarning)
	}
	sqdb, err := db.OpenSQLite(cfg.DBPath, cfg.DBMaxOpenConns, cfg.DBMaxIdleConns, cfg.DBConnMaxLifetime)
	if err != nil {
		log.Fatalf("open db: %v", err)
	}
	defer sqdb.Close()
	for _, migration := range []string{
		"migrations/001_init.sql",
		"migrations/002_users_mail_login.sql",
	} {
		if err := db.ApplyMigrationFile(sqdb, migration); err != nil {
			log.Fatalf("migration %s: %v", migration, err)
		}
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
