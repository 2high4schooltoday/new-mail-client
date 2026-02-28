package mail

import (
	"context"
	"database/sql"
	"fmt"
	"regexp"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/jackc/pgx/v5/stdlib"

	"mailclient/internal/config"
)

var identRx = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

type SQLProvisioner struct {
	db          *sql.DB
	driver      string
	table       string
	emailCol    string
	passCol     string
	activeCol   string
	maildirCol  string
	maildirBase string
}

func NewProvisioner(cfg config.Config) (AuthProvisioner, error) {
	if strings.EqualFold(strings.TrimSpace(cfg.DovecotAuthMode), "pam") {
		return NoopProvisioner{}, nil
	}
	if strings.TrimSpace(cfg.DovecotAuthDBDriver) == "" || strings.TrimSpace(cfg.DovecotAuthDBDSN) == "" {
		return NoopProvisioner{}, nil
	}
	for _, ident := range []string{cfg.DovecotAuthTable, cfg.DovecotEmailColumn, cfg.DovecotPassColumn, cfg.DovecotActiveColumn, cfg.DovecotMaildirColumn} {
		if ident != "" && !identRx.MatchString(ident) {
			return nil, fmt.Errorf("invalid SQL identifier %q", ident)
		}
	}
	db, err := sql.Open(cfg.DovecotAuthDBDriver, cfg.DovecotAuthDBDSN)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(2)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(30 * time.Minute)
	if err := db.Ping(); err != nil {
		return nil, err
	}
	return &SQLProvisioner{
		db:          db,
		driver:      cfg.DovecotAuthDBDriver,
		table:       cfg.DovecotAuthTable,
		emailCol:    cfg.DovecotEmailColumn,
		passCol:     cfg.DovecotPassColumn,
		activeCol:   cfg.DovecotActiveColumn,
		maildirCol:  cfg.DovecotMaildirColumn,
		maildirBase: strings.TrimRight(cfg.DovecotMaildirBase, "/"),
	}, nil
}

func (p *SQLProvisioner) UpsertActiveUser(ctx context.Context, email, passwordHash string) error {
	maildir := p.buildMaildir(email)
	setCols := []string{fmt.Sprintf("%s=%s", p.passCol, p.ph(1))}
	args := []any{passwordHash}
	idx := 2
	if p.activeCol != "" {
		setCols = append(setCols, fmt.Sprintf("%s=%s", p.activeCol, p.ph(idx)))
		args = append(args, 1)
		idx++
	}
	if p.maildirCol != "" {
		setCols = append(setCols, fmt.Sprintf("%s=%s", p.maildirCol, p.ph(idx)))
		args = append(args, maildir)
		idx++
	}
	args = append(args, email)
	updateQ := fmt.Sprintf("UPDATE %s SET %s WHERE %s=%s", p.table, strings.Join(setCols, ","), p.emailCol, p.ph(idx))
	res, err := p.db.ExecContext(ctx, updateQ, args...)
	if err != nil {
		return err
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if rows > 0 {
		return nil
	}

	cols := []string{p.emailCol, p.passCol}
	vals := []any{email, passwordHash}
	if p.activeCol != "" {
		cols = append(cols, p.activeCol)
		vals = append(vals, 1)
	}
	if p.maildirCol != "" {
		cols = append(cols, p.maildirCol)
		vals = append(vals, maildir)
	}
	phs := make([]string, len(vals))
	for i := range vals {
		phs[i] = p.ph(i + 1)
	}
	insertQ := fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s)", p.table, strings.Join(cols, ","), strings.Join(phs, ","))
	if _, err := p.db.ExecContext(ctx, insertQ, vals...); err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "duplicate") || strings.Contains(strings.ToLower(err.Error()), "unique") {
			_, err = p.db.ExecContext(ctx, updateQ, args...)
		}
		return err
	}
	return nil
}

func (p *SQLProvisioner) DisableUser(ctx context.Context, email string) error {
	if p.activeCol == "" {
		return nil
	}
	q := fmt.Sprintf("UPDATE %s SET %s=%s WHERE %s=%s", p.table, p.activeCol, p.ph(1), p.emailCol, p.ph(2))
	_, err := p.db.ExecContext(ctx, q, 0, email)
	return err
}

func (p *SQLProvisioner) ph(i int) string {
	if strings.Contains(strings.ToLower(p.driver), "pgx") || strings.Contains(strings.ToLower(p.driver), "postgres") {
		return fmt.Sprintf("$%d", i)
	}
	return "?"
}

func (p *SQLProvisioner) buildMaildir(email string) string {
	parts := strings.SplitN(email, "@", 2)
	if len(parts) != 2 {
		return p.maildirBase + "/local/default/Maildir"
	}
	local := sanitizePathPart(parts[0])
	domain := sanitizePathPart(parts[1])
	return fmt.Sprintf("%s/%s/%s/Maildir", p.maildirBase, domain, local)
}

func sanitizePathPart(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	if v == "" {
		return "default"
	}
	v = strings.ReplaceAll(v, "..", "")
	v = strings.ReplaceAll(v, "/", "_")
	v = strings.ReplaceAll(v, "\\", "_")
	return v
}
