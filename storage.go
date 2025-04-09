package cqlstorage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/certmagic"
	"github.com/cespare/xxhash/v2"
	"github.com/gocql/gocql"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(&CQLStorage{})
}

// SecondsDuration is a custom duration type that supports configuration as a
// plain number (interpreted as seconds) or as a duration string (e.g., "3s").
type SecondsDuration time.Duration

// UnmarshalJSON supports both number (in seconds) and string (e.g., "3s") formats.
func (d *SecondsDuration) UnmarshalJSON(b []byte) error {
	// Try unmarshaling as a number.
	var num float64
	if err := json.Unmarshal(b, &num); err == nil {
		*d = SecondsDuration(time.Duration(num * float64(time.Second)))
		return nil
	}
	// Otherwise, unmarshal as a string.
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	duration, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	*d = SecondsDuration(duration)
	return nil
}

// MarshalJSON marshals the duration as a string.
func (d SecondsDuration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d).String())
}

// CQLStorage implements both JSON and Caddyfile configuration.
// When configured via Caddyfile, UnmarshalCaddyfile is invoked; when configured via JSON,
// the fields are filled by the JSON adapter, and Provision applies common defaults.
type CQLStorage struct {
	QueryTimeout  SecondsDuration `json:"query_timeout,omitempty"`
	LockTimeout   SecondsDuration `json:"lock_timeout,omitempty"`
	ContactPoints []string        `json:"contact_points,omitempty"`
	Keyspace      string          `json:"keyspace,omitempty"`
	Username      string          `json:"username,omitempty"`
	Password      string          `json:"password,omitempty"`

	session *gocql.Session
}

func (CQLStorage) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID: "caddy.storage.cql",
		New: func() caddy.Module {
			return new(CQLStorage)
		},
	}
}

// UnmarshalCaddyfile is called only when using the Caddyfile adapter.
func (cs *CQLStorage) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	// Process each token in the block.
	for d.Next() {
		key := d.Val()
		switch key {
		case "query_timeout":
			var val string
			if !d.Args(&val) {
				return d.Err("query_timeout requires a value")
			}
			qt, err := strconv.Atoi(val)
			if err != nil {
				return d.Errf("invalid query_timeout: %v", err)
			}
			// Multiply by time.Second so that the value is in seconds.
			cs.QueryTimeout = SecondsDuration(time.Duration(qt) * time.Second)

		case "lock_timeout":
			var val string
			if !d.Args(&val) {
				return d.Err("lock_timeout requires a value")
			}
			lt, err := strconv.Atoi(val)
			if err != nil {
				return d.Errf("invalid lock_timeout: %v", err)
			}
			cs.LockTimeout = SecondsDuration(time.Duration(lt) * time.Second)

		case "contact_points":
			// Allow multiple contact points as separate arguments.
			cp := d.RemainingArgs()
			if len(cp) == 0 {
				return d.Err("contact_points requires at least one contact point")
			}
			cs.ContactPoints = cp

		case "keyspace":
			var val string
			if !d.Args(&val) {
				return d.Err("keyspace requires a value")
			}
			cs.Keyspace = val

		case "username":
			var val string
			if !d.Args(&val) {
				return d.Err("username requires a value")
			}
			cs.Username = val

		case "password":
			var val string
			if !d.Args(&val) {
				return d.Err("password requires a value")
			}
			cs.Password = val
		}
	}
	caddy.Log().Named("storage.cql").Debug("CQLStorage config", zap.Any("config", cs))
	return nil
}

// Provision applies default values and falls back to environment variables when necessary.
// This method is invoked regardless of the configuration source.
func (cs *CQLStorage) Provision(ctx caddy.Context) error {
	// If not set via the configuration file, try environment variables.
	if len(cs.ContactPoints) == 0 {
		if envCP := os.Getenv("CASSANDRA_CONTACT_POINTS"); envCP != "" {
			cs.ContactPoints = splitHosts(envCP)
		}
	}
	if cs.Keyspace == "" {
		cs.Keyspace = os.Getenv("CASSANDRA_KEYSPACE")
	}
	if cs.Username == "" {
		cs.Username = os.Getenv("CASSANDRA_USER")
	}
	if cs.Password == "" {
		cs.Password = os.Getenv("CASSANDRA_PASSWORD")
	}
	if time.Duration(cs.QueryTimeout) == 0 {
		cs.QueryTimeout = SecondsDuration(3 * time.Second)
	}
	if time.Duration(cs.LockTimeout) == 0 {
		cs.LockTimeout = SecondsDuration(60 * time.Second)
	}

	// Validate that we have contact points.
	if len(cs.ContactPoints) == 0 {
		return fmt.Errorf("no valid Cassandra contact points provided")
	}

	cluster := gocql.NewCluster()
	cluster.ProtoVersion = 4
	cluster.Hosts = cs.ContactPoints
	cluster.Keyspace = cs.Keyspace
	cluster.Timeout = time.Duration(cs.QueryTimeout)
	cluster.ConnectTimeout = time.Duration(cs.QueryTimeout)

	// Add authentication if credentials are provided
	if cs.Username != "" && cs.Password != "" {
		cluster.Authenticator = gocql.PasswordAuthenticator{
			Username: cs.Username,
			Password: cs.Password,
		}
	}

	sess, err := cluster.CreateSession()
	if err != nil {
		return fmt.Errorf("failed to create Cassandra session: %w", err)
	}
	cs.session = sess
	caddy.Log().Named("storage.cql").Debug("Provisioned", zap.Any("config", cs))
	return cs.ensureTables()
}

func (cs *CQLStorage) Validate() error {
	if cs.session == nil {
		return errors.New("no Cassandra session; provision failed")
	}
	return nil
}

func (cs *CQLStorage) CertMagicStorage() (certmagic.Storage, error) {
	return NewStorage(*cs)
}

func NewStorage(cfg CQLStorage) (certmagic.Storage, error) {
	if cfg.session == nil {
		return nil, errors.New("Cassandra session not initialized")
	}
	if err := cfg.ensureTables(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (cs *CQLStorage) ensureTables() error {
	if cs.session == nil {
		return errors.New("no Cassandra session available")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cs.QueryTimeout))
	defer cancel()

	if err := cs.session.Query(`
CREATE TABLE IF NOT EXISTS certmagic_data (
	key_hash text PRIMARY KEY,
	key      text,
	value    blob,
	modified timestamp
)`).WithContext(ctx).Exec(); err != nil {
		return fmt.Errorf("creating certmagic_data: %w", err)
	}

	if err := cs.session.Query(`
CREATE TABLE IF NOT EXISTS certmagic_locks (
	key_hash    text PRIMARY KEY,
	key         text,
	locked_at   timestamp,
	expires_at  timestamp
)`).WithContext(ctx).Exec(); err != nil {
		return fmt.Errorf("creating certmagic_locks: %w", err)
	}

	if err := cs.session.Query(`
CREATE CUSTOM INDEX IF NOT EXISTS certmagic_data_key_idx ON certmagic_data (key)
USING 'org.apache.cassandra.index.sasi.SASIIndex'
WITH OPTIONS = {
	'mode': 'PREFIX',
	'analyzer_class': 'org.apache.cassandra.index.sasi.analyzer.StandardAnalyzer',
	'case_sensitive': 'false'
}`).WithContext(ctx).Exec(); err != nil {
		caddy.Log().Named("storage.cql").Warn("Failed to create SASI index", zap.Error(err))
	}
	caddy.Log().Named("storage.cql").Debug("Tables ensured")
	return nil
}

func (cs *CQLStorage) Lock(ctx context.Context, key string) error {
	if cs.session == nil {
		return errors.New("no Cassandra session available")
	}

	keyHash := computeKeyHash(key)
	now := time.Now()
	expires := now.Add(time.Duration(cs.LockTimeout))

	var existingExpires time.Time
	err := cs.session.Query(`
		SELECT expires_at FROM certmagic_locks 
		WHERE key_hash = ?
	`, keyHash).WithContext(ctx).Scan(&existingExpires)

	if err != nil && err != gocql.ErrNotFound {
		return fmt.Errorf("failed to check lock status: %w", err)
	}

	if err != gocql.ErrNotFound && existingExpires.After(now) {
		return fmt.Errorf("key is locked: %s", key)
	}

	err = cs.session.Query(`
		INSERT INTO certmagic_locks (key_hash, key, locked_at, expires_at)
		VALUES (?, ?, ?, ?)
	`, keyHash, key, now, expires).WithContext(ctx).Exec()

	if err != nil {
		return fmt.Errorf("failed to acquire lock for key %s: %w", key, err)
	}

	caddy.Log().Named("storage.cql").Debug("Lock acquired",
		zap.String("key", key),
		zap.Time("expires", expires))
	return nil
}

func (cs *CQLStorage) Unlock(ctx context.Context, key string) error {
	if cs.session == nil {
		return errors.New("no Cassandra session available")
	}

	keyHash := computeKeyHash(key)

	var existingExpires time.Time
	err := cs.session.Query(`
		SELECT expires_at FROM certmagic_locks 
		WHERE key_hash = ?
	`, keyHash).WithContext(ctx).Scan(&existingExpires)

	if err == gocql.ErrNotFound {
		return nil
	}
	if err != nil {
		return fmt.Errorf("error checking lock for key %s: %w", key, err)
	}

	err = cs.session.Query(`
		DELETE FROM certmagic_locks 
		WHERE key_hash = ?
	`, keyHash).WithContext(ctx).Exec()

	if err != nil {
		return fmt.Errorf("unlock error on key %s: %w", key, err)
	}

	caddy.Log().Named("storage.cql").Debug("Lock released",
		zap.String("key", key))
	return nil
}

func (cs *CQLStorage) Store(ctx context.Context, key string, value []byte) error {
	if cs.session == nil {
		return errors.New("no Cassandra session available")
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(cs.QueryTimeout))
	defer cancel()

	keyHash := computeKeyHash(key)
	if err := cs.session.Query(`
INSERT INTO certmagic_data (key_hash, key, value, modified)
VALUES (?, ?, ?, toTimestamp(now()))
`, keyHash, key, value).WithContext(ctx).Exec(); err != nil {
		return fmt.Errorf("store error on key %s: %w", key, err)
	}
	caddy.Log().Named("storage.cql").Debug("Stored key", zap.String("key", key))
	return nil
}

func (cs *CQLStorage) Load(ctx context.Context, key string) ([]byte, error) {
	if cs.session == nil {
		return nil, errors.New("no Cassandra session available")
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(cs.QueryTimeout))
	defer cancel()

	keyHash := computeKeyHash(key)
	var value []byte
	err := cs.session.Query(`SELECT value FROM certmagic_data WHERE key_hash = ?`, keyHash).
		WithContext(ctx).Scan(&value)
	if err == gocql.ErrNotFound {
		return nil, fs.ErrNotExist
	}
	if err != nil {
		return nil, fmt.Errorf("load error on key %s: %w", key, err)
	}
	caddy.Log().Named("storage.cql").Debug("Loaded key", zap.String("key", key))
	return value, nil
}

func (cs *CQLStorage) Delete(ctx context.Context, key string) error {
	if cs.session == nil {
		return errors.New("no Cassandra session available")
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(cs.QueryTimeout))
	defer cancel()

	keyHash := computeKeyHash(key)
	if err := cs.session.Query(`DELETE FROM certmagic_data WHERE key_hash = ?`, keyHash).
		WithContext(ctx).Exec(); err != nil {
		return fmt.Errorf("delete error on key %s: %w", key, err)
	}
	caddy.Log().Named("storage.cql").Debug("Deleted key", zap.String("key", key))
	return nil
}

func (cs *CQLStorage) Exists(ctx context.Context, key string) bool {
	if cs.session == nil {
		return false
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(cs.QueryTimeout))
	defer cancel()

	keyHash := computeKeyHash(key)
	var dummy string
	err := cs.session.Query(`SELECT key_hash FROM certmagic_data WHERE key_hash = ?`, keyHash).
		WithContext(ctx).Scan(&dummy)
	return err == nil
}

func (cs *CQLStorage) List(ctx context.Context, prefix string, recursive bool) ([]string, error) {
	if cs.session == nil {
		return nil, errors.New("no Cassandra session available")
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(cs.QueryTimeout))
	defer cancel()

	if recursive {
		return nil, fmt.Errorf("recursive listing not supported")
	}

	iter := cs.session.Query(`SELECT key FROM certmagic_data`).
		WithContext(ctx).Iter()
	var keys []string
	var k string
	for iter.Scan(&k) {
		if strings.HasPrefix(k, prefix) {
			keys = append(keys, k)
		}
	}
	if err := iter.Close(); err != nil {
		return nil, fmt.Errorf("iterator close error: %w", err)
	}
	caddy.Log().Named("storage.cql").Debug("List keys", zap.String("prefix", prefix), zap.Int("count", len(keys)))
	return keys, nil
}

func (cs *CQLStorage) Stat(ctx context.Context, key string) (certmagic.KeyInfo, error) {
	if cs.session == nil {
		return certmagic.KeyInfo{}, errors.New("no Cassandra session available")
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(cs.QueryTimeout))
	defer cancel()

	keyHash := computeKeyHash(key)
	var value []byte
	var modified time.Time
	err := cs.session.Query(`SELECT value, modified FROM certmagic_data WHERE key_hash = ?`, keyHash).
		WithContext(ctx).Scan(&value, &modified)
	if err == gocql.ErrNotFound {
		return certmagic.KeyInfo{}, fs.ErrNotExist
	}
	if err != nil {
		return certmagic.KeyInfo{}, fmt.Errorf("stat error on key %s: %w", key, err)
	}
	return certmagic.KeyInfo{
		Key:        key,
		Modified:   modified,
		Size:       int64(len(value)),
		IsTerminal: true,
	}, nil
}

func computeKeyHash(s string) string {
	salt := os.Getenv("CQL_HASH_SALT")
	if salt == "" {
		salt = "defaultSalt"
	}
	return fmt.Sprintf("%x", xxhash.Sum64([]byte(s+salt)))
}

func splitHosts(raw string) []string {
	parts := strings.Split(raw, ",")
	var hosts []string
	for _, p := range parts {
		if h := strings.TrimSpace(p); h != "" {
			hosts = append(hosts, h)
		}
	}
	return hosts
}

var (
	_ caddy.Module          = (*CQLStorage)(nil)
	_ caddy.Provisioner     = (*CQLStorage)(nil)
	_ caddy.Validator       = (*CQLStorage)(nil)
	_ caddyfile.Unmarshaler = (*CQLStorage)(nil)
	_ certmagic.Storage     = (*CQLStorage)(nil)
)
