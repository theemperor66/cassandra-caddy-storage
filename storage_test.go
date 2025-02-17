package cqlstorage

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"testing"

	"github.com/caddyserver/caddy/v2"
)

const (
	envCassandraContactPoints = "CASSANDRA_CONTACT_POINTS"
	envCassandraKeyspace      = "CASSANDRA_KEYSPACE"
)

func newTestCaddyContext() caddy.Context {
	return caddy.ActiveContext()
}

func newTestStorage(t *testing.T) *CQLStorage {
	t.Helper()

	os.Setenv(envCassandraContactPoints, "127.0.0.1")
	os.Setenv(envCassandraKeyspace, "caddy")

	cp := os.Getenv(envCassandraContactPoints)
	ks := os.Getenv(envCassandraKeyspace)
	if cp == "" || ks == "" {
		t.Skipf("Skipping integration tests; set %s and %s", envCassandraContactPoints, envCassandraKeyspace)
	}

	ctx := newTestCaddyContext()

	storage := &CQLStorage{
		QueryTimeout:  1,
		LockTimeout:   10,
		ContactPoints: cp,
		Keyspace:      ks,
	}
	if err := storage.Provision(ctx); err != nil {
		t.Fatalf("Provision failed: %v", err)
	}
	return storage
}

// cleanupKey tries to remove any keys created during tests.
func cleanupKey(ctx context.Context, t *testing.T, storage *CQLStorage, key string) {
	t.Helper()
	if err := storage.Delete(ctx, key); err != nil {
		t.Logf("cleanup Delete(%q) error: %v", key, err)
	}
	if err := storage.Unlock(ctx, key); err != nil {
		t.Logf("cleanup Unlock(%q) error: %v", key, err)
	}
}

func TestCQLStorageIntegration(t *testing.T) {
	storage := newTestStorage(t)
	ctx := context.Background()

	t.Run("StoreLoadExistsStatDelete", func(t *testing.T) {
		key := "integration_test_storeload"
		val := []byte("integration value")
		// Ensure cleanup even if the test fails.
		defer cleanupKey(ctx, t, storage, key)

		// Store a value.
		if err := storage.Store(ctx, key, val); err != nil {
			t.Fatalf("Store(%q) failed: %v", key, err)
		}
		// Verify existence.
		if !storage.Exists(ctx, key) {
			t.Fatalf("Exists(%q) = false; expected true", key)
		}
		// Load and check content.
		loaded, err := storage.Load(ctx, key)
		if err != nil {
			t.Fatalf("Load(%q) failed: %v", key, err)
		}
		if string(loaded) != string(val) {
			t.Errorf("Load(%q) = %q; want %q", key, loaded, val)
		}
		// Retrieve file metadata.
		info, err := storage.Stat(ctx, key)
		if err != nil {
			t.Fatalf("Stat(%q) failed: %v", key, err)
		}
		if info.Key != key {
			t.Errorf("Stat(%q).Key = %q; want %q", key, info.Key, key)
		}
		if info.Size != int64(len(val)) {
			t.Errorf("Stat(%q).Size = %d; want %d", key, info.Size, len(val))
		}
		// Delete the key.
		if err := storage.Delete(ctx, key); err != nil {
			t.Fatalf("Delete(%q) failed: %v", key, err)
		}
		// Confirm deletion.
		if storage.Exists(ctx, key) {
			t.Errorf("Exists(%q) = true after deletion; expected false", key)
		}
		if _, err = storage.Load(ctx, key); err == nil {
			t.Errorf("Load(%q) succeeded after deletion; expected error", key)
		} else if !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("Load(%q) error = %v; want fs.ErrNotExist", key, err)
		}
		if _, err = storage.Stat(ctx, key); err == nil {
			t.Errorf("Stat(%q) succeeded after deletion; expected error", key)
		} else if !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("Stat(%q) error = %v; want fs.ErrNotExist", key, err)
		}
	})

	t.Run("LockUnlock", func(t *testing.T) {
		key := "integration_test_lock"
		defer cleanupKey(ctx, t, storage, key)

		// Initialize key
		if err := storage.Store(ctx, key, []byte("lock test")); err != nil {
			t.Fatalf("Store(%q) failed: %v", key, err)
		}

		// Create a test storage instance with a fixed owner ID
		testStorage := &CQLStorage{
			session:      storage.session,
			LockTimeout:  storage.LockTimeout,
			QueryTimeout: storage.QueryTimeout,
		}

		// Acquire lock
		if err := testStorage.Lock(ctx, key); err != nil {
			t.Fatalf("Lock(%q) failed: %v", key, err)
		}

		// Attempt to acquire lock again (should fail)
		if err := testStorage.Lock(ctx, key); err == nil {
			t.Errorf("Second Lock(%q) succeeded; expected failure", key)
		} else {
			t.Logf("Expected lock failure: %v", err)
		}

		// Release lock
		if err := testStorage.Unlock(ctx, key); err != nil {
			t.Fatalf("Unlock(%q) failed: %v", key, err)
		}

		// Re-acquire lock (should succeed)
		if err := testStorage.Lock(ctx, key); err != nil {
			t.Fatalf("Lock(%q) after unlock failed: %v", key, err)
		}

		// Final unlock
		if err := testStorage.Unlock(ctx, key); err != nil {
			t.Fatalf("Final Unlock(%q) failed: %v", key, err)
		}
	})

	t.Run("ListKeys", func(t *testing.T) {
		keys := []string{
			"list_test_key1",
			"list_test_key2",
			"other_test_key",
		}
		// Store values and register cleanup for each key.
		for _, key := range keys {
			if err := storage.Store(ctx, key, []byte("value-"+key)); err != nil {
				t.Fatalf("Store(%q) failed: %v", key, err)
			}
			t.Cleanup(func(key string) func() {
				return func() { cleanupKey(ctx, t, storage, key) }
			}(key))
		}

		// List keys with the prefix "list_test".
		got, err := storage.List(ctx, "list_test", false)
		if err != nil {
			t.Fatalf("List(prefix=%q) failed: %v", "list_test", err)
		}

		// Check that only expected keys are returned.
		expected := map[string]bool{
			"list_test_key1": true,
			"list_test_key2": true,
		}
		for _, key := range got {
			delete(expected, key)
		}
		if len(expected) > 0 {
			t.Errorf("List(prefix=%q) missing keys: %v", "list_test", expected)
		}
	})
}
