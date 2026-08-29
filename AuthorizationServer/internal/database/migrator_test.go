package database

import (
	"testing"
	"testing/fstest"

	"github.com/sameerchandekar/MiniAuth/AuthorizationServer/migrations"
)

func TestLoadMigrationFiles(t *testing.T) {
	mockFS := fstest.MapFS{
		"V1__init_auth_schema.sql": &fstest.MapFile{
			Data: []byte("CREATE TABLE users (id UUID);"),
		},
		"V2__add_oauth_clients.sql": &fstest.MapFile{
			Data: []byte("CREATE TABLE oauth_clients (id UUID);"),
		},
		"V1_1__add_user_indexes.sql": &fstest.MapFile{
			Data: []byte("CREATE INDEX idx_users ON users (id);"),
		},
		"README.md": &fstest.MapFile{
			Data: []byte("# Migrations"),
		},
		"invalid_migration.sql": &fstest.MapFile{
			Data: []byte("INVALID"),
		},
	}

	migrations, err := loadMigrationFiles(mockFS)
	if err != nil {
		t.Fatalf("unexpected error loading migrations: %v", err)
	}

	if len(migrations) != 3 {
		t.Fatalf("expected 3 valid migrations, got %d", len(migrations))
	}

	// Check order: V1, V1.1, V2
	if migrations[0].VersionRaw != "1" || migrations[0].Filename != "V1__init_auth_schema.sql" {
		t.Errorf("expected first migration to be V1, got %s", migrations[0].Filename)
	}
	if migrations[1].VersionRaw != "1.1" || migrations[1].Filename != "V1_1__add_user_indexes.sql" {
		t.Errorf("expected second migration to be V1.1, got %s", migrations[1].Filename)
	}
	if migrations[2].VersionRaw != "2" || migrations[2].Filename != "V2__add_oauth_clients.sql" {
		t.Errorf("expected third migration to be V2, got %s", migrations[2].Filename)
	}

	if migrations[0].Description != "init auth schema" {
		t.Errorf("expected description 'init auth schema', got '%s'", migrations[0].Description)
	}
	if migrations[0].Checksum == 0 {
		t.Errorf("expected non-zero checksum")
	}
}

func TestActualEmbeddedMigrations(t *testing.T) {
	files, err := loadMigrationFiles(migrations.FS)
	if err != nil {
		t.Fatalf("unexpected error loading embedded migrations: %v", err)
	}

	if len(files) < 2 {
		t.Fatalf("expected at least 2 embedded migrations (V1, V2), got %d", len(files))
	}

	if files[0].VersionRaw != "1" || files[0].Filename != "V1__init_auth_schema.sql" {
		t.Errorf("expected first embedded migration to be V1, got %s", files[0].Filename)
	}

	if files[1].VersionRaw != "2" || files[1].Filename != "V2__create_oauth_clients_tables.sql" {
		t.Errorf("expected second embedded migration to be V2, got %s", files[1].Filename)
	}
}
