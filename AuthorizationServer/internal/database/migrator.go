package database

import (
	"context"
	"database/sql"
	"fmt"
	"hash/crc32"
	"io/fs"
	"log/slog"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/sameerchandekar/MiniAuth/AuthorizationServer/migrations"
)

// MigrationFile represents a parsed Flyway SQL migration.
type MigrationFile struct {
	VersionMajor int
	VersionMinor int
	VersionRaw   string
	Description  string
	Filename     string
	SQLContent   string
	Checksum     int32
}

var migrationRegex = regexp.MustCompile(`^V(\d+)(?:_(\d+))?__(.+)\.sql$`)

// RunMigrations discovers and applies all pending SQL migrations against the database.
func RunMigrations(ctx context.Context, db *sql.DB, logger *slog.Logger) error {
	logger.Info("checking database migrations...")

	// 1. Ensure flyway_schema_history table exists
	if err := ensureFlywayHistoryTable(ctx, db); err != nil {
		return fmt.Errorf("failed to ensure flyway schema history table: %w", err)
	}

	// 2. Discover and parse all migration files embedded in binary
	migrationFiles, err := loadMigrationFiles(migrations.FS)
	if err != nil {
		return fmt.Errorf("failed to read embedded migration files: %w", err)
	}

	if len(migrationFiles) == 0 {
		logger.Info("no migration files found to apply")
		return nil
	}

	// 3. Query already applied migrations
	appliedVersions, err := getAppliedVersions(ctx, db)
	if err != nil {
		return fmt.Errorf("failed to query applied migration history: %w", err)
	}

	// 4. Apply pending migrations in order
	currentRank := len(appliedVersions)
	appliedCount := 0

	for _, m := range migrationFiles {
		if appliedVersions[m.VersionRaw] {
			logger.Debug("migration already applied", slog.String("version", m.VersionRaw), slog.String("script", m.Filename))
			continue
		}

		currentRank++
		logger.Info("applying migration...",
			slog.String("version", m.VersionRaw),
			slog.String("description", m.Description),
			slog.String("script", m.Filename),
		)

		startTime := time.Now()
		if err := applyMigration(ctx, db, m, currentRank, startTime); err != nil {
			return fmt.Errorf("failed to apply migration %s: %w", m.Filename, err)
		}

		appliedCount++
		logger.Info("migration applied successfully",
			slog.String("version", m.VersionRaw),
			slog.Duration("duration", time.Since(startTime)),
		)
	}

	if appliedCount == 0 {
		logger.Info("database schema is up to date, no migrations needed")
	} else {
		logger.Info("all pending migrations applied successfully", slog.Int("count", appliedCount))
	}

	return nil
}

func ensureFlywayHistoryTable(ctx context.Context, db *sql.DB) error {
	query := `
	CREATE TABLE IF NOT EXISTS flyway_schema_history (
		installed_rank INT NOT NULL PRIMARY KEY,
		version VARCHAR(50),
		description VARCHAR(200) NOT NULL,
		type VARCHAR(20) NOT NULL,
		script VARCHAR(1000) NOT NULL,
		checksum INT,
		installed_by VARCHAR(100) NOT NULL,
		installed_on TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
		execution_time INT NOT NULL,
		success BOOLEAN NOT NULL
	);
	CREATE INDEX IF NOT EXISTS flyway_schema_history_s_idx ON flyway_schema_history (success);
	`
	_, err := db.ExecContext(ctx, query)
	return err
}

func loadMigrationFiles(embeddedFS fs.FS) ([]MigrationFile, error) {
	entries, err := fs.ReadDir(embeddedFS, ".")
	if err != nil {
		return nil, err
	}

	var migrationFiles []MigrationFile

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}

		matches := migrationRegex.FindStringSubmatch(entry.Name())
		if len(matches) < 4 {
			continue
		}

		major, _ := strconv.Atoi(matches[1])
		minor := 0
		if matches[2] != "" {
			minor, _ = strconv.Atoi(matches[2])
		}

		rawVersion := matches[1]
		if matches[2] != "" {
			rawVersion = matches[1] + "." + matches[2]
		}

		description := strings.ReplaceAll(matches[3], "_", " ")

		content, err := fs.ReadFile(embeddedFS, entry.Name())
		if err != nil {
			return nil, fmt.Errorf("failed to read migration file %s: %w", entry.Name(), err)
		}

		checksum := int32(crc32.ChecksumIEEE(content))

		migrationFiles = append(migrationFiles, MigrationFile{
			VersionMajor: major,
			VersionMinor: minor,
			VersionRaw:   rawVersion,
			Description:  description,
			Filename:     entry.Name(),
			SQLContent:   string(content),
			Checksum:     checksum,
		})
	}

	// Sort migrations by major and minor version
	sort.Slice(migrationFiles, func(i, j int) bool {
		if migrationFiles[i].VersionMajor == migrationFiles[j].VersionMajor {
			return migrationFiles[i].VersionMinor < migrationFiles[j].VersionMinor
		}
		return migrationFiles[i].VersionMajor < migrationFiles[j].VersionMajor
	})

	return migrationFiles, nil
}

func getAppliedVersions(ctx context.Context, db *sql.DB) (map[string]bool, error) {
	rows, err := db.QueryContext(ctx, `SELECT version FROM flyway_schema_history WHERE success = true`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	applied := make(map[string]bool)
	for rows.Next() {
		var v sql.NullString
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		if v.Valid {
			applied[v.String] = true
		}
	}

	return applied, rows.Err()
}

func applyMigration(ctx context.Context, db *sql.DB, m MigrationFile, rank int, startTime time.Time) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() {
		_ = tx.Rollback()
	}()

	// Execute migration SQL
	if _, err := tx.ExecContext(ctx, m.SQLContent); err != nil {
		return fmt.Errorf("error executing migration SQL: %w", err)
	}

	executionTimeMs := int(time.Since(startTime).Milliseconds())

	// Record in flyway_schema_history
	historyQuery := `
	INSERT INTO flyway_schema_history (
		installed_rank, version, description, type, script, checksum, installed_by, execution_time, success
	) VALUES (
		$1, $2, $3, 'SQL', $4, $5, 'miniauth-service', $6, true
	)`

	_, err = tx.ExecContext(ctx, historyQuery, rank, m.VersionRaw, m.Description, m.Filename, m.Checksum, executionTimeMs)
	if err != nil {
		return fmt.Errorf("error recording migration history: %w", err)
	}

	return tx.Commit()
}
