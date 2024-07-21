package migrations

import (
	"context"
	"database/sql"
	"embed"

	"github.com/pressly/goose/v3"
)

//go:embed sql/*.sql
var embedMigrations embed.FS

func Migrate(ctx context.Context, db *sql.DB, dialect string) {
	goose.SetBaseFS(embedMigrations)

	if err := goose.SetDialect(dialect); err != nil {
		panic(err)
	}

	if err := goose.UpContext(ctx, db, "sql"); err != nil {
		panic(err)
	}
}
