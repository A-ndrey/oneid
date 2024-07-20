package driver

import (
	"database/sql"
	"fmt"

	_ "github.com/mattn/go-sqlite3"
)

func NewSQLite(dbname string) (*sql.DB, error) {
	return sql.Open("sqlite3", fmt.Sprintf("file:%s.db?mode=rwc", dbname))
}
