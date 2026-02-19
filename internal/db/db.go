package db

import (
	"database/sql"
	"fmt"

	_ "github.com/mattn/go-sqlite3"
)

func Open(path string) (*sql.DB, error) {
	dsn := fmt.Sprintf("file:%s?_busy_timeout=5000&_foreign_keys=on", path)
	conn, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, err
	}

	if _, err = conn.Exec("PRAGMA journal_mode=WAL;"); err != nil {
		return nil, err
	}
	if _, err = conn.Exec("PRAGMA synchronous=NORMAL;"); err != nil {
		return nil, err
	}

	return conn, nil
}
