package auth

import (
	"context"
	"database/sql"
	"os"

	_ "github.com/mattn/go-sqlite3"
	"github.com/yaitoo/sqle"
	"github.com/yaitoo/sqle/migrate"
)

func createAuthTest(file string) *Auth {
	os.Remove(file)

	db, _ := sql.Open("sqlite3", "file:"+file+"?cache=shared&mode=rwc")
	// db, _ := sql.Open("sqlite3", "file::memory:")

	dbTest := sqle.Open(db)

	//dbTest.SetMaxOpenConns(1)

	authTest := NewAuth(dbTest,
		WithPrefix("test_"),
		WithJWT("jwt"),
		WithAES("aes"),
		WithTOTP("Yaitoo", "Test"),
		WithDHT("auth:email", "auth:mobile"))

	dbTest.NewDHT("auth:email", 0)
	dbTest.NewDHT("auth:mobile", 0)

	err := authTest.Migrate(context.Background(), migrate.WithSuffix(".sqlite"))
	if err != nil {
		panic(err)
	}

	return authTest
}
