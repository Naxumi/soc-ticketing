package postgresql

import "github.com/jackc/pgx/v5/pgconn"

func isUniqueViolation(err error) bool {
	pgErr, ok := err.(*pgconn.PgError)
	if !ok {
		return false
	}
	return pgErr.Code == "23505"
}
