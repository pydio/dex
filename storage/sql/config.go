package sql

import (
	"database/sql"
	"fmt"
	"net/url"
	"strconv"

	"github.com/coreos/dex/storage"
	"github.com/lib/pq"
	sqlite3 "github.com/mattn/go-sqlite3"
	"github.com/sirupsen/logrus"
	"github.com/go-sql-driver/mysql"
	"strings"
)

const (
	// postgres error codes
	pgErrUniqueViolation = "23505" // unique_violation

	// mysql error codes

	mysqlErrorUniqueViolation = uint16(1062) // Duplicate entry for key 'PRIMARY'
)

// SQLite3 options for creating an SQL db.
type SQLite3 struct {
	// File to
	File string `json:"file"`
}

// Open creates a new storage implementation backed by SQLite3
func (s *SQLite3) Open(logger logrus.FieldLogger) (storage.Storage, error) {
	conn, err := s.open(logger)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func (s *SQLite3) open(logger logrus.FieldLogger) (*conn, error) {
	db, err := sql.Open("sqlite3", s.File)
	if err != nil {
		return nil, err
	}
	if s.File == ":memory:" {
		// sqlite3 uses file locks to coordinate concurrent access. In memory
		// doesn't support this, so limit the number of connections to 1.
		db.SetMaxOpenConns(1)
	}

	errCheck := func(err error) bool {
		sqlErr, ok := err.(sqlite3.Error)
		if !ok {
			return false
		}
		return sqlErr.ExtendedCode == sqlite3.ErrConstraintPrimaryKey
	}

	c := &conn{db, flavorSQLite3, logger, errCheck}
	if _, err := c.migrate(); err != nil {
		return nil, fmt.Errorf("failed to perform migrations: %v", err)
	}
	return c, nil
}

const (
	sslDisable    = "disable"
	sslRequire    = "require"
	sslVerifyCA   = "verify-ca"
	sslVerifyFull = "verify-full"
)

// PostgresSSL represents SSL options for Postgres databases.
type PostgresSSL struct {
	Mode   string
	CAFile string
	// Files for client auth.
	KeyFile  string
	CertFile string
}

// Postgres options for creating an SQL db.
type Postgres struct {
	Database string
	User     string
	Password string
	Host     string

	SSL PostgresSSL `json:"ssl" yaml:"ssl"`

	ConnectionTimeout int // Seconds
}

// Open creates a new storage implementation backed by Postgres.
func (p *Postgres) Open(logger logrus.FieldLogger) (storage.Storage, error) {
	conn, err := p.open(logger)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func (p *Postgres) open(logger logrus.FieldLogger) (*conn, error) {
	v := url.Values{}
	set := func(key, val string) {
		if val != "" {
			v.Set(key, val)
		}
	}
	set("connect_timeout", strconv.Itoa(p.ConnectionTimeout))
	set("sslkey", p.SSL.KeyFile)
	set("sslcert", p.SSL.CertFile)
	set("sslrootcert", p.SSL.CAFile)
	if p.SSL.Mode == "" {
		// Assume the strictest mode if unspecified.
		p.SSL.Mode = sslVerifyFull
	}
	set("sslmode", p.SSL.Mode)

	u := url.URL{
		Scheme:   "postgres",
		Host:     p.Host,
		Path:     "/" + p.Database,
		RawQuery: v.Encode(),
	}

	if p.User != "" {
		if p.Password != "" {
			u.User = url.UserPassword(p.User, p.Password)
		} else {
			u.User = url.User(p.User)
		}
	}
	db, err := sql.Open("postgres", u.String())
	if err != nil {
		return nil, err
	}

	errCheck := func(err error) bool {
		sqlErr, ok := err.(*pq.Error)
		if !ok {
			return false
		}
		return sqlErr.Code == pgErrUniqueViolation
	}

	c := &conn{db, flavorPostgres, logger, errCheck}
	if _, err := c.migrate(); err != nil {
		return nil, fmt.Errorf("failed to perform migrations: %v", err)
	}
	return c, nil
}

// MySQL options for creation an MySQL DB
type MySQL struct {
	Database 	string
	User		string
	Password	string
	Host		string
	Port		string
	Protocol	string

	//ConnectionTimeout int // Seconds
}

func (s *MySQL) Open(logger logrus.FieldLogger) (storage.Storage, error){
	conn, err := s.open(logger)
	if (err != nil ){
		return nil, err
	}
	return conn, nil
}

func (s *MySQL) open(logger logrus.FieldLogger) (*conn, error) {
	// dns: [username[:password]@][protocol[(address)]]/dbname
	//var config := &mysql.Config{s.User,s.Password,"tcp",s.Host,s.Database	}

	v := url.Values{}
	set := func(key, val string) {
		if val != "" {
			v.Set(key, val)
		}
	}
	//set("connect_timeout", strconv.Itoa(s.ConnectionTimeout))
	set("parseTime", "true")
	set("multiStatements", "true")
	set("collation", "utf8_general_ci")
	set("charset", "utf8")
	set("autocommit", "false")

	// Set isolation transaction
	set("tx_isolation", "SERIALIZABLE")
	//set("connect_timeout", strconv.Itoa(100))

	if s.Port == ""{
		s.Port = ":3306"
	}

	if s.Protocol == "" {
		s.Protocol = "tcp"
	}

	u := url.URL{
		Scheme:   s.Protocol,
		Host:     s.Protocol + "(" + s.Host + s.Port + ")",
		Path:     "/" + s.Database,
		RawQuery: v.Encode(),
	}

	if s.User != "" {
		if s.Password != "" {
			u.User = url.UserPassword(s.User, s.Password)
		} else {
			u.User = url.User(s.User)
		}
	}
	//dnstest := s.User + ":" + s.Password + "@tcp(" + s.Host + ":3306)/" + s.Database + "?parseTime=true&multiStatements=true&collation=utf8_general_ci&charset=utf8&autocommit=true&tx_isolation=SERIALIZABLE"

	replaceStr := s.Protocol + "://"
	dns := strings.TrimPrefix(u.String(), replaceStr)

	db, err := sql.Open("mysql", dns)
	if err != nil {
		return nil, err
	}
	errCheck := func(err error) bool {
		sqlErr, ok := err.(*mysql.MySQLError)
		if !ok {
			fmt.Printf("MySQL Error: %s Code: %s", sqlErr.Message, sqlErr.Number)
			return false
		}
		if( sqlErr.Number == 1213) {
			return false
		}
		if (sqlErr.Number == 40001){
			return false
		}
		return sqlErr.Number == mysqlErrorUniqueViolation
	}

	c := &conn{db, flavorMySQL, logger, errCheck}
	if _, err := c.migrate(); err != nil {
		return nil, fmt.Errorf("failed to open migrations: %v", err)
	}
	return c, nil
}