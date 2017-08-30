package pydio_sql

import (
	"context"
	"github.com/coreos/dex/connector"
	"github.com/sirupsen/logrus"

	"database/sql"
	"fmt"
	"github.com/coreos/dex/password-hasher"
	"net/url"
	"strings"
)

type Config struct {
	SqlConnection struct {
		Host     string `json:Host,omitempty`
		DBName   string `json:DBName,omitempty`
		UserName string `json:UserName,omitempty`
		Password string `json:Password,omitempty`
	}
	UserTableName       string `json:UserTableName,omitempty`
	UserIDColumn        string `json:UserIDColumn,omitempty`
	PasswordColumn      string `json:PasswordColumn,omitempty`
	PasswordEncryptAlgo string `json:PasswordEncryptAlgo,omitempty`
}

func (c *Config) Open(logger logrus.FieldLogger) (connector.Connector, error) {
	return c.OpenConnector(logger)
}

func (c *Config) OpenConnector(logger logrus.FieldLogger) (interface {
	connector.Connector
	connector.PasswordConnector
	connector.RefreshConnector
}, error) {
	return c.openConnector(logger)
}

func (c *Config) openConnector(logger logrus.FieldLogger) (*pydioSQLConnector, error) {
	return &pydioSQLConnector{*c, logger}, nil
}

type pydioSQLConnector struct {
	Config
	logger logrus.FieldLogger
}

var (
	_ connector.PasswordConnector = (*pydioSQLConnector)(nil)
	_ connector.RefreshConnector  = (*pydioSQLConnector)(nil)
)

func (p *pydioSQLConnector) Login(ctx context.Context, s connector.Scopes, username, password string) (identity connector.Identity, validPassword bool, err error) {
	p.logger.Printf("Login request for User:%s Password:%s", username, password)

	localPassword, err := p.getPassword(username)

	passwd := password_hasher.PydioPW{
		PBKDF2_HASH_ALGORITHM: "sha256",
		PBKDF2_ITERATIONS:     1000,
		PBKDF2_SALT_BYTE_SIZE: 32,
		PBKDF2_HASH_BYTE_SIZE: 24,
		HASH_SECTIONS:         4,
		HASH_ALGORITHM_INDEX:  0,
		HASH_ITERATION_INDEX:  1,
		HASH_SALT_INDEX:       2,
		HASH_PBKDF2_INDEX:     3,
	}

	ret, err := passwd.CheckDBKDF2PydioPwd(password, localPassword)

	if ret {
		identity := connector.Identity{
			UserID:        username,
			Username:      "User Number 001",
			Email:         "u001@pydio.com",
			EmailVerified: true,
			DisplayName:   "",
			Roles:         []string{"defaultRole"},
			GroupPath:     "",
			Groups:        []string{},
			ConnectorData: nil,
		}
		return identity, true, nil
	}
	return connector.Identity{}, false, err
}

func (p *pydioSQLConnector) Refresh(ctx context.Context, s connector.Scopes, ident connector.Identity) (connector.Identity, error) {
	p.logger.Printf("Login request for User:%s Password:%s", ident.UserID)

	if ident.UserID != "" {

		identity := connector.Identity{
			UserID:        "username",
			Username:      "User Number 001",
			Email:         "u001@pydio.com",
			EmailVerified: true,
			DisplayName:   "",
			Roles:         []string{"defaultRole"},
			GroupPath:     "",
			Groups:        []string{},
			ConnectorData: nil,
		}
		return identity, nil
	}
	return connector.Identity{}, fmt.Errorf("User not found")
}

func (p *pydioSQLConnector) getPassword(userid string) (string, error) {

	v := url.Values{}
	set := func(key, val string) {
		if val != "" {
			v.Set(key, val)
		}
	}
	set("parseTime", "true")
	//set("multiStatements", "true")
	set("collation", "utf8_general_ci")
	set("charset", "utf8")
	//set("autocommit", "false")

	u := url.URL{
		Scheme:   "tcp",
		Host:     "tcp" + "(" + p.Config.SqlConnection.Host + ":3306)",
		Path:     "/" + p.Config.SqlConnection.DBName,
		RawQuery: v.Encode(),
	}

	if p.Config.SqlConnection.UserName != "" {
		if p.Config.SqlConnection.Password != "" {
			u.User = url.UserPassword(p.Config.SqlConnection.UserName, p.Config.SqlConnection.Password)
		} else {
			u.User = url.User(p.Config.SqlConnection.UserName)
		}
	}
	replaceStr := "tcp" + "://"
	dns := strings.TrimPrefix(u.String(), replaceStr)
	db, err := sql.Open("mysql", dns)
	defer db.Close()
	if err != nil {
		return "", err
	}

	stmt, err := db.Prepare("SELECT " + p.Config.PasswordColumn + " FROM " + p.Config.UserTableName + " WHERE " + p.Config.UserIDColumn + " = ?")
	if err != nil {
		fmt.Println(err.Error())
		return "", err
	}

	res := stmt.QueryRow(userid)
	defer stmt.Close()
	var password string
	err = res.Scan(&password)

	return password, nil
}
