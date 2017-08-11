package pydio_sql

import (
	"github.com/coreos/dex/connector"
	"github.com/Sirupsen/logrus"
	"context"

	"fmt"
)

type Config struct {

	// Sql connection
	SqlConnection struct {
		Host string `json:Host`
	}

	UserTableName		string	`json:UserTableName`
	UserIDColumn		string	`json:UserIDColumn`
	PasswordColumn		string  `json:PasswordColumn`
	PasswordEncryptAlgo string	`json:PasswordEncryptAlgo`
}
func (c *Config) Open(logger logrus.FieldLogger) (connector.Connector, error) {
	return c.OpenConnector(logger)
}

func (c *Config) OpenConnector(logger logrus.FieldLogger)(interface {
	connector.Connector
	connector.PasswordConnector
	connector.RefreshConnector
}, error) {
	return c.openConnector(logger)
}

func (c *Config) openConnector(logger logrus.FieldLogger) (*pydioSQLConnector, error) {
	return &pydioSQLConnector{*c, logger}, nil
}

type pydioSQLConnector struct{
	Config
	logger logrus.FieldLogger
}

var (
	_ connector.PasswordConnector = (*pydioSQLConnector)(nil)
	_ connector.RefreshConnector  = (*pydioSQLConnector)(nil)
)

func (p *pydioSQLConnector) Login(ctx context.Context, s connector.Scopes, username, password string) (identity connector.Identity, validPassword bool, err error){
	p.logger.Printf("Login request for User:%s Password:%s", username, password)

	if username == "username" && password == "P@ssw0rd" {

		identity = connector.Identity{
			UserID:        "username",
			Username:      "User Number 001",
			Email:         "u001@pydio.com",
			EmailVerified: true,
			DisplayName:   "",
			Roles:         "",
			GroupPath:     "",
			Groups:        []string{},
			ConnectorData: nil,
		}
		return identity, true, nil
	}
	return connector.Identity{}, false, fmt.Errorf("User not found")
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
			Roles:         "",
			GroupPath:     "",
			Groups:        []string{},
			ConnectorData: nil,
		}
		return identity, nil
	}
	return connector.Identity{}, fmt.Errorf("User not found")
}

