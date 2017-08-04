package pydio_sql

import (
	"github.com/coreos/dex/connector"
	"github.com/Sirupsen/logrus"
	"context"

)

type Config struct {

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

func (c *Config) openConnector(logger logrus.FieldLogger) (*pydioWrapperConnector, error) {
	return &pydioWrapperConnector{*c, logger}, nil
}

type pydioWrapperConnector struct{
	Config
	logger logrus.FieldLogger
}

var (
	_ connector.PasswordConnector = (*pydioWrapperConnector)(nil)
	_ connector.RefreshConnector  = (*pydioWrapperConnector)(nil)
)

func (p *pydioWrapperConnector) Login(ctx context.Context, s connector.Scopes, username, password string) (identity connector.Identity, validPassword bool, err error){
	p.logger.Printf("Login request for User:%s Password:%s", username, password)
	identity = connector.Identity{
		UserID: 	"username",
		Username: 	"User Number 001",
		Email:		"u001@pydio.com",
		EmailVerified: true,
		Uuid: 		"",
		Sub: 			"",
		Source: 		"",
		DisplayName: 	"",
		RoleIDs: 		"",
		GroupPath: 		"",
		Groups:			[]string{},
		ConnectorData: 	nil,
	}

	return identity, true, nil
}

func (p *pydioWrapperConnector) Refresh(ctx context.Context, s connector.Scopes, ident connector.Identity) (connector.Identity, error) {
	p.logger.Printf("Refresh request for User ID: %s", ident.UserID)
	ident.UserID = ident.UserID+"c"
	return ident, nil
}

