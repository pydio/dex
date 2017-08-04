package pydio_api

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

func (c *Config) openConnector(logger logrus.FieldLogger) (*pydioAPIConnector, error) {
	return &pydioAPIConnector{*c, logger}, nil
}

type pydioAPIConnector struct{
	Config
	logger logrus.FieldLogger
}

var (
	_ connector.PasswordConnector = (*pydioAPIConnector)(nil)
	_ connector.RefreshConnector  = (*pydioAPIConnector)(nil)
)

/*
func (p *pydioAPIConnector) Open(logger logrus.FieldLogger) (connector.Connector, error){

	return nil, nil
}*/

func (p *pydioAPIConnector) Login(ctx context.Context, s connector.Scopes, username, password string) (identity connector.Identity, validPassword bool, err error){
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

func (p *pydioAPIConnector) Refresh(ctx context.Context, s connector.Scopes, ident connector.Identity) (connector.Identity, error) {
	p.logger.Printf("Refresh request for User ID: %s", ident.UserID)
	ident.UserID = ident.UserID+"c"
	return ident, nil
}

