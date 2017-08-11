package pydio

import (
	"github.com/coreos/dex/connector"
	"github.com/Sirupsen/logrus"
	"context"

	"fmt"
	"encoding/json"
	"github.com/coreos/dex/connector/pydio-ldap"
	"github.com/coreos/dex/connector/pydio-sql"
	"github.com/coreos/dex/connector/pydio-userapi"
	"sort"
)

type Config struct {
	Connectors []ConnectorConfig `json:"pydioconnectors"`
}

type ConnectorConfig struct {
	Type   string `json:"type"`
	ID     int16 `json:"id"`
	Name   string `json:"name"`
	IsLast bool  `json:islast`
	Config json.RawMessage `json:"config"`
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

func (c *Config) openConnector(logger logrus.FieldLogger) (*pydioWrapperConnector, error) {
	return &pydioWrapperConnector{*c, logger}, nil
}

type pydioWrapperConnector struct {
	Config
	logger logrus.FieldLogger
}

var (
	_ connector.PasswordConnector = (*pydioWrapperConnector)(nil)
	_ connector.RefreshConnector  = (*pydioWrapperConnector)(nil)
)

func (p *pydioWrapperConnector) Login(ctx context.Context, s connector.Scopes, username, password string) (identity connector.Identity, validPassword bool, err error) {
	listConnector, err := p.getConnectorList(p.logger)

	for _, pydioConnector := range listConnector {
		identity, ok, err := pydioConnector.Connector.Login(ctx, s, username, password)
		p.logger.Info("Login request for user " + username + " on Sub-connector: " + pydioConnector.Name)
		if err != nil {
			p.logger.Errorf(err.Error())
			p.logger.Info("Failed! Try to use next connectors")
		}
		if ok {
			p.logger.Info("Login Ok for " + username)
			return identity, true, nil
		}
	}
	p.logger.Info("Login failed !")
	return connector.Identity{}, false, nil
}

func (p *pydioWrapperConnector) Refresh(ctx context.Context, s connector.Scopes, ident connector.Identity) (connector.Identity, error) {
	listConnector, _ := p.getConnectorList(p.logger)

	for _, pydioConnector := range listConnector {
		ident, err := pydioConnector.Connector.Refresh(ctx, s, ident)
		if err != nil {
			p.logger.Info("Refresh request for user " + ident.UserID + " failed. Try to use next connectors")
		} else {
			return ident, nil
		}
	}
	return connector.Identity{}, nil
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

func (p *pydioWrapperConnector) getConnectorList(logger logrus.FieldLogger) (connectorList []ConnectorList, err error) {
	// Sort
	sort.Sort(byID(p.Config.Connectors))
	// end sort
	for _, connConfig := range p.Config.Connectors {
		connConnector, er := createConnector(logger, connConfig.Type, connConfig)
		connConnectorFull := ConnectorList{
			Type: connConfig.Type,
			Name: connConfig.Name,
			ID:   connConfig.ID,
			Connector: connConnector.(interface {
				connector.Connector
				connector.PasswordConnector
				connector.RefreshConnector
			}),
		}
		if er != nil {
			logger.Errorf(er.Error())
		}
		connectorList = append(connectorList, connConnectorFull)
	}
	return connectorList, nil
}

type ConnectorList struct {
	Type   string `json:"type"`
	Name   string `json:"name"`
	ID     int16 `json:"id"`
	IsLast bool  `json:islast`
	Connector interface {
		connector.Connector
		connector.PasswordConnector
		connector.RefreshConnector
	}
}

// Connector is a magical type that can unmarshal YAML dynamically. The
// Type field determines the connector type, which is then customized for Config.
type PydioConnector struct {
	Type   string `json:"type"`
	Name   string `json:"name"`
	ID     int16 `json:"id"`
	IsLast bool  `json:islast`
	Config PydioConnectorConfig `json:"config"`
}

type PydioConnectorConfig interface {
	Open(logrus.FieldLogger) (connector.Connector, error)
}

// ConnectorsConfig variable provides an easy way to return a config struct
// depending on the connector type.
var PydioConnectorsConfig = map[string]func() PydioConnectorConfig{
	"pydio-ldap": func() PydioConnectorConfig { return new(pydio_ldap.Config) },
	"pydio-sql":  func() PydioConnectorConfig { return new(pydio_sql.Config) },
	"pydio-api":  func() PydioConnectorConfig { return new(pydio_api.Config) },
}

// openConnector will parse the connector config and open the connector.
func createConnector(logger logrus.FieldLogger, connectorType string, connectorConfig ConnectorConfig) (connector.Connector, error) {
	var c connector.Connector

	if connectorConfig.Type == connectorType {
		//logger.Info("parse connector config: Type: Name == %s:%s", connectorConfig.Type, connectorConfig.Name)
		f, ok := PydioConnectorsConfig[connectorType]
		if !ok {
			return c, fmt.Errorf("unknown connector type %q", connectorType)
		}

		connConfig := f()
		if connectorConfig.Config != nil {
			//data := []byte(connectorConfig.Config)
			if err := json.Unmarshal(connectorConfig.Config, connConfig); err != nil {
				logger.Errorf("parse connector config: %v", err)
				return c, fmt.Errorf("parse connector config: %v", err)
			}
		}

		c, err := connConfig.Open(logger)
		if err != nil {
			logger.Errorf("failed to create connector %s: %v", connectorConfig.ID, err)
			return c, fmt.Errorf("failed to create connector %s: %v", connectorConfig.ID, err)
		}

		return c, nil
	}

	return nil, fmt.Errorf("unknown connector type %q", connectorType)
}

type byID []ConnectorConfig

func (n byID) Len() int           { return len(n) }
func (n byID) Less(i, j int) bool { return n[i].ID > n[j].ID }
func (n byID) Swap(i, j int)      { n[i], n[j] = n[j], n[i] }
