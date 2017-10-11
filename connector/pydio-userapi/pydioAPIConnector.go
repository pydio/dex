package pydio_api

import (
	"context"

	"github.com/coreos/dex/connector"
	"github.com/golang/protobuf/ptypes/any"
	"github.com/micro/go-micro/client"
	"github.com/micro/go-plugins/client/grpc"
	"github.com/micro/protobuf/ptypes"
	"github.com/pydio/services/common"
	"github.com/pydio/services/common/proto/idm"
	"github.com/pydio/services/common/service/proto"
	"github.com/sirupsen/logrus"
)

type Config struct {
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

func (c *Config) openConnector(logger logrus.FieldLogger) (*pydioAPIConnector, error) {
	return &pydioAPIConnector{
		Config: *c,
		logger: logger,
		client: grpc.NewClient(),
	}, nil
}

type pydioAPIConnector struct {
	Config
	logger            logrus.FieldLogger
	client            client.Client
	UserServiceClient idm.UserServiceClient
	RoleServiceClient idm.RoleServiceClient
}

var (
	_ connector.PasswordConnector = (*pydioAPIConnector)(nil)
	_ connector.RefreshConnector  = (*pydioAPIConnector)(nil)
)

func (p *pydioAPIConnector) loadUserInfo(ctx context.Context, identity *connector.Identity) error {

	if p.RoleServiceClient == nil {
		p.RoleServiceClient = idm.NewRoleServiceClient(common.SERVICE_GRPC_NAMESPACE_ + common.SERVICE_ROLE, p.client)
	}
	//p.RoleServiceClient.SearchRole(ctx, idm.SearchRoleRequest{
	//	Query:
	//})
	query, _ := ptypes.MarshalAny(&idm.RoleSingleQuery{
		Uuid: []string{identity.UserID},
		IsUserRole:true,
	})
	var roles []string

	if stream, err := p.RoleServiceClient.SearchRole(context.Background(), &idm.SearchRoleRequest{
		Query: &service.Query{
			SubQueries: []*any.Any{query},
		},
	}); err != nil {
		return err
	} else {

		defer stream.Close()

		for {
			response, err := stream.Recv()
			if err != nil {
				break
			}
			roles = append(roles, response.GetRole().GetUuid())
		}
	}

	identity.Roles = roles

	return nil
}

func (p *pydioAPIConnector) Login(ctx context.Context, s connector.Scopes, username, password string) (identity connector.Identity, validPassword bool, err error) {

	if p.UserServiceClient == nil {
		p.UserServiceClient = idm.NewUserServiceClient(common.SERVICE_GRPC_NAMESPACE_ + common.SERVICE_USER, p.client)
	}

	resp, err := p.UserServiceClient.BindUser(ctx, &idm.BindUserRequest{UserName: username, Password: password})
	if err != nil {
		return connector.Identity{}, false, err
	}

	identity = connector.Identity{
		UserID:        username,
		Username:      resp.User.Login,
		Email:         resp.User.Uuid + "@pydio.com",
		EmailVerified: true,
		DisplayName:   "",
		GroupPath:     resp.User.GroupPath,
		AuthSource:    "pydioapi",
		Roles:         []string{},
		Groups:        []string{},
		ConnectorData: nil,
	}

	// Load identity data from DB
	p.loadUserInfo(ctx, &identity)

	return identity, true, nil
}

func (p *pydioAPIConnector) Refresh(ctx context.Context, s connector.Scopes, ident connector.Identity) (connector.Identity, error) {

	p.logger.Printf("Refresh request for User ID: %s", ident.UserID)
	ident.UserID = ident.UserID + "c"
	// Refresh identity data from DB
	p.loadUserInfo(ctx, &ident)

	return ident, nil
}
