package pydio_ldap

import (
	"github.com/coreos/dex/connector"
	"github.com/Sirupsen/logrus"
	"github.com/pydio/poc/lib-pydio-ldap"
	"fmt"
	"context"
	"gopkg.in/ldap.v2"
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

func (c *Config) openConnector(logger logrus.FieldLogger) (*pydioLDAPConnector, error) {
	return &pydioLDAPConnector{*c, logger}, nil
}

type pydioLDAPConnector struct{
	Config
	logger logrus.FieldLogger
}

var (
	_ connector.PasswordConnector = (*pydioLDAPConnector)(nil)
	_ connector.RefreshConnector  = (*pydioLDAPConnector)(nil)
)

func (p *pydioLDAPConnector) Login(ctx context.Context, s connector.Scopes, username, password string) (identity connector.Identity, validPassword bool, err error){
	p.logger.Printf("Login request for User:%s Password:%s", username, password)
	identity = connector.Identity{
		UserID: 	"",
		Username: 	"",
		Email:		"",
		EmailVerified: true,

		Groups:			[]string{},
		ConnectorData: 	nil,
	}

	conf := getConfig("openldap")

	var logger logrus.FieldLogger
	server, err := conf.OpenConnection(logger)
	if err != nil{
	    fmt.Println("Errorrrrr: %v", err)
	}
	ok, err := server.CheckPassword(username, password)
	if err != nil{
		return connector.Identity{}, false, err
	}
	if !ok {
		return connector.Identity{}, false, fmt.Errorf("Login failed")
	}

	fullAttributeUser, err := server.GetUser(username, []string{"uid", "displayName", "mail", "eduPersonAffiliation"})

	identity.UserID = fullAttributeUser.GetAttributeValue("uid")
	identity.Username = fullAttributeUser.GetAttributeValue("displayName")
	identity.Email 	  = fullAttributeUser.GetAttributeValue("mail")

	return identity, true, nil
}

func (p *pydioLDAPConnector) Refresh(ctx context.Context, s connector.Scopes, ident connector.Identity) (connector.Identity, error) {
	p.logger.Printf("Refresh request for User ID: %s", ident.UserID)
	ident.UserID = ident.UserID+"c"
	return ident, nil
}

func getConfig(server string) *lib_pydio_ldap.Config{
	if server == "openldap" {
		conf := &lib_pydio_ldap.Config{
			Host:                  "192.168.0.8:389",
			Connection:            "normal",
			SkipVerifyCertificate: true,
			RootCA:                "",
			RootCAData:            []byte{},
			//BindDN: "pydio@lab.py",
			//BindPW: "P@ssw0rd",

			PageSize:                  500,
			SupportNestedGroup:        false,
			ActivePydioMemberOf:       true,
			UserAttributeMeaningMemberOf: "memberOf",
			GroupValueFormatInMemberOf: "dn",
			GroupAttributeMeaningMember: "member",
			GroupAttributeMemberValueFormat: "dn",
		}

		conf.User.IDAttribute = "uid"
		conf.User.DNs = []string{"ou=people,dc=vpydio,dc=fr"}
		conf.User.Filter = "(objectClass=inetOrgPerson)"
		//conf.User.IDAttribute = "samaccountname"
		//conf.User.DNs = []string{"ou=company,dc=lab,dc=py"}
		//conf.User.Filter = "(objectClass=user)"
		conf.User.Scope = "sub"

		conf.Group.IDAttribute = "cn"
		conf.Group.DNs = []string{"ou=company,dc=vpydio,dc=fr"}
		conf.Group.Filter = "(objectClass=groupOfNames)"
		conf.Group.Scope = "sub"
		conf.Group.DisplayAttribute = "cn"
		return conf
	}

	conf := &lib_pydio_ldap.Config{
		Host:                  "192.168.0.11:389",
		Connection:            "normal",
		SkipVerifyCertificate: true,
		RootCA:                "",
		RootCAData:            []byte{},
		BindDN: "pydio@lab.py",
		BindPW: "P@ssw0rd",

		PageSize:                  500,
		SupportNestedGroup:        true,
		ActivePydioMemberOf:       false,
		UserAttributeMeaningMemberOf: "memberOf",
		GroupValueFormatInMemberOf: "dn",
		GroupAttributeMeaningMember: "member",
		GroupAttributeMemberValueFormat: "dn",
	}

	conf.User.IDAttribute = "samaccountname"
	conf.User.DNs = []string{"ou=company,dc=lab,dc=py"}
	conf.User.Filter = "(objectClass=user)"
	conf.User.Scope = "sub"

	conf.Group.IDAttribute = "cn"
	//conf.Group.DNs = []string{"ou=company,dc=lab,dc=py", "ou=partner,dc=lab,dc=py"}
	conf.Group.DNs = []string{"ou=company,dc=lab,dc=py"}
	conf.Group.Filter = "(&(objectClass=group)(!(samaccountname=level0101)))"
	conf.Group.Scope = "sub"
	conf.Group.DisplayAttribute = "samaccountname"

	if server == "ad" {
		return conf
	}
	return conf
}

func (p *pydioLDAPConnector) MappUser(ruleSet []lib_pydio_ldap.MappingRule, user *ldap.Entry) (ident connector.Identity, err error){

}