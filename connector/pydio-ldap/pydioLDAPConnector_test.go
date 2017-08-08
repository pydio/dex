package pydio_ldap


import(
	"testing"
	"github.com/ghodss/yaml"
	_ "github.com/Sirupsen/logrus"
	_ "fmt"
	_ "github.com/pydio/poc/lib-pydio-ldap"
	_ "github.com/coreos/dex/connector"
)

var _ = yaml.YAMLToJSON

/*
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

func getRules() []lib_pydio_ldap.MappingRule{
	rules := []lib_pydio_ldap.MappingRule{}

	rule1 := lib_pydio_ldap.MappingRule{
		RuleName:"Rule01",
		LeftAttribute:"DisplayName",
		RightAttribute:"DisplayName",
		RuleString: "",
		RolePrefix: "",
	}
	rule2 := lib_pydio_ldap.MappingRule{
		RuleName:"Rule02",
		LeftAttribute:"Roles",
		RightAttribute:"eduPersonAffiliation",
		RuleString: "",
		RolePrefix: "",
	}

	rules = append(rules, rule1)
	rules = append(rules, rule2)
	return rules
}


func TestNormalMapp(t *testing.T){
	pydioLdap := new(pydioLDAPConnector)
	username := "amalip01"
	userpassword := "P@ssw0rd"
	scopes := connector.Scopes{true, true, true, true, true, true}
	ident, ok, err := pydioLdap.Login(nil, scopes, username, userpassword)
	if err != nil{

	}
	if !ok {

	}
}*/

func TestDNFormat(t *testing.T){
	if !IsDnFormat("cn=abc,dc=fr,dc=com") {
		t.Errorf("")
	}
	if !IsDnFormat(`cn=abc\,t,dc=fr,dc=com`) {
		t.Errorf("")
	}
}