package pydio

import (
	"fmt"
	_ "fmt"
	_ "github.com/coreos/dex/connector"
	"github.com/ghodss/yaml"
	"github.com/hashicorp/packer/common/json"
	_ "github.com/kylelemons/godebug/pretty"
	_ "github.com/pydio/poc/lib-pydio-ldap"
	_ "github.com/sirupsen/logrus"
	"testing"
)

var _ = yaml.YAMLToJSON

func TestUnMarshalConfig(t *testing.T) {
	rawData := []byte(`
{"pydioconnectors":[{"config":{"BindDN":"","BindPW":"","Connection":"normal","DomainName":"pydio.com","Group":{"DisplayAttribute":"cn","Dns":["ou=groups,dc=vpydio,dc=fr"],"Filter":"(objectClass=groupOfNames)","IDAttribute":"uid","Scope":"sub"},"GroupAttributeMeaningMember":"member","GroupAttributeMemberValueFormat":"dn","GroupValueFormatInMemberOf":"dn","Host":"192.168.0.8:389","MappingRules":{"Rules":[{"LeftAttribute":"DisplayName","RightAttribute":"displayName","RuleName":"rule01","RuleString":""},{"LeftAttribute":"Roles","RightAttribute":"eduPersonAffiliation","RolePrefix":"ldap_","RuleName":"rule02","RuleString":""},{"LeftAttribute":"Roles","RightAttribute":"memberOf","RolePrefix":"ldap_","RuleName":"rule03","RuleString":""}]},"PageSize":500,"SkipVerifyCertificate":true,"SupportNestedGroup":false,"User":{"Dns":["ou=people,dc=vpydio,dc=fr","ou=visitor,dc=vpydio,dc=fr"],"Filter":"(objectClass=eduPerson)","IDAttribute":"uid","Scope":"sub"},"UserAttributeMeaningMemberOf":"memberOf","activepydiomemberof":true},"id":1,"name":"pydio-ldap","type":"ldap"},{"config":null,"id":0,"name":"externalDB","type":"pydio-sql"},{"config":null,"id":0,"name":"pydio-mysql-base","type":"pydio-sql"}]}
`)

	var c Config
	if err := json.Unmarshal(rawData, &c); err != nil {
		t.Fatalf("failed to decode config: %v", err)
	}
	fmt.Printf("Oho: %v", c)
	for _, test := range c.Connectors {
		fmt.Println(test.Name)
	}
}
