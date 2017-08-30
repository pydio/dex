package pydio_ldap

import (
	"fmt"
	_ "fmt"
	_ "github.com/coreos/dex/connector"
	"github.com/ghodss/yaml"
	_ "github.com/pydio/poc/lib-pydio-ldap"
	_ "github.com/sirupsen/logrus"
	"testing"
)

var _ = yaml.YAMLToJSON

func TestDNFormat(t *testing.T) {
	rawData := []byte(`
        DomainName: "pydio.com"
        Host: 192.168.0.8:389
        Connection: normal
        SkipVerifyCertificate: True
        #RootCA: ""
        #RootCAData: ""
        BindDN: ""
        BindPW: ""
        User:
          Dns:
          - ou=people,dc=vpydio,dc=fr
          - ou=visitor,dc=vpydio,dc=fr
          Filter: (objectClass=eduPerson)
          IDAttribute: "uid"
          Scope: "sub"
        Group:
          Dns:
          - ou=groups,dc=vpydio,dc=fr
          Filter: (objectClass=groupOfNames)
          IDAttribute: uid
          DisplayAttribute: cn
          Scope: "sub"
        PageSize: 500
        UserAttributeMeaningMemberOf: memberOf
        SupportNestedGroup: false
        activepydiomemberof: true
        GroupValueFormatInMemberOf: dn
        GroupAttributeMeaningMember: member
        GroupAttributeMemberValueFormat: dn
        MappingRules:
          Rules:
          - RuleName: rule01
            LeftAttribute: DisplayName
            RightAttribute: displayName
            RuleString: ""
          - RuleName: rule02
            LeftAttribute: Roles
            RightAttribute: eduPersonAffiliation
            RuleString: ""
            RolePrefix: "ldap_"
          - RuleName: rule03
            LeftAttribute: Roles
            RightAttribute: memberOf
            RuleString: ""
            RolePrefix: "ldap_"
`)

	var c Config
	if err := yaml.Unmarshal(rawData, &c); err != nil {
		t.Fatalf("failed to decode config: %v", err)
	}
	fmt.Printf("Oho: %v", c)
}
