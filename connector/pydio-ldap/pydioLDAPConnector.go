package pydio_ldap

import (
	"github.com/coreos/dex/connector"
	"github.com/Sirupsen/logrus"
	"github.com/pydio/poc/lib-pydio-ldap"
	"fmt"
	"context"
	"gopkg.in/ldap.v2"
	"strings"
	"regexp"
)

type Config struct {
	lib_pydio_ldap.Config
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

func (c *Config) openConnector(logger logrus.FieldLogger) (*pydioLDAPConnector, error) {
	return &pydioLDAPConnector{*c, logger}, nil
}

type pydioLDAPConnector struct {
	Config
	logger logrus.FieldLogger
}

var (
	_ connector.PasswordConnector = (*pydioLDAPConnector)(nil)
	_ connector.RefreshConnector  = (*pydioLDAPConnector)(nil)
)

func (p *pydioLDAPConnector) Login(ctx context.Context, s connector.Scopes, username, password string) (identity connector.Identity, validPassword bool, err error) {
	p.logger.Printf("Login request for User:%s", username)
	identity = connector.Identity{
		UserID:        "",
		Username:      "",
		Email:         "",
		EmailVerified: true,

		Groups:        []string{},
		ConnectorData: nil,
	}

	conf := getConfig("openldap")

	var logger logrus.FieldLogger
	server, err := conf.OpenConnection(logger)
	if err != nil {
		fmt.Println("Error: %v", err)
	}
	ok, err := server.CheckPassword(username, password)
	if err != nil {
		return connector.Identity{}, false, err
	}
	if !ok {
		return connector.Identity{}, false, fmt.Errorf("Login failed")
	}

	rules := getRules()
	defaultRules := []lib_pydio_ldap.MappingRule{}
	defaultRule := lib_pydio_ldap.MappingRule{
		RuleName:       "ldapDefaultRule01",
		LeftAttribute:  "UserID",
		RightAttribute: conf.User.IDAttribute,
		RuleString:     "",
		RolePrefix:     "",
	}
	defaultRuleSource := lib_pydio_ldap.MappingRule{
		RuleName:       "ldapDefaultRuleAuthSource",
		LeftAttribute:  "AuthSource",
		RightAttribute: "ldap",
		RuleString:     "",
		RolePrefix:     "",
	}
	defaultRules = append(defaultRules, defaultRule)
	defaultRules = append(defaultRules, defaultRuleSource)

	if len(rules) > 0 {
		for _, rule := range rules {
			defaultRules = append(defaultRules, rule)
		}
	}

	expected := []string{}
	if len(defaultRules) > 0 {
		for _, rule := range defaultRules {
			expected = append(expected, rule.RightAttribute)
		}
	}

	fullAttributeUser, err := server.GetUser(username, expected)
	// TODO Check scope
	ident, err := p.MapUser(defaultRules, fullAttributeUser)
	if err != nil {
		return connector.Identity{}, false, err
	}
	return ident, true, nil
}

func (p *pydioLDAPConnector) Refresh(ctx context.Context, s connector.Scopes, ident connector.Identity) (connector.Identity, error) {
	p.logger.Printf("Refresh request for User ID: %s", ident.UserID)

	conf := getConfig("openldap")
	var logger logrus.FieldLogger
	server, err := conf.OpenConnection(logger)

	if err != nil {
		fmt.Println("Error: %v", err)
	}

	rules := getRules()
	defaultRules := []lib_pydio_ldap.MappingRule{}
	defaultRule := lib_pydio_ldap.MappingRule{
		RuleName:       "ldapDefaultRule01",
		LeftAttribute:  "UserID",
		RightAttribute: conf.User.IDAttribute,
		RuleString:     "",
		RolePrefix:     "",
	}
	defaultRuleSource := lib_pydio_ldap.MappingRule{
		RuleName:       "ldapDefaultRuleAuthSource",
		LeftAttribute:  "AuthSource",
		RightAttribute: "ldap",
		RuleString:     "",
		RolePrefix:     "",
	}
	defaultRules = append(defaultRules, defaultRule)
	defaultRules = append(defaultRules, defaultRuleSource)

	if len(rules) > 0 {
		for _, rule := range rules {
			defaultRules = append(defaultRules, rule)
		}
	}

	expected := []string{}
	if len(defaultRules) > 0 {
		for _, rule := range defaultRules {
			expected = append(expected, rule.RightAttribute)
		}
	}

	fullAttributeUser, err := server.GetUser(ident.UserID, expected)
	// TODO Check scope
	identity, err := p.MapUser(defaultRules, fullAttributeUser)
	if err != nil {
		return connector.Identity{}, err
	}
	return identity, nil
}

func (p *pydioLDAPConnector) MapUser(ruleSet []lib_pydio_ldap.MappingRule, user *ldap.Entry) (ident connector.Identity, err error) {
	//ident = connector.Identity{}
	p.Config.UserAttributeMeaningMemberOf = "memberOf"
	if len(ruleSet) > 0 {
		for _, rule := range ruleSet {
			rightValues := user.GetAttributeValues(rule.RightAttribute)
			if rightValues != nil {
				if p.Config.UserAttributeMeaningMemberOf == rule.RightAttribute {
					rightValues = convertDNtoName(rightValues)
				}

				rightValues = removeLdapEscape(rightValues)
				rightValues = sanitizeValues(rightValues)

				if rule.LeftAttribute == "Roles" {
					fmt.Printf("Rule name: %s", rule.RuleName)
					fmt.Println("")
					fmt.Printf("user list: %v", sanitizeValues(strings.Split(rule.RuleString, ",")))
					fmt.Println("")
					fmt.Printf("ldap list: %v", rightValues)
					fmt.Println("===========")

					if rule.RuleString != "" {
						rightValues = filterPreg(rule.RuleString, rightValues)
						fmt.Printf("after filter preg: %v", rightValues)
						fmt.Println("===========")
						rightValues = filterList(sanitizeValues(strings.Split(rule.RuleString, ",")), rightValues)
					}

					fmt.Printf("after filter list: %v", rightValues)
					fmt.Println("===========")
					rightValues = addPrefix(rule.RolePrefix, rightValues)
				}

				connector.SetAttribute(&ident, rule.LeftAttribute, rightValues)
			}
		}
	}
	return ident, nil
}

/////////////////////////////////////////////////////
/////////////////////////////////////////////////////
/////////////////////////////////////////////////////
func getConfig(server string) *lib_pydio_ldap.Config {
	if server == "openldap" {
		conf := &lib_pydio_ldap.Config{
			Host:                  "192.168.0.8:389",
			Connection:            "normal",
			SkipVerifyCertificate: true,
			RootCA:                "",
			RootCAData:            []byte{},
			//BindDN: "pydio@lab.py",
			//BindPW: "P@ssw0rd",

			PageSize:                        500,
			SupportNestedGroup:              false,
			ActivePydioMemberOf:             true,
			UserAttributeMeaningMemberOf:    "memberOf",
			GroupValueFormatInMemberOf:      "dn",
			GroupAttributeMeaningMember:     "member",
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
		BindDN:                "pydio@lab.py",
		BindPW:                "P@ssw0rd",

		PageSize:                        500,
		SupportNestedGroup:              true,
		ActivePydioMemberOf:             false,
		UserAttributeMeaningMemberOf:    "memberOf",
		GroupValueFormatInMemberOf:      "dn",
		GroupAttributeMeaningMember:     "member",
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

func getRules() []lib_pydio_ldap.MappingRule {
	rules := []lib_pydio_ldap.MappingRule{}

	rule1 := lib_pydio_ldap.MappingRule{
		RuleName:       "Rule01",
		LeftAttribute:  "DisplayName",
		RightAttribute: "displayName",
		RuleString:     "",
		RolePrefix:     "",
	}
	rule2 := lib_pydio_ldap.MappingRule{
		RuleName:       "Rule02",
		LeftAttribute:  "Roles",
		RightAttribute: "eduPersonAffiliation",
		RuleString:     "researcher, staff",
		RolePrefix:     "ldap_",
	}

	rule3 := lib_pydio_ldap.MappingRule{
		RuleName:       "Rule03",
		LeftAttribute:  "UserName",
		RightAttribute: "displayName",
		RuleString:     "",
		RolePrefix:     "",
	}

	rule4 := lib_pydio_ldap.MappingRule{
		RuleName:       "Rule04",
		LeftAttribute:  "Email",
		RightAttribute: "mail",
		RuleString:     "",
		RolePrefix:     "",
	}

	rule5 := lib_pydio_ldap.MappingRule{
		RuleName:       "Rule05",
		LeftAttribute:  "Roles",
		RightAttribute: "memberOf",
		RuleString:     "",
		RolePrefix:     "ldap_",
	}

	rules = append(rules, rule1)
	rules = append(rules, rule2)
	rules = append(rules, rule3)
	rules = append(rules, rule4)
	rules = append(rules, rule5)
	return rules
}

// https://www.ietf.org/rfc/rfc2253.txt
func IsDnFormat(str string) (bool) {
	RegExp := `^(?:[A-Za-z][\w-]*|\d+(?:\.\d+)*)=(?:#(?:[\dA-Fa-f]{2})+|(?:[^,=\+<>#;\\"]|\\[,=\+<>#;\\"]|\\[\dA-Fa-f]{2})*|"(?:[^\\"]|\\[,=\+<>#;\\"]|\\[\dA-Fa-f]{2})*")(?:\+(?:[A-Za-z][\w-]*|\d+(?:\.\d+)*)=(?:#(?:[\dA-Fa-f]{2})+|(?:[^,=\+<>#;\\"]|\\[,=\+<>#;\\"]|\\[\dA-Fa-f]{2})*|"(?:[^\\"]|\\[,=\+<>#;\\"]|\\[\dA-Fa-f]{2})*"))*(?:,(?:[A-Za-z][\w-]*|\d+(?:\.\d+)*)=(?:#(?:[\dA-Fa-f]{2})+|(?:[^,=\+<>#;\\"]|\\[,=\+<>#;\\"]|\\[\dA-Fa-f]{2})*|"(?:[^\\"]|\\[,=\+<>#;\\"]|\\[\dA-Fa-f]{2})*")(?:\+(?:[A-Za-z][\w-]*|\d+(?:\.\d+)*)=(?:#(?:[\dA-Fa-f]{2})+|(?:[^,=\+<>#;\\"]|\\[,=\+<>#;\\"]|\\[\dA-Fa-f]{2})*|"(?:[^\\"]|\\[,=\+<>#;\\"]|\\[\dA-Fa-f]{2})*"))*)*$`

	ok, err := regexp.MatchString(RegExp, str)
	if err != nil {
		return false
	}
	return ok
}

func sanitizeValues(strs []string) ([]string) {
	str := []string{}
	if len(strs) > 0 {
		for _, s := range strs {
			str = append(str, strings.TrimSpace(s))
		}
		return str
	} else {
		return strs
	}
}

// Remove ldap escape but except \,
func removeLdapEscape(strs []string) ([]string) {
	str := []string{}
	if len(strs) > 0 {
		for _, s := range strs {
			replacer := strings.NewReplacer(`\=`, "=", `\+`, "=", `\<`, "<", `\>`, ">", `\#`, "#", `\;`, ";")
			replacer2 := strings.NewReplacer(`\,`, "[U0001]")
			replacer3 := strings.NewReplacer("[U0001]", `\,`, ",", `\,`)
			str = append(str, replacer3.Replace(replacer2.Replace(replacer.Replace(s))))
		}
		return str
	} else {
		return strs
	}

}

// Try to extract value from distinguishedName
// For example:
// member: uid=user01,dc=com,dc=fr
// member: uid=user02,dc=com,dc=fr
// member: uid=user03,dc=com,dc=fr
// return an array like:
//	user01
//	user02
//	user03
func convertDNtoName(strs []string) ([]string) {
	str := []string{}
	if len(strs) > 0 {
		for _, s := range strs {
			// https://www.ietf.org/rfc/rfc2253.txt defines '#' as a special character
			// However, openldap use # as normal character.
			// So the IsDnFormat does not work properly.
			newS := strings.NewReplacer("#", "[UOO01]").Replace(s)
			if IsDnFormat(newS) {
				replacer := strings.NewReplacer(`\,`, "[U0000]")
				reverseReplacer := strings.NewReplacer("[U0000]", `\,`)
				rl := replacer.Replace(newS)
				rlarr := strings.Split(rl, ",")
				if len(rlarr) > 0 {
					firstRDN := rlarr[0]
					firstRDNright := strings.Split(firstRDN, "=")[1]
					str = append(str, strings.NewReplacer("[UOO01]", "#").Replace(reverseReplacer.Replace(firstRDNright)))
				}
			} else {
				str = append(str, strings.NewReplacer("[UOO01]", "#").Replace(newS))
			}
		}
		return str
	} else {
		return strs
	}
}

func addPrefix(prefix string, strs []string) ([]string) {
	str := []string{}
	if len(strs) > 0 && prefix != "" {
		for _, s := range strs {
			str = append(str, prefix+s)
		}
		return str
	} else {
		return strs
	}
}

func filterPreg(preg string, strs []string) ([]string) {
	str := []string{}
	if len(strs) > 0 && preg != "" {
		defaultPrefix := "^preg:*"
		for _, s := range strs {
			// Test format of preg. Should be preg:xxxx
			matched, err := regexp.MatchString(defaultPrefix, preg)
			if matched && err == nil {
				r := strings.NewReplacer("preg:", "")
				ruleString := r.Replace(preg)
				matched, _ := regexp.MatchString(ruleString, s)
				if matched {
					str = append(str, s)
				}
				return str
			}
		}
	}
	return strs
}

func filterList(list []string, strs []string) ([]string) {
	if len(list) > 0 && len(strs) > 0 {
		intersectionList := []string{}
		for _, l := range list {
			for _, s := range strs{
				if l == s {
					intersectionList = append(intersectionList, s)
				}
			}
		}
		return intersectionList
	} else {
		return strs
	}
}
