package storage

import (
	"testing"
	"fmt"
)

func TestMarshallClaims(t *testing.T) {
	claims := PydioClaims{
		GroupPath: "OU=test/OU=People/DC=vpydio,DC=fr/",
		DisplayName: "DisplayName",
		Roles: "role1, role2, role3",
		AuthSource: "ldap",
	}
	str := claims.JsonMarshal()
	fmt.Printf("JSON STRING: %s", str)
}

func TestUnMarshallClaims (t *testing.T){
	str := `{"AuthSource":"ldap","DisplayName":"DisplayName","Roles":"role1, role2, role3","GroupPath":"OU=test/OU=People/DC=vpydio,DC=fr/"}`
	pc := new(PydioClaims)
	err := pc.JsonUnMarshal(str)
	if err != nil {
		t.Errorf("Error unmarshall")
	}
	fmt.Printf("PydioClaims: %v", pc)
}