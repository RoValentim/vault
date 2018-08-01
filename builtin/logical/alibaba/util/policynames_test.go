package util

import (
	"fmt"
	"testing"

	"github.com/aliyun/alibaba-cloud-sdk-go/services/ram"
)

// TODO write more and better tests
func TestGenPolicyNameNormalLengths(t *testing.T) {
	username, err := GenerateUsername("displayName", "userGroupName")
	if err != nil {
		t.Fatal(err)
	}
	policy := &ram.Policy{
		PolicyName: "fooNamefooNamefooNamefooNamefooNamefooNamefooNamefooNamefooNamefooNamefooName",
		PolicyType: "SystemSystemSystemSystemSystemSystemSystemSystemSystemSystemSystemSystemSystemSystem",
	}
	policyName, err := GeneratePolicyName(username, policy)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(policyName)
	fmt.Println(len(policyName))
}
