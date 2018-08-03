package alibaba

import (
	"github.com/aliyun/alibaba-cloud-sdk-go/sdk"
	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/auth/credentials"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/ram"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/sts"
)

const (
	/*
		The RAM endpoint requires https, but the default scheme is http.
	*/
	scheme = "https"

	/*
		There's only one endpoint for the Alibaba RAM and STS API;
		yet their client requires that a region be passed in. This
		is supported by both their docs and the endpoints shown in
		their Go SDK. We just pass in a plug region so we don't need
		to do any gymnastics to determine what region we're in when
		it makes no difference in the endpoints we'll ultimately use.
	*/
	region = "us-east-1"
)

func getRAMClient(key, secret string) (*ram.Client, error) {
	config := sdk.NewConfig()
	config.Scheme = scheme
	cred := credentials.NewAccessKeyCredential(key, secret)
	return ram.NewClientWithOptions(region, config, cred)
}

// TODO need to test this client IRL
func getSTSClient(key, secret string) (*sts.Client, error) {
	config := sdk.NewConfig()
	config.Scheme = scheme
	return sts.NewClientWithOptions(region, config, credentials.NewAccessKeyCredential(key, secret))
}

func deleteAccessKey(client *ram.Client, userName, accessKeyID string) error {
	req := ram.CreateDeleteAccessKeyRequest()
	req.UserAccessKeyId = accessKeyID
	req.UserName = userName
	if _, err := client.DeleteAccessKey(req); err != nil {
		return err
	}
	return nil
}

func deletePolicy(client *ram.Client, policyName string) error {
	req := ram.CreateDeletePolicyRequest()
	req.PolicyName = policyName
	if _, err := client.DeletePolicy(req); err != nil {
		return err
	}
	return nil
}

func detachPolicy(client *ram.Client, userName, policyName, policyType string) error {
	req := ram.CreateDetachPolicyFromUserRequest()
	req.UserName = userName
	req.PolicyName = policyName
	req.PolicyType = policyType
	if _, err := client.DetachPolicyFromUser(req); err != nil {
		return err
	}
	return nil
}

// Note: deleteUser will fail if the user is presently associated with anything
// in Alibaba.
func deleteUser(client *ram.Client, userName string) error {
	req := ram.CreateDeleteUserRequest()
	req.UserName = userName
	if _, err := client.DeleteUser(req); err != nil {
		return err
	}
	return nil
}
