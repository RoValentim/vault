package alibaba

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/aliyun/alibaba-cloud-sdk-go/services/ram"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/sts"
	"github.com/hashicorp/vault/builtin/logical/alibaba/util"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

func (b *backend) pathCreds() *framework.Path {
	return &framework.Path{
		Pattern: "creds/" + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Name of the role",
			},
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation: b.pathCredsRead,
		},
		HelpSynopsis:    pathCredsHelpSyn,
		HelpDescription: pathCredsHelpDesc,
	}
}

func (b *backend) pathCredsRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("name").(string)
	role, err := readRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}

	if role.RoleARN != "" {
		stsClient, err := getSTSClient()
		if err != nil {
			return nil, err
		}
		assumeRoleReq := sts.CreateAssumeRoleRequest()
		assumeRoleReq.RoleArn = role.RoleARN
		assumeRoleReq.RoleSessionName = "testing" // TODO obviously needs something better
		assumeRoleResp, err := stsClient.AssumeRole(assumeRoleReq)
		if err != nil {
			return nil, err
		}
		resp := b.Secret(secretType).Response(map[string]interface{}{
			"access_key":     assumeRoleResp.Credentials.AccessKeyId,
			"secret_key":     assumeRoleResp.Credentials.AccessKeySecret,
			"security_token": assumeRoleResp.Credentials.SecurityToken,
			"expiration":     assumeRoleResp.Credentials.Expiration, // TODO this date format may not follow our API's date format
		}, map[string]interface{}{
			// TODO am I using all these things?
			// TODO also, this doesn't have a username so this needs to be handled during revocation
			"role_name":     roleName,
			"access_key_id": assumeRoleResp.Credentials.AccessKeyId,
		})

		if role.TTL != 0 {
			resp.Secret.TTL = role.TTL
		}
		if role.MaxTTL != 0 {
			resp.Secret.MaxTTL = role.MaxTTL
		}
		return resp, nil
	}

	creds, err := readCredentials(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	ramClient, err := getRAMClient(creds.AccessKey, creds.SecretKey)
	if err != nil {
		return nil, err
	}
	userName, err := util.GenerateUsername(req.DisplayName, roleName)
	if err != nil {
		return nil, err
	}
	createUserReq := ram.CreateCreateUserRequest()
	createUserReq.UserName = userName
	createUserReq.DisplayName = userName
	if _, err := ramClient.CreateUser(createUserReq); err != nil {
		return nil, err
	}

	for _, inlinePolicy := range role.InlinePolicies {
		policyName, err := util.GeneratePolicyName(userName, inlinePolicy)
		if err != nil {
			return nil, err
		}
		policyDoc, err := json.Marshal(inlinePolicy)
		if err != nil {
			return nil, err
		}
		createPolicyReq := ram.CreateCreatePolicyRequest()
		createPolicyReq.PolicyName = policyName
		createPolicyReq.Description = fmt.Sprintf("Created by Vault for %s using role %s.", req.DisplayName, roleName)
		createPolicyReq.PolicyDocument = string(policyDoc)

		createPolicyResp, err := ramClient.CreatePolicy(createPolicyReq)
		if err != nil {
			return nil, err
		}

		attachPolReq := ram.CreateAttachPolicyToUserRequest()
		attachPolReq.UserName = userName
		attachPolReq.PolicyName = createPolicyResp.Policy.PolicyName
		attachPolReq.PolicyType = createPolicyResp.Policy.PolicyType
		if _, err := ramClient.AttachPolicyToUser(attachPolReq); err != nil {
			return nil, err
		}
	}

	// TODO maybe I should make remote policies just be []*ram.Policy so I can iterate them all together
	for _, remotePol := range role.RemotePolicies {
		attachPolReq := ram.CreateAttachPolicyToUserRequest()
		attachPolReq.UserName = userName
		attachPolReq.PolicyName = remotePol.Name
		attachPolReq.PolicyType = remotePol.Type
		if _, err := ramClient.AttachPolicyToUser(attachPolReq); err != nil {
			return nil, err
		}
	}

	accessKeyReq := ram.CreateCreateAccessKeyRequest()
	accessKeyReq.UserName = userName
	accessKeyResp, err := ramClient.CreateAccessKey(accessKeyReq)
	if err != nil {
		// Try to back out the user we created.
		// We have to remove them from the group first.
		removeFromGroup(ramClient, userName, roleName)
		deleteUser(ramClient, userName)
		return nil, err
	}
	resp := b.Secret(secretType).Response(map[string]interface{}{
		"access_key": accessKeyResp.AccessKey.AccessKeyId,
		"secret_key": accessKeyResp.AccessKey.AccessKeySecret,
	}, map[string]interface{}{
		// TODO am I using all these things?
		"username":      userName,
		"role_name":     roleName,
		"access_key_id": accessKeyResp.AccessKey.AccessKeyId,
	})

	if role.TTL != 0 {
		resp.Secret.TTL = role.TTL
	}
	if role.MaxTTL != 0 {
		resp.Secret.MaxTTL = role.MaxTTL
	}
	return resp, nil
}

// TODO update this stuff
const pathCredsHelpSyn = `
Generate an access key pair for a specific role.
`

const pathCredsHelpDesc = `
This path will generate a new, never before used key pair for
accessing AWS. The IAM policy used to back this key pair will be
the "user_group_name" parameter. For example, if this backend is mounted at "aws",
then "aws/creds/deploy" would generate access keys for the "deploy" role.

The access keys will have a lease associated with them. The access keys
can be revoked by using the lease ID.
`
