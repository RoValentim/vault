package alibaba

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/aliyun/alibaba-cloud-sdk-go/services/ram"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/sts"
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

	if role.isAssumeRoleMethod() {
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
			"role_name":     roleName, // in use
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
	userName := generateUsername(req.DisplayName, roleName)

	/*
		Now we're embarking upon a multi-step process that could fail at any time.
		If it does, let's do our best to clean up after ourselves. Success will be
		our flag at the end indicating whether we should leave things be, or clean
		things up, based on how we exit this method. Since defer statements are
		last-in-first-out, it will perfectly reverse the order of everything just
		like we need.
	*/
	success := false

	createUserReq := ram.CreateCreateUserRequest()
	createUserReq.UserName = userName
	createUserReq.DisplayName = userName
	createUserResp, err := ramClient.CreateUser(createUserReq)
	if err != nil {
		return nil, err
	}
	defer func() {
		if !success {
			if err := deleteUser(ramClient, createUserResp.User.UserName); err != nil {
				if b.Logger().IsError() {
					b.Logger().Error(fmt.Sprintf("unable to delete user %s", userName), err)
				}
			}
		}
	}()

	// We need to gather up all the names and types of the remote policies we're
	// about to create so we can detach and delete them later.
	inlinePolicies := make([]*remotePolicy, len(role.InlinePolicies))

	for i, inlinePolicy := range role.InlinePolicies {

		// By combining the userName with the particular policy's UUID,
		// it'll be possible to figure out who this policy is for and which one
		// it is using the policy name alone.
		policyName := userName + "-" + inlinePolicy.UUID

		policyDoc, err := json.Marshal(inlinePolicy.PolicyDocument)
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

		inlinePolicies[i] = &remotePolicy{
			Name: createPolicyResp.Policy.PolicyName,
			Type: createPolicyResp.Policy.PolicyType,
		}

		// This defer is in this loop on purpose. It wouldn't be appropriate
		// to call the defer on each iteration, because we won't know until
		// afterwards whether we've been successful.
		defer func() {
			if !success {
				if err := deletePolicy(ramClient, createPolicyResp.Policy.PolicyName); err != nil {
					if b.Logger().IsError() {
						b.Logger().Error(fmt.Sprintf("unable to delete policy %s", createPolicyResp.Policy.PolicyName), err)
					}
				}
			}
		}()

		attachPolReq := ram.CreateAttachPolicyToUserRequest()
		attachPolReq.UserName = userName
		attachPolReq.PolicyName = createPolicyResp.Policy.PolicyName
		attachPolReq.PolicyType = createPolicyResp.Policy.PolicyType
		if _, err := ramClient.AttachPolicyToUser(attachPolReq); err != nil {
			return nil, err
		}
		// This defer is also in this loop on purpose.
		defer func() {
			if !success {
				if err := detachPolicy(ramClient, attachPolReq.UserName, attachPolReq.PolicyName, attachPolReq.PolicyType); err != nil {
					if b.Logger().IsError() {
						b.Logger().Error(fmt.Sprintf("unable to detach policy name:%s, type:%s from user:%s", attachPolReq.PolicyName, attachPolReq.PolicyType, attachPolReq.UserName))
					}
				}
			}
		}()
	}

	for _, remotePol := range role.RemotePolicies {
		attachPolReq := ram.CreateAttachPolicyToUserRequest()
		attachPolReq.UserName = userName
		attachPolReq.PolicyName = remotePol.Name
		attachPolReq.PolicyType = remotePol.Type
		if _, err := ramClient.AttachPolicyToUser(attachPolReq); err != nil {
			return nil, err
		}
		// This defer is also in this loop on purpose.
		defer func() {
			if !success {
				if err := detachPolicy(ramClient, attachPolReq.UserName, attachPolReq.PolicyName, attachPolReq.PolicyType); err != nil {
					if b.Logger().IsError() {
						b.Logger().Error(fmt.Sprintf("unable to detach policy name:%s, type:%s from user:%s", attachPolReq.PolicyName, attachPolReq.PolicyType, attachPolReq.UserName))
					}
				}
			}
		}()
	}

	accessKeyReq := ram.CreateCreateAccessKeyRequest()
	accessKeyReq.UserName = userName
	accessKeyResp, err := ramClient.CreateAccessKey(accessKeyReq)
	if err != nil {
		return nil, err
	}
	// We don't need a defer here to clean this up because there are
	// no further errors returned below. However, if that ever changed,
	// we would need to add a defer here. Likewise, it's safe to mark
	// success because there are not further possible errors.
	success = true

	resp := b.Secret(secretType).Response(map[string]interface{}{
		"access_key": accessKeyResp.AccessKey.AccessKeyId,
		"secret_key": accessKeyResp.AccessKey.AccessKeySecret,
	}, map[string]interface{}{
		"username":        userName,
		"role_name":       roleName,
		"access_key_id":   accessKeyResp.AccessKey.AccessKeyId,
		"remote_policies": role.RemotePolicies,
		"inline_policies": inlinePolicies,
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
