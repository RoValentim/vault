package alibaba

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"time"

	"github.com/hashicorp/vault/builtin/logical/alibaba/clients"
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
	if role == nil {
		// Attempting to read a role that doesn't exist.
		return nil, nil
	}

	creds, err := readCredentials(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if creds == nil {
		return nil, errors.New("unable to create secret because no credentials are configured")
	}

	userName := generateUsername(req.DisplayName, roleName)

	if role.isSTS() {
		client, err := clients.NewSTSClient(creds.AccessKey, creds.SecretKey)
		if err != nil {
			return nil, err
		}
		assumeRoleResp, err := client.AssumeRole(userName, role.RoleARN)
		if err != nil {
			return nil, err
		}
		// Parse the expiration into a time, so that when we return it from our API it's formatted
		// the same way as how _we_ format times, so callers won't have to have different time parsers.
		expiration, err := time.Parse("2006-01-02T15:04:05Z", assumeRoleResp.Credentials.Expiration)
		if err != nil {
			return nil, err
		}
		resp := b.Secret(secretType).Response(map[string]interface{}{
			"access_key":     assumeRoleResp.Credentials.AccessKeyId,
			"secret_key":     assumeRoleResp.Credentials.AccessKeySecret,
			"security_token": assumeRoleResp.Credentials.SecurityToken,
			"expiration":     expiration,
		}, map[string]interface{}{
			"is_sts": true,
		})

		if role.TTL != 0 {
			resp.Secret.TTL = role.TTL
		}
		if role.MaxTTL != 0 {
			resp.Secret.MaxTTL = role.MaxTTL
		}
		return resp, nil
	}

	client, err := clients.NewRAMClient(creds.AccessKey, creds.SecretKey)
	if err != nil {
		return nil, err
	}

	/*
		Now we're embarking upon a multi-step process that could fail at any time.
		If it does, let's do our best to clean up after ourselves. Success will be
		our flag at the end indicating whether we should leave things be, or clean
		things up, based on how we exit this method. Since defer statements are
		last-in-first-out, it will perfectly reverse the order of everything just
		like we need.
	*/
	success := false

	createUserResp, err := client.CreateUser(userName)
	if err != nil {
		return nil, err
	}
	defer func() {
		if success {
			return
		}
		if err := client.DeleteUser(createUserResp.User.UserName); err != nil {
			if b.Logger().IsError() {
				b.Logger().Error(fmt.Sprintf("unable to delete user %s", userName), err)
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

		createPolicyResp, err := client.CreatePolicy(policyName, string(policyDoc))
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
			if success {
				return
			}
			if err := client.DeletePolicy(createPolicyResp.Policy.PolicyName); err != nil {
				if b.Logger().IsError() {
					b.Logger().Error(fmt.Sprintf("unable to delete policy %s", createPolicyResp.Policy.PolicyName), err)
				}
			}
		}()

		if err := client.AttachPolicy(userName, createPolicyResp.Policy.PolicyName, createPolicyResp.Policy.PolicyType); err != nil {
			return nil, err
		}
		// This defer is also in this loop on purpose.
		defer func() {
			if success {
				return
			}
			if err := client.DetachPolicy(userName, createPolicyResp.Policy.PolicyName, createPolicyResp.Policy.PolicyType); err != nil {
				if b.Logger().IsError() {
					b.Logger().Error(fmt.Sprintf(
						"unable to detach policy name:%s, type:%s from user:%s", createPolicyResp.Policy.PolicyName, createPolicyResp.Policy.PolicyType, userName))
				}
			}
		}()
	}

	for _, remotePol := range role.RemotePolicies {
		if err := client.AttachPolicy(userName, remotePol.Name, remotePol.Type); err != nil {
			return nil, err
		}
		// This defer is also in this loop on purpose.
		defer func() {
			if success {
				return
			}
			if err := client.DetachPolicy(userName, remotePol.Name, remotePol.Type); err != nil {
				if b.Logger().IsError() {
					b.Logger().Error(fmt.Sprintf("unable to detach policy name:%s, type:%s from user:%s", remotePol.Name, remotePol.Type, userName))
				}
			}
		}()
	}

	accessKeyResp, err := client.CreateAccessKey(userName)
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
		"is_sts":          false,
		"username":        userName,
		"access_key_id":   accessKeyResp.AccessKey.AccessKeyId,
		"inline_policies": inlinePolicies,
		"remote_policies": role.RemotePolicies,
	})

	if role.TTL != 0 {
		resp.Secret.TTL = role.TTL
	}
	if role.MaxTTL != 0 {
		resp.Secret.MaxTTL = role.MaxTTL
	}
	return resp, nil
}

func generateUsername(displayName, roleName string) string {
	username := fmt.Sprintf("%s-%s-", displayName, roleName)
	if len(username) > 48 {
		username = username[0:48]
	}
	return fmt.Sprintf("%s%d-%d", username, time.Now().Unix(), rand.Int31n(10000))
}

const pathCredsHelpSyn = `
Generate an access key pair for a specific role.
`

const pathCredsHelpDesc = `
This path will generate a new, never before used key pair for
accessing AliCloud. The RAM policies used to back this key pair will be
configured on the role. For example, if this backend is mounted at "alicloud",
then "alicloud/creds/deploy" would generate access keys for the "deploy" role.

The access keys will have a ttl associated with them. The access keys
can be revoked by ???.
`

// TODO need to replace the ??? above with what you actually do.
