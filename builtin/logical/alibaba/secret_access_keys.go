package alibaba

import (
	"context"
	"fmt"

	"github.com/aliyun/alibaba-cloud-sdk-go/services/ram"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

const secretType = "access_key"

func secretAccessKeys() *framework.Secret {
	return &framework.Secret{
		Type: secretType,
		Fields: map[string]*framework.FieldSchema{
			"access_key": {
				Type:        framework.TypeString,
				Description: "Access Key",
			},

			"secret_key": {
				Type:        framework.TypeString,
				Description: "Secret Key",
			},
		},
		Renew:  secretAccessKeysRenew,
		Revoke: secretAccessKeysRevoke,
	}
}

func secretAccessKeysRenew(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	userGroupName := data.Get("name").(string)

	resp := &logical.Response{Secret: req.Secret}

	role, err := readRole(ctx, req.Storage, userGroupName)
	if err != nil {
		return nil, err
	}
	if role.TTL != 0 {
		resp.Secret.TTL = role.TTL
	}
	if role.MaxTTL != 0 {
		resp.Secret.MaxTTL = role.MaxTTL
	}
	return resp, nil
}

func secretAccessKeysRevoke(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {

	usernameRaw, ok := req.Secret.InternalData["username"]
	if !ok {
		return nil, fmt.Errorf("secret is missing username internal data")
	}
	userName, ok := usernameRaw.(string)
	if !ok {
		return nil, fmt.Errorf("secret is missing username internal data")
	}

	roleNameRaw, ok := req.Secret.InternalData["role_name"]
	if !ok {
		return nil, fmt.Errorf("secret is missing role_name internal data")
	}
	roleName, ok := roleNameRaw.(string)
	if !ok {
		return nil, fmt.Errorf("secret is missing role_name internal data")
	}

	accessKeyIDRaw, ok := req.Secret.InternalData["access_key_id"]
	if !ok {
		return nil, fmt.Errorf("secret is missing access_key_id internal data")
	}
	accessKeyID, ok := accessKeyIDRaw.(string)
	if !ok {
		return nil, fmt.Errorf("secret is missing access_key_id internal data")
	}

	creds, err := readCredentials(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	client, err := getRAMClient(creds.AccessKey, creds.SecretKey)
	if err != nil {
		return nil, err
	}

	// TODO this all needs to be updated now that we have 3 methods, but get them working first
	/*
		The most important thing for us to delete is the access key, as it's what
		we've shared with the caller to use as credentials, so let's do that first.
	*/
	if err := deleteAccessKey(client, userName, accessKeyID); err != nil {
		return nil, err
	}

	/*
		Now let's back that user out of the user group.
	*/
	if err := removeFromGroup(client, userName, roleName); err != nil {
		return nil, err
	}

	/*
		At this point, deleting the user SHOULD succeed but an important caveat
		is that if somebody, out-of-band from Vault, added policies to them,
		added them to another user group, added an MFA device, or associated
		ANYTHING else to them, this will fail. We don't try to hunt down and
		delete every possible thing you can associate with a user in Alibaba,
		because that list will change over time, and it would also add a bunch
		of latency to this code.
	*/
	if err := deleteUser(client, userName); err != nil {
		return nil, err
	}
	return nil, nil
}

func deleteAccessKey(client *ram.Client, userName, accessKeyID string) error {
	accessKeyReq := ram.CreateDeleteAccessKeyRequest()
	accessKeyReq.UserAccessKeyId = accessKeyID
	accessKeyReq.UserName = userName
	if _, err := client.DeleteAccessKey(accessKeyReq); err != nil {
		return err
	}
	return nil
}

func removeFromGroup(client *ram.Client, userName, userGroupName string) error {
	removeUserReq := ram.CreateRemoveUserFromGroupRequest()
	removeUserReq.UserName = userName
	removeUserReq.GroupName = userGroupName
	if _, err := client.RemoveUserFromGroup(removeUserReq); err != nil {
		return err
	}
	return nil
}

// Note: deleteUser will fail if the user is presently associated with anything
// in Alibaba.
func deleteUser(client *ram.Client, userName string) error {
	deleteUserReq := ram.CreateDeleteUserRequest()
	deleteUserReq.UserName = userName
	if _, err := client.DeleteUser(deleteUserReq); err != nil {
		return err
	}
	return nil
}
