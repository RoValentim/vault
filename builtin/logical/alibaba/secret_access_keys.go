package alibaba

import (
	"context"

	"fmt"

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

	roleName, err := getStringValue(req.Secret.InternalData, "role_name")
	if err != nil {
		return nil, err
	}

	role, err := readRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}

	if role.isAssumeRoleMethod() {
		// TODO - this and return
	}

	creds, err := readCredentials(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	ramClient, err := getRAMClient(creds.AccessKey, creds.SecretKey)
	if err != nil {
		return nil, err
	}

	userName, err := getStringValue(req.Secret.InternalData, "username")
	if err != nil {
		return nil, err
	}

	accessKeyID, err := getStringValue(req.Secret.InternalData, "access_key_id")
	if err != nil {
		return nil, err
	}

	// Delete the access key first so if all else fails, the access key is revoked.
	if err := deleteAccessKey(ramClient, userName, accessKeyID); err != nil {
		return nil, err
	}

	// Inline policies are currently stored as remote policies, because they have been
	// instantiated remotely and we need their name and type to now detach and delete them.
	inlinePolicies, err := getRemotePolicies(req.Secret.InternalData, "inline_policies")
	if err != nil {
		return nil, err
	}
	for _, inlinePolicy := range inlinePolicies {
		if err := detachPolicy(ramClient, userName, inlinePolicy.Name, inlinePolicy.Type); err != nil {
			return nil, err
		}
		if err := deletePolicy(ramClient, inlinePolicy.Name); err != nil {
			return nil, err
		}
	}

	// These just need to be detached, but we're not going to delete them because they're
	// supposed to be longstanding.
	remotePolicies, err := getRemotePolicies(req.Secret.InternalData, "remote_policies")
	if err != nil {
		return nil, err
	}
	for _, remotePolicy := range remotePolicies {
		if err := detachPolicy(ramClient, userName, remotePolicy.Name, remotePolicy.Type); err != nil {
			return nil, err
		}
	}

	// Finally, delete the user. Note: this will fail if any other new associations have been
	// created with the user out of band from Vault. For example, if a new API key had been
	// manually created for them in their console that Vault didn't know about, or some other
	// thing had been created. Luckily the err returned is pretty explanatory so that will
	// help with debugging.
	if err := deleteUser(ramClient, userName); err != nil {
		return nil, err
	}
	return nil, nil
}

func getStringValue(internalData map[string]interface{}, key string) (string, error) {
	valueRaw, ok := internalData[key]
	if !ok {
		return "", fmt.Errorf("secret is missing %s internal data", key)
	}
	value, ok := valueRaw.(string)
	if !ok {
		return "", fmt.Errorf("secret is missing %s internal data", key)
	}
	return value, nil
}

func getRemotePolicies(internalData map[string]interface{}, key string) ([]*remotePolicy, error) {
	valuesRaw, ok := internalData[key]
	if !ok {
		return nil, fmt.Errorf("secret is missing %s internal data", key)
	}
	values, ok := valuesRaw.([]interface{})
	if !ok {
		return nil, fmt.Errorf("secret is missing %s internal data", key)
	}
	policies := make([]*remotePolicy, len(values))
	for i, v := range values {
		policy, ok := v.(*remotePolicy)
		if !ok {
			return nil, fmt.Errorf("could not convert %+v to a policy", v)
		}
		policies[i] = policy
	}
	return policies, nil
}
