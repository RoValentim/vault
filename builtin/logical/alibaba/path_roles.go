package alibaba

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/go-errors/errors"
	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

func pathListRole() *framework.Path {
	return &framework.Path{
		Pattern: "role/?$",
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ListOperation: operationRolesList,
		},
		HelpSynopsis:    pathListRolesHelpSyn,
		HelpDescription: pathListRolesHelpDesc,
	}
}

func pathListRoles() *framework.Path {
	return &framework.Path{
		Pattern: "roles/?$",
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ListOperation: operationRolesList,
		},
		HelpSynopsis:    pathListRolesHelpSyn,
		HelpDescription: pathListRolesHelpDesc,
	}
}

func (b *backend) pathRole() *framework.Path {
	return &framework.Path{
		Pattern: "role/" + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Name of the user group",
			},
			"role_arn": {
				Type: framework.TypeString,
				Description: `ARN of the role to be assumed. If provideded, inline_policies and 
remote_policies should be blank.`,
			},
			"inline_policies": {
				Type:        framework.TypeString,
				Description: "JSON of policies to be dynamically applied to users of this role.",
			},
			"remote_policies": {
				Type: framework.TypeCommaStringSlice,
				Description: `The name and type of each remote policy to be applied. 
Example: "name:AliyunRDSReadOnlyAccess,type:System".`,
			},
			"ttl": {
				Type: framework.TypeDurationSecond,
				Description: `Duration in seconds after which the issued token should expire. Defaults
to 0, in which case the value will fallback to the system/mount defaults.`,
			},
			"max_ttl": {
				Type:        framework.TypeDurationSecond,
				Description: "The maximum allowed lifetime of tokens issued using this role.",
			},
		},
		ExistenceCheck: b.operationRoleExistenceCheck,
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.CreateOperation: b.operationRoleCreateUpdate,
			logical.UpdateOperation: b.operationRoleCreateUpdate,
			logical.ReadOperation:   operationRoleRead,
			logical.DeleteOperation: operationRoleDelete,
		},
		HelpSynopsis:    pathRolesHelpSyn,
		HelpDescription: pathRolesHelpDesc,
	}
}

func (b *backend) operationRoleExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	entry, err := readRole(ctx, req.Storage, data.Get("name").(string))
	if err != nil {
		return false, err
	}
	return entry != nil, nil
}

func (b *backend) operationRoleCreateUpdate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("name").(string)

	role, err := readRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}
	if role == nil && req.Operation == logical.UpdateOperation {
		return nil, fmt.Errorf("no role found to update for %s", roleName)
	} else if role == nil {
		role = &roleEntry{}
	}

	if raw, ok := data.GetOk("role_arn"); ok {
		role.RoleARN = raw.(string)
	}
	if raw, ok := data.GetOk("inline_policies"); ok {
		policyDocsStr := raw.(string)

		var policyDocs []map[string]interface{}
		if err := json.Unmarshal([]byte(policyDocsStr), &policyDocs); err != nil {
			return nil, err
		}

		// If any inline policies were set before, we need to clear them and consider
		// these the new ones.
		role.InlinePolicies = make([]*inlinePolicy, len(policyDocs))

		for i, policyDoc := range policyDocs {
			uid, err := uuid.GenerateUUID()
			if err != nil {
				return nil, err
			}
			uid = strings.Replace(uid, "-", "", -1)
			role.InlinePolicies[i] = &inlinePolicy{
				UUID:           uid,
				PolicyDocument: policyDoc,
			}
		}
	}
	if raw, ok := data.GetOk("remote_policies"); ok {
		strPolicies := raw.([]string)

		// If any remote policies were set before, we need to clear them and consider
		// these the new ones.
		role.RemotePolicies = make([]*remotePolicy, len(strPolicies))

		for i, strPolicy := range strPolicies {
			policy := &remotePolicy{}
			kvPairs := strings.Split(strPolicy, ",")
			for _, kvPair := range kvPairs {
				kvFields := strings.Split(kvPair, ":")
				if len(kvFields) != 2 {
					return nil, fmt.Errorf("unable to recognize pair in %s", kvPair)
				}
				switch kvFields[0] {
				case "name":
					policy.Name = kvFields[1]
				case "type":
					policy.Type = kvFields[1]
				default:
					return nil, fmt.Errorf("invalid key: %s", kvFields[0])
				}
			}
			if policy.Name == "" {
				return nil, fmt.Errorf("policy name is required in %s", strPolicy)
			}
			if policy.Type == "" {
				return nil, fmt.Errorf("policy type is required in %s", strPolicy)
			}
			role.RemotePolicies[i] = policy
		}
	}
	if raw, ok := data.GetOk("ttl"); ok {
		role.TTL = time.Duration(raw.(int)) * time.Second
	}
	if raw, ok := data.GetOk("max_ttl"); ok {
		role.MaxTTL = time.Duration(raw.(int)) * time.Second
	}

	// Now that the role is built, validate it.
	if role.MaxTTL > 0 && role.TTL > role.MaxTTL {
		return nil, errors.New("ttl exceeds max_ttl")
	}
	if role.isSTS() {
		if len(role.RemotePolicies) > 0 {
			return nil, errors.New("remote_policies must be blank when an arn is present")
		}
		if len(role.InlinePolicies) > 0 {
			return nil, errors.New("inline_policies must be blank when an arn is present")
		}
	} else {
		if len(role.InlinePolicies)+len(role.RemotePolicies) == 0 {
			return nil, errors.New("must include an arn, or at least one of inline_policies or remote_policies")
		}
	}

	entry, err := logical.StorageEntryJSON("role/"+roleName, role)
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	if role.TTL > b.System().MaxLeaseTTL() {
		resp := &logical.Response{}
		resp.AddWarning(fmt.Sprintf("ttl of %data exceeds the system max ttl of %data, the latter will be used during login", role.TTL, b.System().MaxLeaseTTL()))
		return resp, nil
	}
	return nil, nil
}

func operationRoleRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	role, err := readRole(ctx, req.Storage, data.Get("name").(string))
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, nil
	}
	return &logical.Response{
		Data: map[string]interface{}{
			"role_arn":        role.RoleARN,
			"remote_policies": role.RemotePolicies,
			"inline_policies": role.InlinePolicies,
			"ttl":             role.TTL / time.Second,
			"max_ttl":         role.MaxTTL / time.Second,
		},
	}, nil
}

func operationRoleDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	if err := req.Storage.Delete(ctx, "role/"+data.Get("name").(string)); err != nil {
		return nil, err
	}
	return nil, nil
}

func operationRolesList(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	entries, err := req.Storage.List(ctx, "role/")
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(entries), nil
}

func readRole(ctx context.Context, s logical.Storage, roleName string) (*roleEntry, error) {
	role, err := s.Get(ctx, "role/"+roleName)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, nil
	}
	result := &roleEntry{}
	if err := role.DecodeJSON(result); err != nil {
		return nil, err
	}
	return result, nil
}

type roleEntry struct {
	RoleARN        string          `json:"role_arn"`
	RemotePolicies []*remotePolicy `json:"remote_policies"`
	InlinePolicies []*inlinePolicy `json:"inline_policies"`
	TTL            time.Duration   `json:"ttl"`
	MaxTTL         time.Duration   `json:"max_ttl"`
}

func (r *roleEntry) isSTS() bool {
	return r.RoleARN != ""
}

// Policies don't have ARNs and instead, their unique combination of their name and type comprise
// their unique identifier.
type remotePolicy struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

type inlinePolicy struct {
	// UUID is used in naming the policy. The policy document has no fields
	// that would reliably be there and make a beautiful, human-readable name.
	// So instead, we generate a UUID for it and use that in the policy name,
	// which is likewise returned when roles are read so policy names can be
	// tied back to which policy document they're for.
	UUID           string                 `json:"hash"`
	PolicyDocument map[string]interface{} `json:"policy_document"`
}

const pathListRolesHelpSyn = `List the existing roles in this backend`

const pathListRolesHelpDesc = `Roles will be listed by the role name.`

const pathRolesHelpSyn = `
Read, write and reference RAM policies that access keys can be made for.
`

const pathRolesHelpDesc = `
This path allows you to read and write roles that are used to
create access keys. These roles are associated with RAM policies that
map directly to the route to read the access keys. For example, if the
backend is mounted at "alicloud" and you create a role at "alicloud/roles/deploy"
then a user could request access credConfig at "aliclouc/creds/deploy".

You can supply inline or remote policies, or
provide a reference to an existing AliCloud role by supplying the full arn
reference. Inline policies written are normal
RAM policies. Vault will not attempt to parse these except to validate
that they're basic JSON. No validation is performed on arn references.

To validate the keys, attempt to read an access key after writing the policy.
`
