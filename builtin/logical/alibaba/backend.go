package alibaba

import (
	"context"
	"strings"

	"github.com/aliyun/alibaba-cloud-sdk-go/sdk"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

// TODO why was the AWS backend using WAL, and likewise rolling them back? See if you can learn anything from the PR.

func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := newBackend(sdk.NewConfig())
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

// newBackend allows us to pass in the clientConfig for testing purposes.
func newBackend(clientConfig *sdk.Config) logical.Backend {
	var b backend
	b.Backend = &framework.Backend{
		Help: strings.TrimSpace(backendHelp),
		PathsSpecial: &logical.Paths{
			SealWrapStorage: []string{
				"config",
			},
		},
		Paths: []*framework.Path{
			pathConfig(),
			b.pathRole(),
			pathListRole(),
			pathListRoles(),
			b.pathCreds(),
		},
		Secrets: []*framework.Secret{
			b.pathSecrets(),
		},
		BackendType: logical.TypeLogical,
	}
	b.clientConfig = clientConfig
	return b
}

type backend struct {
	*framework.Backend

	clientConfig *sdk.Config
}

const backendHelp = `
The AliCloud backend dynamically generates AliCloud access keys for a set of
RAM policies. The AliCloud access keys have a configurable ttl set and
are automatically revoked at the end of the ttl.

After mounting this backend, credentias to generate RAM keys must
be configured and roles must be written using
the "role/" endpoints before any access keys can be generated.
`
