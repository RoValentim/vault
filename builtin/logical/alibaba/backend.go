package alibaba

import (
	"context"
	"strings"

	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
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
			secretAccessKeys(),
		},
		BackendType: logical.TypeLogical,
	}
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

type backend struct {
	*framework.Backend
}

const backendHelp = `
The AliCloud backend dynamically generates AliCloud access keys for a set of
RAM policies. The AliCloud access keys have a configurable ttl set and
are automatically revoked at the end of the ttl.

After mounting this backend, credentias to generate RAM keys must
be configured and roles must be written using
the "role/" endpoints before any access keys can be generated.
`
