package alibaba

import (
	"os"
	"testing"
)

func TestAcceptance(t *testing.T) {
	if os.Getenv("VAULT_ACC") != "1" {
		t.SkipNow()
	}
	// TODO - test that actually really hits Alibaba if env creds are set
}
