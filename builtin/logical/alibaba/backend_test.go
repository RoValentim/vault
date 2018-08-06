package alibaba

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
)

const inlinePolicies = `[
	{
		"Statement": [{
			"Action": ["rds:*"],
			"Effect": "Allow",
			"Resource": ["acs:oss:*:*:*"]
		}],
		"Version": "1"
	},
	{
		"Statement": [{
			"Action": ["oss:*"],
			"Effect": "Allow",
			"Resource": ["acs:oss:*:*:*"]
		}],
		"Version": "1"
	}
]
`

//
//var (
//	testCtx     = context.Background()
//	testStorage = &logical.InmemStorage{}
//	testBackend = func() logical.Backend {
//		client := cleanhttp.DefaultClient()
//		client.Transport = &fauxRoundTripper{}
//		b := newBackend(client)
//		conf := &logical.BackendConfig{
//			System: &logical.StaticSystemView{
//				DefaultLeaseTTLVal: time.Hour,
//				MaxLeaseTTLVal:     time.Hour,
//			},
//		}
//		if err := b.Setup(testCtx, conf); err != nil {
//			panic(err)
//		}
//		return b
//	}()
//)

// TODO write full set of sunny path tests for the STS method
// TODO write full set of sunny path tests for the RAM method
// TODO ensure the revocation and renewal paths are tested both IRL and have coverage here

type fauxRoundTripper struct{}

// This simply returns a spoofed successful response from the GetCallerIdentity endpoint.
func (f *fauxRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	respBody := map[string]string{
		"RequestId":    "2C9BE469-4A35-44D5-9529-CAA280B11603",
		"UserId":       "216959339000654321",
		"AccountId":    "5138828231865461",
		"RoleId":       "1234",
		"Arn":          "acs:ram::5138828231865461:assumed-role/elk/vm-ram-i-rj978rorvlg76urhqh7q",
		"IdentityType": "assumed-role",
		"PrincipalId":  "vm-ram-i-rj978rorvlg76urhqh7q",
	}
	b, err := json.Marshal(respBody)
	if err != nil {
		return nil, err
	}
	resp := &http.Response{
		Body:       ioutil.NopCloser(bytes.NewReader(b)),
		StatusCode: 200,
	}
	return resp, nil
}
