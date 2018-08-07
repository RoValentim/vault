package alibaba

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/aliyun/alibaba-cloud-sdk-go/sdk"
	"github.com/hashicorp/vault/logical"
)

func setup() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		// Note: All responses below are directly from AliCloud's documentation
		// and none reflect real values.
		action := r.URL.Query().Get("Action")
		switch action {

		case "CreateUser":
			w.WriteHeader(200)
			w.Write([]byte(`{
				"RequestId": "04F0F334-1335-436C-A1D7-6C044FE73368",
				"User": {
					"UserId": "1227489245380721",
					"UserName": "zhangqiang",
					"DisplayName": "zhangqiang",
					"MobilePhone": "86-18600008888",
					"Email": "zhangqiang@example.com",
					"Comments": "This is a cloud computing engineer.",
					"CreateDate": "2015-01-23T12:33:18Z"
				}
			}`))

		case "DeleteUser":
			w.WriteHeader(200)
			w.Write([]byte(`{
				"RequestId": "1C488B66-B819-4D14-8711-C4EAAA13AC01"
			}`))

		case "CreatePolicy":
			w.WriteHeader(200)
			w.Write([]byte(`{
				"RequestId": "9B34724D-54B0-4A51-B34D-4512372FE1BE",
				"Policy": {
					"PolicyName": "OSS-Administrator",
					"PolicyType": "Custom",
					"Description": "OSS administrator permission",
					"DefaultVersion": "v1",
					"CreateDate": "2015-01-23T12:33:18Z"
				}
			}`))

		case "DeletePolicy":
			w.WriteHeader(200)
			w.Write([]byte(`{
				"RequestId": "898FAB24-7509-43EE-A287-086FE4C44394"
			}`))

		case "AttachPolicyToUser":
			w.WriteHeader(200)
			w.Write([]byte(`    {
				"RequestId": "697852FB-50D7-44D9-9774-530C31EAC572"
			}`))

		case "DetachPolicyFromUser":
			w.WriteHeader(200)
			w.Write([]byte(`    {
				"RequestId": "697852FB-50D7-44D9-9774-530C31EAC572"
			}`))

		case "CreateAccessKey":
			w.WriteHeader(200)
			w.Write([]byte(`    {
				"RequestId": "04F0F334-1335-436C-A1D7-6C044FE73368",
				"AccessKey": {
					"AccessKeyId": "0wNEpMMlzy7szvai",
					"AccessKeySecret": "PupkTg8jdmau1cXxYacgE736PJj4cA",
					"Status": "Active",
					"CreateDate": "2015-01-23T12:33:18Z"
				}
			}`))

		case "DeleteAccessKey":
			w.WriteHeader(200)
			w.Write([]byte(`    {
				"RequestId": "04F0F334-1335-436C-A1D7-6C044FE73368"
			}`))

		case "AssumeRole":
			w.WriteHeader(200)
			w.Write([]byte(`    {
				"Credentials": {
					"AccessKeyId": "STS.L4aBSCSJVMuKg5U1vFDw",
					"AccessKeySecret": "wyLTSmsyPGP1ohvvw8xYgB29dlGI8KMiH2pKCNZ9",
					"Expiration": "2015-04-09T11:52:19Z",
					"SecurityToken": "CAESrAIIARKAAShQquMnLIlbvEcIxO6wCoqJufs8sWwieUxu45hS9AvKNEte8KRUWiJWJ6Y+YHAPgNwi7yfRecMFydL2uPOgBI7LDio0RkbYLmJfIxHM2nGBPdml7kYEOXmJp2aDhbvvwVYIyt/8iES/R6N208wQh0Pk2bu+/9dvalp6wOHF4gkFGhhTVFMuTDRhQlNDU0pWTXVLZzVVMXZGRHciBTQzMjc0KgVhbGljZTCpnJjwySk6BlJzYU1ENUJuCgExGmkKBUFsbG93Eh8KDEFjdGlvbkVxdWFscxIGQWN0aW9uGgcKBW9zczoqEj8KDlJlc291cmNlRXF1YWxzEghSZXNvdXJjZRojCiFhY3M6b3NzOio6NDMyNzQ6c2FtcGxlYm94L2FsaWNlLyo="
				},
				"AssumedRoleUser": {
					"arn": "acs:sts::1234567890123456:assumed-role/AdminRole/alice",
					"AssumedRoleUserId":"344584339364951186:alice"
					},
				"RequestId": "6894B13B-6D71-4EF5-88FA-F32781734A7F"
			}`))
		}
	}))
}

func teardown(ts *httptest.Server) {
	ts.Close()
}

func newTestEnv(testURL string) (*testEnv, error) {
	ctx := context.Background()
	b, err := testBackend(ctx, testURL)
	if err != nil {
		return nil, err
	}
	return &testEnv{
		Backend: b,
		Context: ctx,
		Storage: &logical.InmemStorage{},
	}, nil
}

type testEnv struct {
	Backend logical.Backend
	Context context.Context
	Storage logical.Storage
}

// This test thoroughly exercises all endpoints, and tests the policy-based creds
// sunny path.
func TestDynamicPolicyBasedCreds(t *testing.T) {
	ts := setup()
	defer teardown(ts)
	env, err := newTestEnv(ts.URL)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("add config", env.AddConfig)
	t.Run("read config", env.ReadFirstConfig)
	t.Run("update config", env.UpdateConfig)
	t.Run("read config", env.ReadSecondConfig)
	t.Run("delete config", env.DeleteConfig)
	t.Run("read config", env.ReadEmptyConfig)
	t.Run("add config", env.AddConfig)

	t.Run("add policy-based role", env.AddPolicyBasedRole)
	t.Run("read policy-based role", env.ReadPolicyBasedRole)
	t.Run("add arn-based role", env.AddARNBasedRole)
	t.Run("read arn-based role", env.ReadARNBasedRole)
	t.Run("list two roles", env.ListTwoRoles)
	t.Run("delete arn-based role", env.DeleteARNBasedRole)
	t.Run("list one role", env.ListOneRole)
	// TODO need to add an update role test where you update all the fields and check them
	// TODO also need to make sure they're staying the same if not updated in that situation

	t.Run("read policy-based creds", env.ReadPolicyBasedCreds)
	t.Run("operationRenew policy-based creds", env.RenewPolicyBasedCreds)
	t.Run("revoke policy-based creds", env.RevokePolicyBasedCreds)
}

// Since all endpoints were exercised in the previous test, we just need one that
// gets straight to the point testing the STS creds sunny path.
func TestDynamicSTSCreds(t *testing.T) {
	ts := setup()
	defer teardown(ts)
	env, err := newTestEnv(ts.URL)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("add config", env.AddConfig)
	t.Run("add arn-based role", env.AddARNBasedRole)
	t.Run("read arn-based creds", env.ReadARNBasedCreds)
	t.Run("operationRenew arn-based creds", env.RenewARNBasedCreds)
	t.Run("revoke arn-based creds", env.RevokeARNBasedCreds)
}

func (e *testEnv) AddConfig(t *testing.T) {
	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config",
		Storage:   e.Storage,
		Data: map[string]interface{}{
			"access_key": "fizz",
			"secret_key": "buzz",
		},
	}
	resp, err := e.Backend.HandleRequest(e.Context, req)
	if err != nil {
		t.Fatal(err)
	}
	if resp != nil {
		t.Fatal("expected nil response to represent a 204")
	}
}

func (e *testEnv) ReadFirstConfig(t *testing.T) {
	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "config",
		Storage:   e.Storage,
	}
	resp, err := e.Backend.HandleRequest(e.Context, req)
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil {
		t.Fatal("expected a response")
	}
	if resp.Data["access_key"] != "fizz" {
		t.Fatal("expected access_key of fizz")
	}
	if resp.Data["secret_key"] != nil {
		t.Fatal("secret_key should not be returned")
	}
}

func (e *testEnv) UpdateConfig(t *testing.T) {
	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config",
		Storage:   e.Storage,
		Data: map[string]interface{}{
			"access_key": "foo",
			"secret_key": "bar",
		},
	}
	resp, err := e.Backend.HandleRequest(e.Context, req)
	if err != nil {
		t.Fatal(err)
	}
	if resp != nil {
		t.Fatal("expected nil response to represent a 204")
	}
}

func (e *testEnv) ReadSecondConfig(t *testing.T) {
	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "config",
		Storage:   e.Storage,
	}
	resp, err := e.Backend.HandleRequest(e.Context, req)
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil {
		t.Fatal("expected a response")
	}
	if resp.Data["access_key"] != "foo" {
		t.Fatal("expected access_key of foo")
	}
	if resp.Data["secret_key"] != nil {
		t.Fatal("secret_key should not be returned")
	}
}

func (e *testEnv) DeleteConfig(t *testing.T) {
	req := &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "config",
		Storage:   e.Storage,
	}
	resp, err := e.Backend.HandleRequest(e.Context, req)
	if err != nil {
		t.Fatal(err)
	}
	if resp != nil {
		t.Fatal("expected nil response to represent a 204")
	}
}

func (e *testEnv) ReadEmptyConfig(t *testing.T) {
	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "config",
		Storage:   e.Storage,
	}
	resp, err := e.Backend.HandleRequest(e.Context, req)
	if err != nil {
		t.Fatal(err)
	}
	if resp != nil {
		t.Fatal("expected nil response to represent a 204")
	}
}

func (e *testEnv) AddPolicyBasedRole(t *testing.T) {
	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "role/policy-based",
		Storage:   e.Storage,
		Data: map[string]interface{}{
			"remote_policies": []string{"name:AliyunOSSReadOnlyAccess,type:System"},
			"inline_policies": rawInlinePolicies,
		},
	}
	resp, err := e.Backend.HandleRequest(e.Context, req)
	if err != nil {
		t.Fatal(err)
	}
	if resp != nil {
		t.Fatal("expected nil response to represent a 204")
	}
}

func (e *testEnv) ReadPolicyBasedRole(t *testing.T) {
	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "role/policy-based",
		Storage:   e.Storage,
	}
	resp, err := e.Backend.HandleRequest(e.Context, req)
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil {
		t.Fatal("expected a response")
	}

	if resp.Data["role_arn"] != "" {
		t.Fatalf("expected no role_arn but received %s", resp.Data["role_arn"])
	}

	inlinePolicies := resp.Data["inline_policies"].([]*inlinePolicy)
	for i, inlinePolicy := range inlinePolicies {
		if inlinePolicy.PolicyDocument["Version"] != "1" {
			t.Fatalf("expected version of 1 but received %s", inlinePolicy.PolicyDocument["Version"])
		}
		stmts := inlinePolicy.PolicyDocument["Statement"].([]interface{})
		if len(stmts) != 1 {
			t.Fatalf("expected 1 statement but received %d", len(stmts))
		}
		stmt := stmts[0].(map[string]interface{})
		action := stmt["Action"].([]interface{})[0].(string)
		if stmt["Effect"] != "Allow" {
			t.Fatalf("expected Allow statement but received %s", stmt["Effect"])
		}
		resource := stmt["Resource"].([]interface{})[0].(string)
		if resource != "acs:oss:*:*:*" {
			t.Fatalf("received incorrect resource: %s", resource)
		}
		switch i {
		case 0:
			if action != "rds:*" {
				t.Fatalf("expected rds:* but received %s", action)
			}
		case 1:
			if action != "oss:*" {
				t.Fatalf("expected oss:* but received %s", action)
			}
		}
	}

	remotePolicies := resp.Data["remote_policies"].([]*remotePolicy)
	for _, remotePol := range remotePolicies {
		if remotePol.Name != "AliyunOSSReadOnlyAccess" {
			t.Fatalf("received unexpected policy name of %s", remotePol.Name)
		}
		if remotePol.Type != "System" {
			t.Fatalf("received unexpected policy type of %s", remotePol.Type)
		}
	}

	ttl := fmt.Sprintf("%d", resp.Data["ttl"])
	if ttl != "0" {
		t.Fatalf("expected ttl of 0 but received %s", ttl)
	}

	maxTTL := fmt.Sprintf("%d", resp.Data["max_ttl"])
	if maxTTL != "0" {
		t.Fatalf("expected max_ttl of 0 but received %s", maxTTL)
	}
}

func (e *testEnv) AddARNBasedRole(t *testing.T) {
	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "role/role-based",
		Storage:   e.Storage,
		Data: map[string]interface{}{
			"role_arn": "acs:ram::5138828231865461:role/hastrustedactors",
			"ttl":      10,
			"max_ttl":  10,
		},
	}
	resp, err := e.Backend.HandleRequest(e.Context, req)
	if err != nil {
		t.Fatal(err)
	}
	if resp != nil {
		t.Fatal("expected nil response to represent a 204")
	}
}

func (e *testEnv) ReadARNBasedRole(t *testing.T) {
	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "role/role-based",
		Storage:   e.Storage,
	}
	resp, err := e.Backend.HandleRequest(e.Context, req)
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil {
		t.Fatal("expected a response")
	}

	if resp.Data["role_arn"] != "acs:ram::5138828231865461:role/hastrustedactors" {
		t.Fatalf("received unexpected role_arn of %s", resp.Data["role_arn"])
	}

	inlinePolicies := resp.Data["inline_policies"].([]*inlinePolicy)
	if len(inlinePolicies) != 0 {
		t.Fatalf("expected no inline policies but received %+v", inlinePolicies)
	}

	remotePolicies := resp.Data["remote_policies"].([]*remotePolicy)
	if len(remotePolicies) != 0 {
		t.Fatalf("expected no remote policies but received %+v", remotePolicies)
	}

	ttl := fmt.Sprintf("%d", resp.Data["ttl"])
	if ttl != "10" {
		t.Fatalf("expected ttl of 10 but received %s", ttl)
	}

	maxTTL := fmt.Sprintf("%d", resp.Data["max_ttl"])
	if maxTTL != "10" {
		t.Fatalf("expected max_ttl of 10 but received %s", maxTTL)
	}
}

func (e *testEnv) ListTwoRoles(t *testing.T) {
	req := &logical.Request{
		Operation: logical.ListOperation,
		Path:      "role",
		Storage:   e.Storage,
	}
	resp, err := e.Backend.HandleRequest(e.Context, req)
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil {
		t.Fatal("expected a response")
	}
	keys := resp.Data["keys"].([]string)
	if len(keys) != 2 {
		t.Fatalf("expected 2 keys but received %d", len(keys))
	}
	if keys[0] != "policy-based" {
		t.Fatalf("expectied policy-based role name but received %s", keys[0])
	}
	if keys[1] != "role-based" {
		t.Fatalf("expected role-based role name but received %s", keys[1])
	}
}

func (e *testEnv) DeleteARNBasedRole(t *testing.T) {
	req := &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "role/role-based",
		Storage:   e.Storage,
	}
	resp, err := e.Backend.HandleRequest(e.Context, req)
	if err != nil {
		t.Fatal(err)
	}
	if resp != nil {
		t.Fatal("expected nil response to represent a 204")
	}
}

func (e *testEnv) ListOneRole(t *testing.T) {
	req := &logical.Request{
		Operation: logical.ListOperation,
		Path:      "roles",
		Storage:   e.Storage,
	}
	resp, err := e.Backend.HandleRequest(e.Context, req)
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil {
		t.Fatal("expected a response")
	}
	keys := resp.Data["keys"].([]string)
	if len(keys) != 1 {
		t.Fatalf("expected 2 keys but received %d", len(keys))
	}
	if keys[0] != "policy-based" {
		t.Fatalf("expectied policy-based role name but received %s", keys[0])
	}
}

func (e *testEnv) ReadPolicyBasedCreds(t *testing.T) {
	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/policy-based",
		Storage:   e.Storage,
	}
	resp, err := e.Backend.HandleRequest(e.Context, req)
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil {
		t.Fatal("expected a response")
	}

	if resp.Data["access_key"] != "0wNEpMMlzy7szvai" {
		t.Fatalf("received unexpected access_key of %s", resp.Data["access_key"])
	}
	if resp.Data["secret_key"] != "PupkTg8jdmau1cXxYacgE736PJj4cA" {
		t.Fatalf("received unexpected secret_key of %s", resp.Data["secret_key"])
	}
}

func (e *testEnv) RenewPolicyBasedCreds(t *testing.T) {
	var policyDocs []map[string]interface{}
	if err := json.Unmarshal([]byte(rawInlinePolicies), &policyDocs); err != nil {
		t.Fatal(err)
	}
	inlinePolicies := make([]*inlinePolicy, len(policyDocs))
	for i, policyDoc := range policyDocs {
		inlinePolicies[i] = &inlinePolicy{
			UUID:           fmt.Sprintf("%d", i),
			PolicyDocument: policyDoc,
		}
	}

	remotePolicies := []*remotePolicy{{Name: "somePolicyName", Type: "somePolicyType"}}

	secret := &logical.Secret{
		InternalData: map[string]interface{}{
			"role_name":       "my-role",
			"is_sts":          false,
			"username":        "displayName-roleName-1533674550-2687",
			"access_key_id":   "0wNEpMMlzy7szvai", // TODO is this safe? Is internal data encrypted?
			"inline_policies": inlinePolicies,
			"remote_policies": remotePolicies,
			"secret_type":     secretType,
		},
	}

	req := &logical.Request{
		Operation: logical.RenewOperation,
		Storage:   e.Storage,
		Secret:    secret,
		Data: map[string]interface{}{
			"lease_id": "foo",
		},
	}
	resp, err := e.Backend.HandleRequest(e.Context, req)
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil {
		t.Fatal("expected a response")
	}
	if resp.Secret != secret {
		t.Fatalf("expected %+v but got %+v", secret, resp.Secret)
	}
}

func (e *testEnv) RevokePolicyBasedCreds(t *testing.T) {
	remotePolicies := []*remotePolicy{{Name: "someRemotePolicyName", Type: "someRemotePolicyType"}}
	secret := &logical.Secret{
		InternalData: map[string]interface{}{
			"role_name":     "my-role",
			"is_sts":        false,
			"username":      "displayName-roleName-1533674550-2687",
			"access_key_id": "0wNEpMMlzy7szvai",
			// Inline policies are provided on the auth as remote policies because they really have been
			// instantiated somewhere remotely, and we need to differentiate between the inline (ephemeral)
			// ones, and the remote (static) ones.
			"inline_policies": []*remotePolicy{
				{Name: "someInlinePolicyName", Type: "someInlinePolicyType"},
			},
			"remote_policies": remotePolicies,
			"secret_type":     secretType,
		},
	}

	req := &logical.Request{
		Operation: logical.RevokeOperation,
		Storage:   e.Storage,
		Secret:    secret,
		Data: map[string]interface{}{
			"lease_id": "foo",
		},
	}
	resp, err := e.Backend.HandleRequest(e.Context, req)
	if err != nil {
		t.Fatal(err)
	}
	if resp != nil {
		t.Fatal("expected nil response to represent a 204")
	}
}

func (e *testEnv) ReadARNBasedCreds(t *testing.T) {
	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/role-based",
		Storage:   e.Storage,
	}
	resp, err := e.Backend.HandleRequest(e.Context, req)
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil {
		t.Fatal("expected a response")
	}

	if resp.Data["access_key"] != "STS.L4aBSCSJVMuKg5U1vFDw" {
		t.Fatalf("received unexpected access_key of %s", resp.Data["access_key"])
	}
	if resp.Data["secret_key"] != "wyLTSmsyPGP1ohvvw8xYgB29dlGI8KMiH2pKCNZ9" {
		t.Fatalf("received unexpected secret_key of %s", resp.Data["secret_key"])
	}
	if fmt.Sprintf("%s", resp.Data["expiration"]) != "2015-04-09 11:52:19 +0000 UTC" {
		t.Fatalf("received unexpected expiration of %s", resp.Data["expiration"])
	}
	if resp.Data["security_token"] != "CAESrAIIARKAAShQquMnLIlbvEcIxO6wCoqJufs8sWwieUxu45hS9AvKNEte8KRUWiJWJ6Y+YHAPgNwi7yfRecMFydL2uPOgBI7LDio0RkbYLmJfIxHM2nGBPdml7kYEOXmJp2aDhbvvwVYIyt/8iES/R6N208wQh0Pk2bu+/9dvalp6wOHF4gkFGhhTVFMuTDRhQlNDU0pWTXVLZzVVMXZGRHciBTQzMjc0KgVhbGljZTCpnJjwySk6BlJzYU1ENUJuCgExGmkKBUFsbG93Eh8KDEFjdGlvbkVxdWFscxIGQWN0aW9uGgcKBW9zczoqEj8KDlJlc291cmNlRXF1YWxzEghSZXNvdXJjZRojCiFhY3M6b3NzOio6NDMyNzQ6c2FtcGxlYm94L2FsaWNlLyo=" {
		t.Fatalf("received unexpected security token of %s", resp.Data["security_token"])
	}
}

func (e *testEnv) RenewARNBasedCreds(t *testing.T) {
	req := &logical.Request{
		Operation: logical.RenewOperation,
		Storage:   e.Storage,
		Secret: &logical.Secret{
			InternalData: map[string]interface{}{
				"is_sts":      true,
				"secret_type": secretType,
			},
		},
		Data: map[string]interface{}{
			"lease_id": "foo",
		},
	}
	resp, err := e.Backend.HandleRequest(e.Context, req)
	if err != nil {
		t.Fatal(err)
	}
	if resp != nil {
		t.Fatal("expected nil response to represent a 204")
	}
}

func (e *testEnv) RevokeARNBasedCreds(t *testing.T) {
	req := &logical.Request{
		Operation: logical.RevokeOperation,
		Storage:   e.Storage,
		Secret: &logical.Secret{
			InternalData: map[string]interface{}{
				"is_sts":      true,
				"secret_type": secretType,
			},
		},
		Data: map[string]interface{}{
			"lease_id": "foo",
		},
	}
	resp, err := e.Backend.HandleRequest(e.Context, req)
	if err != nil {
		t.Fatal(err)
	}
	if resp != nil {
		t.Fatal("expected nil response to represent a 204")
	}
}

func testBackend(context context.Context, testURL string) (logical.Backend, error) {
	clientConfig := sdk.NewConfig()

	// Our test server doesn't use TLS, so we need to set the scheme to match that.
	clientConfig.Scheme = "http"

	// Use a URL updater configured to point all requests at
	// our local test server.
	clientConfig.HttpTransport = &http.Transport{}
	updater, err := newURLUpdater(testURL)
	if err != nil {
		return nil, err
	}
	clientConfig.HttpTransport.Proxy = updater.Proxy

	b := newBackend(clientConfig)
	conf := &logical.BackendConfig{
		System: &logical.StaticSystemView{
			DefaultLeaseTTLVal: time.Hour,
			MaxLeaseTTLVal:     time.Hour,
		},
	}
	if err := b.Setup(context, conf); err != nil {
		panic(err)
	}
	return b, nil
}

/*
	The URL updater uses the Proxy on outbound requests to swap
	a real URL with one generated by httptest. This points requests
	at a local test server, and allows us to return expected
	responses.
*/
func newURLUpdater(testURL string) (*urlUpdater, error) {
	// Example testURL: https://127.0.0.1:46445
	u, err := url.Parse(testURL)
	if err != nil {
		return nil, err
	}
	return &urlUpdater{u}, nil
}

type urlUpdater struct {
	testURL *url.URL
}

func (u *urlUpdater) Proxy(req *http.Request) (*url.URL, error) {
	req.URL.Scheme = u.testURL.Scheme
	req.URL.Host = u.testURL.Host
	return u.testURL, nil
}

const rawInlinePolicies = `[
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
