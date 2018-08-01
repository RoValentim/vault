package alibaba

import (
	"github.com/aliyun/alibaba-cloud-sdk-go/sdk"
	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/auth/credentials"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/ram"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/sts"
)

const (
	/*
		The RAM endpoint requires https, but the default scheme is http.
	*/
	scheme = "https"

	/*
		There's only one endpoint for the Alibaba RAM and STS API;
		yet their client requires that a region be passed in. This
		is supported by both their docs and the endpoints shown in
		their Go SDK. We just pass in a plug region so we don't need
		to do any gymnastics to determine what region we're in when
		it makes no difference in the endpoints we'll ultimately use.
	*/
	region = "us-east-1"
)

func getRAMClient(key, secret string) (*ram.Client, error) {
	config := sdk.NewConfig()
	config.Scheme = scheme
	cred := credentials.NewAccessKeyCredential(key, secret)
	return ram.NewClientWithOptions(region, config, cred)
}

// TODO need to test this client IRL
func getSTSClient() (*sts.Client, error) {
	config := sdk.NewConfig()
	config.Scheme = scheme
	return sts.NewClientWithOptions(region, config, nil)
}
