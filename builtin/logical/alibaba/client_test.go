package alibaba

import (
	"fmt"
	"testing"

	"github.com/aliyun/alibaba-cloud-sdk-go/services/ram"
	"github.com/hashicorp/vault/builtin/logical/alibaba/util"
)

func TestStuffWithTheClient(t *testing.T) {
	key := ""
	secret := ""
	client, err := getRAMClient(key, secret)
	if err != nil {
		panic(err)
	}

	displayName := "becca"
	userGroupName := "developers"

	userName, err := util.GenerateUsername(displayName, userGroupName)
	if err != nil {
		panic(err)
	}

	createUserReq := ram.CreateCreateUserRequest()
	createUserReq.UserName = userName
	createUserReq.DisplayName = userName
	if _, err := client.CreateUser(createUserReq); err != nil {
		panic(err)
	}

	addUserReq := ram.CreateAddUserToGroupRequest()
	addUserReq.UserName = userName
	addUserReq.GroupName = userGroupName
	if _, err := client.AddUserToGroup(addUserReq); err != nil {
		panic(err)
	}

	accessKeyReq := ram.CreateCreateAccessKeyRequest()
	accessKeyReq.UserName = userName
	accessKeyResp, err := client.CreateAccessKey(accessKeyReq)
	if err != nil {
		panic(err)
	}

	fmt.Printf("%+v\n", accessKeyResp.AccessKey)

	listReq := ram.CreateListAccessKeysRequest()
	listReq.UserName = userName
	listResp, err := client.ListAccessKeys(listReq)
	if err != nil {
		panic(err)
	}
	for _, key := range listResp.AccessKeys.AccessKey {
		fmt.Println(key.AccessKeyId)
	}

	delKeyReq := ram.CreateDeleteAccessKeyRequest()
	delKeyReq.UserAccessKeyId = accessKeyResp.AccessKey.AccessKeyId
	delKeyReq.UserName = userName
	if _, err := client.DeleteAccessKey(delKeyReq); err != nil {
		panic(err)
	}

	removeUserReq := ram.CreateRemoveUserFromGroupRequest()
	removeUserReq.UserName = userName
	removeUserReq.GroupName = userGroupName
	if _, err := client.RemoveUserFromGroup(removeUserReq); err != nil {
		panic(err)
	}

	deleteUserReq := ram.CreateDeleteUserRequest()
	deleteUserReq.UserName = userName
	if _, err := client.DeleteUser(deleteUserReq); err != nil {
		panic(err)
	}
}
