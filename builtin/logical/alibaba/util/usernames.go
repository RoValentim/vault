package util

import (
	"strings"

	"github.com/hashicorp/go-uuid"
)

const (
	// Limit set by Alibaba API.
	usernameMaxLength = 64

	// This reserves the length it would take to have a dash in front of the UUID
	// for readability, and 5 significant base64 characters, which provides 1,073,741,824
	// possible random combinations.
	lenReservedForUUID = 6
)

// Normally we'd do something like this to create a username:
// fmt.Sprintf("vault-%s-%s-%s-%d", userGroupName, displayName, userUUID, time.Now().Unix())
// However, Alibaba limits the username length to 1-64, so we have to make some sacrifices.
func GenerateUsername(displayName, roleName string) (string, error) {
	userName := roleName
	if displayName != "" {
		userName += "-" + displayName
	}

	// However long our username is so far with valuable human-readable naming
	// conventions, we need to include at least part of a UUID on the end to minimize
	// the risk of naming collisions.
	if len(userName) > usernameMaxLength-lenReservedForUUID {
		userName = userName[:usernameMaxLength-lenReservedForUUID]
	}

	uid, err := dashlessUUID()
	if err != nil {
		return "", err
	}

	userName += "-" + uid
	if len(userName) > usernameMaxLength {
		// Slice off the excess UUID, bringing UUID length down to possibly only
		// 5 significant characters.
		return userName[:usernameMaxLength], nil
	}
	return userName, nil
}

func dashlessUUID() (string, error) {
	uid, err := uuid.GenerateUUID()
	if err != nil {
		return "", err
	}
	return strings.Replace(uid, "-", "", -1), nil
}
