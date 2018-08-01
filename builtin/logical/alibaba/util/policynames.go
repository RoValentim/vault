package util

import (
	"fmt"

	"github.com/aliyun/alibaba-cloud-sdk-go/services/ram"
)

// Limit set by Alibaba API.
const policyNameMaxLength = 128

func GeneratePolicyName(username string, policy *ram.Policy) (string, error) {

	uid, err := dashlessUUID()
	if err != nil {
		return "", err
	}

	haveTrimmedPolicyName := false
	haveTrimmedPolicyType := false
	policyName := policy.PolicyName
	policyType := policy.PolicyType

	// This loops up to 4 times because the first pass is to just check the length,
	// and the remaining 3 passes are to shorten the uid, policyType, and policyName.
	// It's impossible for the policyName to still not meet length requirements
	// at that point, but just to safeguard against infinite loops, we bound the
	// maximum possible passes at 4.
	for i := 0; i < 4; i++ {
		result := concatPolicyName(username, policyName, policyType, uid)
		excessLength := len(result) - policyNameMaxLength
		if excessLength <= 0 {
			return result, nil
		}

		// The username can only be up to 64 in length, and the two policy
		// types are generally "System" or "Custom", so excess length is
		// likely coming from the policy name.
		// Let's try slicing off some of the UUID first, and if that doesn't
		// work, we'll also slice off some of the policy name, and the policy type
		// after that, why not.

		// The lenReservedForUUID includes a dash, so we're subtracting one to leave room for it.
		if len(uid) != lenReservedForUUID-1 {
			// We haven't already trimmed the UUID, let's try that.
			if excessLength > (lenReservedForUUID - 1) {
				// Suppose the excess length is 100, and the amount to reserve for the UUID itself is 5.
				// We want to slice it to a minimum size of 5.
				uid = uid[:lenReservedForUUID-1]
				continue
			} else {
				// Suppose the excess length is 3, and the amount to reserve for the UUID itself is 5.
				// We want to remove 5 characters from the UUID's current length.
				// This would hold true if the excess length and the reserved length were both 5.
				uid = uid[:len(uid)-excessLength]
				continue
			}
		}

		// It's unlikely we would ever have a long policy type, but if we did,
		// it would be preferable to keep more of the policy name, which is why
		// we trim the type first.
		if !haveTrimmedPolicyType {
			if len(policyType) > excessLength {
				policyType = policyType[:len(policyType)-excessLength]
			} else if len(policyType) > 6 {
				policyType = policyType[:6]
			}
			haveTrimmedPolicyType = true
			continue
		}

		if !haveTrimmedPolicyName {
			if len(policyName) > excessLength {
				policyName = policyName[:len(policyName)-excessLength]
			} else if len(policyName) > 6 {
				policyName = policyName[:6]
			}
			haveTrimmedPolicyName = true
			continue
		}
	}
	return "", fmt.Errorf("unable to build a policy name using %s, %s, and %s", username, policy.PolicyName, policy.PolicyType)
}

func concatPolicyName(username, policyName, policyType, uid string) string {
	result := username
	if policyName != "" {
		result += "-" + policyName
	}
	if policyType != "" {
		result += "-" + policyType
	}
	result += "-" + uid
	return result
}
