package alibaba

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

// TODO write full set of sunny path tests for the STS method
// TODO write full set of sunny path tests for the RAM method
// TODO ensure the revocation and renewal paths are tested both IRL and have coverage here
