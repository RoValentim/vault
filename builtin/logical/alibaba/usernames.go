package alibaba

import (
	"fmt"
	"math/rand"
	"time"
)

// TODO this doesn't need to be here anymore
// TODO need to test this to see how it looks and how it behaves
// TODO this should be up to 64 minus the length of the other things, is 48 really the room to play?
func generateUsername(displayName, roleName string) string {
	username := fmt.Sprintf("%s-%s-", displayName, roleName)
	if len(username) > 48 {
		username = username[0:48]
	}
	return fmt.Sprintf("%s%d-%d", username, time.Now().Unix(), rand.Int31n(10000))
}
