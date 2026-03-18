package privdrop

import (
	"fmt"
	"os/user"
	"strconv"
)

// resolveGroups looks up supplementary group IDs for the given UID,
// matching setpriv's --init-groups behavior (initgroups(username, gid)).
// Returns the list of GIDs as uint32 values.
func resolveGroups(uid uint32) ([]uint32, error) {
	u, err := user.LookupId(strconv.FormatUint(uint64(uid), 10))
	if err != nil {
		return nil, fmt.Errorf("looking up UID %d: %w", uid, err)
	}

	gidStrs, err := u.GroupIds()
	if err != nil {
		return nil, fmt.Errorf("resolving groups for %s: %w", u.Username, err)
	}

	gids := make([]uint32, 0, len(gidStrs))

	for _, s := range gidStrs {
		gid, err := strconv.ParseUint(s, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("parsing group ID %q: %w", s, err)
		}

		gids = append(gids, uint32(gid))
	}

	return gids, nil
}
