package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/goccy/go-yaml"

	"go.jacobcolvin.com/terrarium/eventstore"
)

// MaxPolicyBytes bounds each part of the policy that the get_policy
// tool returns. A policy document longer than MaxPolicyBytes ends in
// [TruncationMarker] after at most that many bytes. A rule whose JSON
// form is longer than MaxPolicyBytes is a string that holds the first
// MaxPolicyBytes bytes of that JSON form and ends in
// [TruncationMarker]. The JSON form of each rule list, with the index
// of each rule, holds MaxPolicyBytes bytes or fewer, unless the list
// holds one rule. A rule list therefore holds at least one rule when
// the policy holds a rule at its first index.
const MaxPolicyBytes = 16 * 1024

// The descriptions that the policy tools share.
const (
	redactionDesc = "The store holds `<redacted>` in place of each header value that " +
		"a `headerMatches` entry of the policy sets, because such a value can be a credential. " +
		"The tool therefore withholds those values."

	noSnapshotsMessage = "The event store holds no policy snapshot of this instance. " +
		"An instance records one snapshot each time that it applies a policy. " +
		"A version of terrarium from before the snapshots recorded none. " +
		"The store removes a stopped instance that holds no events, and the snapshots of that instance, " +
		"when the retention age of the store has passed since the instance stopped."
)

// GetPolicyInput holds the arguments of the get_policy tool.
type GetPolicyInput struct {
	Instance  string `json:"instance,omitempty"`
	At        string `json:"at,omitempty"`
	FirstRule int    `json:"first_rule,omitempty"`
}

// PolicyRule is one rule of a rule list in the result of the
// get_policy tool.
type PolicyRule struct {
	Rule      any  `json:"rule"                jsonschema:"the rule, as the JSON form of its entry in the policy document. A string when truncated is true"`
	Index     int  `json:"index"               jsonschema:"index of the rule in its list of the policy. The first rule has index 0. It is the number that rule_index and the reason of a firewall event name"`
	Truncated bool `json:"truncated,omitempty" jsonschema:"true when the JSON form of the rule is longer than 16384 bytes. The rule is then a string that holds the first 16384 bytes of that JSON form and ends in ...[truncated]. Absent otherwise"`
}

// Policy is one policy snapshot in the result of the get_policy tool.
type Policy struct {
	AppliedAt       string       `json:"applied_at"            jsonschema:"time at which the instance finished applying the policy, as an RFC 3339 time"`
	ConfigPath      string       `json:"config_path,omitempty" jsonschema:"path of the config file that held the policy"`
	SHA256          string       `json:"sha256"                jsonschema:"SHA-256 of the stored policy document, in hexadecimal digits"`
	SecurityMode    string       `json:"security_mode"         jsonschema:"how the policy treats egress: unrestricted allows all of it, blocked denies all of it, and filtered allows what the egress rules allow"`
	YAML            string       `json:"yaml"                  jsonschema:"the policy document that the instance stored, which is its parsed config and not the text of the config file. A document longer than 16384 bytes ends in ...[truncated]"`
	Egress          []PolicyRule `json:"egress"                jsonschema:"the rules of the egress list from first_rule on, in the order of the document. An egress rule allows traffic. The list ends early when the next rule takes the JSON of the list past 16384 bytes. Only a list of one rule can be longer"`
	EgressDeny      []PolicyRule `json:"egress_deny"           jsonschema:"the rules of the egressDeny list from first_rule on, in the order of the document. An egressDeny rule drops traffic. The list ends early when the next rule takes the JSON of the list past 16384 bytes. Only a list of one rule can be longer"`
	ID              int64        `json:"id"                    jsonschema:"row ID of the snapshot. A later snapshot has a larger ID"`
	EgressTotal     int          `json:"egress_total"          jsonschema:"number of rules in the egress list of the policy, which can be more than the number of returned rules"`
	EgressDenyTotal int          `json:"egress_deny_total"     jsonschema:"number of rules in the egressDeny list of the policy, which can be more than the number of returned rules"`
}

// PolicyResult is the result of the get_policy tool.
type PolicyResult struct {
	Policy   *Policy `json:"policy,omitempty"  jsonschema:"the snapshot. Absent when the store holds no snapshot for the call"`
	Instance string  `json:"instance"          jsonschema:"ID of the instance that the tool read"`
	Message  string  `json:"message,omitempty" jsonschema:"why the result holds no policy. Absent when the result holds one"`
}

// ListPoliciesInput holds the arguments of the list_policies tool.
type ListPoliciesInput struct {
	Instance string `json:"instance,omitempty"`
	Limit    int    `json:"limit,omitempty"`
}

// SnapshotInfo is one policy snapshot in the result of the
// list_policies tool.
type SnapshotInfo struct {
	AppliedAt    string `json:"applied_at"            jsonschema:"time at which the instance finished applying the policy, as an RFC 3339 time. Pass it as at to get_policy, with the instance of the result as instance, to read the policy"`
	ConfigPath   string `json:"config_path,omitempty" jsonschema:"path of the config file that held the policy"`
	SHA256       string `json:"sha256"                jsonschema:"SHA-256 of the stored policy document, in hexadecimal digits. Two snapshots with the same value hold the same stored document"`
	SecurityMode string `json:"security_mode"         jsonschema:"how the policy treats egress: unrestricted, blocked, or filtered"`
	ID           int64  `json:"id"                    jsonschema:"row ID of the snapshot. A later snapshot has a larger ID"`
	Changed      bool   `json:"changed"               jsonschema:"false when the snapshot before this one holds the same stored document. The stored document holds <redacted> in place of each headerMatches value, so a reload that changes only a header value has changed false. True for the earliest snapshot that the store holds of the instance"`
}

// PoliciesResult is the result of the list_policies tool.
type PoliciesResult struct {
	Instance string         `json:"instance"          jsonschema:"ID of the instance that the tool read"`
	Message  string         `json:"message,omitempty" jsonschema:"why the result holds no snapshot. Absent when the result holds one"`
	Policies []SnapshotInfo `json:"policies"          jsonschema:"the snapshots, latest first"`
	Total    int            `json:"total"             jsonschema:"number of snapshots of the instance in the store, which can be more than the number of returned snapshots"`
}

// getPolicy implements the get_policy tool.
func getPolicy(ctx context.Context, db *database, in GetPolicyInput) (PolicyResult, error) {
	var at time.Time

	// A call passes at when the value is not empty. The zero time is a
	// valid at, so at.IsZero cannot tell the two calls apart.
	hasAt := in.At != ""
	if hasAt {
		var err error

		at, err = eventstore.ParseUntil(in.At, time.Now())
		if err != nil {
			return PolicyResult{}, fmt.Errorf("at: %w", err)
		}
	}

	instance, err := resolveInstance(ctx, db, in.Instance)
	if err != nil {
		return PolicyResult{}, err
	}

	out := PolicyResult{Instance: instance}

	var (
		stored eventstore.StoredPolicy
		ok     bool
	)

	if !hasAt {
		stored, ok, err = db.LatestPolicy(ctx, instance)
	} else {
		stored, ok, err = db.PolicyAt(ctx, instance, at)
	}

	if err != nil {
		return PolicyResult{}, fmt.Errorf("reading the policy snapshot: %w", err)
	}

	if !ok {
		out.Message, err = noPolicyMessage(ctx, db, instance, at, hasAt)
		if err != nil {
			return PolicyResult{}, err
		}

		return out, nil
	}

	var rules struct {
		Egress     []any `yaml:"egress"`
		EgressDeny []any `yaml:"egressDeny"`
	}

	err = yaml.Unmarshal([]byte(stored.YAML), &rules)
	if err != nil {
		return PolicyResult{}, fmt.Errorf("parsing the policy document of snapshot %d: %w", stored.ID, err)
	}

	policy := &Policy{
		AppliedAt:       formatTime(stored.AppliedAt),
		ConfigPath:      truncate(stored.ConfigPath),
		SHA256:          stored.SHA256,
		SecurityMode:    string(stored.Mode),
		YAML:            truncateAt(stored.YAML, MaxPolicyBytes),
		ID:              stored.ID,
		EgressTotal:     len(rules.Egress),
		EgressDenyTotal: len(rules.EgressDeny),
	}

	policy.Egress, err = policyRules(rules.Egress, in.FirstRule)
	if err != nil {
		return PolicyResult{}, fmt.Errorf("egress rules of snapshot %d: %w", stored.ID, err)
	}

	policy.EgressDeny, err = policyRules(rules.EgressDeny, in.FirstRule)
	if err != nil {
		return PolicyResult{}, fmt.Errorf("egressDeny rules of snapshot %d: %w", stored.ID, err)
	}

	out.Policy = policy

	return out, nil
}

// noPolicyMessage returns the message of a get_policy result without
// a policy. A call without at, which hasAt reports, is a call for the
// latest snapshot. A call for a time before the earliest snapshot of
// the instance gets a message that names the time of that snapshot.
func noPolicyMessage(
	ctx context.Context,
	db *database,
	instance string,
	at time.Time,
	hasAt bool,
) (string, error) {
	if !hasAt || instance == "" {
		return noSnapshotsMessage, nil
	}

	infos, err := db.Policies(ctx, instance)
	if err != nil {
		return "", fmt.Errorf("listing the policy snapshots: %w", err)
	}

	if len(infos) == 0 {
		return noSnapshotsMessage, nil
	}

	earliest := formatTime(infos[len(infos)-1].AppliedAt)

	return fmt.Sprintf("The event store holds no policy snapshot of this instance from %s or earlier. "+
		"The earliest snapshot is from %s. An instance records its first snapshot at the end of its setup, "+
		"and the store removes the snapshots that are older than its retention. "+
		"Call get_policy with `at` set to %s to read the earliest snapshot. "+
		"An event from before that time can belong to another instance. "+
		"To read the policy of such an event, pass the instance that recorded it as `instance`.",
		at.UTC().Format(time.RFC3339Nano), earliest, earliest), nil
}

// policyRules returns the rules of one list of a policy document from
// the index first on, each with its index in the list. A rule whose
// JSON form is longer than [MaxPolicyBytes] becomes the result of
// [truncateAt] for that JSON form. The result ends before the entry
// that takes the JSON form of the list past [MaxPolicyBytes]. It
// holds at least one rule when the list holds the index first, so
// only a list of one rule can be longer than [MaxPolicyBytes].
func policyRules(rules []any, first int) ([]PolicyRule, error) {
	out := []PolicyRule{}

	// The size starts with the brackets of the list.
	for i, size := max(first, 0), len("[]"); i < len(rules); i++ {
		raw, err := json.Marshal(rules[i])
		if err != nil {
			return nil, fmt.Errorf("encoding rule %d: %w", i, err)
		}

		rule := PolicyRule{Rule: rules[i], Index: i}

		if len(raw) > MaxPolicyBytes {
			rule.Rule, rule.Truncated = truncateAt(string(raw), MaxPolicyBytes), true
		}

		entry, err := json.Marshal(rule)
		if err != nil {
			return nil, fmt.Errorf("encoding rule %d: %w", i, err)
		}

		n := len(entry)
		if len(out) > 0 {
			// The comma before the entry.
			n++
		}

		if len(out) > 0 && size+n > MaxPolicyBytes {
			break
		}

		size += n

		out = append(out, rule)
	}

	return out, nil
}

// listPolicies implements the list_policies tool.
func listPolicies(ctx context.Context, db *database, in ListPoliciesInput) (PoliciesResult, error) {
	instance, err := resolveInstance(ctx, db, in.Instance)
	if err != nil {
		return PoliciesResult{}, err
	}

	out := PoliciesResult{Instance: instance, Policies: []SnapshotInfo{}}

	// The empty instance ID selects the snapshots of every instance
	// in the reader, but the tool reads one instance.
	if instance == "" {
		out.Message = noSnapshotsMessage

		return out, nil
	}

	infos, err := db.Policies(ctx, instance)
	if err != nil {
		return PoliciesResult{}, fmt.Errorf("listing the policy snapshots: %w", err)
	}

	if len(infos) == 0 {
		out.Message = noSnapshotsMessage

		return out, nil
	}

	out.Total = len(infos)

	for i := range infos[:min(len(infos), clampLimit(in.Limit))] {
		info := &infos[i]

		out.Policies = append(out.Policies, SnapshotInfo{
			AppliedAt:    formatTime(info.AppliedAt),
			ConfigPath:   truncate(info.ConfigPath),
			SHA256:       info.SHA256,
			SecurityMode: string(info.Mode),
			ID:           info.ID,
			// The snapshots are in order from the latest one, so
			// the snapshot before this one follows it.
			Changed: i+1 == len(infos) || infos[i+1].SHA256 != info.SHA256,
		})
	}

	return out, nil
}
