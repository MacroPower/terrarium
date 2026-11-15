package mcpserver

import (
	"cmp"
	"context"
	"fmt"
	"time"
	"unicode/utf8"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"go.jacobcolvin.com/terrarium/eventstore"
)

// The bounds of a tool result.
const (
	// DefaultLimit is the number of rows that a tool returns at
	// most when its call omits `limit`.
	DefaultLimit = 50

	// MaxLimit is the number of rows that a tool returns at most.
	// A call with a larger `limit` returns MaxLimit rows.
	MaxLimit = 200

	// MaxFieldBytes is the length in bytes of the longest string
	// value that a tool returns in full. A longer value ends in
	// [TruncationMarker] after at most MaxFieldBytes bytes of the
	// value. The bound does not apply to the policy document and the
	// rules of the get_policy tool. [MaxPolicyBytes] bounds those.
	MaxFieldBytes = 256

	// TruncationMarker ends a string value that a tool cut at
	// [MaxFieldBytes] or at [MaxPolicyBytes].
	TruncationMarker = "...[truncated]"
)

// defaultSince is the start of the window of a tool call that omits
// `since`. It matches the default of the `terrarium stats` flag.
const defaultSince = "24h"

// heartbeatStaleAfter is the age past which get_health reports a
// heartbeat as stale. An instance records one heartbeat in each
// [eventstore.HeartbeatInterval], so a stale heartbeat means that the
// instance missed two of them.
const heartbeatStaleAfter = 2 * eventstore.HeartbeatInterval

// The descriptions of the arguments that several tools share.
const (
	sinceDesc = "Start of the time window, inclusive. A Go duration before now, " +
		"such as 30m or 24h, or an RFC 3339 time. Defaults to 24h."
	untilDesc    = "End of the time window, inclusive, as an RFC 3339 time. Defaults to now."
	instanceDesc = "ID of the instance to read, from list_instances. " +
		"Defaults to the instance with the latest start."
	limitDesc = "Maximum number of rows. Defaults to 50. A value greater than 200 returns 200 rows."
)

// The values that the tools accept for an argument with a fixed set
// of values.
var (
	sourceValues = []string{
		string(eventstore.SourceDNS),
		string(eventstore.SourceEnvoy),
		string(eventstore.SourceFirewall),
	}

	decisionValues = []string{
		string(eventstore.DecisionAllow),
		string(eventstore.DecisionDeny),
		string(eventstore.DecisionError),
	}

	topDecisionValues = []string{
		string(eventstore.DecisionAllow),
		string(eventstore.DecisionDeny),
	}

	topByValues = []string{
		string(eventstore.TopByDomain),
		string(eventstore.TopBySNI),
		string(eventstore.TopByPath),
	}
)

// ListInstancesInput holds the arguments of the list_instances tool.
type ListInstancesInput struct {
	Limit int `json:"limit,omitempty"`
}

// InstanceInfo is one run of terrarium in the result of the
// list_instances tool.
type InstanceInfo struct {
	ID         string `json:"id"                    jsonschema:"ID of the instance"`
	Mode       string `json:"mode"                  jsonschema:"terrarium command of the run: init, daemon, or proxy"`
	Name       string `json:"name,omitempty"        jsonschema:"name of the run. A proxy records its listen address and port"`
	ConfigPath string `json:"config_path,omitempty" jsonschema:"path of the config file of the run"`
	StartedAt  string `json:"started_at"            jsonschema:"start of the run, as an RFC 3339 time"`
	EndedAt    string `json:"ended_at,omitempty"    jsonschema:"end of the run, as an RFC 3339 time. Absent when the run recorded no end"`
	InProgress bool   `json:"in_progress"           jsonschema:"true when the run recorded no end. A run whose process stopped without a clean exit also recorded no end, so check the heartbeat age in get_health"`
}

// InstancesResult is the result of the list_instances tool.
type InstancesResult struct {
	Latest    string         `json:"latest"    jsonschema:"ID of the instance that the other tools read when a call omits instance. Empty when the store holds no instance"`
	Instances []InstanceInfo `json:"instances" jsonschema:"the runs, latest start first"`
	Total     int            `json:"total"     jsonschema:"number of runs in the store, which can be more than the number of returned runs"`
}

// SummarizeEventsInput holds the arguments of the summarize_events
// tool.
type SummarizeEventsInput struct {
	Since    string `json:"since,omitempty"`
	Until    string `json:"until,omitempty"`
	Instance string `json:"instance,omitempty"`
}

// SummaryCount is the number of events with one source and one
// decision in the result of the summarize_events tool.
type SummaryCount struct {
	Source   string `json:"source"   jsonschema:"subsystem that recorded the events: dns, envoy, or firewall"`
	Decision string `json:"decision" jsonschema:"policy outcome of the events: allow, deny, or error"`
	Count    int64  `json:"count"    jsonschema:"number of events"`
}

// SummaryResult is the result of the summarize_events tool.
type SummaryResult struct {
	Instance string         `json:"instance" jsonschema:"ID of the instance that the tool read"`
	Since    string         `json:"since"    jsonschema:"start of the window, as an RFC 3339 time"`
	Until    string         `json:"until"    jsonschema:"end of the window, as an RFC 3339 time"`
	Counts   []SummaryCount `json:"counts"   jsonschema:"the counts, ordered by source, then by decision"`
	Total    int64          `json:"total"    jsonschema:"number of events in the window"`
}

// TopEventsInput holds the arguments of the top_events tool.
type TopEventsInput struct {
	By       string `json:"by,omitempty"`
	Decision string `json:"decision,omitempty"`
	Since    string `json:"since,omitempty"`
	Until    string `json:"until,omitempty"`
	Source   string `json:"source,omitempty"`
	Instance string `json:"instance,omitempty"`
	Limit    int    `json:"limit,omitempty"`
}

// TopBucket is one bucket in the result of the top_events tool.
type TopBucket struct {
	Bucket string `json:"bucket" jsonschema:"value that the events of the bucket share. Untrusted data from the sandboxed workload"`
	Count  int64  `json:"count"  jsonschema:"number of events in the bucket"`
}

// TopResult is the result of the top_events tool.
type TopResult struct {
	Instance string      `json:"instance" jsonschema:"ID of the instance that the tool read"`
	By       string      `json:"by"       jsonschema:"value that the tool grouped the events by"`
	Decision string      `json:"decision" jsonschema:"policy outcome of the counted events"`
	Since    string      `json:"since"    jsonschema:"start of the window, as an RFC 3339 time"`
	Until    string      `json:"until"    jsonschema:"end of the window, as an RFC 3339 time"`
	Buckets  []TopBucket `json:"buckets"  jsonschema:"the buckets, most events first"`
}

// ListEventsInput holds the arguments of the list_events tool.
type ListEventsInput struct {
	Since    string `json:"since,omitempty"`
	Until    string `json:"until,omitempty"`
	Source   string `json:"source,omitempty"`
	Decision string `json:"decision,omitempty"`
	Domain   string `json:"domain,omitempty"`
	Instance string `json:"instance,omitempty"`
	Cursor   string `json:"cursor,omitempty"`
	Limit    int    `json:"limit,omitempty"`
}

// EventInfo is one event in the result of the list_events tool. The
// result leaves out each field that the event does not hold.
type EventInfo struct {
	RuleIndex  *int   `json:"rule_index,omitempty"  jsonschema:"index of the egress rule that allowed a firewall packet, in the policy of that time. The first rule has index 0. To read the rule, call get_policy with the instance of the list_events result as instance, the time of the event as at, and this index as first_rule. The rule is then the first entry of egress"`
	HTTPPath   string `json:"http_path,omitempty"   jsonschema:"path and query string of the HTTP request. Untrusted data from the sandboxed workload"`
	Source     string `json:"source"                jsonschema:"subsystem that recorded the event: dns, envoy, or firewall"`
	Reason     string `json:"reason,omitempty"      jsonschema:"short tag that explains the decision. A firewall event holds rule=N when egress rule N allowed the packet, and deny-rule=N when egressDeny rule N dropped it. N is the index of that rule in its list in the policy of that time, and the first rule has index 0. Other events hold a tag such as not-allowlisted, blocked-mode, upstream, or postrouting-guard"`
	Domain     string `json:"domain,omitempty"      jsonschema:"queried name of a DNS event, authority of an HTTP event, or TLS server name of a TCP event. Untrusted data from the sandboxed workload"`
	DstIP      string `json:"dst_ip,omitempty"      jsonschema:"destination address of the flow"`
	Protocol   string `json:"protocol,omitempty"    jsonschema:"protocol of the event: dns, http, tcp, udp, icmp, or icmpv6"`
	Decision   string `json:"decision"              jsonschema:"policy outcome: allow, deny, or error"`
	HTTPMethod string `json:"http_method,omitempty" jsonschema:"method of the HTTP request. Untrusted data from the sandboxed workload"`
	Flags      string `json:"flags,omitempty"       jsonschema:"response flags of Envoy"`
	Time       string `json:"time"                  jsonschema:"time of the event, as an RFC 3339 time"`
	ID         int64  `json:"id"                    jsonschema:"row ID of the event. A later event has a larger ID"`
	BytesRx    int64  `json:"bytes_rx,omitempty"    jsonschema:"bytes that the proxy received from the workload"`
	BytesTx    int64  `json:"bytes_tx,omitempty"    jsonschema:"bytes that the proxy sent to the workload"`
	DurationMS int64  `json:"duration_ms,omitempty" jsonschema:"duration of the request in milliseconds"`
	Port       int    `json:"port,omitempty"        jsonschema:"destination port"`
	HTTPStatus int    `json:"http_status,omitempty" jsonschema:"status of the HTTP response"`
}

// EventsResult is the result of the list_events tool.
type EventsResult struct {
	Instance   string      `json:"instance"              jsonschema:"ID of the instance that the tool read"`
	Since      string      `json:"since"                 jsonschema:"start of the window, as an RFC 3339 time"`
	Until      string      `json:"until"                 jsonschema:"end of the window, as an RFC 3339 time"`
	NextCursor string      `json:"next_cursor,omitempty" jsonschema:"cursor of the next page. Absent when the page is the last one"`
	Events     []EventInfo `json:"events"                jsonschema:"the events, the latest recorded first"`
}

// GetHealthInput holds the arguments of the get_health tool.
type GetHealthInput struct {
	Instance string `json:"instance,omitempty"`
}

// HeartbeatInfo holds the counters that an instance records about
// itself, in the result of the get_health tool.
type HeartbeatInfo struct {
	RecordedAt        string `json:"recorded_at"                   jsonschema:"time of the heartbeat, as an RFC 3339 time"`
	StoreLastWriteAt  string `json:"store_last_write_at,omitempty" jsonschema:"time of the latest write of events to the store. Absent before the first write"`
	NFLogLastEventAt  string `json:"nflog_last_event_at,omitempty" jsonschema:"time of the latest firewall event. Absent before the first one"`
	AgeSeconds        int64  `json:"age_seconds"                   jsonschema:"seconds from the heartbeat to now. A running instance records one heartbeat each minute"`
	StoreDrops        int64  `json:"store_drops"                   jsonschema:"events that the instance dropped because the store wrote too slowly"`
	NFLogKernelDrops  uint64 `json:"nflog_kernel_drops"            jsonschema:"firewall log records that the kernel dropped"`
	NFLogParseErrors  uint64 `json:"nflog_parse_errors"            jsonschema:"firewall log records that the instance did not parse"`
	DNSCacheSize      int64  `json:"dns_cache_size"                jsonschema:"entries in the cache that maps an address to its DNS name"`
	DNSCacheEvictions uint64 `json:"dns_cache_evictions"           jsonschema:"entries that the DNS cache evicted"`
	Stale             bool   `json:"stale"                         jsonschema:"true when the instance missed two heartbeats, so it has probably stopped"`
}

// HealthResult is the result of the get_health tool.
type HealthResult struct {
	Heartbeat            *HeartbeatInfo `json:"heartbeat,omitempty"     jsonschema:"latest heartbeat of the instance. Absent when the instance recorded none"`
	Instance             string         `json:"instance"                jsonschema:"ID of the instance whose heartbeat the tool read"`
	DatabasePath         string         `json:"database_path"           jsonschema:"path of the event store database"`
	LastEventAt          string         `json:"last_event_at,omitempty" jsonschema:"time of the latest event of any instance. Absent when the store holds no event"`
	DatabaseSizeBytes    int64          `json:"database_size_bytes"     jsonschema:"size of the database file in bytes"`
	Events24h            int64          `json:"events_24h"              jsonschema:"events of any instance in the last 24 hours"`
	FirewallEvents1h     int64          `json:"firewall_events_1h"      jsonschema:"firewall events of any instance in the last hour"`
	FirewallNullDomain1h int64          `json:"firewall_null_domain_1h" jsonschema:"firewall events in the last hour without a domain name"`
}

// addTools registers every tool of the server.
func (s *Server) addTools() {
	mcp.AddTool(s.server, &mcp.Tool{
		Name:  "list_instances",
		Title: "List terrarium runs",
		Description: "Lists the runs of terrarium that the event store knows, latest start first. " +
			"Each run is one instance, with its mode, its start, its end, and whether it is in progress. " +
			"Pass the ID of a run as `instance` to another tool to read an earlier run.",
		Annotations: readOnly("List terrarium runs"),
		InputSchema: inputSchema[ListInstancesInput](func(p properties) {
			p.describe("limit", limitDesc).minimum(1)
		}),
	}, handler(s, listInstances))

	mcp.AddTool(s.server, &mcp.Tool{
		Name:  "summarize_events",
		Title: "Summarize egress events",
		Description: "Counts the events of one run in a time window by source and decision. " +
			"The sources are dns, envoy, and firewall, and the decisions are allow, deny, and error. " +
			"Call it first to see how much traffic the policy allowed and denied.",
		Annotations: readOnly("Summarize egress events"),
		InputSchema: inputSchema[SummarizeEventsInput](func(p properties) {
			p.describe("since", sinceDesc)
			p.describe("until", untilDesc)
			p.describe("instance", instanceDesc)
		}),
	}, handler(s, summarizeEvents))

	mcp.AddTool(s.server, &mcp.Tool{
		Name:  "top_events",
		Title: "Top egress destinations",
		Description: "Returns the values with the most allowed or denied events of one run in a time window. " +
			"It groups the events by domain name, by TLS server name, or by HTTP path without the query string. " +
			"The default returns the most denied domains, which are the names that the policy blocks.",
		Annotations: readOnly("Top egress destinations"),
		InputSchema: inputSchema[TopEventsInput](func(p properties) {
			p.describe("by", "Value to group the events by. Defaults to domain. "+
				"sni counts only TCP events, and path counts only HTTP events.").
				enum(topByValues)
			p.describe("decision", "Policy outcome of the events to count. Defaults to deny.").
				enum(topDecisionValues)
			p.describe("since", sinceDesc)
			p.describe("until", untilDesc)
			p.describe("source", "Count only the events of this subsystem.").enum(sourceValues)
			p.describe("instance", instanceDesc)
			p.describe("limit", limitDesc).minimum(1)
		}),
	}, handler(s, topEvents))

	mcp.AddTool(s.server, &mcp.Tool{
		Name:  "list_events",
		Title: "List egress events",
		Description: "Lists the events of one run in a time window, the latest recorded first. " +
			"Each event is one decision on a DNS query, a proxied request, or a firewall packet. " +
			"A full page holds `next_cursor`. To read the next page, call the tool again with that " +
			"cursor and with the `instance`, `since`, and `until` of the result.",
		Annotations: readOnly("List egress events"),
		InputSchema: inputSchema[ListEventsInput](func(p properties) {
			p.describe("since", sinceDesc)
			p.describe("until", untilDesc)
			p.describe("source", "Return only the events of this subsystem.").enum(sourceValues)
			p.describe("decision", "Return only the events with this policy outcome.").enum(decisionValues)
			p.describe("domain", "Return only the events of this domain name and of its subdomains. "+
				"The match ignores letter case and one trailing dot.")
			p.describe("instance", instanceDesc)
			p.describe("cursor", "The next_cursor of an earlier call with the same filters. "+
				"The call returns the events that follow that page.")
			p.describe("limit", limitDesc).minimum(1)
		}),
	}, handler(s, listEvents))

	mcp.AddTool(s.server, &mcp.Tool{
		Name:  "get_health",
		Title: "Event store health",
		Description: "Reports how well terrarium records events: the counters of the latest heartbeat " +
			"of one run, the age of that heartbeat, the time of the latest event, the number of events " +
			"in the last 24 hours, and the size of the database. " +
			"Call it when events are missing. Dropped events and a stale heartbeat explain gaps.",
		Annotations: readOnly("Event store health"),
		InputSchema: inputSchema[GetHealthInput](func(p properties) {
			p.describe("instance", "ID of the instance whose heartbeat to read, from list_instances. "+
				"Defaults to the instance with the latest start.")
		}),
	}, handler(s, getHealth))

	mcp.AddTool(s.server, &mcp.Tool{
		Name:  "get_policy",
		Title: "Applied policy",
		Description: "Returns the policy that one run of terrarium applied, from the snapshot that the run " +
			"recorded in the event store. The run enforced that policy, and the config file can hold " +
			"another one by now. Without `at`, the tool returns the latest snapshot of the run. " +
			"With `at`, it returns the snapshot that was in force at that time. " +
			"To find the rule behind a firewall event, pass the `instance` of the list_events result " +
			"that holds the event as `instance` and the `time` of the event as `at`. " +
			"The `rule_index` of the event and a reason of rule=N are indexes into `egress`, " +
			"and a reason of deny-rule=N is an index into `egress_deny`. " +
			"Pass that index as `first_rule`, so the rule is the first entry of its list " +
			"whatever the size of the policy. " +
			"A reload switches the firewall before the run records its snapshot, " +
			"so an event from shortly before the `applied_at` of the next snapshot " +
			"can come from that next policy. When the rule does not match the event, " +
			"compare the event time with the `applied_at` values of list_policies. " + redactionDesc,
		Annotations: readOnly("Applied policy"),
		InputSchema: inputSchema[GetPolicyInput](func(p properties) {
			p.describe("instance", instanceDesc)
			p.describe("at", "Time at which the policy was in force, as an RFC 3339 time, "+
				"such as the `time` of an event. Defaults to the latest snapshot of the instance.")
			p.describe("first_rule", "Index of the first rule to return in `egress` and in `egress_deny`. "+
				"Defaults to 0. Set it to read the rules that follow a list that ended early.").
				minimum(0)
		}),
	}, handler(s, getPolicy))

	mcp.AddTool(s.server, &mcp.Tool{
		Name:  "list_policies",
		Title: "List policy snapshots",
		Description: "Lists the policy snapshots of one run, latest first, without the policy documents. " +
			"A run records one snapshot when it starts and one after each reload of its config. " +
			"`changed` tells whether a snapshot holds another stored document than the snapshot before it. " +
			"The stored document holds <redacted> in place of each headerMatches value, " +
			"so a reload that changes only a header value has `changed` false. " +
			"To read the policy of a snapshot, pass its `applied_at` as `at` and the `instance` " +
			"of the result as `instance` to get_policy.",
		Annotations: readOnly("List policy snapshots"),
		InputSchema: inputSchema[ListPoliciesInput](func(p properties) {
			p.describe("instance", instanceDesc)
			p.describe("limit", limitDesc).minimum(1)
		}),
	}, handler(s, listPolicies))
}

// readOnly returns the annotations of a tool that only reads the
// local event store.
func readOnly(title string) *mcp.ToolAnnotations {
	closedWorld := false

	return &mcp.ToolAnnotations{
		Title:          title,
		ReadOnlyHint:   true,
		IdempotentHint: true,
		OpenWorldHint:  &closedWorld,
	}
}

// properties holds the schemas of the arguments of one tool by name.
type properties map[string]*jsonschema.Schema

// property is the schema of one argument of a tool.
type property struct {
	schema *jsonschema.Schema
}

// describe sets the description of the argument with the given name
// and returns the argument. It panics for a name that the input type
// of the tool does not hold.
func (p properties) describe(name, description string) property {
	schema, ok := p[name]
	if !ok {
		panic(fmt.Sprintf("mcpserver: the tool input has no argument %q", name))
	}

	schema.Description = description

	return property{schema: schema}
}

// enum limits the argument to the given values.
func (p property) enum(values []string) {
	p.schema.Enum = make([]any, 0, len(values))
	for _, v := range values {
		p.schema.Enum = append(p.schema.Enum, v)
	}
}

// minimum sets the least value of the argument.
func (p property) minimum(n float64) {
	p.schema.Minimum = &n
}

// inputSchema returns the JSON schema of the tool input type In after
// edit changes the schemas of its arguments. It panics for a type
// that has no JSON schema, which is a fault of this package.
//
// The edit must not set Default on any argument. When a schema holds
// a default, go-sdk v1.8.0 panics on a call whose arguments are null,
// and the panic ends the server process. The handlers apply the
// defaults instead, and the descriptions state them.
func inputSchema[In any](edit func(p properties)) *jsonschema.Schema {
	schema, err := jsonschema.For[In](nil)
	if err != nil {
		panic(fmt.Sprintf("mcpserver: inferring the input schema: %v", err))
	}

	edit(schema.Properties)

	return schema
}

// listInstances implements the list_instances tool.
func listInstances(ctx context.Context, db *database, in ListInstancesInput) (InstancesResult, error) {
	instances, err := db.Instances(ctx)
	if err != nil {
		return InstancesResult{}, fmt.Errorf("listing the instances: %w", err)
	}

	latest, _, err := db.LatestInstanceID(ctx)
	if err != nil {
		return InstancesResult{}, fmt.Errorf("finding the latest instance: %w", err)
	}

	out := InstancesResult{
		Latest:    latest,
		Instances: make([]InstanceInfo, 0, min(len(instances), clampLimit(in.Limit))),
		Total:     len(instances),
	}

	for _, inst := range instances[:cap(out.Instances)] {
		out.Instances = append(out.Instances, InstanceInfo{
			ID:         inst.ID,
			Mode:       string(inst.Mode),
			Name:       truncate(inst.Name),
			ConfigPath: truncate(inst.ConfigPath),
			StartedAt:  formatTime(inst.StartedAt),
			EndedAt:    formatTime(inst.EndedAt),
			InProgress: inst.EndedAt.IsZero(),
		})
	}

	return out, nil
}

// summarizeEvents implements the summarize_events tool.
func summarizeEvents(ctx context.Context, db *database, in SummarizeEventsInput) (SummaryResult, error) {
	filter, err := selectEvents(ctx, db, in.Since, in.Until, in.Instance)
	if err != nil {
		return SummaryResult{}, err
	}

	rows, err := db.Summary(ctx, filter)
	if err != nil {
		return SummaryResult{}, fmt.Errorf("counting the events: %w", err)
	}

	out := SummaryResult{
		Instance: filter.Instance,
		Since:    formatTime(filter.Since),
		Until:    formatTime(filter.Until),
		Counts:   make([]SummaryCount, 0, len(rows)),
	}

	for _, row := range rows {
		out.Counts = append(out.Counts, SummaryCount{
			Source:   string(row.Source),
			Decision: string(row.Decision),
			Count:    row.Count,
		})

		out.Total += row.Count
	}

	return out, nil
}

// topEvents implements the top_events tool.
func topEvents(ctx context.Context, db *database, in TopEventsInput) (TopResult, error) {
	by := cmp.Or(in.By, string(eventstore.TopByDomain))
	decision := cmp.Or(in.Decision, string(eventstore.DecisionDeny))

	filter, err := selectEvents(ctx, db, in.Since, in.Until, in.Instance)
	if err != nil {
		return TopResult{}, err
	}

	filter.Source = eventstore.Source(in.Source)
	filter.Decision = eventstore.Decision(decision)

	rows, err := db.Top(ctx, eventstore.TopQuery{
		By:     eventstore.TopBy(by),
		Filter: filter,
		Limit:  clampLimit(in.Limit),
	})
	if err != nil {
		return TopResult{}, fmt.Errorf("counting the top events: %w", err)
	}

	out := TopResult{
		Instance: filter.Instance,
		By:       by,
		Decision: decision,
		Since:    formatTime(filter.Since),
		Until:    formatTime(filter.Until),
		Buckets:  make([]TopBucket, 0, len(rows)),
	}

	for _, row := range rows {
		out.Buckets = append(out.Buckets, TopBucket{Bucket: truncate(row.Bucket), Count: row.Count})
	}

	return out, nil
}

// listEvents implements the list_events tool.
func listEvents(ctx context.Context, db *database, in ListEventsInput) (EventsResult, error) {
	filter, err := selectEvents(ctx, db, in.Since, in.Until, in.Instance)
	if err != nil {
		return EventsResult{}, err
	}

	filter.Source = eventstore.Source(in.Source)
	filter.Decision = eventstore.Decision(in.Decision)
	filter.Domain = in.Domain

	page, err := db.Events(ctx, eventstore.EventsQuery{
		Cursor: in.Cursor,
		Filter: filter,
		Limit:  clampLimit(in.Limit),
	})
	if err != nil {
		return EventsResult{}, fmt.Errorf("listing the events: %w", err)
	}

	out := EventsResult{
		Instance:   filter.Instance,
		Since:      formatTime(filter.Since),
		Until:      formatTime(filter.Until),
		NextCursor: page.NextCursor,
		Events:     make([]EventInfo, 0, len(page.Events)),
	}

	for i := range page.Events {
		out.Events = append(out.Events, eventInfo(&page.Events[i]))
	}

	return out, nil
}

// eventInfo returns the tool result form of the stored event e.
func eventInfo(e *eventstore.StoredEvent) EventInfo {
	info := EventInfo{
		ID:         e.ID,
		Time:       formatTime(e.Time),
		Source:     string(e.Source),
		Decision:   string(e.Decision),
		Reason:     truncate(string(e.Reason)),
		Domain:     truncate(e.Domain),
		Protocol:   string(e.Protocol),
		HTTPMethod: truncate(e.HTTPMethod),
		HTTPPath:   truncate(e.HTTPPath),
		Flags:      truncate(e.Flags),
		BytesRx:    e.BytesRx,
		BytesTx:    e.BytesTx,
		DurationMS: e.DurationMS,
		Port:       e.Port,
		HTTPStatus: e.HTTPStatus,
	}

	if e.DstIP.IsValid() {
		info.DstIP = e.DstIP.String()
	}

	if e.HasRuleIndex {
		info.RuleIndex = &e.RuleIndex
	}

	return info
}

// getHealth implements the get_health tool.
func getHealth(ctx context.Context, db *database, in GetHealthInput) (HealthResult, error) {
	instance, err := resolveInstance(ctx, db, in.Instance)
	if err != nil {
		return HealthResult{}, err
	}

	h, err := db.Health(ctx, instance)
	if err != nil {
		return HealthResult{}, fmt.Errorf("reading the health of the store: %w", err)
	}

	out := HealthResult{
		Instance:             instance,
		DatabasePath:         db.path,
		LastEventAt:          formatTime(h.LastEvent),
		DatabaseSizeBytes:    db.size,
		Events24h:            h.Events24h,
		FirewallEvents1h:     h.FirewallEvents1h,
		FirewallNullDomain1h: h.FirewallNullDomain1h,
	}

	if h.HasHeartbeat {
		age := time.Since(h.Heartbeat.RecordedAt)

		out.Heartbeat = &HeartbeatInfo{
			RecordedAt:        formatTime(h.Heartbeat.RecordedAt),
			StoreLastWriteAt:  formatTime(h.Heartbeat.EventStoreLastWrite),
			NFLogLastEventAt:  formatTime(h.Heartbeat.NFLogLastEvent),
			AgeSeconds:        int64(age / time.Second),
			StoreDrops:        h.Heartbeat.EventStoreDropCount,
			NFLogKernelDrops:  h.Heartbeat.NFLogKernelDrops,
			NFLogParseErrors:  h.Heartbeat.NFLogParseErrors,
			DNSCacheSize:      h.Heartbeat.DNSCacheSize,
			DNSCacheEvictions: h.Heartbeat.DNSCacheEvictions,
			Stale:             age > heartbeatStaleAfter,
		}
	}

	return out, nil
}

// selectEvents returns the filter that selects the events of one
// instance in one time window. The empty since starts the window
// [defaultSince] before now, and the empty until ends the window now.
// The empty instance selects the instance of [resolveInstance].
func selectEvents(ctx context.Context, db *database, since, until, instance string) (eventstore.Filter, error) {
	now := time.Now()

	start, err := eventstore.ParseSince(cmp.Or(since, defaultSince), now)
	if err != nil {
		return eventstore.Filter{}, fmt.Errorf("since: %w", err)
	}

	end, err := eventstore.ParseUntil(until, now)
	if err != nil {
		return eventstore.Filter{}, fmt.Errorf("until: %w", err)
	}

	instance, err = resolveInstance(ctx, db, instance)
	if err != nil {
		return eventstore.Filter{}, err
	}

	return eventstore.Filter{Since: start, Until: end, Instance: instance}, nil
}

// resolveInstance returns the ID of the instance that a tool call
// reads. The empty explicit ID selects the instance of
// [eventstore.Reader.LatestInstanceID], as the `terrarium stats`
// commands do. The result is empty when the store holds no instance.
func resolveInstance(ctx context.Context, db *database, explicit string) (string, error) {
	if explicit != "" {
		return explicit, nil
	}

	id, _, err := db.LatestInstanceID(ctx)
	if err != nil {
		return "", fmt.Errorf("finding the latest instance: %w", err)
	}

	return id, nil
}

// clampLimit returns the number of rows that a tool returns for the
// `limit` argument n. A value of zero or less returns [DefaultLimit],
// and a value greater than [MaxLimit] returns [MaxLimit].
func clampLimit(n int) int {
	switch {
	case n <= 0:
		return DefaultLimit
	case n > MaxLimit:
		return MaxLimit
	}

	return n
}

// formatTime returns t in UTC as an RFC 3339 time, with the fraction
// of the second that t holds. It returns the empty string for the
// zero time.
func formatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}

	return t.UTC().Format(time.RFC3339Nano)
}

// truncate returns s when it holds [MaxFieldBytes] bytes or fewer,
// and the result of [truncateAt] at that length for a longer s.
func truncate(s string) string {
	return truncateAt(s, MaxFieldBytes)
}

// truncateAt returns s when it holds limit bytes or fewer. It cuts a
// longer s at the last rune boundary within that length and appends
// [TruncationMarker]. The workload chooses the value of an event
// field, so s can hold bytes that are not UTF-8. A valid rune has at
// most [utf8.UTFMax]-1 continuation bytes, so truncateAt looks back
// that many bytes for the start of a rune. When it finds none, the
// bytes there are not UTF-8, and it cuts s at limit. An unbounded
// scan drops the valid text before a long run of such bytes.
func truncateAt(s string, limit int) string {
	if len(s) <= limit {
		return s
	}

	cut := limit
	for range utf8.UTFMax - 1 {
		if utf8.RuneStart(s[cut]) {
			break
		}

		cut--
	}

	if !utf8.RuneStart(s[cut]) {
		cut = limit
	}

	return s[:cut] + TruncationMarker
}
