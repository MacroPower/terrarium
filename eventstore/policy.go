package eventstore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"time"
)

// SecurityMode names how a policy treats egress. The `policies` row
// of a [PolicySnapshot] holds it.
type SecurityMode string

// SecurityMode values.
const (
	// SecurityUnrestricted is a policy without egress rules, which
	// allows all egress.
	SecurityUnrestricted SecurityMode = "unrestricted"

	// SecurityBlocked is a policy that denies all egress.
	SecurityBlocked SecurityMode = "blocked"

	// SecurityFiltered is a policy whose rules allow part of the
	// egress.
	SecurityFiltered SecurityMode = "filtered"
)

// PolicySnapshot is one policy that a process applied. The process
// passes it to [Store.RecordPolicy], and a [Reader] returns it as a
// [StoredPolicy].
type PolicySnapshot struct {
	// AppliedAt is the time at which the process finished applying
	// the policy. [Store.RecordPolicy] sets the zero value to the
	// time of the call.
	AppliedAt time.Time

	// ConfigPath is the path of the config file that holds the
	// policy.
	ConfigPath string

	// Mode is the security mode of the policy.
	Mode SecurityMode

	// YAML is the policy document. The store writes it as it is, and
	// the unprivileged user of [WithUID] can read the database. The
	// caller must therefore remove each secret from the document
	// before the call.
	YAML string
}

// RecordPolicy sends p to the writer goroutine, which adds it to the
// `policies` table as a snapshot of this instance, with the SHA-256
// of [PolicySnapshot.YAML]. [Reader.LatestPolicy] then returns the
// policy that the instance enforces. [Reader.PolicyAt] returns the
// policy that the instance enforced at the time of an event.
//
// RecordPolicy follows the rules of [Store.Emit]. The send does not
// block. When the channel is full, RecordPolicy drops the snapshot
// and logs a warning. A nil receiver is a no-op, and so is a call
// after [Store.Close].
//
// The pruner of [Retention.MaxAge] removes a snapshot when a later
// snapshot of the same instance is also older than MaxAge. It
// therefore keeps the latest snapshot of every instance, and for each
// time within MaxAge it keeps the snapshot that was in force.
func (s *Store) RecordPolicy(p PolicySnapshot) {
	if s == nil {
		return
	}

	if p.AppliedAt.IsZero() {
		p.AppliedAt = time.Now()
	}

	s.closeMu.RLock()
	defer s.closeMu.RUnlock()

	if s.closed {
		return
	}

	select {
	case s.policyCh <- p:
	default:
		s.logger.Warn("eventstore policy channel full, dropping policy snapshot")
	}
}

// drainPolicies writes each pending policy snapshot before the writer
// goroutine returns, so that a snapshot recorded right before
// [Store.Close] reaches the database.
func (s *Store) drainPolicies() {
	for {
		select {
		case p := <-s.policyCh:
			s.insertPolicy(p)
		default:
			return
		}
	}
}

// insertPolicy writes p into the `policies` table through the
// connection of the writer goroutine.
func (s *Store) insertPolicy(p PolicySnapshot) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	sum := sha256.Sum256([]byte(p.YAML))

	_, err := s.db.ExecContext(ctx, `
		INSERT INTO policies (
			instance_id, applied_at, config_path, sha256, security_mode, yaml
		) VALUES (?, ?, ?, ?, ?, ?)
	`,
		s.instanceID,
		p.AppliedAt.UnixMicro(),
		p.ConfigPath,
		hex.EncodeToString(sum[:]),
		string(p.Mode),
		p.YAML,
	)
	if err != nil {
		s.logger.Warn("eventstore policy snapshot insert", slog.Any("err", err))
	}
}

// prunePoliciesByAge runs on the ticker of [WithPruneInterval]. It
// deletes one chunk of the snapshots that another snapshot of the
// same instance replaced before the cutoff of [Retention.MaxAge]. See
// [Store.RecordPolicy] for the snapshots that it keeps.
//
// The row comparison orders two snapshots of one instance by their
// time and then by their row ID. Exactly one of two snapshots with
// the same time therefore counts as the later one.
func (s *Store) prunePoliciesByAge() {
	r := s.retention.Load()
	if r == nil || r.MaxAge <= 0 {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cutoff := time.Now().Add(-r.MaxAge).UnixMicro()

	_, err := s.db.ExecContext(ctx, `
		DELETE FROM policies WHERE id IN (
			SELECT p.id FROM policies p
			WHERE p.applied_at < ?1
			  AND EXISTS (
				SELECT 1 FROM policies n
				WHERE n.instance_id = p.instance_id
				  AND n.applied_at <= ?1
				  AND (n.applied_at, n.id) > (p.applied_at, p.id)
			  )
			LIMIT ?2
		)`,
		cutoff, pruneChunkSize,
	)
	if err != nil {
		s.logger.Debug("retention: pruning policy snapshots", slog.Any("err", err))
	}
}
