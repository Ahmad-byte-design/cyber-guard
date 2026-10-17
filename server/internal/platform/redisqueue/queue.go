package redisqueue

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

// Scan job queue operations.
//
// # What is in a queue message
//
// A scan ID and nothing else. ADR 0013 forbids a raw URL in the queue payload,
// and that rule is enforced by the *shape* of this file: every exported
// operation takes a scan ID, so there is no parameter through which a caller
// could pass a URL. A Redis dump reveals which scans exist and nothing about
// what was being scanned.
//
// # Why a plain list, and why there is no in-flight list
//
// BRPOP removes a message on delivery. A worker that crashes after popping
// therefore loses that message from Redis — which is fine here, because
// MongoDB is authoritative (ADR 0002) and still holds the scan in `queued` or
// `running`. The reconciler in internal/scans re-enqueues any active scan that
// has stopped progressing.
//
// The conventional alternative, BRPOPLPUSH into an in-flight list with a lease,
// would recover in seconds instead of the reconciler's window. It was rejected
// because it adds a second piece of state that can disagree with the first: a
// message stuck in the in-flight list because the reaper died, or a message
// removed from the in-flight list by a completion that did not actually happen.
// Since MongoDB already provides exactly-once recovery for the thing that
// matters, the extra state buys latency, not correctness.
//
// The cost is honest and worth stating: recovery latency is the reconciler's
// stall threshold plus one tick, not one second. For a sandbox detonation that
// is irrelevant; for a scan awaiting a verdict it is the difference between a
// few seconds and a couple of minutes.
//
// # Delivery semantics
//
// At-least-once. Duplicates are expected and must be harmless: a scan that is
// already terminal is a no-op when claimed again, and a scan with a stored
// provider job ID resumes polling rather than submitting again.

// Queue key names. Prefixed so a shared Redis instance cannot collide with
// another deployment, and namespaced by environment where one is configured.
const (
	keyQueue     = "cyberguard:queue:scans"
	keyScheduled = "cyberguard:queue:scans:scheduled"
)

// Job is one unit of queued work: a scan identifier and nothing sensitive.
type Job struct {
	// ScanID is CyberGuard's own scan identifier.
	ScanID string
}

// Valid reports whether the job carries a usable scan ID.
func (j Job) Valid() bool { return strings.TrimSpace(j.ScanID) != "" }

// claimGrace is added to a blocking pop's own timeout when deriving a read
// deadline.
//
// Redis may overshoot the requested block under load, so the derived deadline
// must be a little later than the block or an idle worker would occasionally
// report a failure instead of an empty queue.
const claimGrace = time.Second

// maxScanIDLen bounds what is accepted from Redis.
//
// The HTTP layer caps scan IDs at 64 characters. A longer value means the
// queue is corrupt or was written by something else, and it is rejected rather
// than forwarded to the database.
const maxScanIDLen = 64

// ErrJobInvalid is returned when a queue message does not carry a usable scan
// ID.
//
// It is a permanent condition: the message is dropped rather than retried,
// because re-reading the same corrupt message can never produce a valid one.
var ErrJobInvalid = errors.New("redisqueue: job does not carry a valid scan id")

// Enqueue appends a scan ID to the pending queue.
//
// It is the only way work enters the queue, and it deliberately takes no
// payload. A caller wanting to attach data has no parameter to attach it to.
//
// Failure matters. If this returns an error the scan is already durably
// recorded in MongoDB and the reconciler will re-enqueue it, so an enqueue
// failure delays work rather than losing it.
func (c *Client) Enqueue(ctx context.Context, scanID string) error {
	scanID = strings.TrimSpace(scanID)
	if scanID == "" {
		return errors.New("redisqueue: scanID is required")
	}
	if len(scanID) > maxScanIDLen {
		return fmt.Errorf("redisqueue: scanID exceeds %d characters", maxScanIDLen)
	}
	if c == nil || c.rdb == nil {
		return redis.ErrClosed
	}

	if err := c.rdb.RPush(ctx, keyQueue, scanID).Err(); err != nil {
		return fmt.Errorf("redisqueue: enqueue: %w", err)
	}
	return nil
}

// EnqueueRetry schedules a scan ID to become visible after delay.
//
// Retries are held in a sorted set scored by due time rather than slept on in
// the worker. Sleeping in the worker would pin a concurrency slot for minutes
// and make a restart lose the schedule; a scored set survives both.
//
// The message becomes visible only when PromoteDue runs, which the worker does
// on every tick. Visibility is therefore the worker's tick interval, not the
// exact delay — the delay is a floor, not a guarantee.
func (c *Client) EnqueueRetry(ctx context.Context, scanID string, delay time.Duration) error {
	scanID = strings.TrimSpace(scanID)
	if scanID == "" {
		return errors.New("redisqueue: scanID is required")
	}
	if len(scanID) > maxScanIDLen {
		return fmt.Errorf("redisqueue: scanID exceeds %d characters", maxScanIDLen)
	}
	if c == nil || c.rdb == nil {
		return redis.ErrClosed
	}
	if delay < 0 {
		delay = 0
	}

	due := time.Now().Add(delay).UnixMilli()
	if err := c.rdb.ZAdd(ctx, keyScheduled, redis.Z{
		Score:  float64(due),
		Member: scanID,
	}).Err(); err != nil {
		return fmt.Errorf("redisqueue: enqueue retry: %w", err)
	}
	return nil
}

// PromoteDue moves every due retry onto the pending queue and returns how many
// were promoted.
//
// Each member is removed from the scheduled set and pushed with one script, so
// a crash cannot drop a member between the two operations and leave it
// scheduled forever — invisible to every future tick.
func (c *Client) PromoteDue(ctx context.Context, limit int) (int, error) {
	if c == nil || c.rdb == nil {
		return 0, redis.ErrClosed
	}
	if limit <= 0 {
		limit = 100
	}

	// Everything happens inside the script, including the read. Doing the
	// ZRANGEBYSCORE in Go first would make the read and the move two round
	// trips, and a failure between them would leave members decided-for but
	// never moved.
	promoted, err := promoteDueScript.Run(ctx, c.rdb,
		[]string{keyScheduled, keyQueue}, time.Now().UnixMilli(), limit).Int()
	if err != nil {
		return 0, fmt.Errorf("redisqueue: promote due: %w", err)
	}
	return promoted, nil
}

// promoteDueScript moves due members from the scheduled set to the queue.
//
// KEYS[1] scheduled set, KEYS[2] pending queue.
// ARGV[1] the current Unix time in milliseconds.
// ARGV[2] the maximum number of members to move in one call.
//
// The ZREM-before-RPUSH order is what makes a crash safe. A member removed from
// the scheduled set and lost before it reached the queue would be invisible to
// every future tick — a permanently stuck job. Pushing first and removing
// after would invert the risk into a duplicate, and a duplicate job is a no-op:
// the scan is either already finished or still resumable. Duplicates are
// therefore the cheap failure and losses are the expensive one.
var promoteDueScript = redis.NewScript(`
local due = redis.call('ZRANGEBYSCORE', KEYS[1], '-inf', ARGV[1], 'LIMIT', 0, tonumber(ARGV[2]))
if #due == 0 then return 0 end
local moved = 0
for _, member in ipairs(due) do
  if redis.call('ZREM', KEYS[1], member) == 1 then
    redis.call('RPUSH', KEYS[2], member)
    moved = moved + 1
  end
end
return moved
`)

// Claim blocks until a job is available or the timeout elapses.
//
// It returns ErrNoJob on timeout, which is a normal idle condition and not an
// error worth logging loudly. A redis.Nil from the blocking pop is translated
// into it so callers have one thing to branch on.
//
// At-least-once: a message claimed here may be delivered again if the worker
// crashes, which is why claiming a terminal scan is a no-op rather than an
// error.
func (c *Client) Claim(ctx context.Context, block time.Duration) (Job, error) {
	if c == nil || c.rdb == nil {
		return Job{}, redis.ErrClosed
	}

	derived := false

	var (
		timeout time.Duration
		seconds float64
	)
	if block > 0 {
		timeout = block
		seconds = block.Seconds()
	}

	// go-redis applies a context *deadline* to a socket read but does not act
	// on plain cancellation while a read is already in flight. A worker blocked
	// in BLPOP would therefore ignore SIGTERM until its block elapsed.
	//
	// Deriving a deadline from the block bounds that wait explicitly, so
	// shutdown latency is the block plus a small grace rather than "however
	// long the caller asked for". The derived deadline maps to ErrNoJob rather
	// than an error: the block simply ran out, which is the idle condition.
	if timeout > 0 {
		if _, hasDeadline := ctx.Deadline(); !hasDeadline {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, timeout+claimGrace)
			defer cancel()
			derived = true
		}
	}

	// BLPOP, not BRPOP.
	//
	// Both pop one scan id, but BLPOP takes from the head and BRPOP from the
	// tail, while producers RPUSH to the tail. BRPOP would therefore reverse
	// the queue: a burst of submissions would be analysed last-in-first-out, in
	// the opposite order to the one they arrived.
	//
	// BLPOP head + RPUSH tail is the FIFO pairing ADR 0013 specifies.
	var args []any
	if timeout > 0 {
		// Redis 6.0+ accepts a fractional timeout, which is what lets a
		// sub-second block actually block.
		//
		// Rounding to whole seconds would be wrong in the worst possible way:
		// a sub-second block rounds to "0", and Redis reads "0" as "block
		// forever" rather than "do not block". The consumer would then hang
		// until the read timeout instead of polling on its schedule.
		args = []any{keyQueue, strconv.FormatFloat(seconds, 'f', 3, 64)}
	} else {
		// No timeout argument at all is the non-blocking form of BLPOP.
		args = []any{keyQueue}
	}

	result, err := c.rdb.Do(ctx, append([]any{"BLPOP"}, args...)...).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return Job{}, ErrNoJob
		}
		// The derived deadline firing means the block elapsed, which is an
		// idle result rather than a failure.
		if derived && errors.Is(err, context.DeadlineExceeded) {
			return Job{}, ErrNoJob
		}
		return Job{}, fmt.Errorf("redisqueue: claim: %w", err)
	}

	values, ok := result.([]any)
	if !ok || len(values) != 2 {
		return Job{}, ErrJobInvalid
	}
	scanID, ok := values[1].(string)
	if !ok {
		return Job{}, ErrJobInvalid
	}

	job := Job{ScanID: strings.TrimSpace(scanID)}
	if !job.Valid() || len(job.ScanID) > maxScanIDLen {
		return Job{}, ErrJobInvalid
	}
	return job, nil
}

// ErrNoJob is returned by Claim when the timeout elapsed with nothing to do.
var ErrNoJob = errors.New("redisqueue: no job available")

// Depth reports how many scans are waiting to be claimed.
//
// It is a diagnostic, not a control: it is read for logging and cannot be used
// to make a correctness decision, because the value can change immediately
// after it is read.
func (c *Client) Depth(ctx context.Context) (int64, error) {
	if c == nil || c.rdb == nil {
		return 0, redis.ErrClosed
	}
	n, err := c.rdb.LLen(ctx, keyQueue).Result()
	if err != nil {
		return 0, fmt.Errorf("redisqueue: depth: %w", err)
	}
	return n, nil
}

// ScheduledDepth reports how many retries are waiting for their due time.
func (c *Client) ScheduledDepth(ctx context.Context) (int64, error) {
	if c == nil || c.rdb == nil {
		return 0, redis.ErrClosed
	}
	n, err := c.rdb.ZCard(ctx, keyScheduled).Result()
	if err != nil {
		return 0, fmt.Errorf("redisqueue: scheduled depth: %w", err)
	}
	return n, nil
}
