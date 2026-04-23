package g3lib

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/redis/go-redis/v9"
)

const REDIS_HOST     = "REDIS_HOST"
const REDIS_PORT     = "REDIS_PORT"
const REDIS_PASSWORD = "REDIS_PASSWORD"

type KeyValueStoreClient struct {
	c *redis.Client
}

type G3Report struct {
	ScanID string   `json:"scanid"      validate:"required,uuid"`   // ID for the Golismero scan.
	Issues []string `json:"issues"      validate:"dive,mongodb"`    // Issues reported by Golismero plugins.
	//Title string `json:"name"        validate:"required"`           // Report title.
	//Author string `json:"author"      validate:"required"`          // Report author.
	//Client string `json:"client"      validate:"required"`          // Client the report will be delivered to.
}

// Connect to the Redis server.
func ConnectToKeyValueStore() (KeyValueStoreClient, error) {
	var rdb_client KeyValueStoreClient

	host := os.Getenv(REDIS_HOST)
	if host == "" {
		return rdb_client, errors.New("missing environment variable: " + REDIS_HOST)
	}

	port := os.Getenv(REDIS_PORT)
	if port == "" {
		return rdb_client, errors.New("missing environment variable: " + REDIS_PORT)
	}

	password := os.Getenv(REDIS_PASSWORD)
	if password == "" {
		return rdb_client, errors.New("missing environment variable: " + REDIS_PASSWORD)
	}

	rdb := redis.NewClient(&redis.Options{
		Network:  "tcp",
		Addr:     fmt.Sprintf("%s:%s", host, port),
		Password: password,
		DB:       0,
	})

	err := rdb.Ping(context.Background()).Err()

	rdb_client.c = rdb
	return rdb_client, err
}

// Defer this call after ConnectToKeyValueStore().
func DisconnectFromKeyValueStore(rdb KeyValueStoreClient) error {
	if rdb.c == nil {
		return nil
	}
	err := rdb.c.Close()
	rdb.c = nil
	return err
}

// Load the report information object from Redis.
func LoadReportInfo(rdb KeyValueStoreClient, scanid string) (G3Report, error) {
	var report G3Report
    jsonStr, err := rdb.c.Get(context.Background(), "g3report:" + scanid).Result()
	if err != nil {
		return report, err
	}
	jsonBytes := []byte(jsonStr)
	err = json.Unmarshal(jsonBytes, &report)
	return report, err
}

// Save the report information object into Redis.
func SaveReportInfo(rdb KeyValueStoreClient, info G3Report) error {
	jsonBytes, err := json.Marshal(info)
	if err != nil {
		return err
	}
	return rdb.c.Set(context.Background(), "g3report:" + info.ScanID, string(jsonBytes), 0).Err()
}

// Delete the report information object from Redis.
func DeleteReportInfo(rdb KeyValueStoreClient, scanid string) error {
	return rdb.c.Del(context.Background(), "g3report:" + scanid).Err()
}

///////////////////////////////////////////////////////////////////////////////////////////////////
// Live task state — ephemeral per-scan tracking of dispatched/running/completed tasks.
//
// Shape:
//   - Set  g3:scan:<scanid>:tasks              members = task IDs for the scan
//   - Hash g3:scan:<scanid>:task:<taskid>      fields: tool, dispatch_ts, worker, start_ts,
//                                                      state, complete_ts, error_msg
//
// Writer ownership: scanner creates entries on dispatch and closes them on response/cancel;
// worker stamps its ID and start_ts when it accepts the task. Both write to Redis independently;
// the operations are hash-field updates so they don't race meaningfully.
//
// Lifecycle: keys live while the scan is running. Scanner deletes the whole keyset when the
// scan reaches a terminal state (FINISHED/ERROR/CANCELED). The /scan/delete handler also calls
// DeleteTaskStates as a belt-and-braces cleanup.
///////////////////////////////////////////////////////////////////////////////////////////////////

// TaskState — one row in the live-task view. Mirrors the Redis hash fields.
type TaskState struct {
	TaskID     string `json:"taskid"`
	Tool       string `json:"tool,omitempty"`
	DispatchTS int64  `json:"dispatch_ts,omitempty"`
	Worker     string `json:"worker,omitempty"`
	StartTS    int64  `json:"start_ts,omitempty"`
	State      string `json:"state,omitempty"`        // RUNNING / DONE / ERROR / CANCELED
	CompleteTS int64  `json:"complete_ts,omitempty"`
	ErrorMsg   string `json:"error_msg,omitempty"`
}

func taskSetKey(scanid string) string          { return "g3:scan:" + scanid + ":tasks" }
func taskHashKey(scanid, taskid string) string { return "g3:scan:" + scanid + ":task:" + taskid }

// Task state machine:
//
//   DISPATCHED ──(worker accepts)──▶ RUNNING ──(worker completes)──▶ DONE / ERROR / CANCELED
//        │                             │
//        └──(scanner cancels)──▶ CANCELING ◀──(scanner cancels)──┘
//                                     │
//                          (worker wraps up)──▶ CANCELED
//
// Authority split:
//   - Scanner writes transition states that reflect *intent*: DISPATCHED (I asked), CANCELING (I'm asking you to stop).
//   - Worker writes outcome states that reflect *reality*: RUNNING, DONE, ERROR, CANCELED.
// This gives an honest live view (a stuck worker stays visibly CANCELING) and an observable
// wind-down duration (CANCELING → CANCELED span).

// Scanner calls this right after SendTask returns successfully.
func SetTaskDispatched(rdb KeyValueStoreClient, scanid, taskid, tool string, dispatchTS int64) error {
	ctx := context.Background()
	if err := rdb.c.SAdd(ctx, taskSetKey(scanid), taskid).Err(); err != nil {
		return err
	}
	return rdb.c.HSet(ctx, taskHashKey(scanid, taskid),
		"tool", tool,
		"dispatch_ts", dispatchTS,
		"state", "DISPATCHED",
	).Err()
}

// Worker calls this when it accepts a task (case 2 of CancelTracker.AddTaskIfNew).
// Transitions state DISPATCHED → RUNNING and stamps the worker identity.
func SetTaskRunning(rdb KeyValueStoreClient, scanid, taskid, workerid string, startTS int64) error {
	return rdb.c.HSet(context.Background(), taskHashKey(scanid, taskid),
		"worker", workerid,
		"start_ts", startTS,
		"state", "RUNNING",
	).Err()
}

// Scanner calls this on a stop request. State=CANCELING is guarded: we only transition from
// DISPATCHED or RUNNING. If a task already reached a terminal state (worker finished in the
// window between user hitting cancel and the cancel handler running), don't stomp it.
func SetTaskCancelling(rdb KeyValueStoreClient, scanid, taskid string) error {
	ctx := context.Background()
	current, err := rdb.c.HGet(ctx, taskHashKey(scanid, taskid), "state").Result()
	if err != nil && err != redis.Nil {
		return err
	}
	if current != "DISPATCHED" && current != "RUNNING" {
		return nil // already terminal or CANCELING — preserve
	}
	return rdb.c.HSet(ctx, taskHashKey(scanid, taskid), "state", "CANCELING").Err()
}

// Worker calls this when the task reaches a terminal state (DONE / ERROR / CANCELED).
// Worker is the sole writer of terminal states, so no guard is needed against stomping.
// errMsg is optional ("" to omit).
func SetTaskTerminal(rdb KeyValueStoreClient, scanid, taskid, state string, completeTS int64, errMsg string) error {
	fields := []any{"state", state, "complete_ts", completeTS}
	if errMsg != "" {
		fields = append(fields, "error_msg", errMsg)
	}
	return rdb.c.HSet(context.Background(), taskHashKey(scanid, taskid), fields...).Err()
}

// Load every task state for a scan. Returns an empty slice if the scan has no Redis state
// (either never running or already cleaned up after a terminal transition).
func GetTaskStates(rdb KeyValueStoreClient, scanid string) ([]TaskState, error) {
	ctx := context.Background()
	taskIDs, err := rdb.c.SMembers(ctx, taskSetKey(scanid)).Result()
	if err != nil {
		return nil, err
	}
	states := make([]TaskState, 0, len(taskIDs))
	for _, taskid := range taskIDs {
		fields, err := rdb.c.HGetAll(ctx, taskHashKey(scanid, taskid)).Result()
		if err != nil {
			return states, err
		}
		if len(fields) == 0 {
			continue // hash already deleted but set entry lingered
		}
		state := TaskState{TaskID: taskid}
		state.Tool = fields["tool"]
		state.Worker = fields["worker"]
		state.State = fields["state"]
		state.ErrorMsg = fields["error_msg"]
		if v, ok := fields["dispatch_ts"]; ok {
			fmt.Sscanf(v, "%d", &state.DispatchTS)
		}
		if v, ok := fields["start_ts"]; ok {
			fmt.Sscanf(v, "%d", &state.StartTS)
		}
		if v, ok := fields["complete_ts"]; ok {
			fmt.Sscanf(v, "%d", &state.CompleteTS)
		}
		states = append(states, state)
	}
	return states, nil
}

// Delete every Redis key for a scan's task state. Scanner calls this on terminal transition;
// /scan/delete calls it in the cleanup fanout. Safe on empty (no-op if nothing is there).
func DeleteTaskStates(rdb KeyValueStoreClient, scanid string) error {
	ctx := context.Background()
	taskIDs, err := rdb.c.SMembers(ctx, taskSetKey(scanid)).Result()
	if err != nil {
		return err
	}
	keys := make([]string, 0, len(taskIDs)+1)
	keys = append(keys, taskSetKey(scanid))
	for _, taskid := range taskIDs {
		keys = append(keys, taskHashKey(scanid, taskid))
	}
	if len(keys) == 0 {
		return nil
	}
	return rdb.c.Del(ctx, keys...).Err()
}
