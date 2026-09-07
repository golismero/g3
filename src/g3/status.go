package g3

var _STATUS_MANAGED    = "managed"
var _STATUS_WAITING    = "waiting"
var _STATUS_DISPATCHED = "dispatched"
var _STATUS_RUNNING    = "running"
var _STATUS_CANCELED   = "canceled"
var _STATUS_DONE       = "done"
var _STATUS_WARNING    = "warning"
var _STATUS_ERROR      = "error"

var STATUS_MANAGED = &_STATUS_MANAGED
var STATUS_WAITING = &_STATUS_WAITING
var STATUS_DISPATCHED = &_STATUS_DISPATCHED
var STATUS_RUNNING = &_STATUS_RUNNING
var STATUS_CANCELED = &_STATUS_CANCELED
var STATUS_DONE = &_STATUS_DONE
var STATUS_WARNING = &_STATUS_WARNING
var STATUS_ERROR = &_STATUS_ERROR

func IsStatusTerminal(status string) bool {
	switch status {
	case "canceled", "done", "warning", "error":
		return true
	default:
		return false
	}
}
