package g3lib

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/url"
	"os"
	"runtime/debug"
	"slices"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"

	log "golismero.com/g3log"
)

const MQTT_URL = "MQTT_URL"

const MQTT_QOS = 2
const MQTT_PERSIST = false
const MQTT_QUIESCE = 15
const MQTT_MAX_ATTEMPTS = 3
var   MQTT_BACKOFFS     = []time.Duration{1 * time.Second, 3 * time.Second}

const MQTT_CONNECT_TIMEOUT      = 15
const MQTT_CONNECT_MAX_ATTEMPTS = 5
var   MQTT_CONNECT_BACKOFFS     = []time.Duration{
	2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second,
}

const G3SCANNERSUBTOPIC     = "$share/g3scanner/scan"
const G3SCANNERPUBTOPIC     = "scan"
const G3SCANNERSTOPTOPIC    = "stop"
const G3SCANSTATUSTOPIC     = "status"
const G3WORKERSUBTOPIC      = "$share/g3worker/tool/"
const G3WORKERPUBTOPIC      = "tool/"
const G3CANCELTOPIC         = "cancel"
const G3RESPONSETOPIC       = "response/"
const G3REPORTSUBTOPIC      = "$share/g3worker/report/"
const G3REPORTPUBTOPIC      = "report/"
const G3DISPATCHTOPIC       = "dispatch"

type G3MESSAGETYPE string
const (
	MSG_TASK     G3MESSAGETYPE = "task"
	MSG_SCAN     G3MESSAGETYPE = "scan"
	MSG_STATUS   G3MESSAGETYPE = "status"
	MSG_CANCEL   G3MESSAGETYPE = "cancel"
	MSG_STOP     G3MESSAGETYPE = "stop"
	MSG_RESPONSE G3MESSAGETYPE = "response"
	MSG_REPORT   G3MESSAGETYPE = "report"
	MSG_DISPATCH G3MESSAGETYPE = "dispatch"
)
var VALID_MSG = [...]G3MESSAGETYPE{MSG_TASK, MSG_SCAN, MSG_STATUS, MSG_CANCEL, MSG_RESPONSE, MSG_REPORT, MSG_DISPATCH}

type G3SCANSTATUS string
const (
	STATUS_WAITING  G3SCANSTATUS = "WAITING"
	STATUS_RUNNING  G3SCANSTATUS = "RUNNING"
	STATUS_ERROR    G3SCANSTATUS = "ERROR"
	STATUS_CANCELED G3SCANSTATUS = "CANCELED"
	STATUS_FINISHED G3SCANSTATUS = "FINISHED"
	STATUS_UNKNOWN  G3SCANSTATUS = "UNKNOWN"
	STATUS_MANAGED  G3SCANSTATUS = "MANAGED"  // Externally-managed scan; g3scanner never emits or overwrites this.
)
var VALID_STATUS = [...]G3SCANSTATUS{STATUS_WAITING, STATUS_RUNNING, STATUS_ERROR, STATUS_CANCELED, STATUS_FINISHED, STATUS_UNKNOWN, STATUS_MANAGED}

const NIL_TASKID = "00000000-0000-0000-0000-000000000000"

type G3Message struct {
	MessageType G3MESSAGETYPE   `json:"msgtype"     validate:"required"`
	SenderID string             `json:"senderid"    validate:"required"`
	ScanID string               `json:"scanid"      validate:"required,uuid4"`
}

type G3TaskMessage struct {
	G3Message
	TaskID string               `json:"taskid"      validate:"required,uuid4"`
}

type G3Task struct {            // MessageType: MSG_TASK
	G3TaskMessage
	DataID string               `json:"dataid"      validate:"required,mongodb"`
	Tool string                 `json:"tool"        validate:"required"`
	Index int                   `json:"index"       validate:"gte=0"`
}

type G3ReportTask struct {      // MessageType: MSG_REPORT
	G3TaskMessage
	Tool   string `json:"tool"   validate:"required"`
	Preset string `json:"preset"`                      // resolved name; "" only when plugin has reporter:{} with no commands
}

type G3Dispatch struct {        // MessageType: MSG_DISPATCH
	G3TaskMessage               // embeds ScanID + TaskID; TaskID is required,uuid4
	Kind   string `json:"kind"   validate:"required,oneof=tool report"`
	Tool   string `json:"tool"   validate:"required"`
	// kind=tool fields:
	DataID string `json:"dataid,omitempty" validate:"omitempty,mongodb"`
	Index  int    `json:"index,omitempty"  validate:"gte=0"`
	// kind=report fields:
	Preset string `json:"preset,omitempty"`
}

type G3Response struct {        // MessageType: MSG_RESPONSE
	G3TaskMessage
	Response []string           `json:"response"    validate:"dive,mongodb"`
}

type G3CancelTask struct {      // MessageType: MSG_CANCEL
	G3Message
	Tasks []string              `json:"tasks"       validate:"required"`
	Handled bool                `json:"handled"`
}

type G3Scan struct {            // MessageType: MSG_SCAN
	G3Message
	Mode string                 `json:"mode"        validate:"required"`
	Pipelines [][]string        `json:"pipelines"`  // can be empty
	// Report mirrors ParsedScript.Report. Non-nil means the script declared a
	// report directive. Tool == "" signals the built-in MarkdownReporter
	// (run in-process from g3scanner); Tool != "" signals a plugin reporter
	// (dispatched to a worker via dispatchTask).
	Report *ParsedReport        `json:"report,omitempty"`
}

type G3ScanStatus struct {      // MessageType: MSG_STATUS
	G3Message
	Status G3SCANSTATUS         `json:"status"`
	// Progress is intentionally a pointer so senders that don't know
	// the current progress (e.g. SendScanStopped, SendScanFailed) can
	// leave it nil. With omitempty, nil is omitted from the wire JSON;
	// receivers (DB updater, TUI) interpret nil as "no change to
	// progress" — never as zero.
	Progress *int               `json:"progress,omitempty"`
	Message string       	    `json:"message"`
}

type G3ScanStop struct {        // MessageType: MSG_STOP
	G3Message
}

// G3ScanRemoved is the WS notification payload pushed on the
// "scanremoved" channel when a scan is deleted server-side. It carries
// only the scan id — any further state is by definition gone — and
// lets subscribed clients drop the entry immediately rather than wait
// for the next periodic /scan/progress snapshot to reveal the absence.
type G3ScanRemoved struct {
	ScanID string               `json:"scanid"      validate:"required,uuid4"`
}

type MessageQueueClient mqtt.Client

type TaskHandler func(MessageQueueClient, G3Task)
type CancelHandler func(MessageQueueClient, G3CancelTask)
type ResponseHandler func(MessageQueueClient, G3Response)
type NewScanHandler func(MessageQueueClient, G3Scan)
type ScanStatusHandler func(MessageQueueClient, G3ScanStatus)
type ScanStopHandler func(MessageQueueClient, G3ScanStop)
type ReportTaskHandler func(MessageQueueClient, G3ReportTask)
type DispatchHandler func(MessageQueueClient, G3Dispatch)

// Connect to the MQTT broker.
func ConnectToBroker(clientid string) (MessageQueueClient, error) {

	// If no client ID was given, make one up.
	if clientid == "" {
		clientid = uuid.NewString()
	}

	// Parse the MQTT connection URL.
	uristr := os.Getenv(MQTT_URL)
	if uristr == "" {
		return nil, errors.New("missing environment variable: " + MQTT_URL)
	}
	uri, err := url.Parse(uristr)
	if err != nil {
		return nil, err
	}

	// MQTT connection options.
	opts := mqtt.NewClientOptions()
	opts.AddBroker(fmt.Sprintf("tcp://%s", uri.Host))
	opts.SetUsername(uri.User.Username())
	password, _ := uri.User.Password()
	opts.SetPassword(password)
	opts.SetClientID(clientid)
	opts.SetOrderMatters(false)		// needed to send replies to our messages without deadlocking
	opts.SetCleanSession(false)		// we want past messages when reconnecting

	// Connect to the broker, with bounded retry for startup-ordering races
	// (e.g. mosquitto not yet accepting connections when the worker boots).
	client := mqtt.NewClient(opts)
	var lastErr error
	for attempt := 0; attempt < MQTT_CONNECT_MAX_ATTEMPTS; attempt++ {
		if attempt > 0 {
			backoff := MQTT_CONNECT_BACKOFFS[attempt-1]
			log.Debugf("Retrying connect to broker (attempt %d/%d) after %s",
				attempt+1, MQTT_CONNECT_MAX_ATTEMPTS, backoff)
			time.Sleep(backoff)
		}
		token := client.Connect()
		if !token.WaitTimeout(MQTT_CONNECT_TIMEOUT * time.Second) {
			lastErr = fmt.Errorf("connect to broker timed out after %ds", MQTT_CONNECT_TIMEOUT)
			continue
		}
		if err := token.Error(); err != nil {
			lastErr = err
			continue
		}
		if attempt > 0 {
			log.Debugf("Connect to broker succeeded on attempt %d", attempt+1)
		}
		return client, nil
	}
	return nil, fmt.Errorf("connect to broker failed after %d attempts: %w",
		MQTT_CONNECT_MAX_ATTEMPTS, lastErr)
}

// Defer this call right after calling ConnectToBroker().
func DisconnectFromBroker(client MessageQueueClient) {
	if client != nil {
		client.Disconnect(MQTT_QUIESCE * 1000);
	}
}

// Get the client ID for this connected MQTT client.
func GetClientID(client MessageQueueClient) string {
	opts := client.OptionsReader()
	clientid := opts.ClientID()
	return clientid
}

// Send a new scan message to the broker.
func SendNewScan(client MessageQueueClient, scanid, mode string, pipelines [][]string, report *ParsedReport) error {
	msg := G3Scan{}
	msg.MessageType = MSG_SCAN
	msg.SenderID = GetClientID(client)
	msg.ScanID = scanid
	msg.Mode = mode
	msg.Pipelines = pipelines
	msg.Report = report
	err := validator.New().Struct(msg)
	if err != nil {
		return err
	}
	return SendMQPayload(client, G3SCANNERPUBTOPIC, msg)
}

// Send a scan stop message to the broker.
func SendScanStop(client MessageQueueClient, scanid string) error {
	msg := G3ScanStop{}
	msg.MessageType = MSG_STOP
	msg.SenderID = GetClientID(client)
	msg.ScanID = scanid
	err := validator.New().Struct(msg)
	if err != nil {
		return err
	}
	return SendMQPayload(client, G3SCANNERSTOPTOPIC, msg)
}

// Send a running scan progress message to the broker.
func SendScanProgress(client MessageQueueClient, scanid string, currentScanStep, totalScanSteps int) error {
	if totalScanSteps <= 0 {
		return errors.New("totalScanSteps must be positive")
	}
	progress := (currentScanStep * 100) / totalScanSteps
	if progress < 0 {
		progress = 0
	} else if progress > 100 {
		progress = 100
	}
	msg := G3ScanStatus{}
	msg.MessageType = MSG_STATUS
	msg.SenderID = GetClientID(client)
	msg.ScanID = scanid
	msg.Status = STATUS_RUNNING
	msg.Progress = &progress
	if progress == 100 {
		msg.Message = "Analyzing results..."
	} else {
		msg.Message = fmt.Sprintf("Running... (%d/%d steps complete)", currentScanStep, totalScanSteps)
	}
	err := validator.New().Struct(msg)
	if err != nil {
		return err
	}
	return SendMQPayload(client, G3SCANSTATUSTOPIC, msg)
}

// Send a scan canceled message to the broker.
func SendScanStopped(client MessageQueueClient, scanid string) error {
	msg := G3ScanStatus{}
	msg.MessageType = MSG_STATUS
	msg.SenderID = GetClientID(client)
	msg.ScanID = scanid
	msg.Status = STATUS_CANCELED
	msg.Message = "Scan was canceled by the user."
	err := validator.New().Struct(msg)
	if err != nil {
		return err
	}
	return SendMQPayload(client, G3SCANSTATUSTOPIC, msg)
}

// Send a scan failed message to the broker.
func SendScanFailed(client MessageQueueClient, scanid, errorMessage string) error {
	if errorMessage == "" {
		errorMessage = "Scan failed, check logs for errors."
	}
	msg := G3ScanStatus{}
	msg.MessageType = MSG_STATUS
	msg.SenderID = GetClientID(client)
	msg.ScanID = scanid
	msg.Status = STATUS_ERROR
	msg.Message = errorMessage
	err := validator.New().Struct(msg)
	if err != nil {
		return err
	}
	return SendMQPayload(client, G3SCANSTATUSTOPIC, msg)
}

// Send a scan completed message to the broker.
func SendScanCompleted(client MessageQueueClient, scanid string) error {
	hundred := 100
	msg := G3ScanStatus{}
	msg.MessageType = MSG_STATUS
	msg.SenderID = GetClientID(client)
	msg.ScanID = scanid
	msg.Status = STATUS_FINISHED
	msg.Progress = &hundred
	msg.Message = "Scan complete."
	err := validator.New().Struct(msg)
	if err != nil {
		return err
	}
	return SendMQPayload(client, G3SCANSTATUSTOPIC, msg)
}

// SendTask publishes a tool task to a worker via the tool/<name> topic.
// The caller is responsible for generating taskid (e.g. via uuid.NewString())
// and supplying dataid (the MongoDB id of the G3Data the worker will operate on).
// Generating the task ID outside this function lets out-of-band state (Redis,
// SQL logs) be set up before the message is published — otherwise a worker
// might pick up the task and race ahead of the scanner's own bookkeeping.
func SendTask(client MessageQueueClient, scanid, taskid, tool string, index int, dataid string) error {
	msg := G3Task{}
	msg.MessageType = MSG_TASK
	msg.SenderID = GetClientID(client)
	msg.TaskID = taskid
	msg.ScanID = scanid
	msg.Tool = tool
	msg.Index = index
	msg.DataID = dataid
	err := validator.New().Struct(msg)
	if err != nil {
		return err
	}
	topic := G3WORKERPUBTOPIC + tool
	return SendMQPayload(client, topic, msg)
}

// SendDispatch publishes a G3Dispatch to the scanner's dispatch topic.
// The caller (g3api) is responsible for generating the TaskID, validating
// the request shape against plugin metadata, and populating kind-specific
// fields. The scanner re-validates kind-specific fields on receipt and
// publishes to the appropriate worker topic.
func SendDispatch(client MessageQueueClient, msg G3Dispatch) error {
	msg.MessageType = MSG_DISPATCH
	msg.SenderID = GetClientID(client)
	if err := validator.New().Struct(msg); err != nil {
		return err
	}
	return SendMQPayload(client, G3DISPATCHTOPIC, msg)
}

// Send a report task to the MQTT broker. Mirrors SendTask but uses the
// report/<tool> topic family and a G3ReportTask payload (no DataID/Index).
// The caller is responsible for generating the task ID and setting up
// out-of-band state (Redis, SQL logs) before publishing — same race
// concern as SendTask.
func SendReportTask(client MessageQueueClient, scanid, taskid, tool, preset string) error {
	msg := G3ReportTask{}
	msg.MessageType = MSG_REPORT
	msg.SenderID = GetClientID(client)
	msg.TaskID = taskid
	msg.ScanID = scanid
	msg.Tool = tool
	msg.Preset = preset
	err := validator.New().Struct(msg)
	if err != nil {
		return err
	}
	topic := G3REPORTPUBTOPIC + tool
	return SendMQPayload(client, topic, msg)
}

// Send a task cancellation message to the broker.
func SendTaskCancel(client MessageQueueClient, scanid string, tasks []string) error {
	return sendTaskCancelInternal(client, scanid, tasks, false)
}

// Send a task cancellation successful message to the broker.
func SendTaskCancelHandled(client MessageQueueClient, scanid string, tasks []string) error {
	return sendTaskCancelInternal(client, scanid, tasks, true)
}

func sendTaskCancelInternal(client MessageQueueClient, scanid string, tasks []string, handled bool) error {
	if len(tasks) == 0 {
		return nil
	}
	msg := G3CancelTask{}
	msg.MessageType = MSG_CANCEL
	msg.SenderID = GetClientID(client)
	msg.Tasks = tasks
	msg.ScanID = scanid
	msg.Handled = handled
	err := validator.New().Struct(msg)
	if err != nil {
		return err
	}
	return SendMQPayload(client, G3CANCELTOPIC, msg)
}

// Send an empty task response to the broker.
func SendEmptyResponse(client MessageQueueClient, scanid string, taskid string) error {
	msg := G3Response{}
	msg.MessageType = MSG_RESPONSE
	msg.SenderID = GetClientID(client)
	msg.TaskID = taskid
	msg.ScanID = scanid
	err := validator.New().Struct(msg)
	if err != nil {
		return err
	}
	topic := G3RESPONSETOPIC + msg.ScanID
	return SendMQPayload(client, topic, msg)
}

// Send a task response to the MQTT broker.
func SendResponse(client MessageQueueClient, task G3Task, outputArray []G3Data) (string, error) {
	var err error
	msg := G3Response{}
	msg.MessageType = MSG_RESPONSE
	msg.SenderID = GetClientID(client)
	msg.TaskID = task.TaskID
	msg.ScanID = task.ScanID
	for _, data := range outputArray {
		if _, ok := data["_id"]; !ok {
			// TODO save to database automatically?
			err = errors.New("data missing _id, save to database first")
			continue
		}
		msg.Response = append(msg.Response, data["_id"].(string))
	}
	if len(msg.Response) == 0 {
		return "", err
	}
	err = validator.New().Struct(msg)
	if err != nil {
		return "", err
	}
	topic := G3RESPONSETOPIC + msg.ScanID
	return msg.TaskID, SendMQPayload(client, topic, msg)
}

// Send an arbitrary JSON payload to any topic on the MQTT broker.
// Normally just called internally.
func SendMQPayload(client MessageQueueClient, topic string, msg any) error {
	log.Debug("Publishing to: " + topic)
	msgtext, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	var lastErr error
	for attempt := 0; attempt < MQTT_MAX_ATTEMPTS; attempt++ {
		if attempt > 0 {
			backoff := MQTT_BACKOFFS[attempt-1]
			log.Debugf("Retrying publish to %q (attempt %d/%d) after %s",
				topic, attempt+1, MQTT_MAX_ATTEMPTS, backoff)
			time.Sleep(backoff)
		}
		token := client.Publish(topic, MQTT_QOS, MQTT_PERSIST, msgtext)
		if !token.WaitTimeout(MQTT_QUIESCE * time.Second) {
			lastErr = fmt.Errorf("publish to %q timed out after %ds", topic, MQTT_QUIESCE)
			continue
		}
		if err := token.Error(); err != nil {
			if log.LogLevel == "DEBUG" {
				debug.PrintStack()
			}
			lastErr = err
			continue
		}
		if attempt > 0 {
			log.Debugf("Publish to %q succeeded on attempt %d", topic, attempt+1)
		}
		return nil
	}
	return fmt.Errorf("publish to %q failed after %d attempts: %w",
		topic, MQTT_MAX_ATTEMPTS, lastErr)
}

// Subscribe to a series of tool topics.
func SubscribeAsWorker(client MessageQueueClient, tools []string, callback TaskHandler) []string {

	// Build a map of topic strings and qos bytes.
	filters := map[string]byte{}
	for _, tool := range tools {
		log.Debug("Subscribing to: " + G3WORKERSUBTOPIC + tool)
		filters[G3WORKERSUBTOPIC + tool] = byte(MQTT_QOS)
	}

	// Subscribe to all of the topics.
	client.SubscribeMultiple(filters, func(client mqtt.Client, msg mqtt.Message) {

		// Decode the JSON payload.
		var task G3Task
		err := json.Unmarshal(msg.Payload(), &task)
		if err != nil {
			log.Error("Error parsing JSON payload from MQTT message: " + err.Error())
			return
		}

		// Validate the task object.
		err = validator.New().Struct(task)
		if err != nil || task.MessageType != MSG_TASK {
			log.Error("Malformed task object received: " + err.Error())
			return
		}

		// Call the task handler synchronously.
		// This prevents receiving more tasks while running this one.
		callback(client, task)
	})

	// Return the list of topics being subscribed to.
	return slices.Sorted(maps.Keys(filters))
}

// Subscribe to a series of reporter-topic shares — parallel to SubscribeAsWorker
// but routed through the report/<tool> topic family with G3ReportTask payloads.
func SubscribeAsReporter(client MessageQueueClient, tools []string, callback ReportTaskHandler) []string {

	// Build a map of topic strings and qos bytes.
	filters := map[string]byte{}
	for _, tool := range tools {
		log.Debug("Subscribing to: " + G3REPORTSUBTOPIC + tool)
		filters[G3REPORTSUBTOPIC + tool] = byte(MQTT_QOS)
	}

	// Subscribe to all of the topics.
	client.SubscribeMultiple(filters, func(client mqtt.Client, msg mqtt.Message) {

		// Decode the JSON payload.
		var task G3ReportTask
		err := json.Unmarshal(msg.Payload(), &task)
		if err != nil {
			log.Error("Error parsing JSON payload from MQTT message: " + err.Error())
			return
		}

		// Validate.
		err = validator.New().Struct(task)
		if err != nil || task.MessageType != MSG_REPORT {
			if err != nil {
				log.Error("Malformed report task received: " + err.Error())
			} else {
				log.Error("Malformed report task received: wrong MessageType")
			}
			return
		}

		// Call the report-task handler synchronously.
		// This prevents receiving more tasks while running this one.
		callback(client, task)
	})

	// Return the list of topics being subscribed to.
	return slices.Sorted(maps.Keys(filters))
}

// Subscribe to the cancellation topic for workers.
func SubscribeToCancel(client mqtt.Client, callback CancelHandler) string {
	topic := G3CANCELTOPIC
	log.Debug("Subscribing to: " + topic)
	client.Subscribe(topic, MQTT_QOS, func(client mqtt.Client, msg mqtt.Message) {
		var payload G3CancelTask
		err := json.Unmarshal(msg.Payload(), &payload)
		if err != nil {
			log.Error("Error parsing JSON payload from MQTT message: " + err.Error())
		} else {
			err = validator.New().Struct(payload)
			if err != nil || payload.MessageType != MSG_CANCEL {
				log.Error("Malformed task object received: " + err.Error())
			} else {
				callback(client, payload)
			}
		}
	})
	return topic
}

// Subscribe to the scanner topic to receive scan requests.
func SubscribeAsScanner(client MessageQueueClient, callback NewScanHandler) string {
	topic := G3SCANNERSUBTOPIC
	log.Debug("Subscribing to: " + topic)
	client.Subscribe(topic, MQTT_QOS, func(client mqtt.Client, msg mqtt.Message) {
		var payload G3Scan
		err := json.Unmarshal(msg.Payload(), &payload)
		if err != nil {
			log.Error("Error parsing JSON payload from MQTT message: " + err.Error())
		} else {
			err = validator.New().Struct(payload)
			if err != nil || payload.MessageType != MSG_SCAN {
				log.Error("Malformed task object received: " + err.Error())
			} else {
				callback(client, payload)
			}
		}
	})
	return topic
}

// SubscribeAsDispatcher registers the scanner as a dispatch consumer.
// Unlike SubscribeAsScanner (which spawns a per-scan ScanRunner goroutine
// to handle MSG_SCAN), this handler runs at the scanner-process level and
// handles dispatches for any scan — including ones with no active ScanRunner
// (e.g. dispatching a reporter for a terminated scan).
func SubscribeAsDispatcher(client MessageQueueClient, callback DispatchHandler) string {
	log.Debug("Subscribing to: " + G3DISPATCHTOPIC)
	client.Subscribe(G3DISPATCHTOPIC, MQTT_QOS, func(client mqtt.Client, msg mqtt.Message) {

		// Decode the JSON payload.
		var dispatch G3Dispatch
		err := json.Unmarshal(msg.Payload(), &dispatch)
		if err != nil {
			log.Error("Error parsing JSON payload from MQTT message: " + err.Error())
			return
		}

		// Validate.
		err = validator.New().Struct(dispatch)
		if err != nil || dispatch.MessageType != MSG_DISPATCH {
			if err != nil {
				log.Error("Malformed dispatch object received: " + err.Error())
			} else {
				log.Error("Malformed dispatch object received: wrong MessageType")
			}
			return
		}

		// Run the dispatch handler synchronously. The work is light (one
		// Redis write, one SQL write, one MQTT publish) so spawning a
		// goroutine per message would be premature.
		callback(client, dispatch)
	})
	return G3DISPATCHTOPIC
}

// Subscribe to the scanner stop topic to receive scan stop requests.
func SubscribeToStop(client MessageQueueClient, callback ScanStopHandler) string {
	topic := G3SCANNERSTOPTOPIC
	log.Debug("Subscribing to: " + topic)
	client.Subscribe(topic, MQTT_QOS, func(client mqtt.Client, msg mqtt.Message) {
		var payload G3ScanStop
		err := json.Unmarshal(msg.Payload(), &payload)
		if err != nil {
			log.Error("Error parsing JSON payload from MQTT message: " + err.Error())
		} else {
			err = validator.New().Struct(payload)
			if err != nil || payload.MessageType != MSG_STOP {
				log.Error("Malformed task object received: " + err.Error())
			} else {
				callback(client, payload)
			}
		}
	})
	return topic
}

// Subscribe to the response topic for a scan.
func SubscribeToResponses(client mqtt.Client, scanid string, callback ResponseHandler) string {
	topic := G3RESPONSETOPIC + scanid
	log.Debug("Subscribing to: " + topic)
	client.Subscribe(topic, MQTT_QOS, func(client mqtt.Client, msg mqtt.Message) {
		var payload G3Response
		err := json.Unmarshal(msg.Payload(), &payload)
		if err != nil {
			log.Error("Error parsing JSON payload from MQTT message: " + err.Error())
		} else {
			err = validator.New().Struct(payload)
			if err != nil || payload.MessageType != MSG_RESPONSE {
				log.Error("Malformed task object received: " + err.Error())
			} else {
				go callback(client, payload)
			}
		}
	})
	return topic
}

// Subscribe to the scanner response topic to receive scan status updates.
func SubscribeAsAPI(client MessageQueueClient, callback ScanStatusHandler) string {
	topic := G3SCANSTATUSTOPIC
	log.Debug("Subscribing to: " + topic)
	client.Subscribe(topic, MQTT_QOS, func(client mqtt.Client, msg mqtt.Message) {
		var payload G3ScanStatus
		err := json.Unmarshal(msg.Payload(), &payload)
		if err != nil {
			log.Error("Error parsing JSON payload from MQTT message: " + err.Error())
		} else {
			err = validator.New().Struct(payload)
			if err != nil || payload.MessageType != MSG_STATUS {
				log.Error("Malformed task object received: " + err.Error())
			} else {
				callback(client, payload)
			}
		}
	})
	return topic
}

// Defer this call after SubscribeAsWorker(), SubscribeAsScanner(), SubscribeToCancel() and SubscribeAsScanner().
func Unsubscribe(client MessageQueueClient, topics ...string) {
	for _, topic := range topics {
		log.Debug("Unsubscribing from: " + topic)
	}
	token := client.Unsubscribe(topics...)
	for !token.WaitTimeout(MQTT_QUIESCE * time.Second) {}
}
