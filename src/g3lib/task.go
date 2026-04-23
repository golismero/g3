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

const G3SCANNERSUBTOPIC     = "$share/g3scanner/scan"
const G3SCANNERPUBTOPIC     = "scan"
const G3SCANNERSTOPTOPIC    = "stop"
const G3SCANSTATUSTOPIC     = "status"
const G3WORKERSUBTOPIC      = "$share/g3worker/tool/"
const G3WORKERPUBTOPIC      = "tool/"
const G3CANCELTOPIC         = "cancel"
const G3RESPONSETOPIC       = "response/"

type G3MESSAGETYPE string
const (
	MSG_TASK     G3MESSAGETYPE = "task"
	MSG_SCAN     G3MESSAGETYPE = "scan"
	MSG_STATUS   G3MESSAGETYPE = "status"
	MSG_CANCEL   G3MESSAGETYPE = "cancel"
	MSG_STOP     G3MESSAGETYPE = "stop"
	MSG_RESPONSE G3MESSAGETYPE = "response"
)
var VALID_MSG = [...]G3MESSAGETYPE{MSG_TASK, MSG_SCAN, MSG_STATUS, MSG_CANCEL, MSG_RESPONSE}

type G3SCANSTATUS string
const (
	STATUS_WAITING  G3SCANSTATUS = "WAITING"
	STATUS_RUNNING  G3SCANSTATUS = "RUNNING"
	STATUS_ERROR    G3SCANSTATUS = "ERROR"
	STATUS_CANCELED G3SCANSTATUS = "CANCELED"
	STATUS_FINISHED G3SCANSTATUS = "FINISHED"
)
var VALID_STATUS = [...]G3SCANSTATUS{STATUS_WAITING, STATUS_RUNNING, STATUS_ERROR, STATUS_CANCELED, STATUS_FINISHED}

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
}

type G3ScanStatus struct {      // MessageType: MSG_STATUS
	G3Message
	Status G3SCANSTATUS         `json:"status"`
	Progress int			    `json:"progress"`
	Message string       	    `json:"message"`
}

type G3ScanStop struct {        // MessageType: MSG_STOP
	G3Message
}

type MessageQueueClient mqtt.Client

type TaskHandler func(MessageQueueClient, G3Task)
type CancelHandler func(MessageQueueClient, G3CancelTask)
type ResponseHandler func(MessageQueueClient, G3Response)
type NewScanHandler func(MessageQueueClient, G3Scan)
type ScanStatusHandler func(MessageQueueClient, G3ScanStatus)
type ScanStopHandler func(MessageQueueClient, G3ScanStop)

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

	// Connect to the broker.
	client := mqtt.NewClient(opts)
	token := client.Connect()
	for !token.WaitTimeout(MQTT_QUIESCE * time.Second) {}
	return client, token.Error()
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
func SendNewScan(client MessageQueueClient, scanid, mode string, pipelines [][]string) error {
	msg := G3Scan{}
	msg.MessageType = MSG_SCAN
	msg.SenderID = GetClientID(client)
	msg.ScanID = scanid
	msg.Mode = mode
	msg.Pipelines = pipelines
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
	msg.Progress = progress
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
	msg := G3ScanStatus{}
	msg.MessageType = MSG_STATUS
	msg.SenderID = GetClientID(client)
	msg.ScanID = scanid
	msg.Status = STATUS_FINISHED
	msg.Message = "Scan complete."
	err := validator.New().Struct(msg)
	if err != nil {
		return err
	}
	return SendMQPayload(client, G3SCANSTATUSTOPIC, msg)
}

// Send a task to the MQTT broker.
func SendTask(client MessageQueueClient, scanid string, tool string, index int, data G3Data) (string, error) {
	msg := G3Task{}
	msg.MessageType = MSG_TASK
	msg.SenderID = GetClientID(client)
	msg.TaskID = uuid.NewString()
	msg.ScanID = scanid
	msg.Tool = tool
	msg.Index = index
	if _, ok := data["_id"]; ok {
		msg.DataID = data["_id"].(string)
	} else {
		return "", errors.New("data missing _id, save to database first")
	}
	err := validator.New().Struct(msg)
	if err != nil {
		return "", err
	}
	topic := G3WORKERPUBTOPIC + tool
	return msg.TaskID, SendMQPayload(client, topic, msg)
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
