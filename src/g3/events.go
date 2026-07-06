package g3

import (
	"encoding/json"
	"errors"
)

type LogLine struct {
	Timestamp uint64     `json:"ts"                  validate:"gt=0"`
	Text      string     `json:"text"`
}

type StatusUpdate struct {
	Seq uint64           `json:"seq"                 validate:"gt=0"`
	Status string        `json:"status"              validate:"required,oneof=waiting dispatched running canceled warning error done managed"`
}

type ProgressUpdate struct {
	StatusUpdate
	Progress uint        `json:"progress,omitempty"  validate:"omitempty,gte=0,lte=100"`
	Message string       `json:"msg,omitempty"`
}

type SubscriptionKey struct {
	Channel string       `json:"channel"             validate:"required,oneof=* created deleted status progress logs input output"`
	ScanID string        `json:"scanid,omitempty"    validate:"omitempty,uuid"`
	TaskID string        `json:"taskid,omitempty"    validate:"omitempty,uuid"`
}

type SubscriptionRequest struct {
	SubscriptionKey
	Action string        `json:"action"              validate:"required,oneof=subscribe unsubscribe"`
}

type SubscriptionData struct {
	SubscriptionKey
	Error string         `json:"error,omitempty"`
	Data json.RawMessage `json:"data,omitempty"`
}

func (sd SubscriptionData) Status() (StatusUpdate, error) {
	var update = StatusUpdate{
		Seq: 0,
		Status: "error",
	}
	if sd.Channel != "status" {
		return update, errors.New("Not a status update event")
	}
	err := json.Unmarshal(sd.Data, &update)
	if err == nil {
		err = Validate.Struct(&update)
	}
	return update, err
}

func (sd SubscriptionData) Progress() (ProgressUpdate, error) {
	var update = ProgressUpdate{
		StatusUpdate: StatusUpdate{
			Seq: 0,
			Status: "error",
		},
		Progress: 100,
		Message: "",
	}
	if sd.Channel != "progress" {
		return update, errors.New("Not a progress update event")
	}
	err := json.Unmarshal(sd.Data, &update)
	if err == nil {
		err = Validate.Struct(&update)
	}
	return update, err
}

func (sd SubscriptionData) Logs() ([]LogLine, error) {
	var log_lines []LogLine
	if sd.Channel != "logs" {
		return log_lines, errors.New("Not a logging event")
	}
	err := json.Unmarshal(sd.Data, &log_lines)
	if err == nil {
		err = Validate.Var(log_lines, "dive")
	}
	return log_lines, err
}

func (sd SubscriptionData) Input() (string, error) {
	var data_id = "00000000-0000-0000-0000-000000000000"
	if sd.Channel != "input" {
		return data_id, errors.New("Not an input event")
	}
	err := json.Unmarshal(sd.Data, &data_id)
	if err == nil {
		err = Validate.Var(data_id, "required,uuid")
	}
	return data_id, err
}

func (sd SubscriptionData) Output() ([]string, error) {
	var output_data_ids []string
	if sd.Channel != "output" {
		return output_data_ids, errors.New("Not an output event")
	}
	err := json.Unmarshal(sd.Data, &output_data_ids)
	if err == nil {
		err = Validate.Var(&output_data_ids, "dive,required,uuid")
	}
	return output_data_ids, err
}
