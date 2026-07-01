package g3model

import (
	"encoding/json"
	"errors"
)

const NIL_UUID = "00000000-0000-0000-0000-000000000000"

type LogLine struct {
	Timestamp int64      `json:"ts"                  validate:"gte=0"`
	Text      string     `json:"text"`
}

type StatusUpdate struct {
	Seq int              `json:"seq"                 validate:"gt=0"`
	Status string        `json:"status"              validate:"required,oneof=waiting dispatched running canceled warning error done managed"`
}

type ProgressUpdate struct {
	StatusUpdate
	Progress int         `json:"progress,omitempty"  validate:"omitempty,gte=0,lte=100"`
	Message string       `json:"msg,omitempty"`
}

type SubscriptionKey struct {
	Channel string       `json:"channel"             validate:"required,oneof=* created deleted status progress logs input output"`
	ScanID string        `json:"scanid,omitempty"    validate:"omitempty,uuid|eq=*"`
	TaskID string        `json:"taskid,omitempty"    validate:"omitempty,uuid|eq=*"`
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

func (self SubscriptionData) Status() (StatusUpdate, error) {
	var update = StatusUpdate{
		Seq: 0,
		Status: "error",
	}
	if self.Channel != "status" {
		return update, errors.New("Not a status update event")
	}
	err := json.Unmarshal(self.Data, &update)
	if err == nil {
		err = Validate.Struct(&update)
	}
	return update, err
}

func (self SubscriptionData) Progress() (ProgressUpdate, error) {
	var update = ProgressUpdate{
		StatusUpdate: StatusUpdate{
			Seq: 0,
			Status: "error",
		},
		Progress: 100,
		Message: "",
	}
	if self.Channel != "progress" {
		return update, errors.New("Not a progress update event")
	}
	err := json.Unmarshal(self.Data, &update)
	if err == nil {
		err = Validate.Struct(&update)
	}
	return update, err
}

func (self SubscriptionData) Logs() ([]LogLine, error) {
	var log_lines []LogLine
	if self.Channel != "logs" {
		return log_lines, errors.New("Not a logging event")
	}
	err := json.Unmarshal(self.Data, &log_lines)
	if err == nil {
		err = Validate.Var(log_lines, "dive")
	}
	return log_lines, err
}

func (self SubscriptionData) Input() (string, error) {
	var data_id = NIL_UUID
	if self.Channel != "input" {
		return data_id, errors.New("Not an input event")
	}
	err := json.Unmarshal(self.Data, &data_id)
	if err == nil {
		err = Validate.Var(data_id, "required,uuid,ne="+NIL_UUID)
	} 
	return data_id, err
}

func (self SubscriptionData) Output() ([]string, error) {
	var output_data_ids []string
	if self.Channel != "output" {
		return output_data_ids, errors.New("Not an output event")
	}
	err := json.Unmarshal(self.Data, &output_data_ids)
	if err == nil {
		err = Validate.Var(&output_data_ids, "dive,required,uuid,ne="+NIL_UUID)
	}
	return output_data_ids, err
}
