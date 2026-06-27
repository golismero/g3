package g3model

import (
	"encoding/json"
	"errors"
)

const NIL_UUID = "00000000-0000-0000-0000-000000000000"

type LogLine struct {
	Timestamp int64      `json:"ts"                validate:"gte=0"`
	Text      string     `json:"text"`
}

type SubscriptionKey struct {
	Channel string       `json:"channel"           validate:"required,oneof=all created deleted status logs input output"`
	ScanID string        `json:"scanid,omitempty"  validate:"omitempty,uuid,ne=00000000-0000-0000-0000-000000000000"`
	TaskID string        `json:"taskid,omitempty"  validate:"omitempty,uuid,ne=00000000-0000-0000-0000-000000000000"`
}

type SubscriptionRequest struct {
	SubscriptionKey
	Action string        `json:"action"            validate:"required,oneof=subscribe unsubscribe"`
}

type SubscriptionData struct {
	SubscriptionKey
	Error string         `json:"error,omitempty"`
	Data json.RawMessage `json:"data,omitempty"`
}

func (self SubscriptionData) Status() (string, error) {
	var status string = "error"
	if self.Channel != "status" {
		return status, errors.New("Not a status change event")
	}
	err := json.Unmarshal(self.Data, &status)
	if err == nil {
		err = Validate.Var(status, "required,oneof=error warning waiting dispatched running canceled done managed")
	}
	return status, err
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
	var data_id string = NIL_UUID
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
