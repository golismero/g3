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
