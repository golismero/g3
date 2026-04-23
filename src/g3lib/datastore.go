package g3lib

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"sort"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

const MONGO_URL = "MONGO_URL"

type DatastoreClient struct {
	c *mongo.Client
}

type LoadDataCallback func(G3Data)(error)

// Connect to the Mongo database and ping it to ensure the connection was successful.
// Without running at least one command, merely creating the client does not ensure a connection.
func ConnectToDatastore() (DatastoreClient, error) {
	var dbclient DatastoreClient
	uri := os.Getenv(MONGO_URL)
	if uri == "" {
		return dbclient, errors.New("missing environment variable: " + MONGO_URL)
	}
	client, err := mongo.Connect(context.Background(), options.Client().ApplyURI(uri))
	dbclient.c = client
	if err == nil {
		var result bson.M
		err = client.Database("admin").RunCommand(context.Background(), bson.D{primitive.E{Key: "ping", Value: 1}}).Decode(&result)
	}
	return dbclient, err
}

// Defer this call right after calling ConnectToDatastore().
func DisconnectFromDatastore(client DatastoreClient) {
	if client.c != nil {
		client.c.Disconnect(context.Background())
		client.c = nil
	}
}

// Produce a list of scan IDs from the database.
func EnumerateScans(dbclient DatastoreClient) ([]string, error) {
	var scanidlist []string
	dbs, err := dbclient.c.ListDatabaseNames(context.Background(), bson.M{"name": primitive.Regex{Pattern: `^scan\-`}})
	if err == nil {
		scanidlist = make([]string, len(dbs))
		for index, name := range dbs {
			scanidlist[index] = name[5:]
		}
	}
	return scanidlist, err
}

// Load a single G3 object from the database.
func LoadOne(dbclient DatastoreClient, scanid string, dataid string) (G3Data, error) {
	var data G3Data
	dataList, err := LoadData(dbclient, scanid, []string{dataid})
	if err == nil {
		if len(dataList) == 1 {
			data = dataList[0]
		} else {
			err = errors.New("Data object not found: " + dataid)
		}
	}
	return data, err
}

// Load an array of G3 objects from the database.
func LoadData(dbclient DatastoreClient, scanid string, dataIds []string) ([]G3Data, error) {
	var jsonArray []G3Data

	// Prepare the database query.
	// If we have a list of IDs, filter by the _id property.
	// If we have an empty list, retrieve all objects in the collection.
	query := bson.M{}
	if len(dataIds) > 0 {
		objectIds := make([]primitive.ObjectID, len(dataIds))
		for index, idstring := range dataIds {
			objid, err := primitive.ObjectIDFromHex(idstring)
			if err != nil {
				return jsonArray, err
			}
			objectIds[index] = objid
		}
		query = bson.M{"_id": bson.M{"$in": objectIds}}
	}

	// Fetch the data.
	err := LoadDataWithCallback(dbclient, scanid, query, func(data G3Data)(error) {
		jsonArray = append(jsonArray, data)
		return nil
	})
	return jsonArray, err
}

// Get all data IDs for a given scan.
func GetScanDataIDs(dbclient DatastoreClient, scanid string) ([]string, error) {
	var idArray []string
	err := LoadDataWithCallback(dbclient, scanid, bson.M{}, func(data G3Data)(error) {
		dataid, ok := data["_id"]
		if !ok {
			return errors.New("internal error")
		}
		idArray = append(idArray, dataid.(string))
		return nil
	})
	return idArray, err
}

// Fetch data that matches a specific fingerprint.
func LoadFingerprintMatches(dbclient DatastoreClient, scanid string, fingerprints []string) ([]G3Data, error) {
	query := bson.M{"_fp": bson.M{"$in": fingerprints}}
	var jsonArray []G3Data
	err := LoadDataWithCallback(dbclient, scanid, query, func(data G3Data)(error) {
		jsonArray = append(jsonArray, data)
		return nil
	})
	return jsonArray, err
}

// Fetch data IDs that matches a specific fingerprint.
func GetFingerprintMatchesIDs(dbclient DatastoreClient, scanid string, fingerprints []string) ([]string, error) {
	query := bson.M{"_fp": bson.M{"$in": fingerprints}}
	var idArray []string
	err := LoadDataWithCallback(dbclient, scanid, query, func(data G3Data)(error) {
		idArray = append(idArray, data["_id"].(string))
		return nil
	})
	return idArray, err
}

// Fetch issues that match a specific plugin.
func LoadIssues(dbclient DatastoreClient, scanid, tool string) ([]G3Data, error) {
	query := bson.M{
		"$and": []bson.M{
			{"_type": "issue"},
			{"_tool": tool},
		},
	}
	var jsonArray []G3Data
	err := LoadDataWithCallback(dbclient, scanid, query, func(data G3Data)(error) {
		jsonArray = append(jsonArray, data)
		return nil
	})
	return jsonArray, err
}

// Fetch issue IDs that match a specific plugin.
func GetIssueIDs(dbclient DatastoreClient, scanid, tool string) ([]string, error) {
	var query bson.M
	if tool == "*" {
		query = bson.M{"_type": "issue"}
	} else {
		query = bson.M{
			"$and": []bson.M{
				{"_type": "issue"},
				{"_tool": tool},
			},
		}
	}
	var idArray []string
	err := LoadDataWithCallback(dbclient, scanid, query, func(data G3Data)(error) {
		idArray = append(idArray, data["_id"].(string))
		return nil
	})
	return idArray, err
}

// Fetch the list of tools that were used in a scan.
func GetScanTools(dbclient DatastoreClient, scanid string) ([]string, error) {
	tools := make(StringSet)
	err := LoadDataWithCallback(dbclient, scanid, bson.M{}, func(data G3Data)(error) {
		name, ok := data["_tool"]
		if ok && name.(string) != "g3" {
			tools.Add(name.(string))
		}
		return nil
	})
	toolsList := tools.ToArray()
	sort.Strings(toolsList)
	return toolsList, err
}

// Fetch the list of tools that reported issues in a scan.
func GetScanIssueTools(dbclient DatastoreClient, scanid string) ([]string, error) {
	tools := make(StringSet)
	err := LoadDataWithCallback(dbclient, scanid, bson.M{"_type": "issue"}, func(data G3Data)(error) {
		name, ok := data["_tool"]
		if ok && name.(string) != "g3" {
			tools.Add(name.(string))
		}
		return nil
	})
	toolsList := tools.ToArray()
	sort.Strings(toolsList)
	return toolsList, err
}

// Load an array of G3 objects from the database, invoking a callback for each.
func LoadDataWithCallback(dbclient DatastoreClient, scanid string, query bson.M, callback LoadDataCallback) error {
	client := dbclient.c

	// The information for each scan is stored in its own database.
	// Inside that database, the "data" collection stores all of the scan results.
	coll := client.Database("scan-" + scanid).Collection("data")

	// Execute the query. This will return a cursor object.
	cursor, err := coll.Find(context.Background(), query)
	if err != nil {
		return err
	}
	defer cursor.Close(context.Background())

	// Iterate the cursor object, converting every result into JSON.
	// The conversion is needed because MongoDB uses BSON which is not compatible.
	// https://www.mongodb.com/basics/bson
	for cursor.Next(context.Background()) {
		var document bson.M
		e := cursor.Decode(&document)
		if e != nil {
			err = e
			continue
		}
		bsonBytes, e := json.Marshal(document)
		if e != nil {
			err = e
			continue
		}
		var data G3Data
		e = json.Unmarshal(bsonBytes, &data)
		if e != nil {
			err = e
			continue
		}
		e = callback(data)
		if e != nil {
			return e		// Stop immediately if the callback throws an error.
		}
	}

	// Return any error that might have happened.
	return err
}

// Save an array of G3 objects into the database.
func SaveData(dbclient DatastoreClient, scanid, taskid string, outputArray []G3Data) ([]string, error) {
	client := dbclient.c

	// We will return a list of MongoDB IDs, one for each object stored in the database.
	insertedIds := []string{}

	// Scan ID cannot be nil.
	if scanid == "" {
		return insertedIds, errors.New("nil scan ID received")
	}

	// If no task ID was given, use the nil UUID.
	// This will happen for target data, since it was not generated by any plugin.
	if taskid == "" {
		taskid = NIL_TASKID
	}

	// If no objects are given, just return.
	if len(outputArray) == 0 {
		return insertedIds, nil
	}

	// Convert the JSON objects into BSON, to be stored in the database.
	// Make sure we don't have any objects that already have an ID.
	// We will consider that a hard error since it indicates a logic flaw.
	docs := []interface{}{}
	for _, data := range outputArray {
		if _, ok := data["_id"]; ok {
			return insertedIds, errors.New("cannot insert object already in database: " + data["_id"].(string))
		}
		data["_scanid"] = scanid
		data["_taskid"] = taskid
		jsonData, err := json.Marshal(data)
		if err != nil {
			return insertedIds, err
		}
		var bsonData interface{}
		err = bson.UnmarshalExtJSON(jsonData, true, &bsonData)
		if err != nil {
			return insertedIds, err
		}
		docs = append(docs, bsonData)
	}

	// The information for each scan is stored in its own database.
	// Inside that database, the "data" collection stores all of the scan results.
	coll := client.Database("scan-" + scanid).Collection("data")

	// Insert the new objects into the database and keep their IDs.
	// We need to convert the IDs since they're not strings.
	result, err := coll.InsertMany(context.Background(), docs)
	if err != nil {
		return insertedIds, err
	}
	for _, objectid := range result.InsertedIDs {
		insertedIds = append(insertedIds, objectid.(primitive.ObjectID).Hex())
	}

	// Set the IDs into our G3 objects, to indicate we have already stored them.
	if len(insertedIds) == len(outputArray) {
		for index, dataid := range insertedIds {
			outputArray[index]["_id"] = dataid
		}
	} else {
		err = errors.New("internal error")
	}

	// Return the inserted IDs and any errors that occurred.
	return insertedIds, err
}

// Delete the data for a given scan.
func DropScanData(dbclient DatastoreClient, scanid string) error {
	return dbclient.c.Database("scan-" + scanid).Drop(context.Background())
}
