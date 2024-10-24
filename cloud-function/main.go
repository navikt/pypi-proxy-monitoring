package main

import (
	"context"
	"fmt"
	"log"

	"github.com/GoogleCloudPlatform/functions-framework-go/functions"
	"github.com/cloudevents/sdk-go/v2/event"
)

type MessagePublishedData struct {
	Message PubSubMessage
}

type PubSubMessage struct {
	Data []byte `json:"data"`
}

func init() {
	functions.CloudEvent("Entrypoint", entrypoint)
}

func entrypoint(ctx context.Context, e event.Event) error {
	var msg MessagePublishedData
	if err := e.DataAs(&msg); err != nil {
		return fmt.Errorf("event.DataAs: %v", err)
	}

	log.Printf("pubsub datas: %s", string(msg.Message.Data))
	return nil
}
