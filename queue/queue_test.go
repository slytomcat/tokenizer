package queue

import (
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/sqs"

	"github.com/slytomcat/tokenizer/tools"
)

func TestNew(t *testing.T) {
	conf := struct{ QUEUE Config }{}
	err := tools.ReadJSON("../config.json", &conf)
	if err != nil {
		t.Fatal(err)
	}
	q, err := NewQueue(&conf.QUEUE)
	if err != nil {
		t.Fatal(err)
	}

	// clearance
	req, _ := q.q.PurgeQueueRequest(&sqs.PurgeQueueInput{
		QueueUrl: aws.String(q.queueURL),
	})
	req.Send()

	tdata1 := QData{
		URL:     "some url",
		Payload: "some payload",
	}

	err = q.Send(tdata1)
	if err != nil {
		t.Fatal(err)
	}

	// err = q.Send(tdata2)
	// if err != nil {
	// 	t.Fatal(err)
	// }

	// _ = q.Send(tdata3)

	data, receipt, err := q.Receive()
	if err != nil {
		t.Fatal(err)
	}
	t.Log(*data)

	err = q.Delete(receipt)
	if err != nil {
		t.Fatal(err)
	}

	err = q.Check()
	if err != nil {
		t.Fatal(err)
	}

	data, receipt, err = q.Receive()
	if err == nil {
		t.Fatal("no error when expected")
	}
	t.Logf("expected error: %v", err)

	// clearance
	req, _ = q.q.PurgeQueueRequest(&sqs.PurgeQueueInput{
		QueueUrl: aws.String(q.queueURL),
	})
	req.Send()

	q.q.DeleteQueue(&sqs.DeleteQueueInput{QueueUrl: aws.String(q.queueURL)})

	data, receipt, err = q.Receive()
	if err == nil {
		t.Fatal("no error when expected")
	}
	t.Logf("expected error: %v", err)

	q, err = NewQueue(&conf.QUEUE)
	if err != nil {
		t.Fatal(err)
	}

}
