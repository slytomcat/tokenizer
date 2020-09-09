package queue

import (
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/sqs"

	"github.com/slytomcat/tokenizer/tools"
)

func TestNew(t *testing.T) {
	conf := struct{ QUEUE Config }{}
	err := tools.GetConfig("../config.json", "", &conf)
	tools.PanicIf(err)
	q, err := NewQueue(&conf.QUEUE)
	tools.PanicIf(err)

	tdata1 := "test data 1"
	tdata2 := "test data 2"
	tdata3 := "test data 3"

	err = q.Send(tdata1)
	tools.PanicIf(err)

	err = q.Send(tdata2)
	tools.PanicIf(err)

	_ = q.Send(tdata3)

	data, receipt, err := q.Receive()
	tools.PanicIf(err)
	t.Log(data)

	q.Delete(receipt)

	req, _ := q.q.PurgeQueueRequest(&sqs.PurgeQueueInput{
		QueueUrl: aws.String(q.queueURL),
	})
	req.Send()

}
