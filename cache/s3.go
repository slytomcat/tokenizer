package cache

import (
	"bytes"
	"io/ioutil"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
)

// Config - cache cofiguration
type Config struct {
	Bucket     string
	Region     string
	AccesKeyID string
	SecretKey  string
}

// Cache - cache
type Cache struct {
	svc    *s3.S3
	bucket string
}

// NewCache creates new cache connection
func NewCache(conf *Config) Cache {

	sess := session.Must(session.NewSession())

	svc := s3.New(sess,
		&aws.Config{
			Region:      aws.String(conf.Region),
			Credentials: credentials.NewStaticCredentials(conf.AccesKeyID, conf.SecretKey, ""),
		})

	return Cache{svc: svc, bucket: conf.Bucket}
}

// Put - puts the data under specified path
func (c Cache) Put(path string, payload []byte) error {

	params := &s3.PutObjectInput{
		Bucket: aws.String(c.bucket), // Required
		Key:    aws.String(path),     // Required
		ACL:    aws.String("bucket-owner-full-control"),
		Body:   bytes.NewReader(payload),
		// CacheControl:         aws.String("CacheControl"),
		// ContentDisposition:   aws.String("ContentDisposition"),
		// ContentEncoding:      aws.String("ContentEncoding"),
		// ContentLanguage:      aws.String("ContentLanguage"),
		ContentLength: aws.Int64(int64(len(payload))),
		// ContentType:          aws.String("ContentType"),
		Expires: aws.Time(time.Now().Add(time.Hour * 1)),
		// GrantFullControl:     aws.String("GrantFullControl"),
		// GrantRead: aws.String("GrantRead"),
		// GrantReadACP:         aws.String("GrantReadACP"),
		// GrantWriteACP:        aws.String("GrantWriteACP"),
		// RequestPayer:         aws.String("RequestPayer"),
		// SSECustomerAlgorithm: aws.String("SSECustomerAlgorithm"),
		// SSECustomerKey:       aws.String("SSECustomerKey"),
		// SSECustomerKeyMD5:    aws.String("SSECustomerKeyMD5"),
		// SSEKMSKeyId:          aws.String("SSEKMSKeyId"),
	}
	_, err := c.svc.PutObject(params)

	//if err != nil {
	// Print the error, cast err to awserr.Error to get the Code and
	// Message from an error.
	//}
	return err

}

// Get - get
func (c Cache) Get(path string) ([]byte, error) {
	params := &s3.GetObjectInput{
		Bucket: aws.String(c.bucket),
		Key:    aws.String(path),
	}

	resp, err := c.svc.GetObject(params)
	if err != nil {
		return nil, err
	}
	payload, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return payload, nil
}
