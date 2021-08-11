package tools

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func ExampleErrorCollector() {
	collect, report := ErrorCollector("test errors: %+v")

	fmt.Println(report())

	collect(errors.New("error 1"))

	fmt.Println(report())

	collect(errors.New("error 2"))

	fmt.Println(report())

	// Output:
	// <nil>
	// test errors: [error 1]
	// test errors: [error 1 error 2]
}

func ExampleDebug() {
	saveD := DEBUG
	defer func() {
		DEBUG = saveD
	}()

	DEBUG = true

	Debug("it is %s that should be shown", "DEBUG message")

	DEBUG = false

	Debug("it is %s than shouldn't be shown", "DEBUG message")

	// Output:
	// DEBUG: it is DEBUG message that should be shown
}

func TestReadPath(t *testing.T) {

	env := "TEST_ENV_TEST_TEST"
	defer os.Setenv(env, "")
	testString := "AAAA"
	os.Setenv(env, testString)

	// binary data
	data, err := ReadPath("$"+env, true)
	assert.NoError(t, err)
	expected := []byte{0, 0, 0}
	assert.Equal(t, expected, data)

	// non-binary data
	data, err = ReadPath("$"+env, false)
	assert.NoError(t, err)
	assert.Equal(t, []byte(testString), data)

	// wrong binary data
	os.Setenv(env, "not base64 string")
	data, err = ReadPath("$"+env, true)
	assert.Error(t, err)
	assert.Nil(t, data)

	// file reading cases are tested through the ReadJSON tests
}

func TestReadJSON(t *testing.T) {

	// test data
	type cnf struct {
		SVal string
		NVal int
	}
	c0 := cnf{
		SVal: "string",
		NVal: 42,
	}
	c0b, _ := json.Marshal(c0)

	// env tests
	env := "TEST_ENV_TEST_TEST"
	defer os.Setenv(env, "")

	os.Setenv(env, string(c0b))
	c1 := cnf{}

	assert.NoError(t, ReadJSON("$"+env, &c1))

	assert.Equal(t, c0, c1, "Stored and received data are not equal")

	os.Setenv(env, `{"wrong":"JSON`)
	assert.Error(t, ReadJSON("$"+env, &c1))

	// file tests
	assert.Error(t, ReadJSON("non/existing/path", &c1))

	tmpfile, err := ioutil.TempFile("", "example")
	assert.NoError(t, err)

	defer os.Remove(tmpfile.Name()) // clean up
	defer tmpfile.Close()

	_, err = tmpfile.Write(c0b)
	assert.NoError(t, err)
	assert.NoError(t, tmpfile.Close())

	c2 := cnf{}

	assert.NoError(t, ReadJSON(tmpfile.Name(), &c2))
	assert.Equal(t, c0, c2)

	tmpfile1, err := ioutil.TempFile("", "example1")
	assert.NoError(t, err)

	defer os.Remove(tmpfile1.Name()) // clean up
	defer tmpfile1.Close()

	_, err = tmpfile1.Write([]byte("{not json}"))
	assert.NoError(t, err)
	assert.NoError(t, tmpfile1.Close())

	c2 = cnf{}

	assert.Error(t, ReadJSON(tmpfile1.Name(), &c2))
}

func TestUpdater(t *testing.T) {
	update, updated := Updater()
	val := "val"
	valN := val
	update(&val, valN)
	assert.False(t, *updated, "no changes reports update")
	valN = "new val"
	update(&val, valN)
	assert.True(t, *updated, "changes reports no update")
	valN = val
	update(&val, valN)
	assert.True(t, *updated, "no changes after cahnges reports no update")
}

func TestPanicIfNO(t *testing.T) {
	defer func() {
		assert.Nil(t, recover(), "panic when not expected")
	}()
	var err error
	PanicIf(err)
}

func TestPanicIfYES(t *testing.T) {
	defer func() {
		assert.NotNil(t, recover(), "no panic when expected")
	}()
	PanicIf(errors.New("test error"))
}

func TestBodyReader(t *testing.T) {
	data := `{"key":"val"}`
	dStruct := struct {
		Key string
	}{}

	assert.NoError(t, ReadBodyToStruct(ioutil.NopCloser(bytes.NewReader([]byte(data))), &dStruct))
	assert.Equal(t, "val", dStruct.Key)

	data = `{"wrong":"JSON"`
	assert.Error(t, ReadBodyToStruct(ioutil.NopCloser(bytes.NewReader([]byte(data))), &dStruct))

	assert.Error(t, ReadBodyToStruct(wr{}, &dStruct))
}

type wr struct{}

func (wr) Close() error { return nil }

func (wr) Read([]byte) (int, error) {
	return 0, errors.New("expected error")
}

func TestAppLog(t *testing.T) {
	r, w, _ := os.Pipe()
	stdOut := os.Stdout
	defer func() { os.Stdout = stdOut }()
	os.Stdout = w

	l := NewAppLog("localhost", "testApp", "tokenizer", "prod")
	l.Print("INFO", "testType", "test messge", struct {
		Question string
		Answer   int
	}{
		Question: "The Ultimate Question of Life, the Universe, and Everything",
		Answer:   42,
	})

	w.Close()
	out, err := io.ReadAll(r)
	assert.NoError(t, err)
	assert.Contains(t, string(out), `"data":{"Question":"The Ultimate Question of Life, the Universe, and Everything","Answer":42}`)
}

func ExampleUniqueID() {
	rand.Seed(42)
	fmt.Println(UniqueID())
	// Output:
	// U4x_lrFkvxuXu59LtHLon1sUhPJSCcnZ
}
