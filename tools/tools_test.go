package tools

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"testing"
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
	if err != nil {
		t.Fatal(err)
	}
	expected := []byte{0, 0, 0}
	if !bytes.Equal(data, expected) {
		t.Fatalf("wrong data read: expected: %+v, received: %+v", expected, data)
	}

	// non-binary data
	data, err = ReadPath("$"+env, false)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(data, []byte(testString)) {
		t.Fatalf("wrong data read: expected: %+v, received: %+v", testString, data)
	}

	// wrong binary data
	os.Setenv(env, "not base64 string")
	data, err = ReadPath("$"+env, true)
	if err == nil {
		t.Fatal("no error when expected")
	}

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

	err := ReadJSON("$"+env, &c1)
	if err != nil {
		t.Fatal(err)
	}

	if c1.NVal != c0.NVal || c1.SVal != c0.SVal {
		t.Fatalf("Stored and received data are not equal:\nstored: (%v)\nreceived: (%v)", c0, c1)
	}

	os.Setenv(env, `{"wrong":"JSON`)
	err = ReadJSON("$"+env, &c1)
	if err == nil {
		t.Fatal("no error when expected")
	}

	// file tests
	err = ReadJSON("non/existing/path", &c1)
	if err == nil {
		t.Fatal("no error when expected")
	}

	tmpfile, err := ioutil.TempFile("", "example")
	if err != nil {
		t.Fatal(err)
	}

	defer os.Remove(tmpfile.Name()) // clean up
	defer tmpfile.Close()

	if _, err := tmpfile.Write(c0b); err != nil {
		t.Fatal(err)
	}
	if err := tmpfile.Close(); err != nil {
		t.Fatal(err)
	}

	c2 := cnf{}

	err = ReadJSON(tmpfile.Name(), &c2)

	if err != nil {
		t.Fatal(err)
	}

	if c2.NVal != c0.NVal || c2.SVal != c0.SVal {
		t.Fatalf("Stored and received data are not equal:\nstored: (%v)\nreceived: (%v)", c0, c1)
	}

	tmpfile1, err := ioutil.TempFile("", "example1")
	if err != nil {
		t.Fatal(err)
	}

	defer os.Remove(tmpfile1.Name()) // clean up
	defer tmpfile1.Close()

	if _, err := tmpfile1.Write([]byte("{not json}")); err != nil {
		t.Fatal(err)
	}
	if err := tmpfile1.Close(); err != nil {
		t.Fatal(err)
	}

	c2 = cnf{}

	err = ReadJSON(tmpfile1.Name(), &c2)

	if err == nil {
		t.Fatal("no error when expected")
	}
}

func TestUpdater(t *testing.T) {
	update, updated := Updater()
	val := "val"
	valN := val
	update(&val, valN)
	if *updated {
		t.Fatal("no changes reports update")
	}
	valN = "new val"
	update(&val, valN)
	if !*updated {
		t.Fatal("changes reports no update")
	}
	valN = val
	update(&val, valN)
	if !*updated {
		t.Fatal("no changes after cahnges reports no update")
	}
}

func TestPanicIfNO(t *testing.T) {
	defer func() {
		p := recover()
		if p != nil {
			t.Fatal("panic when not expected")
		}
	}()
	var err error
	PanicIf(err)
}

func TestPanicIfYES(t *testing.T) {
	defer func() {
		p := recover()
		if p == nil {
			t.Fatal("no panic when expected")
		}
	}()
	PanicIf(errors.New("test error"))
}

func TestBodyReader(t *testing.T) {
	data := `{"key":"val"}`
	dStruct := struct {
		Key string
	}{}

	err := ReadBodyToStruct(ioutil.NopCloser(bytes.NewReader([]byte(data))), &dStruct)

	if err != nil {
		t.Fatal(err)
	}

	if dStruct.Key != "val" {
		t.Fatal("wrong value")
	}

	data = `{"wrong":"JSON"`

	err = ReadBodyToStruct(ioutil.NopCloser(bytes.NewReader([]byte(data))), &dStruct)

	if err == nil {
		t.Fatal("no erroro when expected")
	}

	t.Logf("receiver expected error: %v", err)

	err = ReadBodyToStruct(wr{}, &dStruct)

	if err == nil {
		t.Fatal("no erroro when expected")
	}

	t.Logf("receiver expected error: %v", err)

}

type wr struct{}

func (wr) Close() error { return nil }

func (wr) Read([]byte) (int, error) {
	return 0, errors.New("expected error")
}

func TestAppLog(t *testing.T) {
	l := NewAppLog("localhost", "testApp", "tokenizer", "prod")
	l.Print("INFO", "testType", "test messge", struct {
		Question string
		Answer   int
	}{
		Question: "The Ultimate Question of Life, the Universe, and Everything",
		Answer:   42,
	})
}
