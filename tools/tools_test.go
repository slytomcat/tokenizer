package tools

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/ioutil"
	"os"
	"testing"
)

func TestErrorCollector(t *testing.T) {
	col, rep := ErrorCollector("test errors: %+v")

	if rep() != nil {
		t.Fatal("empty colector reports not nil")
	}

	col(errors.New("error 1"))

	if rep() == nil {
		t.Fatal("colector with error reports nil")
	}

	t.Log(rep())
	exp := "test errors: [error 1]"
	if rep().Error() != exp {
		t.Errorf("unexpected report: got: '%s', expected: %s", rep(), exp)
	}

	col(errors.New("error 2"))

	if rep() == nil {
		t.Fatal("colector with error reports nil")
	}
	t.Log(rep())
	exp = "test errors: [error 1 error 2]"
	if rep().Error() != exp {
		t.Errorf("unexpected report: got: '%s', expected: %s", rep(), exp)
	}
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

func TestGetConfig(t *testing.T) {
	type cnf struct {
		SVal string
		NVal int
	}

	c0 := cnf{
		SVal: "string",
		NVal: 42,
	}
	c0b, _ := json.Marshal(c0)

	env := "TEST_ENV_TEST_TEST"
	os.Setenv(env, string(c0b))
	defer os.Setenv(env, "")

	c1 := cnf{}

	err := GetConfig("/some/file/that/not/exists", env, &c1)

	if err != nil {
		t.Fatal(err)
	}

	if c1.NVal != c0.NVal || c1.SVal != c0.SVal {
		t.Fatalf("Stored and received data are not equal:\nstored: (%v)\nreceived: (%v)", c0, c1)
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

	err = GetConfig(tmpfile.Name(), "", &c2)

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

	err = GetConfig(tmpfile1.Name(), "", &c2)

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
