package tools

import (
	"errors"
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
