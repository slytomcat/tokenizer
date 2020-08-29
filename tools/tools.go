package mdes

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
)

// ReadFile returns []byte buffer with file contet
func ReadFile(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return ioutil.ReadAll(file)
}

// ReadJSON returns []byte buffer with file contet
func ReadJSON(path string, i interface{}) error {
	file, err := ReadFile(path)
	if err != nil {
		return fmt.Errorf("file opening/reading error; %w", err)
	}
	if err = json.Unmarshal(file, i); err != nil {
		return fmt.Errorf("file content parsing error; %w", err)
	}
	return nil
}

func ErrorCollector(name string) (func(error), func() error) {
	var errs []error
	collect := func(err error) {
		if err != nil {
			errs = append(errs, err)
		}
	}
	report := func() error {
		if len(errs) > 0 {
			return fmt.Errorf(name, errs)
		}
		return nil
	}
	return collect, report
}
