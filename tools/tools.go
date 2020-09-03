package tools

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
)

// DEBUG is the flag that allove to output debugging information. It should be disabled in PROD environment
var DEBUG = debug == "y"
var debug = "y" // cange it via ldflags to disable debugging in PROD

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

// ErrorCollector - errors collector and reporter
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

// Debug - logging debug info
func Debug(format string, args ...interface{}) {
	if DEBUG {
		fmt.Printf("DEBUG: "+format, args...)
		fmt.Println()
	}
}

// GetConfig try to get configuration from file or from environmrnt variable
func GetConfig(path, env string, conf interface{}) error {

	// try to read config file
	err1 := ReadJSON(path, conf)

	// try to read config from environment
	err2 := json.Unmarshal([]byte(os.Getenv(env)), conf)

	if err1 != nil && err2 != nil {
		return fmt.Errorf("cofig was not read, errors: [%v,%v]", err1, err2)
	}

	Debug("INFO: service configuration: %+v", conf)

	return nil
}

// PanicIf panics if provided error is not nil
func PanicIf(err error) {
	if err != nil {
		panic(err)
	}
}

// Updater returns update() and updated()
func Updater() (func(*string, string), *bool) {
	updated := false
	update := func(val *string, nVal string) {
		if nVal != "" && *val != nVal {
			*val = nVal
			updated = true
		}
	}
	//report := func() bool { return updated }
	return update, &updated
}

// ReadBodyToStruct reads request body into interface{}
func ReadBodyToStruct(body io.ReadCloser, i interface{}) error {
	data, err := ioutil.ReadAll(body)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, i)
}
