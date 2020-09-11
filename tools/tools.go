package tools

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"
)

// DEBUG is the flag that allove to output debugging information. It should be disabled in PROD environment
var (
	DEBUG = debug == "y"
	debug = "y" // cange it via ldflags to disable debugging in PROD (see ../build_prod.bash)

)

// ReadPath returns []byte buffer with file or environment variable content.
// When path starts with "$" then the environment variable is read. If binary = true then environment variable interpreted as base64(std) encoded data.
// For conventional path (like "/some/dir/file") the file content is returned.
func ReadPath(path string, binary bool) ([]byte, error) {
	if strings.HasPrefix(path, "$") {
		// get data from environment
		if !binary {
			return []byte(os.Getenv(path[1:])), nil
		}
		data, err := base64.StdEncoding.DecodeString(os.Getenv(path[1:]))
		if err != nil {
			return nil, err
		}
		return data, nil
	}
	// get data from file
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return ioutil.ReadAll(file)
}

// ReadJSON reads the data from path and tries to unmarshal it into supplied structure.
// See ReadFile description for details on reading data by path.
func ReadJSON(path string, i interface{}) error {
	file, err := ReadPath(path, false)
	if err != nil {
		return fmt.Errorf("data receiving error; %w", err)
	}
	if err = json.Unmarshal(file, i); err != nil {
		return fmt.Errorf("data parsing error; %w", err)
	}
	return nil
}

// ErrorCollector - errors collector and reporter.
// It returns two function:
// - func(error) : should be used to report errors. Errors equal to nil are ignored.
// - func() error : to report about collected errors. It returns nil if no error were collected.
// The format parameter is used to format the resulting error
func ErrorCollector(format string) (func(error), func() error) {
	var errs []error
	collect := func(err error) {
		if err != nil {
			errs = append(errs, err)
		}
	}
	report := func() error {
		if len(errs) > 0 {
			return fmt.Errorf(format, errs)
		}
		return nil
	}
	return collect, report
}

// Debug - logging of debug info
func Debug(format string, args ...interface{}) {
	if DEBUG {
		fmt.Printf("DEBUG: "+format, args...)
		fmt.Println()
	}
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
