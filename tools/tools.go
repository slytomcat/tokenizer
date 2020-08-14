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
