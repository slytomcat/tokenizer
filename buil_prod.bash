#!/bin/bash

CGO_ENABLED=0 go build -ldflags "-X 'main.version=$(git describe --tags)' -X 'github.com/slytomcat/tokenizer/tools.debug=n'"
