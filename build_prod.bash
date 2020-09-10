#!/bin/bash

CGO_ENABLED=0 go build -a -ldflags "-X 'main.version=$(git describe --tags)' -X 'github.com/slytomcat/tokenizer/tools.debug=n'"
