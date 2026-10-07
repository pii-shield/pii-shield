#!/bin/bash
set -e
rm -f pii-shield
go build -o pii-shield ./cmd/cleaner
