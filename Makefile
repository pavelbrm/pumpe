BASE_PATH := $(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))
MKFILE_PATH := $(BASE_PATH)/Makefile
COVER_OUT := cover.out

.DEFAULT_GOAL := help

BUILD_ID := `git rev-parse --short HEAD`

lint: ## Lint code
	golangci-lint run -v


build: ## Build
	mkdir -p bin
	CGO_ENABLED=0 go build -ldflags "-s -w" -o bin/pumpe ./cmd/pumpe


build_with_race: ## Build code with the race detector enabled
	go build -race


test: ## Run tests
	go test -v -count=1 -coverprofile=$(COVER_OUT) ./...


cover: ## Show test coverage
	@if [ -f $(COVER_OUT) ]; then \
		go tool cover -func=$(COVER_OUT); \
		rm -f $(COVER_OUT); \
	else \
		echo "$(COVER_OUT) is missing. Please run 'make test'"; \
	fi


clean: ## Clean up
	@rm -f $(COVER_OUT)
	@find $(BASE_PATH) -name ".DS_Store" -depth -exec rm {} \;


help: ## Show help message
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'


.PHONY: help lint build_with_race test cover clean
