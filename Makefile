dpl ?= build.env
include $(dpl)
export $(shell sed 's/=.*//' $(dpl))

.PHONY: clean help local image push all

# HELP
# This will output the help for each task
# thanks to https://marmelab.com/blog/2016/02/29/auto-documented-makefile.html

help: ## This help.
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

.DEFAULT_GOAL := help

kcdt: ## Creates the kcdt exe in the build folder.
	@gcc kcdt.c -o build/kcdt -lcurl -l:libcjson.a -l:libprocps.a -Wall

local: ## Creates the image using the output of `make kcdt` and the build.env params.
	@cd build && docker build --no-cache -t $(DOCKER_REPO)/$(APP_NAME):$(VERSION_TAG) .

image: ## Builds kcdt in an image then creates a run image based on hte build.env params.
	@cd build && cp ../kcdt.c ../Makefile ../build.env . && docker build --no-cache -t $(DOCKER_REPO)/$(APP_NAME):$(VERSION_TAG) . -f Dockerfile.image-build && rm kcdt.c Makefile build.env

push: ## Push the image to your docker repo.
	@docker push $(DOCKER_REPO)/$(APP_NAME):$(VERSION_TAG)

all: ## Run clean, kcdt, image and push as one command.
	make clean
	make kcdt
	make image
	make push

clean: ## Removes the kcdt exe from the build folder.
	@rm -f build/kcdt
