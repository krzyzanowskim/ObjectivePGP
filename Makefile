.PHONY: frameworks

CWD := $(abspath $(patsubst %/,%,$(dir $(abspath $(lastword $(MAKEFILE_LIST))))))

frameworks:
	$(CWD)/scripts/build-frameworks.sh

all: frameworks
