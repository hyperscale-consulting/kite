SHELL := /bin/bash
VERSION := $(shell uv version --short)

test:
	uv run pytest

tag:
	git tag -a v$(VERSION) -m "Release $(VERSION)"
