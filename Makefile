PYTHON ?= python3
RUFF   ?= ruff
MYPY   ?= mypy
PIPX   ?= pipx
RUFFFLAGS ?=

# Run the tests against the source tree, no install needed.
export PYTHONPATH := $(CURDIR)/src$(if $(PYTHONPATH),:$(PYTHONPATH))

.PHONY: help check test lint format format-check typecheck dev build \
	install uninstall clean

help:
	@echo "make check         run lint, format-check, typecheck and test"
	@echo "make test          run the unit tests"
	@echo "make lint          run ruff check"
	@echo "make format        format the code with ruff"
	@echo "make format-check  check the formatting"
	@echo "make typecheck     run mypy"
	@echo "make dev           editable install with ruff and mypy"
	@echo "make build         build a wheel into dist/"
	@echo "make install       install the keysign command with pipx"
	@echo "make uninstall     remove it again"
	@echo "make clean         remove build output and caches"

check: lint format-check typecheck test

test:
	$(PYTHON) -m unittest discover -s tests -v

lint:
	$(RUFF) check $(RUFFFLAGS) .

format:
	$(RUFF) format .
	$(RUFF) check --fix --select I .

format-check:
	$(RUFF) format --check --diff .

typecheck:
	$(MYPY)

dev:
	$(PYTHON) -m pip install -e '.[dev]'

build:
	$(PYTHON) -m pip wheel --no-deps -w dist .

install:
	$(PIPX) install --force .

uninstall:
	$(PIPX) uninstall keysign

clean:
	rm -rf build dist src/*.egg-info .mypy_cache .ruff_cache
	rm -rf src/keysign/__pycache__ tests/__pycache__
