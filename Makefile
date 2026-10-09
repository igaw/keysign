PYTHON ?= python3
RUFF   ?= ruff
MYPY   ?= mypy
RUFFFLAGS ?=
PREFIX ?= $(HOME)/.local
BINDIR ?= $(PREFIX)/bin

.PHONY: help check test lint format format-check typecheck install uninstall clean

help:
	@echo "make check         run lint, format-check, typecheck and test"
	@echo "make test          run the unit tests"
	@echo "make lint          run ruff check"
	@echo "make format        format the code with ruff"
	@echo "make format-check  check the formatting"
	@echo "make typecheck     run mypy"
	@echo "make install       install keysign to $(BINDIR)"
	@echo "make uninstall     remove keysign from $(BINDIR)"
	@echo "make clean         remove caches"

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

install:
	install -D -m 755 keysign $(DESTDIR)$(BINDIR)/keysign

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/keysign

clean:
	rm -rf __pycache__ tests/__pycache__ .mypy_cache .ruff_cache
