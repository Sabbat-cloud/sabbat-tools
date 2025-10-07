# Makefile for sabbat-tools
.PHONY: test lint fmt install dev clean

PY?=python3

install:
	$(PY) -m pip install -e .

dev:
	$(PY) -m pip install -e ".[detect,images,hardened]"
	$(PY) -m pip install -U pytest ruff

test:
	$(PY) -m pytest -vv

lint:
	ruff check .

fmt:
	ruff check . --fix

clean:
	find . -name "__pycache__" -type d -exec rm -rf {} + || true
	find . -name "*.pyc" -delete || true

toc:
		python3 scripts/gen_toc.py README.md README-ES.md --maxlevel 4

