#Makefile for sabbat-tools
# Variables
PY?=python3
VENV?=.venv
GEOIP_DIR?=data/GeoLite2
GEOIP_DB?=$(GEOIP_DIR)/GeoLite2-Country.mmdb
GEOLITE_LICENSE_KEY?=$(GEOLITE_LICENSE_KEY)

.PHONY: venv install download-geolite verify-extras lint test build clean

venv:
	$(PY) -m venv $(VENV)
	. $(VENV)/bin/activate && pip install -U pip wheel

install: venv
	. $(VENV)/bin/activate && pip install -r requirements.txt

download-geolite:
	@mkdir -p $(GEOIP_DIR)
	@if [ -z "$(GEOLITE_LICENSE_KEY)" ]; then \
		echo "ERROR: define GEOLITE_LICENSE_KEY en el entorno"; exit 1; \
	fi
	@$(PY) scripts/download_geolite.py --license-key "$(GEOLITE_LICENSE_KEY)" --out "$(GEOIP_DB)"
	@echo "OK: Base GeoLite2 descargada en $(GEOIP_DB)"

verify-extras:
	@$(PY) scripts/verify_extras.py

lint:
	. $(VENV)/bin/activate && ruff check .

test:
	. $(VENV)/bin/activate && pytest -q

build:
	. $(VENV)/bin/activate && python -m build

clean:
	rm -rf $(VENV) dist build *.egg-info .pytest_cache .ruff_cache
