.PHONY: install test lint format clean dist upload help

help:
	@echo "BlackCloud Development Commands"
	@echo "  make install   Install package in editable mode"
	@echo "  make test      Run test suite"
	@echo "  make lint      Run flake8 linter"
	@echo "  make format    Run black formatter"
	@echo "  make clean     Remove build artifacts"
	@echo "  make dist      Build source and wheel distributions"

install:
	pip install -e ".[dev]"

test:
	pytest tests/ -v

lint:
	flake8 blackcloud/ tests/ --max-line-length=120 --ignore=E203,W503

format:
	black blackcloud/ tests/ --line-length=120

clean:
	rm -rf build/ dist/ *.egg-info .pytest_cache .coverage htmlcov/
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete

dist: clean
	python -m build

upload: dist
	python -m twine upload dist/*
