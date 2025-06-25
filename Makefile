.PHONY: help clean lint format build test install dev-install publish-test publish

help:
	@echo "Available commands:"
	@echo "  help        - Show this help message"
	@echo "  clean       - Clean build artifacts"
	@echo "  lint        - Run linting (flake8, pylint)"
	@echo "  format      - Format code with black"
	@echo "  build       - Build package for distribution"
	@echo "  test        - Run tests"
	@echo "  install     - Install package locally"
	@echo "  dev-install - Install package in development mode"
	@echo "  publish-test - Publish to TestPyPI"
	@echo "  publish     - Publish to PyPI"

clean:
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info/
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete

lint:
	@echo "Running flake8..."
	python -m flake8 --max-line-length=88 --extend-ignore=E203,W503 *.py
	@echo "Running pylint..."
	python -m pylint --disable=C0114,C0116,R0903 *.py

format:
	@echo "Formatting code with black..."
	python -m black --line-length=88 *.py

build: clean
	@echo "Building package..."
	python -m build

test:
	@echo "Running tests..."
	python -m pytest test_*.py -v

install:
	pip install .

dev-install:
	pip install -e .

publish-test: build
	@echo "Publishing to TestPyPI..."
	python -m twine upload --repository testpypi dist/*

publish: build
	@echo "Publishing to PyPI..."
	python -m twine upload dist/*

# Development dependencies
dev-deps:
	pip install black flake8 pylint build twine pytest 