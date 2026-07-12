.PHONY: install dev-install setup up down logs run run-api run-streamlit test coverage format lint typecheck pre-commit clean

install:
	python -m pip install -r requirements.txt

dev-install:
	python -m pip install -r requirements-dev.txt

setup:
	python scripts/start.py

up:
	docker compose up -d --build netwatch

down:
	docker compose down

logs:
	docker compose logs -f netwatch

run: run-api

run-api:
	uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload

run-streamlit:
	streamlit run app.py

test:
	pytest -q

coverage:
	pytest -q --cov=. --cov-report=term-missing --cov-report=xml

format:
	black .
	isort .

lint:
	black --check .
	isort --check-only .
	flake8 .

typecheck:
	mypy .

pre-commit:
	pre-commit run --all-files

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	rm -f .coverage coverage.xml
