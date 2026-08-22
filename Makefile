.PHONY: install test eval run-api run-ui lint docker-build docker-up

install:
	pip install -r requirements.txt

test:
	pytest tests/ -v

eval:
	python evaluation/evaluate.py

run-api:
	uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload

run-ui:
	streamlit run dashboard/app.py

lint:
	flake8 app evaluation tests --count --select=E9,F63,F7,F82 --show-source --statistics || true

docker-build:
	docker build -t promptshield .

docker-up:
	docker compose up -d
