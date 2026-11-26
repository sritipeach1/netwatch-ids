.PHONY: demo lab test train train-real api web
demo:       ## simulated sensor + API + dashboard on :3000
	docker compose up --build
lab:        ## real Suricata lab (Linux Docker host)
	docker compose -f lab/docker-compose.lab.yml up --build
test:
	cd api && python -m pytest -q
train:      ## retrain the flow classifier on simulated traffic
	cd api && python -m app.training
train-real: ## train and evaluate on CIC-IDS2017:  make train-real DATA=path/to/TrafficLabelling
	cd api && python -m app.train_cicids --data "$(DATA)"
api:
	cd api && uvicorn app.main:app --reload --port 8000
web:
	cd web && npm run dev
