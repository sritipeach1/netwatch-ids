.PHONY: demo lab test train api web
demo:       ## simulated sensor + API + dashboard on :3000
	docker compose up --build
lab:        ## real Suricata lab (Linux Docker host)
	docker compose -f lab/docker-compose.lab.yml up --build
test:
	cd api && python -m pytest -q
train:      ## retrain the flow classifier on simulated traffic
	cd api && python -m app.training
api:
	cd api && uvicorn app.main:app --reload --port 8000
web:
	cd web && npm run dev
