.PHONY: all lint types test redteam
all: lint types test redteam
lint:
	ruff check . && ruff format --check .
types:
	mypy src
test:
	pytest --cov=agentmesh -q
redteam:
	python -m agentmesh redteam
