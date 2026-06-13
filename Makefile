.PHONY: validate test run report init-db

validate:
	python scripts/check_requirements.py
	python -m compileall -q .

test:
	python -m unittest discover -s tests

init-db:
	python database/db.py

run:
	python app.py

report:
	python reports/pdf_generator.py
