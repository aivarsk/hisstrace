dist/:
	mkdir -p $@

build: dist/
	rm -rf src/hisstrace/__pycache__ build
	python3 -m pip wheel --no-deps -w dist .

lint:
	ruff check --select I --fix src/hisstrace/*.py tests/*.py
	ruff format src/hisstrace/*.py tests/*.py
	ruff check src/hisstrace tests
	-mypy src/hisstrace
	wc -l src/hisstrace/*.py | sort -n

table:
	python3 generate_table.py

test:
	PYTHONPATH=src python3 -m unittest discover -v -s tests -p "test_*.py"
