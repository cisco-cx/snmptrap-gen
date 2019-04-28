

deps:
	@if [ ! -d mibs.snmplabs.com ]; then \
	  git clone https://github.com/cisco-kusanagi/mibs.snmplabs.com.git; \
	fi

pep8:
	yapf -i $$(find * -type f -name '*.py')
	flake8 --ignore=E501 $$(find * -type f -name '*.py' | grep -v examples)

test: pep8
	pytest $$(find * -type f -name '*.py') -v --capture=no

clean:
	find * -type f -name *.pyc | xargs rm -f
	find * -type f -name *~ |xargs rm -f
	find * -type d -name __pycache__ |xargs rm -rf
	rm -rf *.egg-info
	rm -rf dist/
