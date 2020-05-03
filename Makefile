define ALL
	update-requirements
	update-wheelhouse
endef
ALL:=$(shell echo $(ALL))  # to remove line-feeds

define REQUIREMENTS_FILES
	requirements-dev.txt
	requirements-test.txt
	requirements.txt
endef
REQUIREMENTS_FILES:=$(shell echo $(REQUIREMENTS_FILES))

define REQUIREMENTS_IN
	requirements.in
endef
REQUIREMENTS_IN:=$(shell echo $(REQUIREMENTS_IN))

define REQUIREMENTS_IN_TEST
	requirements-test.in
	requirements.in
endef
REQUIREMENTS_IN_TEST:=$(shell echo $(REQUIREMENTS_IN_TEST))

define REQUIREMENTS_IN_DEV
	requirements-dev.in
	requirements-test.in
	requirements.in
endef
REQUIREMENTS_IN_DEV:=$(shell echo $(REQUIREMENTS_IN_DEV))

offline?=0


.PHONY: all
all: $(ALL)

.PHONY: update-requirements

ifeq (1,$(offline))
PIP_NO_INDEX:=--no-index
endif

FIND_LINKS:=-f virtualenv_support

update-requirements: $(REQUIREMENTS_FILES)
	pip-sync $(FIND_LINKS) $(PIP_NO_INDEX) requirements-dev.txt
	. bin/activate && pip install -e . --no-deps -f virtualenv_support

requirements.txt: $(REQUIREMENTS_IN)
	pip-compile $(FIND_LINKS) $(PIP_NO_INDEX) -o $@ $^

requirements-test.txt: $(REQUIREMENTS_IN_TEST)
	pip-compile $(FIND_LINKS) $(PIP_NO_INDEX) -o $@ $^

requirements-dev.txt: $(REQUIREMENTS_IN_DEV)
	pip-compile $(FIND_LINKS) $(PIP_NO_INDEX) -o $@ $^

.PHONY: update-wheelhouse
update-wheelhouse: bootstrap-virtualenv.py
bootstrap-virtualenv.py: requirements.txt bootstrap-virtualenv.in
	python setup.py virtualenv_bootstrap_script -o $@ -r $<

run-daemon:
	. bin/activate && twistd -y xoauth2relay.tac
