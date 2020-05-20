.PHONY: precommit test lint_cmd test_cmd build_cmd release_cmd clean
test: test_cmd plan_terraform

lint_cmd: precommit
	make -C cmd lint

test_cmd: precommit
	make -C cmd test

build_cmd: precommit
	make -C cmd build

release_cmd: precommit
	make -C cmd release

clean: precommit
	make -C cmd clean

precommit:
ifneq ($(strip $(hooksPath)),.github/hooks)
	@git config --add core.hooksPath .github/hooks
endif
