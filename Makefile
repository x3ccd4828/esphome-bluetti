.PHONY: compile run clean

CONFIG ?= bluetti-el30v2.yaml
IMAGE ?= esphome/esphome

compile:
	podman run --rm -v "$(PWD):/config" -it $(IMAGE) compile $(CONFIG)

run:
	podman run --rm -v "$(PWD):/config" -it $(IMAGE) run $(CONFIG)

clean:
	podman run --rm -v "$(PWD):/config" -it $(IMAGE) clean $(CONFIG)
