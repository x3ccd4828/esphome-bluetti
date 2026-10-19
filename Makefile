.PHONY: compile run logs clean

CONFIG ?= bluetti-el30v2-esp32.yaml
IMAGE ?= docker.io/esphome/esphome:latest
DEVICE ?= bluetti-el30v2.local
CACHE_DIR ?= $(CURDIR)/.esphome/cache

# Host networking lets OTA and mDNS reach the ESP32. Disabling labels allows
# access to this checkout on SELinux hosts without relabeling its files.
ESPHOME = podman run --rm --network=host --security-opt label=disable \
	-v "$(CURDIR):/config" -v "$(CACHE_DIR):/cache" $(IMAGE)

compile run logs clean:
	mkdir -p "$(CACHE_DIR)"
	$(ESPHOME) $@ $(CONFIG) $(if $(filter run logs,$@),--device $(DEVICE))
