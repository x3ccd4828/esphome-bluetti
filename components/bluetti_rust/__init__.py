from pathlib import Path

import esphome.codegen as cg
import esphome.config_validation as cv
from esphome.components import ble_client, esp32
from esphome.const import CONF_ID

DEPENDENCIES = ["ble_client"]
DOMAIN = "bluetti_rust"

bluetti_rust_ns = cg.esphome_ns.namespace("bluetti_rust")
BluettiRust = bluetti_rust_ns.class_(
    "BluettiRust", cg.Component, ble_client.BLEClientNode
)

CONFIG_SCHEMA = (
    cv.Schema(
        {
            cv.GenerateID(): cv.declare_id(BluettiRust),
        }
    )
    .extend(ble_client.BLE_CLIENT_SCHEMA)
    .extend(cv.COMPONENT_SCHEMA)
)

FINAL_VALIDATE_SCHEMA = cv.All(
    cv.only_with_framework("esp-idf"),
    esp32.only_on_variant(
        supported=["ESP32"], msg_prefix="The bundled Bluetti Rust library"
    ),
)


async def to_code(config):
    var = cg.new_Pvariable(config[CONF_ID])
    await cg.register_component(var, config)
    await ble_client.register_ble_node(var, config)

    # This is a bundled archive, not a PlatformIO registry dependency.
    # Let ESP-IDF manage its linking through the component's CMakeLists.txt.
    lib_dir = Path(__file__).resolve().parent / "lib"
    if not (lib_dir / "libbluetti_encryption.a").is_file():
        raise cv.Invalid(f"Bluetti Rust archive is missing from {lib_dir}")
    esp32.add_idf_component(
        name="bluetti_encryption", path=str(lib_dir / "bluetti_encryption")
    )
