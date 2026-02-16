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

FINAL_VALIDATE_SCHEMA = cv.only_with_framework("esp-idf")


async def to_code(config):
    var = cg.new_Pvariable(config[CONF_ID])
    await cg.register_component(var, config)
    await ble_client.register_ble_node(var, config)
