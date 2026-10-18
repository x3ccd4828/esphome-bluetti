import esphome.codegen as cg
import esphome.config_validation as cv
from esphome.components import ble_client, esp32
from esphome.const import CONF_ID

DEPENDENCIES = ["ble_client"]
DOMAIN = "bluetti"

bluetti_ns = cg.esphome_ns.namespace("bluetti")
Bluetti = bluetti_ns.class_("Bluetti", cg.Component, ble_client.BLEClientNode)

CONFIG_SCHEMA = (
    cv.Schema(
        {
            cv.GenerateID(): cv.declare_id(Bluetti),
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

    esp32.include_builtin_idf_component("mbedtls")
    esp32.add_idf_sdkconfig_option("CONFIG_MBEDTLS_MD5_C", True)
