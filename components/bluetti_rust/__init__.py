import esphome.codegen as cg
import esphome.config_validation as cv
from esphome.components import ble_client
from esphome.const import CONF_ID

DEPENDENCIES = ["ble_client"]

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


async def to_code(config):
    var = cg.new_Pvariable(config[CONF_ID])
    await cg.register_component(var, config)
    await ble_client.register_ble_node(var, config)
    
    # Add custom build script to link mbedtls properly
    import pathlib
    script_path = pathlib.Path(__file__).parent / "link_mbedtls.py"
    cg.add_platformio_option("extra_scripts", ["pre:" + str(script_path)])
