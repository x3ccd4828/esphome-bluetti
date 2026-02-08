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

    # Link the pre-compiled Rust static library
    # Get the directory of this __init__.py file to find the library
    import os
    component_dir = os.path.dirname(os.path.realpath(__file__))
    lib_dir = os.path.join(component_dir, "lib")
    
    cg.add_library("bluetti_encryption", lib_dir)
