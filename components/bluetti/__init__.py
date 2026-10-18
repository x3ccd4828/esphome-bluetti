import esphome.codegen as cg
import esphome.config_validation as cv
from esphome.const import CONF_ID, CONF_MAC_ADDRESS
from esphome.core import CORE

DOMAIN = "bluetti"
CONF_ADDRESS_TYPE = "address_type"

bluetti_ns = cg.esphome_ns.namespace("bluetti")
Bluetti = bluetti_ns.class_("Bluetti", cg.Component)


def AUTO_LOAD():
    # Import ESP32's BLE components only on ESP32: their module-level
    # automations register platform-specific schemas.
    return ["bluetooth_connection"] if CORE.is_rp2 else ["ble_client"]


def CONFIG_SCHEMA(config):
    schema = cv.Schema({cv.GenerateID(): cv.declare_id(Bluetti)}).extend(
        cv.COMPONENT_SCHEMA
    )
    if CORE.is_rp2:
        from esphome.components import bluetooth_connection, rp2040_ble

        return cv.All(
            schema.extend(bluetooth_connection.gatt_client_schema()).extend(
                {
                    cv.Required(CONF_MAC_ADDRESS): cv.mac_address,
                    cv.Optional(CONF_ADDRESS_TYPE, default="public"): cv.enum(
                        {"public": 0, "random": 1}, lower=True
                    ),
                }
            ),
            rp2040_ble.consume_connection_slots(1, DOMAIN),
        )(config)
    if CORE.is_esp32:
        from esphome.components import ble_client

        return schema.extend(ble_client.BLE_CLIENT_SCHEMA)(config)
    raise cv.Invalid("Bluetti requires an ESP32 with ESP-IDF or a Pico W / Pico 2 W")


def FINAL_VALIDATE_SCHEMA(config):
    if CORE.is_esp32:
        return cv.only_with_framework("esp-idf")(config)
    return config


async def to_code(config):
    var = cg.new_Pvariable(config[CONF_ID])
    await cg.register_component(var, config)
    if CORE.is_rp2:
        from esphome.components import bluetooth_connection

        backend = await bluetooth_connection.new_gatt_backend(config)
        cg.add(backend.set_listener(var))
        cg.add(var.set_backend(backend))
        cg.add(var.set_mac_address(config[CONF_MAC_ADDRESS].as_hex))
        cg.add(var.set_address_type(config[CONF_ADDRESS_TYPE]))
    else:
        from esphome.components import ble_client, esp32

        await ble_client.register_ble_node(var, config)
        esp32.include_builtin_idf_component("mbedtls")
        esp32.add_idf_sdkconfig_option("CONFIG_MBEDTLS_MD5_C", True)
