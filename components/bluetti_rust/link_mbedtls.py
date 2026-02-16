Import("env")
import os


def patch_cmake_esp_idf(source, target, env):
    """Patch the auto-generated CMakeLists.txt to add mbedtls requirement for ESP-IDF"""
    project_dir = env.subst("$PROJECT_DIR")
    src_cmake = os.path.join(project_dir, "src", "CMakeLists.txt")

    if not os.path.exists(src_cmake):
        return

    with open(src_cmake, "r") as f:
        content = f.read()

    # Only patch if mbedtls is not already there
    if "REQUIRES mbedtls" not in content and "idf_component_register" in content:
        content = content.replace(
            "idf_component_register(SRCS ${app_sources})",
            "idf_component_register(SRCS ${app_sources} REQUIRES mbedtls)",
        )

        with open(src_cmake, "w") as f:
            f.write(content)

        print("✓ Patched src/CMakeLists.txt to include mbedtls (ESP-IDF)")


def add_mbedtls_flags_generic(source, target, env):
    """Add mbedtls linker flags for non ESP-IDF platforms (Arduino, Pico SDK, etc.)"""
    platform = env.get("PIOPLATFORM", "")
    framework = env.get("PIOFRAMEWORK", [])

    # For Raspberry Pi Pico
    if platform == "raspberrypi":
        print("✓ Raspberry Pi Pico detected - mbedtls handling via Pico SDK")
        # Pico SDK mbedtls is usually auto-linked, but we can add explicit flags if needed
        env.Append(LIBS=["pico_mbedtls"])
        return

    # For Arduino framework (not ESP-IDF)
    if "arduino" in framework:
        print("✓ Arduino framework detected - adding mbedtls library")
        # Arduino framework typically has mbedtls available
        env.Append(LIBS=["mbedtls", "mbedcrypto", "mbedx509"])
        return


# Detect platform and apply appropriate fix
platform = env.get("PIOPLATFORM", "")
framework = env.get("PIOFRAMEWORK", [])

if "espidf" in framework or framework == "espidf":
    # ESP-IDF: Patch CMakeLists.txt
    env.AddPreAction("$BUILD_DIR/project_description.json", patch_cmake_esp_idf)
else:
    # Other platforms: Add linker flags
    add_mbedtls_flags_generic(None, None, env)
