cmake_minimum_required(VERSION 3.20)
project(SecureMsg VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ---------------------------------------------------------------------------
# Qt6 — UI framework
# Set Qt6_DIR if Qt is not on PATH: cmake -DQt6_DIR=/path/to/qt/lib/cmake/Qt6
# ---------------------------------------------------------------------------
find_package(Qt6 REQUIRED COMPONENTS Core Widgets Network)
qt_standard_project_setup()

# ---------------------------------------------------------------------------
# libsodium — cryptographic operations (X25519, Ed25519, XSalsa20-Poly1305)
# Install via: apt install libsodium-dev  |  brew install libsodium
#              vcpkg install libsodium     |  conan install libsodium
# ---------------------------------------------------------------------------
find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED libsodium)

# ---------------------------------------------------------------------------
# libcurl — HTTP client for REST API calls
# ---------------------------------------------------------------------------
find_package(CURL REQUIRED)

# ---------------------------------------------------------------------------
# Sources
# ---------------------------------------------------------------------------
set(SOURCES
    src/main.cpp
    src/Client.cpp
    src/Message.cpp
    src/User.cpp
    src/MessageStore.cpp
)

set(HEADERS
    src/Client.hpp
    src/Message.hpp
    src/User.hpp
    src/MessageStore.hpp
)

qt_add_executable(SecureMsg ${SOURCES} ${HEADERS})

target_include_directories(SecureMsg PRIVATE
    src
    ${SODIUM_INCLUDE_DIRS}
)

target_link_libraries(SecureMsg PRIVATE
    Qt6::Core
    Qt6::Widgets
    Qt6::Network
    ${SODIUM_LIBRARIES}
    CURL::libcurl
)

# ---------------------------------------------------------------------------
# Build type defaults
# ---------------------------------------------------------------------------
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# Treat warnings as errors in debug builds
target_compile_options(SecureMsg PRIVATE
    $<$<CONFIG:Debug>:-Wall -Wextra -Wpedantic>
)

install(TARGETS SecureMsg DESTINATION bin)
