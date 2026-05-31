cmake_minimum_required(VERSION 3.20)
project(SecureMsg VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# TCP port the client uses to reach the local crypto daemon.
# Override with -DDAEMON_PORT=<n> to build a second exe that talks to a
# second daemon instance, so two clients can run side-by-side on one host.
set(DAEMON_PORT 47291 CACHE STRING "TCP port for the local crypto daemon (default 47291)")

# ---------------------------------------------------------------------------
# Qt6 — UI framework
# Set Qt6_DIR if Qt is not on PATH: cmake -DQt6_DIR=/path/to/qt/lib/cmake/Qt6
# ---------------------------------------------------------------------------
find_package(Qt6 REQUIRED COMPONENTS Core Widgets Network WebSockets)
qt_standard_project_setup()

# ---------------------------------------------------------------------------
# OpenSSL — direct TLS handshake demo (separate from libcurl's TLS stack)
# ---------------------------------------------------------------------------
find_package(OpenSSL REQUIRED)

# ---------------------------------------------------------------------------
# libcurl — HTTP client for REST API calls
# ---------------------------------------------------------------------------
find_package(CURL REQUIRED)

# ---------------------------------------------------------------------------
# libsodium — cryptographic primitives (via vcpkg unofficial-sodium port)
# ---------------------------------------------------------------------------
find_package(unofficial-sodium CONFIG REQUIRED)

# ---------------------------------------------------------------------------
# Sources
# ---------------------------------------------------------------------------
set(SOURCES
    src/main.cpp
    src/Client.cpp
    src/Message.cpp
    src/User.cpp
    src/MessageStore.cpp
    src/CryptoDaemonClient.cpp
    src/NetworkUtils.cpp
    src/TLSVerifier.cpp
    src/LoginWindow.cpp
    src/MainWindow.cpp
)

set(HEADERS
    src/Client.hpp
    src/Message.hpp
    src/User.hpp
    src/MessageStore.hpp
    src/CryptoDaemonClient.hpp
    src/NetworkUtils.hpp
    src/TLSVerifier.hpp
    src/LoginWindow.hpp
    src/MainWindow.hpp
)

qt_add_executable(SecureMsg ${SOURCES} ${HEADERS})

target_include_directories(SecureMsg PRIVATE
    src
)

target_compile_definitions(SecureMsg PRIVATE
    DAEMON_PORT=${DAEMON_PORT}
)

target_link_libraries(SecureMsg PRIVATE
    Qt6::Core
    Qt6::Widgets
    Qt6::Network
    Qt6::WebSockets
    CURL::libcurl
    unofficial-sodium::sodium
    OpenSSL::SSL
    OpenSSL::Crypto
)

if(WIN32)
    target_link_libraries(SecureMsg PRIVATE Ws2_32 Crypt32)
endif()

# ---------------------------------------------------------------------------
# Build type defaults
# ---------------------------------------------------------------------------
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# Treat warnings as errors in debug builds
target_compile_options(SecureMsg PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/W3>
    $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic>
)

install(TARGETS SecureMsg DESTINATION bin)
