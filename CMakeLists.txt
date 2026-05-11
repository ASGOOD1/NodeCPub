cmake_minimum_required(VERSION 3.23)

project(PCD_project)

set(CMAKE_C_STANDARD 11)
if(APPLE)
    list(APPEND CMAKE_PREFIX_PATH "/opt/homebrew/opt/openssl@3")
    set(OPENSSL_ROOT_DIR "/opt/homebrew/opt/openssl@3")
endif()
find_package(OpenSSL REQUIRED)
find_package(PCRE2   REQUIRED)

option(ENABLE_ASAN "Enable AddressSanitizer" OFF)
option(ENABLE_TSAN "Enable ThreadSanitizer" OFF)

if(ENABLE_ASAN)
    message(STATUS "Building with AddressSanitizer")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=address -fno-omit-frame-pointer")
endif()

if(ENABLE_TSAN)
    message(STATUS "Building with ThreadSanitizer")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=thread -fno-omit-frame-pointer")
endif()


find_program(CLANG_TIDY_EXE NAMES "clang-tidy")
if(CLANG_TIDY_EXE)
    message(STATUS "Found clang-tidy: ${CLANG_TIDY_EXE}")
    set(CMAKE_C_CLANG_TIDY "${CLANG_TIDY_EXE}")
endif()

add_compile_options(
    -Wall
    -Wextra
    -Wpedantic
    -Werror
    -g
    -std=c11
    -D_XOPEN_SOURCE=700
)
set(SOURCES
    src/admin.c
    src/sha256.c
)

add_executable(admin ${SOURCES})


add_compile_options(
    -Wall
    -Wextra
    -Wpedantic
    -Werror
    -g
    -std=c11
    -D_XOPEN_SOURCE=700
)
set(SOURCES
    src/client.c
    src/sha256.c
)

add_executable(client ${SOURCES})

add_compile_options(
    -Wall
    -Wextra
    -Wpedantic
    -Werror
    -g
    -std=c11
    -D_XOPEN_SOURCE=700
)
set(SOURCES
    src/server.c
    src/sha256.c
    src/base64.c
    src/scanner.c
    src/pe_scanner.c
)

add_executable(server ${SOURCES})


find_library(SQLITE3_LIB sqlite3)
if(NOT SQLITE3_LIB)
    message(FATAL_ERROR "Could not find sqlite3 library")
endif()
find_package(libconfig REQUIRED)
target_link_libraries(server PRIVATE ${SQLITE3_LIB} pthread
    OpenSSL::SSL
    OpenSSL::Crypto
    PCRE2::8BIT
    m)
if(NOT APPLE)
target_link_libraries(server PRIVATE uuid)
endif()
target_link_libraries(admin PRIVATE pthread ncurses 
    OpenSSL::SSL
    OpenSSL::Crypto)
target_link_libraries(client PRIVATE pthread 
    OpenSSL::SSL
    OpenSSL::Crypto)
target_include_directories(client PUBLIC ${libconfig_INCLUDE_DIRS})
target_link_libraries(client PUBLIC ${libconfig_LIBRARIES})
target_include_directories(server PRIVATE src/headers)
