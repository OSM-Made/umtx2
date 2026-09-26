cmake_minimum_required(VERSION 3.19)
project(HvDefeat VERSION 1.0.0 LANGUAGES C CXX)

if(DEFINED ENV{PS5_PAYLOAD_SDK})
    set(PS5_SDK_ROOT "$ENV{PS5_PAYLOAD_SDK}" CACHE PATH "PS5 Payload SDK root")
else()
    set(PS5_SDK_ROOT "${CMAKE_SOURCE_DIR}/../../../Vesper/External/PS5-Payload-SDK"
        CACHE PATH "PS5 Payload SDK root (fallback)")
endif()

set(OUTPUT_DIR "${CMAKE_SOURCE_DIR}/Build")
set(PS5_HOST "ps5"  CACHE STRING "PS5 hostname or IP")
set(PS5_PORT "9021" CACHE STRING "PS5 payload port")

find_program(LLVM_STRIP NAMES llvm-strip REQUIRED)

add_executable(HvDefeat main.cpp)

set_target_properties(HvDefeat PROPERTIES
    OUTPUT_NAME              "hv_defeat.elf"
    RUNTIME_OUTPUT_DIRECTORY "${OUTPUT_DIR}"
    CXX_STANDARD             20
    CXX_STANDARD_REQUIRED    ON
)

target_compile_options(HvDefeat PRIVATE -Os -Wall -Werror -g -ffunction-sections -fdata-sections)
target_link_options(HvDefeat PRIVATE -Wl,--gc-sections)
target_link_libraries(HvDefeat PRIVATE kernel_sys c c++)

set(FINAL_ELF "${OUTPUT_DIR}/hv_defeat.elf")

add_custom_command(TARGET HvDefeat POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E make_directory "${OUTPUT_DIR}"
    COMMAND ${CMAKE_COMMAND} -E copy "$<TARGET_FILE:HvDefeat>" "${FINAL_ELF}"
    COMMAND "${LLVM_STRIP}" --strip-all --strip-debug "${FINAL_ELF}"
    COMMENT "Stripping ${FINAL_ELF}"
)

if(CMAKE_HOST_WIN32)
    set(PS5_DEPLOY "${PS5_SDK_ROOT}/win/prospero-deploy.cmd")
else()
    set(PS5_DEPLOY "${PS5_SDK_ROOT}/bin/prospero-deploy")
endif()

add_custom_target(Deploy
    DEPENDS HvDefeat
    COMMAND "${PS5_DEPLOY}" -h "${PS5_HOST}" -p "${PS5_PORT}" "${FINAL_ELF}"
    COMMENT "Deploying ${FINAL_ELF} to ${PS5_HOST}:${PS5_PORT}"
    USES_TERMINAL
)
