if(NOT DEFINED PS5_PAYLOAD_SDK)
    if(DEFINED ENV{PS5_PAYLOAD_SDK})
        set(PS5_PAYLOAD_SDK $ENV{PS5_PAYLOAD_SDK} CACHE PATH "Path to PS5 Payload SDK")
    else()
        message(FATAL_ERROR
            "PS5_PAYLOAD_SDK not set.\n"
            "Set it as an environment variable or in CMakePresets.json")
    endif()
endif()

if(NOT EXISTS "${PS5_PAYLOAD_SDK}/toolchain/prospero.cmake")
    message(FATAL_ERROR
        "Invalid PS5_PAYLOAD_SDK: ${PS5_PAYLOAD_SDK}\n"
        "Could not find toolchain/prospero.cmake")
endif()

include("${PS5_PAYLOAD_SDK}/toolchain/prospero.cmake")
