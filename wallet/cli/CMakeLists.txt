cmake_minimum_required(VERSION 3.13)

set(TARGET_NAME hds-wallet${HDS_TARGET_SUFFIX})


set(CLI_SRC
    cli.cpp
)
if(HDS_LASER_SUPPORT)
    set(CLI_SRC
        ${CLI_SRC}
        laser.cpp
    )
endif()

add_executable(${TARGET_NAME} ${CLI_SRC})
target_compile_definitions(${TARGET_NAME} PRIVATE APP_NAME=\"${TARGET_NAME}\")

if(LINUX)
    target_link_libraries(${TARGET_NAME}
        PRIVATE 
            -static-libstdc++ 
            -static-libgcc)
endif()

configure_file("${PROJECT_SOURCE_DIR}/version.h.in" "${CMAKE_CURRENT_BINARY_DIR}/version.h")
target_include_directories(${TARGET_NAME} PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(${TARGET_NAME}
    PRIVATE
        wallet
        cli
        mnemonic
)

if(HDS_LASER_SUPPORT)
    target_link_libraries(${TARGET_NAME} PRIVATE laser)
endif()

if(HDS_ATOMIC_SWAP_SUPPORT)
    target_link_libraries(${TARGET_NAME} PRIVATE swap)
endif()

if(HDS_LELANTUS_SUPPORT)
    target_compile_definitions(${TARGET_NAME} PRIVATE HDS_LELANTUS_SUPPORT)
    target_link_libraries(${TARGET_NAME} PRIVATE lelantus)
endif()

if(HDS_CONFIDENTIAL_ASSETS_SUPPORT)
    target_link_libraries(${TARGET_NAME} PRIVATE assets)
endif()

if (HDS_SIGN_PACKAGE AND WIN32)
    add_custom_command(
        TARGET ${TARGET_NAME} POST_BUILD
        COMMAND ${SIGNTOOL_EXECUTABLE} sign ${SIGNTOOL_OPTIONS} "${CMAKE_CURRENT_BINARY_DIR}\\{TARGET_NAME}.exe"
    )
endif()
