cmake_minimum_required(VERSION 3.13)

add_subdirectory(core)
add_subdirectory(client)


if(HDS_ATOMIC_SWAP_SUPPORT)
    add_subdirectory(transactions/swaps)
endif()

if(HDS_LELANTUS_SUPPORT)
    add_subdirectory(transactions/lelantus)
endif()

if(HDS_CONFIDENTIAL_ASSETS_SUPPORT)
    add_subdirectory(transactions/assets)
endif()

if (NOT ANDROID AND NOT IOS)
    if(HDS_LASER_SUPPORT)
        add_subdirectory(laser)
    endif()
    if(NOT HDS_WALLET_CLIENT_LIBRARY)
        add_subdirectory(cli)

        add_subdirectory(api)

        add_subdirectory(broadcaster)

        add_subdirectory(service)

        if(HDS_TESTS_ENABLED)
            add_subdirectory(unittests)
        endif()
    endif()
endif()


