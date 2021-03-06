set(TARGET_NAME libbitcoin_message)

file(GLOB SOURCES "*.cpp")
file(GLOB HEADERS "${LIBBITCOIN_INCLUDE_DIR}/message/*.hpp")

add_library(${TARGET_NAME} OBJECT ${SOURCES} ${HEADERS})

if(MSVC)
    target_compile_options(${TARGET_NAME} PUBLIC "/wd4245")
    target_compile_options(${TARGET_NAME} PUBLIC "/wd4505")
    target_compile_options(${TARGET_NAME} PUBLIC "/wd4996")
elseif(APPLE)
    target_compile_options(${TARGET_NAME} PUBLIC -Wno-mismatched-tags)
    target_compile_options(${TARGET_NAME} PUBLIC -Wno-missing-braces)
elseif(ANDROID)
    target_compile_options(${TARGET_NAME} PUBLIC -Wno-tautological-constant-compare)
    target_compile_options(${TARGET_NAME} PUBLIC -Wno-mismatched-tags)
else()
    target_compile_options(${TARGET_NAME} PUBLIC -fpermissive)
endif()

target_link_libraries(${TARGET_NAME} Boost::boost)
