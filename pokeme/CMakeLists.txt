cmake_minimum_required(VERSION 3.20)
project(slugkit-pokeme CXX)


set(${PROJECT_NAME}_SRC
    src/slugkit/pokeme/keys.cpp
    src/slugkit/pokeme/secrets.cpp
    src/slugkit/pokeme/webhook.cpp
)

set(${PROJECT_NAME}_HEADERS
    include/slugkit/pokeme/fwd.hpp
    include/slugkit/pokeme/keys.hpp
    include/slugkit/pokeme/secrets.hpp
    include/slugkit/pokeme/webhook.hpp
)

add_library(${PROJECT_NAME} STATIC ${${PROJECT_NAME}_SRC} ${${PROJECT_NAME}_HEADERS})

target_include_directories(
    ${PROJECT_NAME}
    PUBLIC
        include
)
# OpenSSL directly, not through a userver wrapper: userver's crypto exposes the
# JWT algorithm set, and Ed25519 (PureEdDSA) is not in it.
find_package(OpenSSL REQUIRED)
target_link_libraries(
    ${PROJECT_NAME}
    PUBLIC
        userver::core
    PRIVATE
        OpenSSL::Crypto
)

if(USERVER_POKEME_BUILD_TESTS)
    add_executable(slugkit-pokeme_unittest tests/webhook_test.cpp)
    target_link_libraries(slugkit-pokeme_unittest PRIVATE ${PROJECT_NAME} userver::utest OpenSSL::Crypto)
    add_google_tests(slugkit-pokeme_unittest)
endif()
