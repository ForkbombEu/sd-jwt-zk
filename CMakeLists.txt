cmake_minimum_required(VERSION 3.20)
project(SDJWTZK VERSION 0.1.0 LANGUAGES CXX)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)
include(CTest)

set(SD_JWT_ZK_LONGFELLOW_TARGET "LongfellowZK::static" CACHE STRING
  "Installed LongfellowZK exported target used by sd-jwt-zk")
option(SD_JWT_ZK_ENABLE_SANITIZERS "Enable address and undefined behaviour sanitizers" OFF)
option(SD_JWT_ZK_ENABLE_EXPENSIVE_PROOF_TESTS "Enable tests that require compiled proof circuits (none in bootstrap)" OFF)
find_package(LongfellowZK CONFIG REQUIRED)
if(NOT TARGET "${SD_JWT_ZK_LONGFELLOW_TARGET}")
  message(FATAL_ERROR "SD_JWT_ZK_LONGFELLOW_TARGET must name an installed LongfellowZK target")
endif()

add_library(sd-jwt-zk src/codec.cc src/native.cc src/sha256.cc)
add_library(SDJWTZK::sd-jwt-zk ALIAS sd-jwt-zk)
target_compile_features(sd-jwt-zk PUBLIC cxx_std_20)
target_include_directories(sd-jwt-zk PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)
target_link_libraries(sd-jwt-zk PUBLIC "${SD_JWT_ZK_LONGFELLOW_TARGET}")
target_compile_options(sd-jwt-zk PRIVATE -Wall -Wextra -Wpedantic -Werror)
if(SD_JWT_ZK_ENABLE_SANITIZERS AND CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
  target_compile_options(sd-jwt-zk PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
  target_link_options(sd-jwt-zk PUBLIC -fsanitize=address,undefined)
endif()

add_executable(sd-jwt-zk-cli src/main.cc)
set_target_properties(sd-jwt-zk-cli PROPERTIES OUTPUT_NAME sd-jwt-zk)
target_link_libraries(sd-jwt-zk-cli PRIVATE SDJWTZK::sd-jwt-zk)

install(TARGETS sd-jwt-zk sd-jwt-zk-cli EXPORT SDJWTZKTargets
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(EXPORT SDJWTZKTargets FILE SDJWTZKTargets.cmake NAMESPACE SDJWTZK::
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/SDJWTZK)
configure_package_config_file(cmake/SDJWTZKConfig.cmake.in
  ${CMAKE_CURRENT_BINARY_DIR}/SDJWTZKConfig.cmake
  INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/SDJWTZK)
write_basic_package_version_file(${CMAKE_CURRENT_BINARY_DIR}/SDJWTZKConfigVersion.cmake
  VERSION ${PROJECT_VERSION} COMPATIBILITY SameMajorVersion)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/SDJWTZKConfig.cmake
  ${CMAKE_CURRENT_BINARY_DIR}/SDJWTZKConfigVersion.cmake
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/SDJWTZK)
install(FILES README.md DESTINATION ${CMAKE_INSTALL_DATADIR}/doc/SDJWTZK)

if(BUILD_TESTING)
  add_executable(sd-jwt-zk-tests tests/cpp/test_main.cc)
  target_link_libraries(sd-jwt-zk-tests PRIVATE SDJWTZK::sd-jwt-zk)
  target_compile_definitions(sd-jwt-zk-tests PRIVATE SD_JWT_ZK_TESTDATA_DIR="${CMAKE_CURRENT_SOURCE_DIR}/tests/cpp/testdata")
  add_test(NAME sd-jwt-zk-tests COMMAND sd-jwt-zk-tests)
  add_test(NAME sd-jwt-zk-cli-help COMMAND sd-jwt-zk-cli --help)
  find_package(Python3 COMPONENTS Interpreter REQUIRED)
  add_test(NAME sd-jwt-zk-fixtures COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_fixtures.py)
  add_test(NAME sd-jwt-zk-documentation COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_documentation.py)
endif()
