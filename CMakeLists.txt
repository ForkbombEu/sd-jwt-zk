cmake_minimum_required(VERSION 3.20)
project(SDJWTZK VERSION 0.1.0 LANGUAGES CXX)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)
include(CTest)

set(SD_JWT_ZK_LONGFELLOW_TARGET "LongfellowZK::longfellow-zk" CACHE STRING
  "Installed LongfellowZK exported target used by sd-jwt-zk")
option(SD_JWT_ZK_ENABLE_SANITIZERS "Enable address and undefined behaviour sanitizers" OFF)
option(SD_JWT_ZK_ENABLE_EXPENSIVE_PROOF_TESTS
  "Enable real compiled-circuit proof round-trip tests" OFF)
find_package(LongfellowZK CONFIG REQUIRED)
find_package(OpenSSL REQUIRED COMPONENTS Crypto)
if(NOT TARGET "${SD_JWT_ZK_LONGFELLOW_TARGET}")
  message(FATAL_ERROR "SD_JWT_ZK_LONGFELLOW_TARGET must name an installed LongfellowZK target")
endif()

add_library(sd-jwt-zk src/codec.cc src/native.cc src/restricted_json.cc
  src/sha256.cc src/flat_bearer_witness.cc src/flat_bearer_proof.cc
  src/holder_kb_witness.cc src/holder_credential_witness.cc
  src/holder_bound_proof.cc)
add_library(SDJWTZK::sd-jwt-zk ALIAS sd-jwt-zk)
target_compile_features(sd-jwt-zk PUBLIC cxx_std_20)
target_include_directories(sd-jwt-zk PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)
target_link_libraries(sd-jwt-zk PUBLIC "${SD_JWT_ZK_LONGFELLOW_TARGET}" OpenSSL::Crypto)
target_compile_options(sd-jwt-zk PRIVATE -Wall -Wextra -Wpedantic -Werror)
if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64")
  # The production holder bridge uses Longfellow's GF(2^128) MAC primitive.
  target_compile_options(sd-jwt-zk PRIVATE -mpclmul)
endif()
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
  add_executable(sd-jwt-zk-holder-bound-adapter-contract
    tests/cpp/holder_bound_adapter_contract.cc)
  target_link_libraries(sd-jwt-zk-holder-bound-adapter-contract
    PRIVATE SDJWTZK::sd-jwt-zk)
  add_test(NAME sd-jwt-zk-holder-bound-adapter-contract
    COMMAND sd-jwt-zk-holder-bound-adapter-contract)
  if(SD_JWT_ZK_ENABLE_EXPENSIVE_PROOF_TESTS)
    # These targets compile production-scale circuits and have measured peak
    # RSS above 1.5 GiB.  Keep them in the same explicit opt-in lane as real
    # proofs so an ordinary CTest run is resource-bounded.
    add_executable(sd-jwt-zk-issuer-relation-compile
      tests/cpp/issuer_relation_compile.cc)
    target_link_libraries(sd-jwt-zk-issuer-relation-compile
      PRIVATE SDJWTZK::sd-jwt-zk)
    add_test(NAME sd-jwt-zk-issuer-relation-compile
      COMMAND sd-jwt-zk-issuer-relation-compile)
    add_executable(sd-jwt-zk-flat-bearer-factory
      tests/cpp/flat_bearer_factory_compile.cc)
    target_link_libraries(sd-jwt-zk-flat-bearer-factory
      PRIVATE SDJWTZK::sd-jwt-zk)
    add_test(NAME sd-jwt-zk-flat-bearer-factory
      COMMAND sd-jwt-zk-flat-bearer-factory)
    add_executable(sd-jwt-zk-flat-bearer-proof-roundtrip
      tests/cpp/flat_bearer_proof_roundtrip.cc)
    target_link_libraries(sd-jwt-zk-flat-bearer-proof-roundtrip
      PRIVATE SDJWTZK::sd-jwt-zk)
    add_test(NAME sd-jwt-zk-flat-bearer-proof-roundtrip
      COMMAND sd-jwt-zk-flat-bearer-proof-roundtrip)
    add_executable(sd-jwt-zk-holder-two-proof-mac-bridge
      tests/cpp/holder_two_proof_mac_bridge.cc)
    target_link_libraries(sd-jwt-zk-holder-two-proof-mac-bridge
      PRIVATE SDJWTZK::sd-jwt-zk)
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64")
      target_compile_options(sd-jwt-zk-holder-two-proof-mac-bridge PRIVATE -mpclmul)
    endif()
    add_test(NAME sd-jwt-zk-holder-two-proof-mac-bridge
      COMMAND sd-jwt-zk-holder-two-proof-mac-bridge)
  endif()
  add_executable(sd-jwt-zk-restricted-json-relation tests/cpp/restricted_json_relation_test.cc)
  target_link_libraries(sd-jwt-zk-restricted-json-relation PRIVATE SDJWTZK::sd-jwt-zk)
  add_test(NAME sd-jwt-zk-restricted-json-relation COMMAND sd-jwt-zk-restricted-json-relation)
  add_executable(sd-jwt-zk-kb-jws-relation tests/cpp/kb_jws_relation_test.cc)
  target_link_libraries(sd-jwt-zk-kb-jws-relation PRIVATE SDJWTZK::sd-jwt-zk)
  add_test(NAME sd-jwt-zk-kb-jws-relation COMMAND sd-jwt-zk-kb-jws-relation)
  add_executable(sd-jwt-zk-holder-issuer-bridge tests/cpp/holder_issuer_bridge_test.cc)
  target_link_libraries(sd-jwt-zk-holder-issuer-bridge PRIVATE SDJWTZK::sd-jwt-zk)
  add_test(NAME sd-jwt-zk-holder-issuer-bridge COMMAND sd-jwt-zk-holder-issuer-bridge)
  add_executable(sd-jwt-zk-holder-fixture-bridge tests/cpp/holder_fixture_bridge_test.cc)
  target_link_libraries(sd-jwt-zk-holder-fixture-bridge PRIVATE SDJWTZK::sd-jwt-zk)
  add_test(NAME sd-jwt-zk-holder-fixture-bridge COMMAND sd-jwt-zk-holder-fixture-bridge)
  add_executable(sd-jwt-zk-active-presentation-hash-bridge
    tests/cpp/active_presentation_hash_bridge_test.cc)
  target_link_libraries(sd-jwt-zk-active-presentation-hash-bridge
    PRIVATE SDJWTZK::sd-jwt-zk)
  add_test(NAME sd-jwt-zk-active-presentation-hash-bridge
    COMMAND sd-jwt-zk-active-presentation-hash-bridge)
  # The production-scale credential composition is intentionally opt-in while
  # its capacity is being reduced; neither it nor the retained monolithic
  # experiment may be selected by the default holder component test set.
  if(SD_JWT_ZK_ENABLE_EXPENSIVE_PROOF_TESTS)
    # This compiler-scale relation test exceeded a 120-second standalone
    # bound.  It remains independent soundness evidence in the opt-in lane.
    add_executable(sd-jwt-zk-active-presentation-message-relation
      tests/cpp/active_presentation_message_relation_test.cc)
    target_link_libraries(sd-jwt-zk-active-presentation-message-relation
      PRIVATE SDJWTZK::sd-jwt-zk)
    add_test(NAME sd-jwt-zk-active-presentation-message-relation
      COMMAND sd-jwt-zk-active-presentation-message-relation)
    add_executable(sd-jwt-zk-holder-presentation-factory
      tests/cpp/holder_presentation_factory_compile.cc)
    target_link_libraries(sd-jwt-zk-holder-presentation-factory
      PRIVATE SDJWTZK::sd-jwt-zk)
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64")
      target_compile_options(sd-jwt-zk-holder-presentation-factory PRIVATE -mpclmul)
    endif()
    add_test(NAME sd-jwt-zk-holder-presentation-factory
      COMMAND sd-jwt-zk-holder-presentation-factory)
    set_tests_properties(sd-jwt-zk-holder-presentation-factory
      PROPERTIES DISABLED TRUE)
    add_executable(sd-jwt-zk-holder-credential-factory
      tests/cpp/holder_credential_factory_compile.cc)
    target_link_libraries(sd-jwt-zk-holder-credential-factory PRIVATE SDJWTZK::sd-jwt-zk)
    target_compile_definitions(sd-jwt-zk-holder-credential-factory
      PRIVATE SD_JWT_ZK_HOLDER_FACTORY_METRICS=1)
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64")
      target_compile_options(sd-jwt-zk-holder-credential-factory PRIVATE -mpclmul)
    endif()
    add_test(NAME sd-jwt-zk-holder-credential-factory
      COMMAND sd-jwt-zk-holder-credential-factory)
    add_executable(sd-jwt-zk-holder-kb-factory
      tests/cpp/holder_kb_factory_compile.cc)
    target_link_libraries(sd-jwt-zk-holder-kb-factory PRIVATE SDJWTZK::sd-jwt-zk)
    target_compile_definitions(sd-jwt-zk-holder-kb-factory
      PRIVATE SD_JWT_ZK_HOLDER_FACTORY_METRICS=1)
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64")
      target_compile_options(sd-jwt-zk-holder-kb-factory PRIVATE -mpclmul)
    endif()
    add_test(NAME sd-jwt-zk-holder-kb-factory COMMAND sd-jwt-zk-holder-kb-factory)
    add_executable(sd-jwt-zk-holder-real-pair-proof tests/cpp/holder_real_pair_proof.cc)
    target_link_libraries(sd-jwt-zk-holder-real-pair-proof PRIVATE SDJWTZK::sd-jwt-zk)
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64")
      target_compile_options(sd-jwt-zk-holder-real-pair-proof PRIVATE -mpclmul)
    endif()
    add_test(NAME sd-jwt-zk-holder-real-pair-proof COMMAND sd-jwt-zk-holder-real-pair-proof)
    add_executable(sd-jwt-zk-holder-bound-api-real-proof
      tests/cpp/holder_bound_api_real_proof.cc)
    target_link_libraries(sd-jwt-zk-holder-bound-api-real-proof
      PRIVATE SDJWTZK::sd-jwt-zk)
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64")
      target_compile_options(sd-jwt-zk-holder-bound-api-real-proof PRIVATE -mpclmul)
    endif()
    add_test(NAME sd-jwt-zk-holder-bound-api-real-proof
      COMMAND sd-jwt-zk-holder-bound-api-real-proof)
  endif()
  add_test(NAME sd-jwt-zk-cli-help COMMAND sd-jwt-zk-cli --help)
  find_package(Python3 COMPONENTS Interpreter REQUIRED)
  add_test(NAME sd-jwt-zk-fixtures COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_fixtures.py)
  add_test(NAME sd-jwt-zk-documentation COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_documentation.py)
endif()
