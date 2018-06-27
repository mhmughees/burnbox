

set(CMAKE_CXX_STANDARD 11)




set(TEST_SRCS test-main.cpp test.cpp testgetallkeys.cpp)
add_executable(tests ${TEST_SRCS})

message(STATUS "Included: " ${CMAKE_SOURCE_DIR})

target_include_directories(tests PUBLIC ${CMAKE_SOURCE_DIR}/src ${CMAKE_BINARY_DIR}/src)

target_link_libraries(tests testb2 cryptopp)

enable_testing()
find_file(test_exec tests PATHS ${CMAKE_BINARY_DIR})

message("\n test cases are ${test_exec}\n")
add_test(tests ${test_exec} -d yes)


#add_executable(b2 main.cpp Tree.cpp Tree.h UtilCrypto.cpp UtilCrypto.h BurnboxApi.cpp BurnboxApi.h UtilPKCrypto.cpp UtilPKCrypto.h Util.h ClientServer.cpp ClientServer.h  test.cpp catch.hpp)
#
#
#FIND_PACKAGE( Boost COMPONENTS system filesystem program_options REQUIRED )
#INCLUDE_DIRECTORIES( ${Boost_INCLUDE_DIR} )
#
#target_link_libraries(b2  protobuf cryptopp  ${Boost_LIBRARIES}  ${Boost_FILESYSTEM_LIBRARY})