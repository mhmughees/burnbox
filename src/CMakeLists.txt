

if (APPLE)
    find_path(FUSE_INCLUDE_DIR fuse.h PATHS /usr/local/include PATH_SUFFIXES osxfuse)
    set(FUSE_LIBRARIES /usr/local/lib/libosxfuse.dylib) #need to check because fuse liberaries is shitty and predefined it to wrong framework
    #
    #
    message("\n included fuse: ${FUSE_LIBRARIES}")
else ()
    find_path(FUSE_INCLUDE_DIR fuse.h PATHS /usr/local/include PATH_SUFFIXES fuse)
    set(FUSE_LIBRARIES /usr/local/lib/x86_64-linux-gnu/libfuse.so)

endif ()
#
include_directories(${FUSE_INCLUDE_DIR})


#add_compile_options(-Wall -Wextra -Wno-unknown-pragmas -std=gnu++11 -v)

#set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fuse-ld=gold")




add_definitions(-D_REENTRANT -D_FILE_OFFSET_BITS=64 -DFUSE_USE_VERSION=28)

find_package(Boost COMPONENTS system filesystem program_options REQUIRED)
include_directories(${Boost_INCLUDE_DIR})


set(SOURCES main.cpp bbfs.cpp bbfs.h log.cpp log.h params.h Tree.cpp Tree.h UtilCrypto.cpp UtilCrypto.h BurnboxApi.cpp BurnboxApi.h UtilPKCrypto.cpp UtilPKCrypto.h Util.h burnboxfs.cpp burnboxfs.h)
add_executable(burnbox ${SOURCES} bbfs.h)
add_library(test_burnbox ${SOURCES})


target_link_libraries(burnbox cryptopp ${Boost_LIBRARIES} ${Boost_FILESYSTEM_LIBRARY} ${FUSE_LIBRARIES})
target_link_libraries(test_burnbox cryptopp ${Boost_LIBRARIES} ${Boost_FILESYSTEM_LIBRARY} ${FUSE_LIBRARIES})