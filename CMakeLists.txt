cmake_minimum_required(VERSION 3.16)
project(mailer CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
if (NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

option(BUNDLED_DEP "Use Bundled OpenSSL, cURL and Boost." OFF)
if (BUNDLED_DEP)
    set(BUNDLED_DEP_PREFIX "Path to bundled output" "build_bundled/output")
    list(INSERT CMAKE_PREFIX_PATH 0 ${BUNDLED_DEP_PREFIX})
endif()

find_package(CURL REQUIRED COMPONENTS SMTP)
set(Boost_USE_STATIC_LIBS   ON)  # only find static libs
set(Boost_USE_DEBUG_LIBS    OFF) # ignore debug libs and
set(Boost_USE_RELEASE_LIBS  ON)  # only find release libs
set(Boost_USE_MULTITHREADED OFF)
find_package(Boost REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(ZNC znc)

# Detect if ZNC's pkg-config definition is broken.
# If it is broken, read the LIBS= defined in the znc-buildmod shellscript.
list(LENGTH ZNC_LIBRARIES LIB_LEN)
if (${LIB_LEN} EQUAL 0)
    find_program(ZNC_BUILDMOD
        NAMES znc-buildmod
    )
    if("${ZNC_BUILDMOD}" EQUAL "ZNC_BUILDMOD-NOTFOUND")
        message(FATAL_ERROR "Could not find znc-buildmod utility")
    endif()

    file(READ "${ZNC_BUILDMOD}" ZNC_LIBS)
    if("${ZNC_LIBS}" MATCHES "LIBS=\"([^$\"]*)")
        string(REGEX REPLACE " +" ";" ZNC_LIBRARIES "${CMAKE_MATCH_1}")
    else()
        message(WARNING "ZNC pkg-config defintion does not list any libraries.")
    endif()
endif()

add_library(${PROJECT_NAME} SHARED ${PROJECT_NAME}.cpp)
target_link_libraries(${PROJECT_NAME}
    PRIVATE ${CURL_LIBRARIES}
    PRIVATE ${ZNC_LIBRARIES}
)
target_include_directories(${PROJECT_NAME}
    PRIVATE ${Boost_INCLUDE_DIRS}
    PRIVATE ${ZNC_INCLUDE_DIRS}
)
target_compile_options(${PROJECT_NAME}
    PRIVATE ${ZNC_CFLAGS}
)

install(TARGETS ${PROJECT_NAME}
    DESTINATION lib/
    PERMISSIONS
        OWNER_READ OWNER_WRITE OWNER_EXECUTE
        GROUP_READ GROUP_EXECUTE
        WORLD_READ WORLD_EXECUTE
)
