cmake_minimum_required( VERSION 2.8 )

project( botan-pottcpp )

include( CTest )
include( CheckCXXCompilerFlag )

find_package( PkgConfig REQUIRED )
pkg_check_modules( BOTAN REQUIRED botan-1.11 )
include_directories( ${BOTAN_INCLUDE_DIRS} )

# Set the standard to the most recent revision supported (C++14 or C++11)
if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU" OR "${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
    CHECK_CXX_COMPILER_FLAG("-std=c++14" CXXFLAG_CPP14)

    if(NOT "${CXXFLAG_CPP14}")
        CHECK_CXX_COMPILER_FLAG("-std=c++11" CXXFLAG_CPP11)

        if(NOT "${CXXFLAG_CPP11}")
            message(WARNING "Your compiler does not support C++11. Please use clang 3.0 or GCC 4.6.")
            set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++0x")
        else()
            set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
        endif()
    else()
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++14")
    endif()
endif()

# Set warning level and enable colorized output on GCC
if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Wshadow")
elseif("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -pedantic")

        # Use colorized output on terminal if supported (GCC 4.9 onwards)
        CHECK_CXX_COMPILER_FLAG("-fdiagnostics-color=auto" _gcc_has_color)
        if("${_gcc_has_color}")
                set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fdiagnostics-color=auto")
        endif()
endif()

add_subdirectory( examples )