cmake_minimum_required (VERSION 2.6)
project (packetier-erps)

# The version number.
set (ERPSd_VERSION_MAJOR 1)
set (ERPSd_VERSION_MINOR 0)

# Set -std=c++11 as the feature of std::thread is used.
set (CMAKE_CXX_STANDARD 11)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

set(CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake_modules)

# configure a header file to pass some of the CMake settings
# to the source code
configure_file (
  "${PROJECT_SOURCE_DIR}/config.h.in"
  "${PROJECT_BINARY_DIR}/config.h"
  )


include_directories(${PROJECT_SOURCE_DIR}/include)
include_directories(${PROJECT_BINARY_DIR})

add_subdirectory(src)

#
# Install target
#
set(CMAKE_INSTALL_PREFIX "${PROJECT_BINARY_DIR}/install/opt/packetier-erps")

#
# build a CPack driven installer package
#

include (InstallRequiredSystemLibraries)
set (CPACK_RESOURCE_FILE_LICENSE
     "${CMAKE_CURRENT_SOURCE_DIR}/License.txt")
set (CPACK_GENERATOR "RPM")
set (CPACK_SOURCE_GENERATOR "RPM")
set (CPACK_PACKAGING_INSTALL_PREFIX ${CMAKE_INSTALL_PREFIX})
set (CPACK_PACKAGE_VERSION_MAJOR "${ERPSd_VERSION_MAJOR}")
set (CPACK_PACKAGE_VERSION_MINOR "${ERPSd_VERSION_MINOR}")
set (CPACK_SOURCE_IGNORE_FILES "build" ".git" "#")
set (CPACK_PACKAGE_DESCRIPTION_FILE "${CMAKE_CURRENT_SOURCE_DIR}/README.txt")

include (CPack)

