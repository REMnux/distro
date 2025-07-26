############################################################
# READ ME CLOSELY! ### READ ME CLOSELY! # READ ME CLOSELY! #
############################################################
#                                                          #
# To compile on Windows requires CMake 3.15 or later, as   #
# well as changing the next line from "VERSION 3.05" to    #
# "VERSION 3.15".  Then comment out the next if-endif      #
# block and recompile.                                     #
#                                                          #
############################################################

cmake_minimum_required(VERSION 3.05)

if (MSVC)
  message(FATAL_ERROR "You need to edit CMakeLists.txt!")
endif()

############################################################
#                                                          #
# There are no more user-serviceable parts.  From here on  #
# out, edit at your own risk.                              #
#                                                          #
############################################################

project(nsrllookup)

# Universal definitions appropriate to all platforms.
#
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED true)
set(CMAKE_BUILD_TYPE Release)
set(MAN_NAMES man1/nsrllookup.1)

# MSVC-specific variables required to get static linkage against both
# the C++ runtime and Boost both.  (It's a little unreasonable to
# expect users to keep track of all those DLLs for what's meant to be
# a self-contained tool.)
#
if (MSVC)
  set(Boost_USE_STATIC_LIBS ON)
  set(Boost_USE_DEBUG_LIBS OFF)
  set(Boost_USE_RELEASE_LIBS ON)
  set(Boost_USE_MULTITHREADED ON)
  set(Boost_USE_STATIC_RUNTIME ON)
  set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded")
endif()

# Acquire the necessary packages, now that the necessary Boost flags
# have been set.  Don't do this before you set all your Boost_*
# variables.
#
find_package(Boost 1.65.0 REQUIRED COMPONENTS program_options system)
find_package(Threads REQUIRED)

# Miscellaneous compile-time defines.  Nothing special here.
#
add_definitions(-DPACKAGE_VERSION="1.4.2"
                -DPACKAGE_URL="https://rjhansen.github.io/nsrlsvr"
                -DPACKAGE_BUGREPORT="rob@hansen.engineering")

# Define the main target, 'nsrllookup'.
#
add_executable(nsrllookup
  src/common.cc
  src/nsrllookup.cc
  src/parse_options.cc
  src/query_server.cc)
target_include_directories(nsrllookup PRIVATE ${Boost_INCLUDE_DIRS} src)
target_link_libraries(nsrllookup Boost::program_options Boost::system
  Threads::Threads)

# In the event we're compiling in MSVC, we need to add another
# preprocessor define and add a few more link libraries.
#
if (MSVC)
  add_definitions(-D_WIN32_WINNT=0x0601)
  target_link_libraries(nsrllookup wsock32 ws2_32 
    Boost::disable_autolinking)
endif()

# UNIX gets its own special case in order to make it comply with GNU
# file layouts and to include libpthread, which is omitted from Boost's
# standard flags for reasons I've never understood.
#
if (UNIX)
  include(GNUInstallDirs)
  add_custom_target(man ALL DEPENDS ${MAN_NAMES})
  install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/man1/nsrllookup.1 DESTINATION
    ${CMAKE_INSTALL_MANDIR}/man1/)
endif()

# And finally, specify an install target.  Ta-da, done.
#
install(TARGETS nsrllookup RUNTIME DESTINATION bin)
