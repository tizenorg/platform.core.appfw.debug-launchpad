CMAKE_MINIMUM_REQUIRED(VERSION 2.6)
SET(CMAKE_ALLOW_LOOSE_LOOP_CONSTRUCTS true)

PROJECT(debug-launchpad C)
SET(VERSION_MAJOR 0)
SET(VERSION "${VERSION_MAJOR}.1.0")

### Global setting ###

SET(PREFIX ${CMAKE_INSTALL_PREFIX})
SET(EXEC_PREFIX "\${prefix}")

# Build type : Release
IF("${CMAKE_BUILD_TYPE}" STREQUAL "")
	SET(CMAKE_BUILD_TYPE "Release")
ENDIF()
MESSAGE("Build type: ${CMAKE_BUILD_TYPE}")

# Set required packages
INCLUDE(FindPkgConfig)

SET(pkgs_requires "dlog glib-2.0 dbus-glib-1 bundle libsmack security-manager")
IF(_APPFW_FEATURE_SOCKET_ACTIVATION)
	SET(pkgs_requires "${pkgs_requires} libsystemd-daemon")
	ADD_DEFINITIONS("-D_APPFW_FEATURE_SOCKET_ACTIVATION")
ENDIF(_APPFW_FEATURE_SOCKET_ACTIVATION)

pkg_check_modules(pkgs REQUIRED ${pkgs_requires})

FIND_LIBRARY(LIB_DL dl)

FOREACH(flag ${pkgs_CFLAGS})
	SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} ${flag}")
ENDFOREACH(flag)

# Compiler flags
INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/include)
INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/feature)
SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} -Wl,-zdefs" )
SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} -fvisibility=hidden")
SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} -fpic")
SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${EXTRA_CFLAGS}")
SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${TEST_CFLAGS}")
SET(CMAKE_C_FLAGS_DEBUG "-O0 -g")
SET(CMAKE_C_FLAGS_RELEASE "-O2")
SET(CMAKE_SKIP_BUILD_RPATH true)

ADD_DEFINITIONS("-DPREFIX=\"${CMAKE_INSTALL_PREFIX}\"")
ADD_DEFINITIONS("-DSHARE_PREFIX=\"/usr/share/aul\"")

# Linker flags
SET(CMAKE_EXE_LINKER_FLAGS "-Wl,--as-needed")

### Build ###
# debug_launchpad_preloading_preinitializing_daemon
SET(DEBUG_LAUNCHPAD "debug_launchpad_preloading_preinitializing_daemon")
add_executable(${DEBUG_LAUNCHPAD}
	src/file_util.c
	src/debug_util.c
	src/security_util.c
	src/signal_util.c
	src/common.c
	src/debug-launchpad.c
	)

target_link_libraries(${DEBUG_LAUNCHPAD} ${pkgs_LDFLAGS} ${LIB_DL} "-pie")
set_target_properties(${DEBUG_LAUNCHPAD} PROPERTIES COMPILE_FLAGS ${CFLAGS} "-fPIE")
set_target_properties(${DEBUG_LAUNCHPAD} PROPERTIES SKIP_BUILD_RPATH true)

INSTALL(TARGETS ${DEBUG_LAUNCHPAD} DESTINATION bin)
