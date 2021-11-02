cmake_minimum_required (VERSION 2.8...3.0)

project ( antianalysis_demos )

set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MT")

set (hdrs
	util.h
	classic_antidbg.h
	classic_antivm.h
	neutrino_checks.h
	kernelmode_antidbg.h
	procmon_check.h
)

set (srcs
	util.cpp
	classic_antidbg.cpp
	classic_antivm.cpp
	neutrino_checks.cpp
	kernelmode_antidbg.cpp
	procmon_check.cpp
)

add_executable ( ${PROJECT_NAME} ${exe_hdrs} ${srcs} main.cpp )
target_link_libraries ( antianalysis_demos fltlib.lib )

INSTALL( TARGETS ${PROJECT_NAME} DESTINATION ${CMAKE_INSTALL_PREFIX} COMPONENT ${PROJECT_NAME} )
