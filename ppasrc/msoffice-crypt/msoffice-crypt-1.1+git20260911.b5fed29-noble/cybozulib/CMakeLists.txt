cmake_minimum_required(VERSION 2.6)
project(cybozulib)

file(GLOB headers include/cybozu/*.hpp)
install(FILES ${headers} DESTINATION include/cybozu)

