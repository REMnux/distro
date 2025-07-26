cmake_minimum_required (VERSION 3.0)
project (gdtoa-desktop LANGUAGES C
                       VERSION 0.1.20180730)

if(CMAKE_SOURCE_DIR STREQUAL PROJECT_SOURCE_DIR)
    option(BUILD_SHARED_LIBS "Build shared library instead of static" ON)
    include("GNUInstallDirs")
endif()

option(GDTOA_USE_LOCALE       "Enable support for locale-specific decimal separator" ON)
option(GDTOA_RENAME_FUNCTIONS "Rename externally-visible functions to avoid conflict with system libraries" ON)
option(GDTOA_ENABLE_SSE2      "Use SSE2 instructions instead of x87 to avoid inconsistent rounding" ON)

set(strtod_c strtod.c)
if("${CMAKE_SYSTEM_PROCESSOR}" STREQUAL "i686")
    if(GDTOA_ENABLE_SSE2)
        message("++ Assuming the CPU does support SSE2, setting compiler flags to use it instead of x87")
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -msse2 -mfpmath=sse")
    else()
        message("++ Using integer arithmetic in strtod")
        set(strtod_c strtodnrp.c)
    endif()
endif()

add_definitions(-DMULTIPLE_THREADS)
if(GDTOA_USE_LOCALE)
    add_definitions(-DUSE_LOCALE)
endif()

if(GDTOA_RENAME_FUNCTIONS)
# List of candidates for renaming was obtained via the following command on original library:
# nm libgdtoa-desktop.so | sed -n 's@.* T \(.*\)@-D\1=gdtoa_\1@p'
    add_definitions(
    -Dadd_nanbits_D2A=gdtoa_add_nanbits_D2A
    -Dany_on_D2A=gdtoa_any_on_D2A
    -Db2d_D2A=gdtoa_b2d_D2A
    -DBalloc_D2A=gdtoa_Balloc_D2A
    -DBfree_D2A=gdtoa_Bfree_D2A
    -Dcmp_D2A=gdtoa_cmp_D2A
    -Dcopybits_D2A=gdtoa_copybits_D2A
    -Dd2b_D2A=gdtoa_d2b_D2A
    -Ddecrement_D2A=gdtoa_decrement_D2A
    -Ddiff_D2A=gdtoa_diff_D2A
    -Ddtoa=gdtoa_dtoa
    -D_fini=gdtoa__fini
    -Dfreedtoa=gdtoa_freedtoa
    -Dg_ddfmt=gdtoa_g_ddfmt
    -Dg_ddfmt_p=gdtoa_g_ddfmt_p
    -Dg_dfmt=gdtoa_g_dfmt
    -Dg_dfmt_p=gdtoa_g_dfmt_p
    -Dgdtoa=gdtoa_gdtoa
    -Dgethex_D2A=gdtoa_gethex_D2A
    -Dg_ffmt=gdtoa_g_ffmt
    -Dg_ffmt_p=gdtoa_g_ffmt_p
    -Dg__fmt_D2A=gdtoa_g__fmt_D2A
    -Dg_Qfmt=gdtoa_g_Qfmt
    -Dg_Qfmt_p=gdtoa_g_Qfmt_p
    -Dg_xfmt=gdtoa_g_xfmt
    -Dg_xfmt_p=gdtoa_g_xfmt_p
    -Dg_xLfmt=gdtoa_g_xLfmt
    -Dg_xLfmt_p=gdtoa_g_xLfmt_p
    -Dhexnan_D2A=gdtoa_hexnan_D2A
    -Dhi0bits_D2A=gdtoa_hi0bits_D2A
    -Di2b_D2A=gdtoa_i2b_D2A
    -Dincrement_D2A=gdtoa_increment_D2A
    -D_init=gdtoa__init
    -Dlo0bits_D2A=gdtoa_lo0bits_D2A
    -Dlshift_D2A=gdtoa_lshift_D2A
    -Dmatch_D2A=gdtoa_match_D2A
    -Dmultadd_D2A=gdtoa_multadd_D2A
    -Dmult_D2A=gdtoa_mult_D2A
    -Dnrv_alloc_D2A=gdtoa_nrv_alloc_D2A
    -Dpow5mult_D2A=gdtoa_pow5mult_D2A
    -Dquorem_D2A=gdtoa_quorem_D2A
    -Dratio_D2A=gdtoa_ratio_D2A
    -Drshift_D2A=gdtoa_rshift_D2A
    -Drv_alloc_D2A=gdtoa_rv_alloc_D2A
    -Ds2b_D2A=gdtoa_s2b_D2A
    -Dset_ones_D2A=gdtoa_set_ones_D2A
    -Dstrcp_D2A=gdtoa_strcp_D2A
    -Dstrtod=gdtoa_strtod
    -Dstrtodg=gdtoa_strtodg
    -DstrtodI=gdtoa_strtodI
    -Dstrtof=gdtoa_strtof
    -DstrtoId=gdtoa_strtoId
    -DstrtoIdd=gdtoa_strtoIdd
    -DstrtoIf=gdtoa_strtoIf
    -DstrtoIg_D2A=gdtoa_strtoIg_D2A
    -DstrtoIQ=gdtoa_strtoIQ
    -DstrtoIx=gdtoa_strtoIx
    -DstrtoIxL=gdtoa_strtoIxL
    -Dstrtopd=gdtoa_strtopd
    -Dstrtopdd=gdtoa_strtopdd
    -Dstrtopf=gdtoa_strtopf
    -DstrtopQ=gdtoa_strtopQ
    -Dstrtopx=gdtoa_strtopx
    -DstrtopxL=gdtoa_strtopxL
    -Dstrtord=gdtoa_strtord
    -Dstrtordd=gdtoa_strtordd
    -Dstrtorf=gdtoa_strtorf
    -DstrtorQ=gdtoa_strtorQ
    -Dstrtorx=gdtoa_strtorx
    -DstrtorxL=gdtoa_strtorxL
    -Dsum_D2A=gdtoa_sum_D2A
    -Dtrailz_D2A=gdtoa_trailz_D2A
    -Dulp_D2A=gdtoa_ulp_D2A
    -DULtod_D2A=gdtoa_ULtod_D2A
    -DULtodd_D2A=gdtoa_ULtodd_D2A
    -DULtof_D2A=gdtoa_ULtof_D2A
    -DULtoQ_D2A=gdtoa_ULtoQ_D2A
    -DULtox_D2A=gdtoa_ULtox_D2A
    -DULtoxL_D2A=gdtoa_ULtoxL_D2A
    )
endif()

set(gdtoa_SOURCES
        gdtoa/dmisc.c
	    gdtoa/dtoa.c
	    gdtoa/g_Qfmt.c
	    gdtoa/g_Qfmt_p.c
	    gdtoa/g__fmt.c
	    gdtoa/g_ddfmt.c
	    gdtoa/g_ddfmt_p.c
	    gdtoa/g_dfmt.c
	    gdtoa/g_dfmt_p.c
	    gdtoa/g_ffmt.c
	    gdtoa/g_ffmt_p.c
	    gdtoa/g_xLfmt.c
	    gdtoa/g_xLfmt_p.c
	    gdtoa/g_xfmt.c
	    gdtoa/g_xfmt_p.c
	    gdtoa/gdtoa.c
	    gdtoa/gethex.c
	    gdtoa/gmisc.c
	    gdtoa/hd_init.c
	    gdtoa/hexnan.c
	    gdtoa/misc.c
	    gdtoa/smisc.c
	    gdtoa/strtoIQ.c
	    gdtoa/strtoId.c
	    gdtoa/strtoIdd.c
	    gdtoa/strtoIf.c
	    gdtoa/strtoIg.c
	    gdtoa/strtoIx.c
	    gdtoa/strtoIxL.c
	    gdtoa/${strtod_c}
	    gdtoa/strtodI.c
	    gdtoa/strtodg.c
	    gdtoa/strtof.c
	    gdtoa/strtopQ.c
	    gdtoa/strtopd.c
	    gdtoa/strtopdd.c
	    gdtoa/strtopf.c
	    gdtoa/strtopx.c
	    gdtoa/strtopxL.c
	    gdtoa/strtorQ.c
	    gdtoa/strtord.c
	    gdtoa/strtordd.c
	    gdtoa/strtorf.c
	    gdtoa/strtorx.c
	    gdtoa/strtorxL.c
	    gdtoa/sum.c
	    gdtoa/ulp.c
        lock.c
        "${PROJECT_BINARY_DIR}/arith.h"
        "${PROJECT_BINARY_DIR}/gd_qnan.h"
)

add_executable(arithchk gdtoa/arithchk.c)
add_custom_command(
    OUTPUT "${PROJECT_BINARY_DIR}/arith.h"
    COMMAND "$<TARGET_FILE:arithchk>" > "${PROJECT_BINARY_DIR}/arith.h"
    DEPENDS "$<TARGET_FILE:arithchk>"
    VERBATIM)

target_include_directories(arithchk
PUBLIC
    ${PROJECT_BINARY_DIR}
)

add_executable(gd_qnan gdtoa/qnan.c "${PROJECT_BINARY_DIR}/arith.h")
add_custom_command(
    OUTPUT "${PROJECT_BINARY_DIR}/gd_qnan.h"
    COMMAND "$<TARGET_FILE:gd_qnan>" > "${PROJECT_BINARY_DIR}/gd_qnan.h"
    DEPENDS "$<TARGET_FILE:gd_qnan>"
    VERBATIM)

target_include_directories(gd_qnan
PUBLIC
    ${PROJECT_BINARY_DIR}
)

add_library(gdtoa-desktop ${gdtoa_SOURCES})

target_include_directories(gdtoa-desktop
PUBLIC
    ${PROJECT_BINARY_DIR}
)

if(GDTOA_RENAME_FUNCTIONS)
    add_custom_command(
        OUTPUT "${PROJECT_BINARY_DIR}/gdtoa-functions-renamed.h"
        COMMAND ${PROJECT_SOURCE_DIR}/rename-functions.sh "${PROJECT_SOURCE_DIR}/gdtoa/gdtoa.h" "${PROJECT_BINARY_DIR}/gdtoa-functions-renamed.h"
        DEPENDS "${PROJECT_SOURCE_DIR}/gdtoa/gdtoa.h"
        VERBATIM)
    add_custom_target(gdtoa_h ALL DEPENDS "${PROJECT_BINARY_DIR}/gdtoa-functions-renamed.h")
endif()

if(CMAKE_SOURCE_DIR STREQUAL PROJECT_SOURCE_DIR)
    configure_file(gdtoa-desktop.pc.cmake "${PROJECT_BINARY_DIR}/gdtoa-desktop.pc" @ONLY)

    install(TARGETS gdtoa-desktop DESTINATION "${CMAKE_INSTALL_LIBDIR}")
    install(FILES "${PROJECT_BINARY_DIR}/arith.h" DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/gdtoa-desktop/")
    install(FILES "${PROJECT_BINARY_DIR}/gdtoa-desktop.pc" DESTINATION "${CMAKE_INSTALL_LIBDIR}/pkgconfig/")
    if(GDTOA_RENAME_FUNCTIONS)
        install(FILES "${PROJECT_BINARY_DIR}/gdtoa-functions-renamed.h" DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/gdtoa-desktop/" RENAME gdtoa-desktop.h)
    else()
        install(FILES "${PROJECT_SOURCE_DIR}/gdtoa/gdtoa.h" DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/gdtoa-desktop/")
    endif()

    # Tests

    foreach(executable dt dItest ddtest dtest ftest Qtest xLtest xtest strtodt)
        add_executable(${executable} EXCLUDE_FROM_ALL "${PROJECT_SOURCE_DIR}/gdtoa/test/${executable}.c"
                                                      "${PROJECT_SOURCE_DIR}/gdtoa/test/getround.c")
        target_include_directories(${executable} PRIVATE "${PROJECT_SOURCE_DIR}/gdtoa/")
        target_link_libraries(${executable} gdtoa-desktop m)
    endforeach()

    add_executable(ddtestsi EXCLUDE_FROM_ALL "${PROJECT_SOURCE_DIR}/gdtoa/test/ddtest.c"
                                             "${PROJECT_SOURCE_DIR}/gdtoa/test/strtopddSI.c"
                                             "${PROJECT_SOURCE_DIR}/gdtoa/test/strtorddSI.c"
                                             "${PROJECT_SOURCE_DIR}/gdtoa/test/strtoIddSI.c"
                                             "${PROJECT_SOURCE_DIR}/gdtoa/test/getround.c")
    target_include_directories(ddtestsi PRIVATE "${PROJECT_SOURCE_DIR}/gdtoa/")
    target_link_libraries(ddtestsi gdtoa-desktop)

    add_executable(dItestsi EXCLUDE_FROM_ALL "${PROJECT_SOURCE_DIR}/gdtoa/test/dItest.c"
                                             "${PROJECT_SOURCE_DIR}/gdtoa/test/strtodISI.c"
                                             "${PROJECT_SOURCE_DIR}/gdtoa/test/strtoIdSI.c"
                                             "${PROJECT_SOURCE_DIR}/gdtoa/test/getround.c")
    target_include_directories(dItestsi PRIVATE "${PROJECT_SOURCE_DIR}/gdtoa/")
    target_link_libraries(dItestsi gdtoa-desktop)

    add_executable(strtodtnrp EXCLUDE_FROM_ALL "${PROJECT_SOURCE_DIR}/gdtoa/strtodnrp.c"
                                               "${PROJECT_SOURCE_DIR}/gdtoa/test/strtodt.c")
    target_include_directories(strtodtnrp PRIVATE "${PROJECT_SOURCE_DIR}/gdtoa/")
    target_link_libraries(strtodtnrp gdtoa-desktop)

    add_executable(xQtest EXCLUDE_FROM_ALL "${PROJECT_SOURCE_DIR}/gdtoa/test/xQtest.c")
    target_include_directories(xQtest PRIVATE "${PROJECT_SOURCE_DIR}/gdtoa/")
    add_custom_command(
        OUTPUT Q.out x.out xL.out
        COMMAND cd "${PROJECT_BINARY_DIR}" && ./xQtest | sed "s@cp @cp ${PROJECT_SOURCE_DIR}/gdtoa/test/@g" | sh
        DEPENDS xQtest
        VERBATIM)
    add_custom_target(Q_out DEPENDS "${PROJECT_BINARY_DIR}/Q.out")
    add_custom_target(x_out DEPENDS "${PROJECT_BINARY_DIR}/x.out")
    add_custom_target(xL_out DEPENDS "${PROJECT_BINARY_DIR}/xL.out")

    add_custom_target(check
        DEPENDS Q_out x_out xL_out dt dItest ddtest dtest ftest Qtest xLtest xtest ddtestsi dItestsi strtodt strtodtnrp
        COMMAND "${PROJECT_SOURCE_DIR}/run-tests.sh" "${PROJECT_SOURCE_DIR}/gdtoa/test" "${PROJECT_BINARY_DIR}"
        VERBATIM)
endif()
