#!/bin/sh

if [ -z "$2" ]; then
    echo "Usage: $0 headerIn.h headerOut.h" >&2
    exit 1
fi

headerIn="$1"
headerOut="$2"

# List of candidates for renaming was obtained via the following command on original library:
# nm libgdtoa-desktop.so | sed -n "s#.* T \(.*\)#    -e 's@\\\<\1\\\>@gdtoa_\1@g'\\\#p"
sed \
    -e 's@\<add_nanbits_D2A\>@gdtoa_add_nanbits_D2A@g'\
    -e 's@\<any_on_D2A\>@gdtoa_any_on_D2A@g'\
    -e 's@\<b2d_D2A\>@gdtoa_b2d_D2A@g'\
    -e 's@\<Balloc_D2A\>@gdtoa_Balloc_D2A@g'\
    -e 's@\<Bfree_D2A\>@gdtoa_Bfree_D2A@g'\
    -e 's@\<cmp_D2A\>@gdtoa_cmp_D2A@g'\
    -e 's@\<copybits_D2A\>@gdtoa_copybits_D2A@g'\
    -e 's@\<d2b_D2A\>@gdtoa_d2b_D2A@g'\
    -e 's@\<decrement_D2A\>@gdtoa_decrement_D2A@g'\
    -e 's@\<diff_D2A\>@gdtoa_diff_D2A@g'\
    -e 's@\<dtoa\>@gdtoa_dtoa@g'\
    -e 's@\<_fini\>@gdtoa__fini@g'\
    -e 's@\<freedtoa\>@gdtoa_freedtoa@g'\
    -e 's@\<g_ddfmt\>@gdtoa_g_ddfmt@g'\
    -e 's@\<g_ddfmt_p\>@gdtoa_g_ddfmt_p@g'\
    -e 's@\<g_dfmt\>@gdtoa_g_dfmt@g'\
    -e 's@\<g_dfmt_p\>@gdtoa_g_dfmt_p@g'\
    -e 's@\<gdtoa\>@gdtoa_gdtoa@g'\
    -e 's@\<gethex_D2A\>@gdtoa_gethex_D2A@g'\
    -e 's@\<g_ffmt\>@gdtoa_g_ffmt@g'\
    -e 's@\<g_ffmt_p\>@gdtoa_g_ffmt_p@g'\
    -e 's@\<g__fmt_D2A\>@gdtoa_g__fmt_D2A@g'\
    -e 's@\<g_Qfmt\>@gdtoa_g_Qfmt@g'\
    -e 's@\<g_Qfmt_p\>@gdtoa_g_Qfmt_p@g'\
    -e 's@\<g_xfmt\>@gdtoa_g_xfmt@g'\
    -e 's@\<g_xfmt_p\>@gdtoa_g_xfmt_p@g'\
    -e 's@\<g_xLfmt\>@gdtoa_g_xLfmt@g'\
    -e 's@\<g_xLfmt_p\>@gdtoa_g_xLfmt_p@g'\
    -e 's@\<hexnan_D2A\>@gdtoa_hexnan_D2A@g'\
    -e 's@\<hi0bits_D2A\>@gdtoa_hi0bits_D2A@g'\
    -e 's@\<i2b_D2A\>@gdtoa_i2b_D2A@g'\
    -e 's@\<increment_D2A\>@gdtoa_increment_D2A@g'\
    -e 's@\<_init\>@gdtoa__init@g'\
    -e 's@\<lo0bits_D2A\>@gdtoa_lo0bits_D2A@g'\
    -e 's@\<lshift_D2A\>@gdtoa_lshift_D2A@g'\
    -e 's@\<match_D2A\>@gdtoa_match_D2A@g'\
    -e 's@\<multadd_D2A\>@gdtoa_multadd_D2A@g'\
    -e 's@\<mult_D2A\>@gdtoa_mult_D2A@g'\
    -e 's@\<nrv_alloc_D2A\>@gdtoa_nrv_alloc_D2A@g'\
    -e 's@\<pow5mult_D2A\>@gdtoa_pow5mult_D2A@g'\
    -e 's@\<quorem_D2A\>@gdtoa_quorem_D2A@g'\
    -e 's@\<ratio_D2A\>@gdtoa_ratio_D2A@g'\
    -e 's@\<rshift_D2A\>@gdtoa_rshift_D2A@g'\
    -e 's@\<rv_alloc_D2A\>@gdtoa_rv_alloc_D2A@g'\
    -e 's@\<s2b_D2A\>@gdtoa_s2b_D2A@g'\
    -e 's@\<set_ones_D2A\>@gdtoa_set_ones_D2A@g'\
    -e 's@\<strcp_D2A\>@gdtoa_strcp_D2A@g'\
    -e 's@\<strtod\>@gdtoa_strtod@g'\
    -e 's@\<strtodg\>@gdtoa_strtodg@g'\
    -e 's@\<strtodI\>@gdtoa_strtodI@g'\
    -e 's@\<strtof\>@gdtoa_strtof@g'\
    -e 's@\<strtoId\>@gdtoa_strtoId@g'\
    -e 's@\<strtoIdd\>@gdtoa_strtoIdd@g'\
    -e 's@\<strtoIf\>@gdtoa_strtoIf@g'\
    -e 's@\<strtoIg_D2A\>@gdtoa_strtoIg_D2A@g'\
    -e 's@\<strtoIQ\>@gdtoa_strtoIQ@g'\
    -e 's@\<strtoIx\>@gdtoa_strtoIx@g'\
    -e 's@\<strtoIxL\>@gdtoa_strtoIxL@g'\
    -e 's@\<strtopd\>@gdtoa_strtopd@g'\
    -e 's@\<strtopdd\>@gdtoa_strtopdd@g'\
    -e 's@\<strtopf\>@gdtoa_strtopf@g'\
    -e 's@\<strtopQ\>@gdtoa_strtopQ@g'\
    -e 's@\<strtopx\>@gdtoa_strtopx@g'\
    -e 's@\<strtopxL\>@gdtoa_strtopxL@g'\
    -e 's@\<strtord\>@gdtoa_strtord@g'\
    -e 's@\<strtordd\>@gdtoa_strtordd@g'\
    -e 's@\<strtorf\>@gdtoa_strtorf@g'\
    -e 's@\<strtorQ\>@gdtoa_strtorQ@g'\
    -e 's@\<strtorx\>@gdtoa_strtorx@g'\
    -e 's@\<strtorxL\>@gdtoa_strtorxL@g'\
    -e 's@\<sum_D2A\>@gdtoa_sum_D2A@g'\
    -e 's@\<trailz_D2A\>@gdtoa_trailz_D2A@g'\
    -e 's@\<ulp_D2A\>@gdtoa_ulp_D2A@g'\
    -e 's@\<ULtod_D2A\>@gdtoa_ULtod_D2A@g'\
    -e 's@\<ULtodd_D2A\>@gdtoa_ULtodd_D2A@g'\
    -e 's@\<ULtof_D2A\>@gdtoa_ULtof_D2A@g'\
    -e 's@\<ULtoQ_D2A\>@gdtoa_ULtoQ_D2A@g'\
    -e 's@\<ULtox_D2A\>@gdtoa_ULtox_D2A@g'\
    -e 's@\<ULtoxL_D2A\>@gdtoa_ULtoxL_D2A@g'\
    "$headerIn" > "$headerOut"
