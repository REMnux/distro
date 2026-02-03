// "jmp undef" gets R_X86_64_PLT32; we want R_X86_64_PC32

  .section HUMF_A, "ax"
    .byte 0xe9  // 5-byte jmp opcode
    .int upx_mmap_and_fd_android - 0f  // force R_X86_64_PC32 relocation
0:

  .section HUMF_L, "ax"
    .byte 0xe9
    .int upx_mmap_and_fd_linux - 0f
0:
