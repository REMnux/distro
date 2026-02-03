  .section HUMF_A, "ax"
    .set noreorder
    j upx_mmap_and_fd_android
      nop
    .set reorder

  .section HUMF_L, "ax"
    .set noreorder
    j upx_mmap_and_fd_linux
      nop
    .set reorder
