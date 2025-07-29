# Take the compiler-generated assembly code for subroutine LzmaDecode(),
# and edit it to become a fall-through block.
# The exit epilog "pop %ebx; pop %esi; pop %edi; pop %ebp; ret"
# might appear twice, and in the middle of the code.
# Move it to the end, delete the 'ret',
# and 'jmp' to the moved epilog.
/popl\t%ebx/{
    h
    c \
    jmp Exit_LzmaDecode
}
/popl\t%esi/,/popl\t%ebp/{
    H
    d
}
/ret$/d
/\.size\tLzmaDecode, \.-LzmaDecode/{
    H
    i \
Exit_LzmaDecode:
    g
}
