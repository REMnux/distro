from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.framework.cmd
import ghidra.program.model.address
import ghidra.program.model.lang
import ghidra.program.model.listing
import java.lang # type: ignore
import java.math # type: ignore


class SetRegisterCmd(ghidra.framework.cmd.Command[ghidra.program.model.listing.Program]):
    """
    Command for setting the value of a register over a range of addresses.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, register: ghidra.program.model.lang.Register, start: ghidra.program.model.address.Address, end: ghidra.program.model.address.Address, value: java.math.BigInteger):
        """
        Constructor for SetRegisterCmd.
        
        :param ghidra.program.model.lang.Register register: the register to change.
        :param ghidra.program.model.address.Address start: the starting address of the range.
        :param ghidra.program.model.address.Address end: the ending address of the range.
        :param java.math.BigInteger value: the value to associated over the range.
                            A null value indicates that no value should be associated over the range.
        """



__all__ = ["SetRegisterCmd"]
