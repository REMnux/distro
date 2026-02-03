from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.framework.cmd
import ghidra.program.model.address
import ghidra.program.model.listing
import ghidra.program.model.symbol
import java.lang # type: ignore


class ClearEquateCmd(ghidra.framework.cmd.Command[ghidra.program.model.listing.Program]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, equateName: typing.Union[java.lang.String, str], addr: ghidra.program.model.address.Address, opIndex: typing.Union[jpype.JInt, int]):
        ...


class SetEquateCmd(ghidra.framework.cmd.Command[ghidra.program.model.listing.Program]):
    """
    Command for setting an equate at a location.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, equateName: typing.Union[java.lang.String, str], addr: ghidra.program.model.address.Address, opIndex: typing.Union[jpype.JInt, int], equateValue: typing.Union[jpype.JLong, int]):
        """
        Constructor
        
        :param java.lang.String or str equateName: the name of the equate to applied or removed at this location.
        :param ghidra.program.model.address.Address addr: the address of the current location.
        :param jpype.JInt or int opIndex: the operand index of the current location.
        :param jpype.JLong or int equateValue: the numeric value at the current location.
        """

    def getEquate(self) -> ghidra.program.model.symbol.Equate:
        ...

    @property
    def equate(self) -> ghidra.program.model.symbol.Equate:
        ...



__all__ = ["ClearEquateCmd", "SetEquateCmd"]
