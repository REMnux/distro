from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.plugin.core.instructionsearch
import ghidra.app.plugin.core.instructionsearch.model
import ghidra.program.model.address
import ghidra.program.model.listing
import java.lang # type: ignore


class InstructionSearchApi_Yara(ghidra.app.plugin.core.instructionsearch.InstructionSearchApi):
    """
    Extends the :obj:`InstructionSearchApi` for YARA users.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @typing.overload
    def getYaraString(self, program: ghidra.program.model.listing.Program, addressRange: ghidra.program.model.address.AddressRange) -> str:
        """
        Returns a YARA-formatted string representing the instructions in the address range
        provided, for the given program.
        
        :param ghidra.program.model.listing.Program program: the program to search
        :param ghidra.program.model.address.AddressRange addressRange: the set of bytes to search for
        :return: 
        :rtype: str
        :raises InvalidInputException:
        """

    @typing.overload
    def getYaraString(self, program: ghidra.program.model.listing.Program, addressRange: ghidra.program.model.address.AddressRange, maskSettings: ghidra.app.plugin.core.instructionsearch.model.MaskSettings) -> str:
        """
        Returns a YARA-formatted string representing the instructions in the address range
        provided, for the given program, with maskings.
        
        :param ghidra.program.model.listing.Program program: the program to search
        :param ghidra.program.model.address.AddressRange addressRange: the set of bytes to search for
        :return: 
        :rtype: str
        :raises InvalidInputException:
        """



__all__ = ["InstructionSearchApi_Yara"]
