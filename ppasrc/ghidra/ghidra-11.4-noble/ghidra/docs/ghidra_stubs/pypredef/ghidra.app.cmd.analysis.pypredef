from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.framework.cmd
import ghidra.program.model.address


class SharedReturnAnalysisCmd(ghidra.framework.cmd.BackgroundCommand[ghidra.program.model.listing.Program]):
    """
    Identifies functions to which Jump references exist and converts 
    the associated branching instruction flow to a CALL-RETURN
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, set: ghidra.program.model.address.AddressSetView, assumeContiguousFunctions: typing.Union[jpype.JBoolean, bool], considerConditionalBranches: typing.Union[jpype.JBoolean, bool]):
        """
        Constructor
        
        :param ghidra.program.model.address.AddressSetView set: set of addresses over which destination functions will be
        examined for Jump reference to those functions.
        :param jpype.JBoolean or bool assumeContiguousFunctions: if true it will be assumed that any unconditional
        jump over another function will trigger a call-return override and the creation of
        :param jpype.JBoolean or bool considerConditionalBranches: if true conditional jumps can also be considered for jumping
        to another function as a shared return.
        a function at the destination.
        """



__all__ = ["SharedReturnAnalysisCmd"]
