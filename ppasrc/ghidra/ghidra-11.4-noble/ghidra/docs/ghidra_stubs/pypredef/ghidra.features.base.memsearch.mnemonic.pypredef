from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.framework.plugintool
import ghidra.program.model.listing
import ghidra.program.util
import java.lang # type: ignore


@typing.type_check_only
class SLMaskControl(java.lang.Object):
    """
    Represents a filter for a single instruction. This defines what portions of the instruction will
    be masked.
    """

    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class MaskValue(java.lang.Object):
    """
    Stores information about the instruction and mask.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, mask: jpype.JArray[jpype.JByte], value: jpype.JArray[jpype.JByte]):
        """
        Constructor.
        
        :param jpype.JArray[jpype.JByte] mask: 
        :param jpype.JArray[jpype.JByte] value:
        """

    @typing.overload
    def __init__(self, mask: jpype.JArray[jpype.JByte], value: jpype.JArray[jpype.JByte], textRepresentation: typing.Union[java.lang.String, str]):
        """
        Constructor.
        
        :param jpype.JArray[jpype.JByte] mask: 
        :param jpype.JArray[jpype.JByte] value: 
        :param java.lang.String or str textRepresentation:
        """

    def getMask(self) -> jpype.JArray[jpype.JByte]:
        ...

    def getValue(self) -> jpype.JArray[jpype.JByte]:
        ...

    def orMask(self, other: jpype.JArray[jpype.JByte]):
        """
        Performs a bitwise OR on the given byte array and mask.  Results are stored internally in
        the 'mask' object.
        
        :param jpype.JArray[jpype.JByte] other:
        """

    def orValue(self, other: jpype.JArray[jpype.JByte]):
        """
        Performs a bitwise OR on the given byte array and instruction value.  Results are stored internally
        in the 'value' object.
        
        :param jpype.JArray[jpype.JByte] other:
        """

    def setMask(self, mask: jpype.JArray[jpype.JByte]):
        ...

    def setValue(self, value: jpype.JArray[jpype.JByte]):
        ...

    @property
    def value(self) -> jpype.JArray[jpype.JByte]:
        ...

    @value.setter
    def value(self, value: jpype.JArray[jpype.JByte]):
        ...

    @property
    def mask(self) -> jpype.JArray[jpype.JByte]:
        ...

    @mask.setter
    def mask(self, value: jpype.JArray[jpype.JByte]):
        ...


class MnemonicSearchPlugin(ghidra.framework.plugintool.Plugin):
    """
    Defines a set of actions that can be performed on a selection to initiate a memory search.  All
    actions will ultimately open the ``MemSearchDialog`` with the search string field 
    pre-populated.
    """

    class_: typing.ClassVar[java.lang.Class]
    maskedBitString: java.lang.String

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        """
        Constructor.
        
        :param ghidra.framework.plugintool.PluginTool tool: the tool
        """


@typing.type_check_only
class MaskGenerator(java.lang.Object):

    @typing.type_check_only
    class MnemonicMaskValue(MaskValue):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, mask: jpype.JArray[jpype.JByte], value: jpype.JArray[jpype.JByte], textRep: typing.Union[java.lang.String, str]):
            """
            
            
            :param jpype.JArray[jpype.JByte] mask: 
            :param jpype.JArray[jpype.JByte] value: 
            :param java.lang.String or str textRep:
            """


    @typing.type_check_only
    class OperandMaskValue(MaskValue):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, maskControl: SLMaskControl):
        """
        Constructor.
        
        :param SLMaskControl maskControl:
        """

    def getMask(self, program: ghidra.program.model.listing.Program, selection: ghidra.program.util.ProgramSelection) -> MaskValue:
        """
        Returns the mask settings for the selected instructions.
        
        :param ghidra.program.model.listing.Program program: 
        :param ghidra.program.util.ProgramSelection selection: 
        :return: 
        :rtype: MaskValue
        """



__all__ = ["SLMaskControl", "MaskValue", "MnemonicSearchPlugin", "MaskGenerator"]
