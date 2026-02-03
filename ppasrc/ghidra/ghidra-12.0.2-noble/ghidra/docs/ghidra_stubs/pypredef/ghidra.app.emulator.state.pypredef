from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.pcode.memstate
import ghidra.program.model.address
import ghidra.program.model.lang
import java.lang # type: ignore
import java.util # type: ignore


class DumpMiscState(RegisterState):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, lang: ghidra.program.model.lang.Language):
        ...


class RegisterState(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def dispose(self):
        ...

    def getKeys(self) -> java.util.Set[java.lang.String]:
        ...

    def getVals(self, key: typing.Union[java.lang.String, str]) -> java.util.List[jpype.JArray[jpype.JByte]]:
        """
        Get the byte array value for a register name
        
        :param java.lang.String or str key: the register name
        :return: a list (used as an optional) containing at most the one byte array giving the
                register's value. If empty, the value if unspecified.
        :rtype: java.util.List[jpype.JArray[jpype.JByte]]
        """

    def isInitialized(self, key: typing.Union[java.lang.String, str]) -> java.util.List[java.lang.Boolean]:
        """
        Check if the register is initialized
        
        :param java.lang.String or str key: the register name
        :return: a list (used as an optional) containing at most the one initialization state. True if
                initialized, false if not. Empty if unspecified.
        :rtype: java.util.List[java.lang.Boolean]
        """

    @typing.overload
    def setVals(self, key: typing.Union[java.lang.String, str], vals: jpype.JArray[jpype.JByte], setInitiailized: typing.Union[jpype.JBoolean, bool]):
        ...

    @typing.overload
    def setVals(self, key: typing.Union[java.lang.String, str], val: typing.Union[jpype.JLong, int], size: typing.Union[jpype.JInt, int], setInitiailized: typing.Union[jpype.JBoolean, bool]):
        ...

    @property
    def vals(self) -> java.util.List[jpype.JArray[jpype.JByte]]:
        ...

    @property
    def keys(self) -> java.util.Set[java.lang.String]:
        ...

    @property
    def initialized(self) -> java.util.List[java.lang.Boolean]:
        ...


class FilteredMemoryPageOverlay(ghidra.pcode.memstate.MemoryPageOverlay):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, spc: ghidra.program.model.address.AddressSpace, ul: ghidra.pcode.memstate.MemoryBank, writeBack: typing.Union[jpype.JBoolean, bool]):
        ...


class FilteredRegisterBank(ghidra.pcode.memstate.MemoryPageBank):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, spc: ghidra.program.model.address.AddressSpace, ps: typing.Union[jpype.JInt, int], initState: RegisterState, lang: ghidra.program.model.lang.Language, writeBack: typing.Union[jpype.JBoolean, bool], faultHandler: ghidra.pcode.memstate.MemoryFaultHandler):
        ...



__all__ = ["DumpMiscState", "RegisterState", "FilteredMemoryPageOverlay", "FilteredRegisterBank"]
