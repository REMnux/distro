from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.program.model.address
import ghidra.program.model.lang
import ghidra.trace.model
import ghidra.trace.model.guest
import ghidra.trace.model.thread


class TraceRegisterContextSpace(TraceRegisterContextOperations):

    class_: typing.ClassVar[java.lang.Class]

    def getAddressSpace(self) -> ghidra.program.model.address.AddressSpace:
        ...

    @property
    def addressSpace(self) -> ghidra.program.model.address.AddressSpace:
        ...


class TraceRegisterContextOperations(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def clear(self, span: ghidra.trace.model.Lifespan, range: ghidra.program.model.address.AddressRange):
        ...

    def getDefaultValue(self, language: ghidra.program.model.lang.Language, register: ghidra.program.model.lang.Register, address: ghidra.program.model.address.Address) -> ghidra.program.model.lang.RegisterValue:
        """
        Get the language-defined default value of the register
        
        :param ghidra.program.model.lang.Language language: the language
        :param ghidra.program.model.lang.Register register: a register in the language
        :param ghidra.program.model.address.Address address: the address from which to read the context
        :return: the default value, or ``null`` if no default is defined for the parameters
        :rtype: ghidra.program.model.lang.RegisterValue
        """

    def getEntry(self, language: ghidra.program.model.lang.Language, register: ghidra.program.model.lang.Register, snap: typing.Union[jpype.JLong, int], address: ghidra.program.model.address.Address) -> java.util.Map.Entry[ghidra.trace.model.TraceAddressSnapRange, ghidra.program.model.lang.RegisterValue]:
        ...

    @typing.overload
    def getRegisterValueAddressRanges(self, language: ghidra.program.model.lang.Language, register: ghidra.program.model.lang.Register, snap: typing.Union[jpype.JLong, int], within: ghidra.program.model.address.AddressRange) -> ghidra.program.model.address.AddressSetView:
        ...

    @typing.overload
    def getRegisterValueAddressRanges(self, language: ghidra.program.model.lang.Language, register: ghidra.program.model.lang.Register, snap: typing.Union[jpype.JLong, int]) -> ghidra.program.model.address.AddressSetView:
        ...

    def getValue(self, language: ghidra.program.model.lang.Language, register: ghidra.program.model.lang.Register, snap: typing.Union[jpype.JLong, int], address: ghidra.program.model.address.Address) -> ghidra.program.model.lang.RegisterValue:
        ...

    def getValueWithDefault(self, platform: ghidra.trace.model.guest.TracePlatform, register: ghidra.program.model.lang.Register, snap: typing.Union[jpype.JLong, int], address: ghidra.program.model.address.Address) -> ghidra.program.model.lang.RegisterValue:
        ...

    def hasRegisterValue(self, language: ghidra.program.model.lang.Language, register: ghidra.program.model.lang.Register, snap: typing.Union[jpype.JLong, int]) -> bool:
        ...

    def hasRegisterValueInAddressRange(self, language: ghidra.program.model.lang.Language, register: ghidra.program.model.lang.Register, snap: typing.Union[jpype.JLong, int], within: ghidra.program.model.address.AddressRange) -> bool:
        ...

    def removeValue(self, language: ghidra.program.model.lang.Language, register: ghidra.program.model.lang.Register, span: ghidra.trace.model.Lifespan, range: ghidra.program.model.address.AddressRange):
        ...

    def setValue(self, language: ghidra.program.model.lang.Language, value: ghidra.program.model.lang.RegisterValue, lifespan: ghidra.trace.model.Lifespan, range: ghidra.program.model.address.AddressRange):
        ...


class TraceRegisterContextManager(TraceRegisterContextOperations):

    class_: typing.ClassVar[java.lang.Class]

    def getRegisterContextRegisterSpace(self, thread: ghidra.trace.model.thread.TraceThread, createIfAbsent: typing.Union[jpype.JBoolean, bool]) -> TraceRegisterContextSpace:
        ...

    def getRegisterContextSpace(self, addressSpace: ghidra.program.model.address.AddressSpace, createIfAbsent: typing.Union[jpype.JBoolean, bool]) -> TraceRegisterContextSpace:
        ...



__all__ = ["TraceRegisterContextSpace", "TraceRegisterContextOperations", "TraceRegisterContextManager"]
