from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.program.model.address
import ghidra.trace.model
import ghidra.trace.model.stack
import ghidra.trace.model.thread
import ghidra.util.database.spatial
import java.lang # type: ignore
import java.util.function # type: ignore


T = typing.TypeVar("T")


class TraceAddressSnapRangePropertyMapSpace(TraceAddressSnapRangePropertyMapOperations[T], typing.Generic[T]):

    class_: typing.ClassVar[java.lang.Class]

    def getAddressSpace(self) -> ghidra.program.model.address.AddressSpace:
        ...

    @property
    def addressSpace(self) -> ghidra.program.model.address.AddressSpace:
        ...


class TraceAddressSnapRangePropertyMapOperations(ghidra.util.database.spatial.SpatialMap[ghidra.trace.model.TraceAddressSnapRange, T, ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMapTree.TraceAddressSnapRangeQuery], typing.Generic[T]):

    class_: typing.ClassVar[java.lang.Class]

    def deleteValue(self, value: T):
        """
        For maps where values are the entries, remove a value
        
        :param T value: the entry to remove
        """

    @typing.overload
    def getAddressSetView(self, span: ghidra.trace.model.Lifespan, predicate: java.util.function.Predicate[T]) -> ghidra.program.model.address.AddressSetView:
        ...

    @typing.overload
    def getAddressSetView(self, span: ghidra.trace.model.Lifespan) -> ghidra.program.model.address.AddressSetView:
        ...

    @typing.overload
    def put(self, address: ghidra.program.model.address.Address, lifespan: ghidra.trace.model.Lifespan, value: T) -> T:
        ...

    @typing.overload
    def put(self, minAddress: ghidra.program.model.address.Address, maxAddress: ghidra.program.model.address.Address, minSnap: typing.Union[jpype.JLong, int], maxSnap: typing.Union[jpype.JLong, int], value: T) -> T:
        ...

    @typing.overload
    def put(self, minAddress: ghidra.program.model.address.Address, maxAddress: ghidra.program.model.address.Address, snap: typing.Union[jpype.JLong, int], value: T) -> T:
        ...

    @typing.overload
    def put(self, range: ghidra.program.model.address.AddressRange, lifespan: ghidra.trace.model.Lifespan, value: T) -> T:
        ...

    @property
    def addressSetView(self) -> ghidra.program.model.address.AddressSetView:
        ...


class TraceAddressSnapRangePropertyMap(TraceAddressSnapRangePropertyMapOperations[T], typing.Generic[T]):

    class_: typing.ClassVar[java.lang.Class]

    def getName(self) -> str:
        ...

    @typing.overload
    def getRegisterSpace(self, thread: ghidra.trace.model.thread.TraceThread, createIfAbsent: typing.Union[jpype.JBoolean, bool]) -> TraceAddressSnapRangePropertyMapSpace[T]:
        ...

    @typing.overload
    def getRegisterSpace(self, frame: ghidra.trace.model.stack.TraceStackFrame, createIfAbsent: typing.Union[jpype.JBoolean, bool]) -> TraceAddressSnapRangePropertyMapSpace[T]:
        ...

    @property
    def name(self) -> java.lang.String:
        ...



__all__ = ["TraceAddressSnapRangePropertyMapSpace", "TraceAddressSnapRangePropertyMapOperations", "TraceAddressSnapRangePropertyMap"]
