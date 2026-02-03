from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.trace.database.target
import ghidra.trace.model.target
import ghidra.trace.model.target.iface
import ghidra.trace.model.target.schema
import ghidra.util.classfinder
import java.lang # type: ignore
import java.util # type: ignore
import java.util.function # type: ignore
import java.util.stream # type: ignore


I = typing.TypeVar("I")
T = typing.TypeVar("T")


class TraceObjectInterfaceUtils(java.lang.Enum[TraceObjectInterfaceUtils]):

    @typing.type_check_only
    class Private(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def getAllConstructors() -> java.util.Map[java.lang.Class[typing.Any], TraceObjectInterfaceFactory.Constructor[typing.Any]]:
        ...

    @staticmethod
    def getConstructorsByName() -> java.util.Map[java.lang.String, TraceObjectInterfaceFactory.Constructor[typing.Any]]:
        ...

    @staticmethod
    def getFixedKeys(traceIf: java.lang.Class[ghidra.trace.model.target.iface.TraceObjectInterface]) -> java.util.Collection[java.lang.String]:
        ...

    @staticmethod
    def getSchemaName(traceIf: java.lang.Class[ghidra.trace.model.target.iface.TraceObjectInterface]) -> str:
        ...

    @staticmethod
    def getShortName(traceIf: java.lang.Class[ghidra.trace.model.target.iface.TraceObjectInterface]) -> str:
        ...

    @staticmethod
    def getValue(object: ghidra.trace.model.target.TraceObject, snap: typing.Union[jpype.JLong, int], key: typing.Union[java.lang.String, str], cls: java.lang.Class[T], def_: T) -> T:
        ...

    @staticmethod
    def isTraceObject(cls: java.lang.Class[typing.Any]) -> bool:
        ...

    @staticmethod
    def requireAnnotation(traceIf: java.lang.Class[ghidra.trace.model.target.iface.TraceObjectInterface]) -> TraceObjectInfo:
        ...

    @staticmethod
    def streamConstructors(schema: ghidra.trace.model.target.schema.TraceObjectSchema) -> java.util.stream.Stream[TraceObjectInterfaceFactory.Constructor[typing.Any]]:
        ...

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> TraceObjectInterfaceUtils:
        ...

    @staticmethod
    def values() -> jpype.JArray[TraceObjectInterfaceUtils]:
        ...


class TraceObjectInterfaceFactory(ghidra.util.classfinder.ExtensionPoint):

    class Constructor(java.lang.Record, typing.Generic[I]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, iface: java.lang.Class[I], ctor: java.util.function.Function[ghidra.trace.database.target.DBTraceObject, I]):
            ...

        def ctor(self) -> java.util.function.Function[ghidra.trace.database.target.DBTraceObject, I]:
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def iface(self) -> java.lang.Class[I]:
            ...

        def toString(self) -> str:
            ...


    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def ctor(iface: java.lang.Class[I], ctor: java.util.function.Function[ghidra.trace.database.target.DBTraceObject, I]) -> TraceObjectInterfaceFactory.Constructor[I]:
        ...

    def getInterfaceConstructors(self) -> java.util.List[TraceObjectInterfaceFactory.Constructor[typing.Any]]:
        ...

    @property
    def interfaceConstructors(self) -> java.util.List[TraceObjectInterfaceFactory.Constructor[typing.Any]]:
        ...


class BuiltinTraceObjectInterfaceFactory(TraceObjectInterfaceFactory):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...



__all__ = ["TraceObjectInterfaceUtils", "TraceObjectInterfaceFactory", "BuiltinTraceObjectInterfaceFactory"]
