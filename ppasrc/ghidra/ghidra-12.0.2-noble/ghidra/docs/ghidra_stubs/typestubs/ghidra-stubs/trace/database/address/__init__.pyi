from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import db
import ghidra.framework.data
import ghidra.program.database
import ghidra.program.model.address
import ghidra.program.model.lang
import ghidra.trace.database
import ghidra.util.database
import ghidra.util.task
import java.lang # type: ignore
import java.lang.reflect # type: ignore
import java.util.concurrent.locks # type: ignore


OT = typing.TypeVar("OT")


class DBTraceOverlaySpaceAdapter(ghidra.trace.database.DBTraceManager):

    class DecodesAddresses(java.lang.Object):
        """
        An interface required for any object having a field using :obj:`AddressDBFieldCodec`.
        """

        class_: typing.ClassVar[java.lang.Class]

        def getOverlaySpaceAdapter(self) -> DBTraceOverlaySpaceAdapter:
            """
            Get the space adapter for the trace containing the object
            
            :return: the adapter
            :rtype: DBTraceOverlaySpaceAdapter
            """

        @property
        def overlaySpaceAdapter(self) -> DBTraceOverlaySpaceAdapter:
            ...


    class AddressDBFieldCodec(ghidra.util.database.DBCachedObjectStoreFactory.AbstractDBFieldCodec[ghidra.program.model.address.Address, OT, db.FixedField10], typing.Generic[OT]):
        """
        Used for objects having an :obj:`Address` field.
         
         
        
        Most managers storing things by address will actually have a table per space, so the address
        is encoded only as an offset. However, any other :obj:`Address` field (not constrained to
        the same space) will need to encode the space information as well. This codec can do that.
        The object will need to return its trace's space adapter, though.
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, objectType: java.lang.Class[OT], field: java.lang.reflect.Field, column: typing.Union[jpype.JInt, int]):
            ...

        @staticmethod
        def decode(enc: jpype.JArray[jpype.JByte], osa: DBTraceOverlaySpaceAdapter) -> ghidra.program.model.address.Address:
            ...

        @staticmethod
        def encode(address: ghidra.program.model.address.Address) -> jpype.JArray[jpype.JByte]:
            ...


    @typing.type_check_only
    class DBTraceOverlaySpaceEntry(ghidra.util.database.DBAnnotatedObject):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, store: ghidra.util.database.DBCachedObjectStore[typing.Any], record: db.DBRecord):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, dbh: db.DBHandle, openMode: ghidra.framework.data.OpenMode, lock: java.util.concurrent.locks.ReadWriteLock, monitor: ghidra.util.task.TaskMonitor, trace: ghidra.trace.database.DBTrace):
        ...

    def createOverlayAddressSpace(self, name: typing.Union[java.lang.String, str], base: ghidra.program.model.address.AddressSpace) -> ghidra.program.model.address.AddressSpace:
        ...

    def deleteOverlayAddressSpace(self, name: typing.Union[java.lang.String, str]):
        ...

    def getOrCreateOverlayAddressSpace(self, name: typing.Union[java.lang.String, str], base: ghidra.program.model.address.AddressSpace) -> ghidra.program.model.address.AddressSpace:
        ...


class TraceAddressFactory(ghidra.program.database.ProgramAddressFactory):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, language: ghidra.program.model.lang.Language, compilerSpec: ghidra.program.model.lang.CompilerSpec, overlayRegionSupplier: ghidra.program.database.OverlayRegionSupplier):
        ...



__all__ = ["DBTraceOverlaySpaceAdapter", "TraceAddressFactory"]
