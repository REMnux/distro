from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import db
import ghidra.framework.data
import ghidra.program.model.address
import ghidra.program.model.lang
import ghidra.program.model.mem
import ghidra.trace.database
import ghidra.trace.database.address
import ghidra.trace.database.map
import ghidra.trace.database.space
import ghidra.trace.database.target
import ghidra.trace.database.thread
import ghidra.trace.model
import ghidra.trace.model.memory
import ghidra.util.database
import ghidra.util.task
import java.lang # type: ignore
import java.nio # type: ignore
import java.util # type: ignore
import java.util.concurrent.locks # type: ignore


class DBTraceMemoryManager(ghidra.trace.database.space.AbstractDBTraceSpaceBasedManager[DBTraceMemorySpace], ghidra.trace.model.memory.TraceMemoryManager, InternalTraceMemoryOperations, ghidra.trace.database.space.DBTraceDelegatingManager[DBTraceMemorySpace]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, dbh: db.DBHandle, openMode: ghidra.framework.data.OpenMode, lock: java.util.concurrent.locks.ReadWriteLock, monitor: ghidra.util.task.TaskMonitor, baseLanguage: ghidra.program.model.lang.Language, trace: ghidra.trace.database.DBTrace, threadManager: ghidra.trace.database.thread.DBTraceThreadManager, overlayAdapter: ghidra.trace.database.address.DBTraceOverlaySpaceAdapter):
        ...


class DBTraceObjectMemory(ghidra.trace.model.memory.TraceMemory, ghidra.trace.database.target.DBTraceObjectInterface):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, object: ghidra.trace.database.target.DBTraceObject):
        ...


class DBTraceObjectRegister(ghidra.trace.model.memory.TraceRegister, ghidra.trace.database.target.DBTraceObjectInterface):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, object: ghidra.trace.database.target.DBTraceObject):
        ...


class InternalTraceMemoryOperations(ghidra.trace.model.memory.TraceMemoryOperations):

    class_: typing.ClassVar[java.lang.Class]

    def getLock(self) -> java.util.concurrent.locks.ReadWriteLock:
        ...

    def getSpace(self) -> ghidra.program.model.address.AddressSpace:
        """
        For register mapping conventions
        
        :return: the address space
        :rtype: ghidra.program.model.address.AddressSpace
        """

    @staticmethod
    def requireOne(states: collections.abc.Sequence, register: ghidra.program.model.lang.Register) -> ghidra.trace.model.memory.TraceMemoryState:
        ...

    @property
    def lock(self) -> java.util.concurrent.locks.ReadWriteLock:
        ...

    @property
    def space(self) -> ghidra.program.model.address.AddressSpace:
        ...


class DBTraceMemBuffer(ghidra.program.model.mem.MemBufferMixin):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, space: DBTraceMemorySpace, snap: typing.Union[jpype.JLong, int], start: ghidra.program.model.address.Address, byteOrder: java.nio.ByteOrder):
        ...


@typing.type_check_only
class DBTraceMemoryBlockEntry(ghidra.util.database.DBAnnotatedObject):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, space: DBTraceMemorySpace, store: ghidra.util.database.DBCachedObjectStore[typing.Any], record: db.DBRecord):
        ...

    def cmpBytes(self, buf: java.nio.ByteBuffer, dstOffset: typing.Union[jpype.JInt, int], len: typing.Union[jpype.JInt, int]) -> int:
        ...

    def copy(self, loc: ghidra.trace.database.DBTraceUtils.OffsetSnap) -> DBTraceMemoryBlockEntry:
        ...

    def getBytes(self, buf: java.nio.ByteBuffer, srcOffset: typing.Union[jpype.JInt, int], len: typing.Union[jpype.JInt, int]) -> int:
        ...

    def getOffset(self) -> int:
        ...

    def getSnap(self) -> int:
        ...

    def isScratch(self) -> bool:
        ...

    def setBytes(self, buf: java.nio.ByteBuffer, dstOffset: typing.Union[jpype.JInt, int], len: typing.Union[jpype.JInt, int]) -> int:
        ...

    def setLoc(self, location: ghidra.trace.database.DBTraceUtils.OffsetSnap):
        ...

    @property
    def offset(self) -> jpype.JLong:
        ...

    @property
    def scratch(self) -> jpype.JBoolean:
        ...

    @property
    def snap(self) -> jpype.JLong:
        ...


class DBTraceObjectRegisterContainer(ghidra.trace.model.memory.TraceRegisterContainer, ghidra.trace.database.target.DBTraceObjectInterface):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, object: ghidra.trace.database.target.DBTraceObject):
        ...


@typing.type_check_only
class DBTraceMemoryStateEntry(ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMapTree.AbstractDBTraceAddressSnapRangePropertyMapData[ghidra.trace.model.memory.TraceMemoryState]):
    """
    INTERNAL: An entry to record memory observation states in the database
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tree: ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMapTree[ghidra.trace.model.memory.TraceMemoryState, typing.Any], store: ghidra.util.database.DBCachedObjectStore[typing.Any], record: db.DBRecord):
        ...


class DBTraceEmptyMemBuffer(ghidra.program.model.mem.MemBufferMixin):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, trace: ghidra.trace.database.DBTrace, start: ghidra.program.model.address.Address, byteOrder: java.nio.ByteOrder):
        ...


class DBTraceMemorySpace(ghidra.trace.model.memory.TraceMemorySpace, InternalTraceMemoryOperations, ghidra.trace.database.space.DBTraceSpaceBased):
    """
    Implements :obj:`TraceMemorySpace` using a database-backed copy-on-write store.
    """

    @typing.type_check_only
    class OutSnap(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, snap: typing.Union[jpype.JLong, int]):
            ...


    class_: typing.ClassVar[java.lang.Class]
    BLOCK_SHIFT: typing.Final = 12
    BLOCK_SIZE: typing.Final = 4096
    BLOCK_MASK: typing.Final = -4096
    DEPENDENT_COMPRESSED_SIZE_TOLERANCE: typing.Final = 1024
    BLOCKS_PER_BUFFER: typing.Final = 256

    def __init__(self, manager: DBTraceMemoryManager, dbh: db.DBHandle, space: ghidra.program.model.address.AddressSpace, ent: ghidra.trace.database.space.AbstractDBTraceSpaceBasedManager.DBTraceSpaceEntry):
        ...

    def checkStateMapIntegrity(self):
        ...

    def getFirstChange(self, span: ghidra.trace.model.Lifespan, range: ghidra.program.model.address.AddressRange) -> int:
        """
        Determine the truncation snap if the given span and range include byte changes
         
         
        
        Code units do not understand or accommodate changes in time, so the underlying bytes of the
        unit must be the same throughout its lifespan. Typically, units are placed with a desired
        creation snap, and then its life is extended into the future opportunistically. Thus, when
        truncating, we desire to keep the start snap, then search for the soonest byte change within
        the desired lifespan. Furthermore, we generally don't permit a unit to exist in both record
        and scratch spaces, i.e., it cannot span both the -1 and 0 snaps.
        
        :param ghidra.trace.model.Lifespan span: the desired lifespan
        :param ghidra.program.model.address.AddressRange range: the address range covered
        :return: the first snap that should be excluded, or :obj:`Long.MIN_VALUE` to indicate no
                change.
        :rtype: int
        """


class DBTraceMemoryRegion(ghidra.trace.model.memory.TraceMemoryRegion, ghidra.trace.database.target.DBTraceObjectInterface):

    @typing.type_check_only
    class Keys(java.lang.Record):

        class_: typing.ClassVar[java.lang.Class]

        def all(self) -> java.util.Set[java.lang.String]:
            ...

        def display(self) -> str:
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def flags(self) -> java.util.Set[java.lang.String]:
            ...

        def hashCode(self) -> int:
            ...

        def isDisplay(self, key: typing.Union[java.lang.String, str]) -> bool:
            ...

        def isFlag(self, key: typing.Union[java.lang.String, str]) -> bool:
            ...

        def isRange(self, key: typing.Union[java.lang.String, str]) -> bool:
            ...

        def range(self) -> str:
            ...

        def toString(self) -> str:
            ...

        @property
        def flag(self) -> jpype.JBoolean:
            ...


    @typing.type_check_only
    class RegionChangeTranslator(ghidra.trace.database.target.DBTraceObjectInterface.Translator[ghidra.trace.model.memory.TraceMemoryRegion]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, object: ghidra.trace.database.target.DBTraceObject):
        ...


class DBTraceMemoryBufferEntry(ghidra.util.database.DBAnnotatedObject):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, dbh: db.DBHandle, store: ghidra.util.database.DBCachedObjectStore[typing.Any], record: db.DBRecord):
        ...

    @typing.overload
    def acquireBlock(self) -> int:
        ...

    @typing.overload
    def acquireBlock(self, blockNum: typing.Union[jpype.JInt, int]):
        ...

    def cmpBytes(self, buf: java.nio.ByteBuffer, blkOffset: typing.Union[jpype.JInt, int], len: typing.Union[jpype.JInt, int], blockNum: typing.Union[jpype.JInt, int]) -> int:
        ...

    def compress(self):
        ...

    def copyFrom(self, dstBlockNum: typing.Union[jpype.JInt, int], srcBuf: DBTraceMemoryBufferEntry, srcBlockNum: typing.Union[jpype.JInt, int]):
        ...

    def decompress(self):
        ...

    def getBytes(self, buf: java.nio.ByteBuffer, srcOffset: typing.Union[jpype.JInt, int], len: typing.Union[jpype.JInt, int], blockNum: typing.Union[jpype.JInt, int]) -> int:
        ...

    def isEmpty(self) -> bool:
        ...

    def isInUse(self, blockNum: typing.Union[jpype.JInt, int]) -> bool:
        ...

    def releaseBlock(self, blockNum: typing.Union[jpype.JInt, int]):
        ...

    def setBytes(self, buf: java.nio.ByteBuffer, dstOffset: typing.Union[jpype.JInt, int], len: typing.Union[jpype.JInt, int], blockNum: typing.Union[jpype.JInt, int]) -> int:
        ...

    @property
    def inUse(self) -> jpype.JBoolean:
        ...

    @property
    def empty(self) -> jpype.JBoolean:
        ...



__all__ = ["DBTraceMemoryManager", "DBTraceObjectMemory", "DBTraceObjectRegister", "InternalTraceMemoryOperations", "DBTraceMemBuffer", "DBTraceMemoryBlockEntry", "DBTraceObjectRegisterContainer", "DBTraceMemoryStateEntry", "DBTraceEmptyMemBuffer", "DBTraceMemorySpace", "DBTraceMemoryRegion", "DBTraceMemoryBufferEntry"]
