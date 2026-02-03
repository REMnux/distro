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
import ghidra.trace.database.memory
import ghidra.trace.model
import ghidra.trace.model.guest
import ghidra.trace.model.symbol
import ghidra.trace.model.target
import ghidra.trace.util
import ghidra.util.database
import ghidra.util.task
import java.lang # type: ignore
import java.util # type: ignore
import java.util.concurrent.locks # type: ignore


class DBTracePlatformManager(ghidra.trace.database.DBTraceManager, ghidra.trace.model.guest.TracePlatformManager):

    class DBTraceHostPlatform(InternalTracePlatform):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, dbh: db.DBHandle, openMode: ghidra.framework.data.OpenMode, lock: java.util.concurrent.locks.ReadWriteLock, monitor: ghidra.util.task.TaskMonitor, baseCompilerSpec: ghidra.program.model.lang.CompilerSpec, trace: ghidra.trace.database.DBTrace):
        ...

    def assertMine(self, platform: ghidra.trace.model.guest.TracePlatform) -> InternalTracePlatform:
        ...

    def getLanguageByKey(self, key: typing.Union[jpype.JInt, int]) -> DBTraceGuestPlatform.DBTraceGuestLanguage:
        ...

    def getLanguageByLanguage(self, language: ghidra.program.model.lang.Language) -> DBTraceGuestPlatform.DBTraceGuestLanguage:
        ...

    def getPlatformByKey(self, key: typing.Union[jpype.JInt, int]) -> InternalTracePlatform:
        ...

    @property
    def languageByKey(self) -> DBTraceGuestPlatform.DBTraceGuestLanguage:
        ...

    @property
    def platformByKey(self) -> InternalTracePlatform:
        ...

    @property
    def languageByLanguage(self) -> DBTraceGuestPlatform.DBTraceGuestLanguage:
        ...


class InternalTracePlatform(ghidra.trace.model.guest.TracePlatform, ghidra.program.model.lang.ProgramArchitecture):

    class_: typing.ClassVar[java.lang.Class]
    REG_MAP_BE: typing.Final = "__reg_map_be__"
    REG_MAP_LE: typing.Final = "__reg_map_le__"

    def getIntKey(self) -> int:
        """
        Get the entry's key in the table as an integer
        
        :return: the key
        :rtype: int
        """

    def getLanguageEntry(self) -> DBTraceGuestPlatform.DBTraceGuestLanguage:
        ...

    def getRegistersRange(self) -> ghidra.program.model.address.AddressRange:
        ...

    def listRegNames(self, register: ghidra.program.model.lang.Register) -> java.util.List[java.lang.String]:
        ...

    @staticmethod
    def regMap(register: ghidra.program.model.lang.Register) -> str:
        ...

    @property
    def intKey(self) -> jpype.JInt:
        ...

    @property
    def languageEntry(self) -> DBTraceGuestPlatform.DBTraceGuestLanguage:
        ...

    @property
    def registersRange(self) -> ghidra.program.model.address.AddressRange:
        ...


class DBTraceObjectRegisterSupport(java.lang.Enum[DBTraceObjectRegisterSupport]):

    class_: typing.ClassVar[java.lang.Class]
    INSTANCE: typing.Final[DBTraceObjectRegisterSupport]

    def onMappingAddedCheckTransfer(self, mapped: ghidra.trace.model.guest.TraceGuestPlatformMappedRange):
        ...

    def onMappingAddedCheckTransferMemoryMapped(self, root: ghidra.trace.model.target.TraceObject, mapped: ghidra.trace.model.guest.TraceGuestPlatformMappedRange):
        ...

    def onSpaceAddedCheckTransfer(self, trace: ghidra.trace.model.Trace, space: ghidra.program.model.address.AddressSpace):
        ...

    def onSymbolAddedCheckTransfer(self, symbol: ghidra.trace.model.symbol.TraceSymbol):
        ...

    def onSymbolAddedCheckTransferToLabel(self, label: ghidra.trace.model.symbol.TraceLabelSymbol, isBigEndian: typing.Union[jpype.JBoolean, bool]):
        ...

    def onValueCreatedCheckTransfer(self, objectValue: ghidra.trace.model.target.TraceObjectValue):
        ...

    def onValueCreatedTransfer(self, registerValue: ghidra.trace.model.target.TraceObjectValue):
        ...

    def processEvent(self, event: ghidra.trace.util.TraceChangeRecord[typing.Any, typing.Any]):
        ...

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> DBTraceObjectRegisterSupport:
        ...

    @staticmethod
    def values() -> jpype.JArray[DBTraceObjectRegisterSupport]:
        ...


class DBTraceGuestPlatformMappedMemory(ghidra.program.model.mem.Memory):
    """
    TODO: Document me
     
     
    
    Note this is the bare minimum to support :obj:`DumbMemBufferImpl`
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, manager: ghidra.trace.database.memory.DBTraceMemoryManager, guest: DBTraceGuestPlatform, snap: typing.Union[jpype.JLong, int]):
        ...


class DBTraceGuestPlatformMappedRange(ghidra.util.database.DBAnnotatedObject, ghidra.trace.model.guest.TraceGuestPlatformMappedRange):

    class_: typing.ClassVar[java.lang.Class]
    TABLE_NAME: typing.Final = "LanguageMappings"

    def __init__(self, manager: DBTracePlatformManager, s: ghidra.util.database.DBCachedObjectStore[typing.Any], r: db.DBRecord):
        ...


class DBTraceGuestPlatform(ghidra.util.database.DBAnnotatedObject, ghidra.trace.model.guest.TraceGuestPlatform, InternalTracePlatform):

    @typing.type_check_only
    class MappedRangeRanger(java.lang.Enum[DBTraceGuestPlatform.MappedRangeRanger], ghidra.trace.util.OverlappingObjectIterator.Ranger[DBTraceGuestPlatformMappedRange]):

        class_: typing.ClassVar[java.lang.Class]
        HOST: typing.Final[DBTraceGuestPlatform.MappedRangeRanger]
        GUEST: typing.Final[DBTraceGuestPlatform.MappedRangeRanger]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> DBTraceGuestPlatform.MappedRangeRanger:
            ...

        @staticmethod
        def values() -> jpype.JArray[DBTraceGuestPlatform.MappedRangeRanger]:
            ...


    class DBTraceGuestLanguage(ghidra.util.database.DBAnnotatedObject):

        class_: typing.ClassVar[java.lang.Class]
        TABLE_NAME: typing.Final = "Languages"

        def __init__(self, store: ghidra.util.database.DBCachedObjectStore[typing.Any], record: db.DBRecord):
            ...

        def getLanguage(self) -> ghidra.program.model.lang.Language:
            ...

        @property
        def language(self) -> ghidra.program.model.lang.Language:
            ...


    class_: typing.ClassVar[java.lang.Class]
    TABLE_NAME: typing.Final = "Platforms"

    def __init__(self, manager: DBTracePlatformManager, store: ghidra.util.database.DBCachedObjectStore[typing.Any], record: db.DBRecord):
        ...

    def mapGuestToHost(self, guestMin: ghidra.program.model.address.Address, guestMax: ghidra.program.model.address.Address) -> ghidra.program.model.address.Address:
        """
        Map an address only if the entire range is contained in a single mapped range
        
        :param ghidra.program.model.address.Address guestMin: the min address of the range to map
        :param ghidra.program.model.address.Address guestMax: the max address of the range to check
        :return: the mapped min address
        :rtype: ghidra.program.model.address.Address
        """



__all__ = ["DBTracePlatformManager", "InternalTracePlatform", "DBTraceObjectRegisterSupport", "DBTraceGuestPlatformMappedMemory", "DBTraceGuestPlatformMappedRange", "DBTraceGuestPlatform"]
