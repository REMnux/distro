from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import generic.util
import ghidra.framework.data
import ghidra.program.model.address
import ghidra.program.model.lang
import ghidra.program.model.listing
import ghidra.program.model.mem
import ghidra.program.model.symbol
import ghidra.program.model.util
import ghidra.program.util
import ghidra.trace.database
import ghidra.trace.database.listing
import ghidra.trace.database.symbol
import ghidra.trace.model
import ghidra.trace.model.listing
import ghidra.trace.model.memory
import ghidra.trace.model.program
import ghidra.trace.model.property
import ghidra.trace.model.symbol
import ghidra.trace.model.thread
import ghidra.trace.util
import ghidra.util
import java.lang # type: ignore
import java.nio # type: ignore
import java.util # type: ignore


T = typing.TypeVar("T")
U = typing.TypeVar("U")


class DBTraceProgramViewFunctionManager(ghidra.program.model.listing.FunctionManager):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, program: DBTraceProgramView):
        ...


class DBTraceProgramViewSymbolTable(ghidra.program.model.symbol.SymbolTable):

    @typing.type_check_only
    class PrimarySymbolIterator(generic.util.AbstractPeekableIterator[ghidra.program.model.symbol.Symbol], ghidra.program.model.symbol.SymbolIterator):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, it: java.util.Iterator[ghidra.program.model.symbol.Symbol]):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, program: DBTraceProgramView):
        ...


class DBTraceProgramViewReferenceManager(AbstractDBTraceProgramViewReferenceManager):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, program: DBTraceProgramView):
        ...


class DBTraceProgramViewFragment(ghidra.program.model.listing.ProgramFragment):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, listing: AbstractDBTraceProgramViewListing, region: ghidra.trace.model.memory.TraceMemoryRegion, snap: typing.Union[jpype.JLong, int]):
        ...


class DBTraceProgramViewBookmarkManager(ghidra.trace.model.program.TraceProgramViewBookmarkManager):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, program: DBTraceProgramView):
        ...


class AbstractDBTraceProgramViewReferenceManager(ghidra.program.model.symbol.ReferenceManager):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, program: DBTraceProgramView):
        ...

    @staticmethod
    def getRefLevel(rt: ghidra.program.model.symbol.RefType) -> int:
        """
        Get the reference level for a given reference type
         
         
        
        TODO: Why is this not a property of :obj:`RefType`, or a static method of
        :obj:`SymbolUtilities`?
         
         
        
        Note that this was copy-pasted from ``BigRefListV0``, and there's an exact copy also in
        ``RefListV0``.
        
        :param ghidra.program.model.symbol.RefType rt: the reference type
        :return: the reference level
        :rtype: int
        """


class DBTraceProgramViewEquateTable(ghidra.program.model.symbol.EquateTable):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, program: DBTraceProgramView):
        ...


class DBTraceProgramViewMemorySpaceBlock(AbstractDBTraceProgramViewMemoryBlock):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, program: DBTraceProgramView, space: ghidra.program.model.address.AddressSpace):
        ...


class AbstractDBTraceProgramViewMemoryBlock(ghidra.program.model.mem.MemoryBlock):

    @typing.type_check_only
    class MyMemoryBlockSourceInfo(ghidra.program.model.mem.MemoryBlockSourceInfo):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]


class DBTraceProgramViewEquate(ghidra.program.model.symbol.Equate):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, program: DBTraceProgramView, equate: ghidra.trace.database.symbol.DBTraceEquate):
        ...


class DBTraceProgramViewProgramContext(ghidra.program.util.AbstractProgramContext):

    @typing.type_check_only
    class NestedAddressRangeIterator(generic.util.FlattenedIterator[U, ghidra.program.model.address.AddressRange], ghidra.program.model.address.AddressRangeIterator, typing.Generic[U]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, program: DBTraceProgramView):
        ...


class AbstractDBTraceProgramViewListing(ghidra.trace.model.program.TraceProgramViewListing):

    @typing.type_check_only
    class DBTraceProgramViewUndefinedData(ghidra.trace.database.listing.UndefinedDBTraceData):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, trace: ghidra.trace.database.DBTrace, snap: typing.Union[jpype.JLong, int], address: ghidra.program.model.address.Address, thread: ghidra.trace.model.thread.TraceThread, frameLevel: typing.Union[jpype.JInt, int]):
            ...


    class_: typing.ClassVar[java.lang.Class]
    EMPTY_STRING_ARRAY: typing.Final[jpype.JArray[java.lang.String]]
    TREE_NAME: typing.Final = "Trace Tree"

    def __init__(self, program: DBTraceProgramView, codeOperations: ghidra.trace.model.listing.TraceCodeOperations):
        ...


class DBTraceProgramView(ghidra.trace.model.program.TraceProgramView):
    """
    A wrapper on a trace, which given a snap, implements the :obj:`Program` interface
     
     
    
    NOTE: Calling :meth:`CodeUnit.getProgram() <CodeUnit.getProgram>` from units contained in this view may not necessarily
    return this same view. If the code unit comes from a less-recent snap than the snap associated
    with this view, the view for that snap is returned instead.
     
     
    
    TODO: Unit tests for all of this.
    """

    @typing.type_check_only
    class EventTranslator(ghidra.trace.util.TypedEventDispatcher, ghidra.trace.database.DBTraceDirectChangeListener):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...

        def fireSymbolAdded(self, queues: ghidra.framework.data.DomainObjectEventQueues, symbol: ghidra.trace.model.symbol.TraceSymbol):
            ...


    @typing.type_check_only
    class OverlappingAddressRangeKeyIteratorMerger(ghidra.util.PairingIteratorMerger[java.util.Map.Entry[ghidra.program.model.address.AddressRange, T], java.util.Map.Entry[ghidra.program.model.address.AddressRange, T], java.util.Map.Entry[ghidra.program.model.address.AddressRange, T]], typing.Generic[T]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, left: java.util.Iterator[java.util.Map.Entry[ghidra.program.model.address.AddressRange, T]], right: java.util.Iterator[java.util.Map.Entry[ghidra.program.model.address.AddressRange, T]]):
            ...


    class_: typing.ClassVar[java.lang.Class]
    TIME_INTERVAL: typing.Final = 100
    BUF_SIZE: typing.Final = 1000

    def __init__(self, trace: ghidra.trace.database.DBTrace, snap: typing.Union[jpype.JLong, int], compilerSpec: ghidra.program.model.lang.CompilerSpec):
        ...

    def updateBytesChanged(self, range: ghidra.program.model.address.AddressRange):
        ...

    def updateMemoryAddRegionBlock(self, region: ghidra.trace.model.memory.TraceMemoryRegion):
        ...

    def updateMemoryAddSpaceBlock(self, space: ghidra.program.model.address.AddressSpace):
        ...

    def updateMemoryChangeRegionBlockFlags(self, region: ghidra.trace.model.memory.TraceMemoryRegion, lifespan: ghidra.trace.model.Lifespan):
        ...

    def updateMemoryChangeRegionBlockLifespan(self, region: ghidra.trace.model.memory.TraceMemoryRegion, oldLifespan: ghidra.trace.model.Lifespan, newLifespan: ghidra.trace.model.Lifespan):
        ...

    def updateMemoryChangeRegionBlockName(self, region: ghidra.trace.model.memory.TraceMemoryRegion):
        ...

    def updateMemoryChangeRegionBlockRange(self, region: ghidra.trace.model.memory.TraceMemoryRegion, oldRange: ghidra.program.model.address.AddressRange, newRange: ghidra.program.model.address.AddressRange):
        ...

    def updateMemoryDeleteRegionBlock(self, region: ghidra.trace.model.memory.TraceMemoryRegion):
        ...

    def updateMemoryDeleteSpaceBlock(self, space: ghidra.program.model.address.AddressSpace):
        ...

    def updateMemoryRefreshBlocks(self):
        ...


class DBTraceVariableSnapProgramView(DBTraceProgramView, ghidra.trace.model.program.TraceVariableSnapProgramView):
    """
    TODO
     
    NOTE: Calling :meth:`CodeUnit.getProgram() <CodeUnit.getProgram>` from units contained in this view does not return
    this same view. Instead, it returns the (fixed-snap) view for the unit's snap.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, trace: ghidra.trace.database.DBTrace, snap: typing.Union[jpype.JLong, int], compilerSpec: ghidra.program.model.lang.CompilerSpec):
        ...


class DBTraceProgramViewPropertyMapManager(ghidra.program.model.util.PropertyMapManager):

    @typing.type_check_only
    class AbstractDBTraceProgramViewPropertyMap(ghidra.program.model.util.PropertyMap[T], typing.Generic[T]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, map: ghidra.trace.model.property.TracePropertyMap[T], name: typing.Union[java.lang.String, str]):
            ...


    @typing.type_check_only
    class DBTraceProgramViewIntPropertyMap(DBTraceProgramViewPropertyMapManager.AbstractDBTraceProgramViewPropertyMap[java.lang.Integer], ghidra.program.model.util.IntPropertyMap):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, map: ghidra.trace.model.property.TracePropertyMap[java.lang.Integer], name: typing.Union[java.lang.String, str]):
            ...


    @typing.type_check_only
    class DBTraceProgramViewLongPropertyMap(DBTraceProgramViewPropertyMapManager.AbstractDBTraceProgramViewPropertyMap[java.lang.Long], ghidra.program.model.util.LongPropertyMap):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, map: ghidra.trace.model.property.TracePropertyMap[java.lang.Long], name: typing.Union[java.lang.String, str]):
            ...


    @typing.type_check_only
    class DBTraceProgramViewStringPropertyMap(DBTraceProgramViewPropertyMapManager.AbstractDBTraceProgramViewPropertyMap[java.lang.String], ghidra.program.model.util.StringPropertyMap):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, map: ghidra.trace.model.property.TracePropertyMap[java.lang.String], name: typing.Union[java.lang.String, str]):
            ...


    @typing.type_check_only
    class DBTraceProgramViewObjectPropertyMap(DBTraceProgramViewPropertyMapManager.AbstractDBTraceProgramViewPropertyMap[T], ghidra.program.model.util.ObjectPropertyMap[T], typing.Generic[T]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, map: ghidra.trace.model.property.TracePropertyMap[T], name: typing.Union[java.lang.String, str]):
            ...


    @typing.type_check_only
    class DBTraceProgramViewVoidPropertyMap(DBTraceProgramViewPropertyMapManager.AbstractDBTraceProgramViewPropertyMap[java.lang.Boolean], ghidra.program.model.util.VoidPropertyMap):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, map: ghidra.trace.model.property.TracePropertyMap[java.lang.Boolean], name: typing.Union[java.lang.String, str]):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, program: DBTraceProgramView):
        ...


class DBTraceProgramViewChangeSet(ghidra.program.model.listing.ProgramChangeSet):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class DBTraceProgramViewRootModule(ghidra.program.model.listing.ProgramModule):

    class_: typing.ClassVar[java.lang.Class]
    EMPTY_MODULE_ARRAY: typing.Final[jpype.JArray[ghidra.program.model.listing.ProgramModule]]

    def __init__(self, listing: AbstractDBTraceProgramViewListing):
        ...


class DBTraceProgramViewListing(AbstractDBTraceProgramViewListing):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, program: DBTraceProgramView):
        ...


class DBTraceProgramViewMemory(AbstractDBTraceProgramViewMemory):

    @typing.type_check_only
    class RegionEntry(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, region: ghidra.trace.model.memory.TraceMemoryRegion, snap: typing.Union[jpype.JLong, int]):
            ...

        def isSameAtDifferentSnap(self, that: DBTraceProgramViewMemory.RegionEntry) -> bool:
            ...

        @property
        def sameAtDifferentSnap(self) -> jpype.JBoolean:
            ...


    @typing.type_check_only
    class RegionsByAddressComputer(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        def compute(self) -> java.util.NavigableMap[ghidra.program.model.address.Address, DBTraceProgramViewMemory.RegionEntry]:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, program: DBTraceProgramView):
        ...

    def updateAddSpaceBlock(self, space: ghidra.program.model.address.AddressSpace):
        ...

    def updateBytesChanged(self, range: ghidra.program.model.address.AddressRange):
        ...

    def updateDeleteSpaceBlock(self, space: ghidra.program.model.address.AddressSpace):
        ...

    def updateRefreshBlocks(self):
        ...


class AbstractDBTraceProgramViewMemory(ghidra.trace.model.program.TraceProgramViewMemory, ghidra.trace.util.MemoryAdapter):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, program: DBTraceProgramView):
        ...


class ByteCache(java.lang.Object):

    @typing.type_check_only
    class Page(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        def contains(self, address: ghidra.program.model.address.Address, length: typing.Union[jpype.JInt, int]) -> bool:
            ...

        def invalidate(self, range: ghidra.program.model.address.AddressRange):
            ...

        def load(self, address: ghidra.program.model.address.Address, length: typing.Union[jpype.JInt, int]) -> int:
            ...


    class_: typing.ClassVar[java.lang.Class]
    BITS: typing.Final = 12
    OFFSET_MASK: typing.Final = -4096
    SIZE: typing.Final = 4096

    def __init__(self, pageCount: typing.Union[jpype.JInt, int]):
        ...

    def canCache(self, address: ghidra.program.model.address.Address, len: typing.Union[jpype.JInt, int]) -> bool:
        ...

    def invalidate(self, range: ghidra.program.model.address.AddressRange):
        ...

    @typing.overload
    def read(self, address: ghidra.program.model.address.Address) -> int:
        ...

    @typing.overload
    def read(self, address: ghidra.program.model.address.Address, buf: java.nio.ByteBuffer) -> int:
        ...


class DBTraceProgramViewMemoryRegionBlock(AbstractDBTraceProgramViewMemoryBlock):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, program: DBTraceProgramView, region: ghidra.trace.model.memory.TraceMemoryRegion, snap: typing.Union[jpype.JLong, int]):
        ...



__all__ = ["DBTraceProgramViewFunctionManager", "DBTraceProgramViewSymbolTable", "DBTraceProgramViewReferenceManager", "DBTraceProgramViewFragment", "DBTraceProgramViewBookmarkManager", "AbstractDBTraceProgramViewReferenceManager", "DBTraceProgramViewEquateTable", "DBTraceProgramViewMemorySpaceBlock", "AbstractDBTraceProgramViewMemoryBlock", "DBTraceProgramViewEquate", "DBTraceProgramViewProgramContext", "AbstractDBTraceProgramViewListing", "DBTraceProgramView", "DBTraceVariableSnapProgramView", "DBTraceProgramViewPropertyMapManager", "DBTraceProgramViewChangeSet", "DBTraceProgramViewRootModule", "DBTraceProgramViewListing", "DBTraceProgramViewMemory", "AbstractDBTraceProgramViewMemory", "ByteCache", "DBTraceProgramViewMemoryRegionBlock"]
