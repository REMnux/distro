from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.program.model.address
import ghidra.program.model.data
import ghidra.program.model.lang
import ghidra.program.model.listing
import ghidra.program.model.pcode
import ghidra.program.model.symbol
import ghidra.trace.model
import ghidra.trace.model.guest
import ghidra.trace.model.listing
import ghidra.trace.model.stack
import ghidra.trace.model.thread
import ghidra.util.database.spatial.rect
import ghidra.util.task
import java.lang # type: ignore
import java.util # type: ignore


T = typing.TypeVar("T")


class TraceShiftedReference(TraceReference, ghidra.program.model.symbol.ShiftedReference):
    ...
    class_: typing.ClassVar[java.lang.Class]


class TraceSymbolWithAddressNoDuplicatesView(TraceSymbolWithAddressView[T], TraceSymbolNoDuplicatesView[T], typing.Generic[T]):
    """
    A symbol view where names cannot be duplicated and things have an address
    """

    class_: typing.ClassVar[java.lang.Class]


class TraceLabelSymbol(TraceSymbolWithLifespan):
    """
    A trace label symbol.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getCodeUnit(self) -> ghidra.trace.model.listing.TraceCodeUnit:
        """
        Get the code unit at this label
        
        :return: the code unit
        :rtype: ghidra.trace.model.listing.TraceCodeUnit
        """

    @property
    def codeUnit(self) -> ghidra.trace.model.listing.TraceCodeUnit:
        ...


class TraceEquateSpace(TraceEquateOperations):

    class_: typing.ClassVar[java.lang.Class]

    def getAddressSpace(self) -> ghidra.program.model.address.AddressSpace:
        ...

    @property
    def addressSpace(self) -> ghidra.program.model.address.AddressSpace:
        ...


class TraceReferenceOperations(java.lang.Object):
    """
    The operations for adding and retrieving references
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def addMemoryReference(self, lifespan: ghidra.trace.model.Lifespan, fromAddress: ghidra.program.model.address.Address, toRange: ghidra.program.model.address.AddressRange, refType: ghidra.program.model.symbol.RefType, source: ghidra.program.model.symbol.SourceType, operandIndex: typing.Union[jpype.JInt, int]) -> TraceReference:
        """
        Add a memory reference
        
        :param ghidra.trace.model.Lifespan lifespan: the span of time where this reference applies
        :param ghidra.program.model.address.Address fromAddress: the from address of the reference
        :param ghidra.program.model.address.AddressRange toRange: the to addresses of the reference
        :param ghidra.program.model.symbol.RefType refType: the type of reference
        :param ghidra.program.model.symbol.SourceType source: how this reference was derived
        :param jpype.JInt or int operandIndex: the operand index for the "from" end, or -1
        :return: the resulting reference
        :rtype: TraceReference
        """

    @typing.overload
    def addMemoryReference(self, lifespan: ghidra.trace.model.Lifespan, fromAddress: ghidra.program.model.address.Address, toAddress: ghidra.program.model.address.Address, refType: ghidra.program.model.symbol.RefType, source: ghidra.program.model.symbol.SourceType, operandIndex: typing.Union[jpype.JInt, int]) -> TraceReference:
        """
        Add a memory reference
        
        :param ghidra.trace.model.Lifespan lifespan: the span of time where this reference applies
        :param ghidra.program.model.address.Address fromAddress: the from address of the reference
        :param ghidra.program.model.address.Address toAddress: the to address of the reference
        :param ghidra.program.model.symbol.RefType refType: the type of reference
        :param ghidra.program.model.symbol.SourceType source: how this reference was derived
        :param jpype.JInt or int operandIndex: the operand index for the "from" end, or -1
        :return: the resulting reference
        :rtype: TraceReference
        """

    def addOffsetReference(self, lifespan: ghidra.trace.model.Lifespan, fromAddress: ghidra.program.model.address.Address, toAddress: ghidra.program.model.address.Address, toAddrIsBase: typing.Union[jpype.JBoolean, bool], offset: typing.Union[jpype.JLong, int], refType: ghidra.program.model.symbol.RefType, source: ghidra.program.model.symbol.SourceType, operandIndex: typing.Union[jpype.JInt, int]) -> TraceOffsetReference:
        """
        Add an offset memory reference
        
        :param ghidra.trace.model.Lifespan lifespan: the span of time where this reference applies
        :param ghidra.program.model.address.Address fromAddress: the from address of the reference
        :param ghidra.program.model.address.Address toAddress: the to address of the reference
        :param jpype.JBoolean or bool toAddrIsBase: indicate whether or not toAddress incorporates the offset. False means
                    toAddress=base+offset. True means toAddress=base.
        :param jpype.JLong or int offset: value added to the base address
        :param ghidra.program.model.symbol.RefType refType: the type of reference
        :param ghidra.program.model.symbol.SourceType source: how this reference was derived
        :param jpype.JInt or int operandIndex: the operand index for the "from" end, or -1
        :return: the resulting reference
        :rtype: TraceOffsetReference
        """

    @typing.overload
    def addReference(self, reference: TraceReference) -> TraceReference:
        """
        A (a copy of) the given reference to this manager
        
        :param TraceReference reference: the reference to add
        :return: the resulting reference
        :rtype: TraceReference
        """

    @typing.overload
    def addReference(self, lifespan: ghidra.trace.model.Lifespan, reference: ghidra.program.model.symbol.Reference) -> TraceReference:
        """
        A (a copy of) the given reference to this manager
        
        :param ghidra.trace.model.Lifespan lifespan: the span of time where this reference applies
        :param ghidra.program.model.symbol.Reference reference: the reference
        :return: the resulting reference
        :rtype: TraceReference
        """

    def addRegisterReference(self, lifespan: ghidra.trace.model.Lifespan, fromAddress: ghidra.program.model.address.Address, toRegister: ghidra.program.model.lang.Register, refType: ghidra.program.model.symbol.RefType, source: ghidra.program.model.symbol.SourceType, operandIndex: typing.Union[jpype.JInt, int]) -> TraceReference:
        """
        Add a register reference
        
        :param ghidra.trace.model.Lifespan lifespan: the span of time where this reference applies
        :param ghidra.program.model.address.Address fromAddress: the from address of the reference
        :param ghidra.program.model.lang.Register toRegister: the to register of the reference
        :param ghidra.program.model.symbol.RefType refType: the type of reference
        :param ghidra.program.model.symbol.SourceType source: how this reference was derived
        :param jpype.JInt or int operandIndex: the operand index for the "from" end, or -1
        :return: the resulting reference
        :rtype: TraceReference
        """

    def addShiftedReference(self, lifespan: ghidra.trace.model.Lifespan, fromAddress: ghidra.program.model.address.Address, toAddress: ghidra.program.model.address.Address, shift: typing.Union[jpype.JInt, int], refType: ghidra.program.model.symbol.RefType, source: ghidra.program.model.symbol.SourceType, operandIndex: typing.Union[jpype.JInt, int]) -> TraceShiftedReference:
        """
        Add a shifted memory reference
        
        :param ghidra.trace.model.Lifespan lifespan: the span of time where this reference applies
        :param ghidra.program.model.address.Address fromAddress: the from address of the reference
        :param ghidra.program.model.address.Address toAddress: the to address of the reference
        :param jpype.JInt or int shift: the number of bits to shift left
        :param ghidra.program.model.symbol.RefType refType: the type of reference
        :param ghidra.program.model.symbol.SourceType source: how this reference was derived
        :param jpype.JInt or int operandIndex: the operand index for the "from" end, or -1
        :return: the resulting reference
        :rtype: TraceShiftedReference
        """

    def addStackReference(self, lifespan: ghidra.trace.model.Lifespan, fromAddress: ghidra.program.model.address.Address, toStackOffset: typing.Union[jpype.JInt, int], refType: ghidra.program.model.symbol.RefType, source: ghidra.program.model.symbol.SourceType, operandIndex: typing.Union[jpype.JInt, int]) -> TraceReference:
        """
        Add a (static) stack reference
        
        :param ghidra.trace.model.Lifespan lifespan: the span of time where this reference applies
        :param ghidra.program.model.address.Address fromAddress: the from address of the reference
        :param jpype.JInt or int toStackOffset: the to offset of the reference
        :param ghidra.program.model.symbol.RefType refType: the type of reference
        :param ghidra.program.model.symbol.SourceType source: how this reference was derived
        :param jpype.JInt or int operandIndex: the operand index for the "from" end, or -1
        :return: the resulting reference
        :rtype: TraceReference
        """

    def clearReferencesFrom(self, span: ghidra.trace.model.Lifespan, range: ghidra.program.model.address.AddressRange):
        """
        Clear all references from the given lifespan and address range
         
         
        
        Any reference intersecting the given "from" parameters will have its lifespan truncated to
        the start of the given lifespan.
        
        :param ghidra.trace.model.Lifespan span: the lifespan to remove
        :param ghidra.program.model.address.AddressRange range: the range to clear
        """

    def clearReferencesTo(self, span: ghidra.trace.model.Lifespan, range: ghidra.program.model.address.AddressRange):
        """
        Clear all references to the given lifespan and address range
         
         
        
        Any reference intersecting the given "to" parameters will have its lifespan truncated to the
        start of the given lifespan.
        
        :param ghidra.trace.model.Lifespan span: the lifespan to remove
        :param ghidra.program.model.address.AddressRange range: the range of clear
        """

    def getFlowReferencesFrom(self, snap: typing.Union[jpype.JLong, int], fromAddress: ghidra.program.model.address.Address) -> java.util.Collection[TraceReference]:
        """
        Get all flow references from the given snapshot and address
        
        :param jpype.JLong or int snap: the snapshot key
        :param ghidra.program.model.address.Address fromAddress: the from address
        :return: the collection of results
        :rtype: java.util.Collection[TraceReference]
        """

    def getPrimaryReferenceFrom(self, snap: typing.Union[jpype.JLong, int], fromAddress: ghidra.program.model.address.Address, operandIndex: typing.Union[jpype.JInt, int]) -> TraceReference:
        """
        Get the primary reference matching from the given snapshot, address, and operand index
        
        :param jpype.JLong or int snap: the snapshot key
        :param ghidra.program.model.address.Address fromAddress: the from address
        :param jpype.JInt or int operandIndex: the operand index for the "from" end, or -1
        :return: the found reference or null
        :rtype: TraceReference
        """

    @typing.overload
    def getReference(self, snap: typing.Union[jpype.JLong, int], fromAddress: ghidra.program.model.address.Address, toRange: ghidra.program.model.address.AddressRange, operandIndex: typing.Union[jpype.JInt, int]) -> TraceReference:
        """
        Find the reference that matches the given parameters
         
         
        
        **NOTE:** It is not sufficient to *intersect* the to range. It must exactly match
        that given.
        
        :param jpype.JLong or int snap: the snapshot key
        :param ghidra.program.model.address.Address fromAddress: the from address
        :param ghidra.program.model.address.AddressRange toRange: the to address range
        :param jpype.JInt or int operandIndex: the operand index for the "from" end, or -1
        :return: the found reference or null
        :rtype: TraceReference
        """

    @typing.overload
    def getReference(self, snap: typing.Union[jpype.JLong, int], fromAddress: ghidra.program.model.address.Address, toAddress: ghidra.program.model.address.Address, operandIndex: typing.Union[jpype.JInt, int]) -> TraceReference:
        """
        Find the reference that matches the given parameters
         
         
        
        **NOTE:** It is not sufficient to *contain* the to address. To to range must be a
        singleton and exactly match that given. To match a range, see
        :meth:`getReference(long, Address, AddressRange, int) <.getReference>`
        
        :param jpype.JLong or int snap: the snapshot key
        :param ghidra.program.model.address.Address fromAddress: the from address
        :param ghidra.program.model.address.Address toAddress: the to address
        :param jpype.JInt or int operandIndex: the operand index for the "from" end, or -1
        :return: the found reference or null
        :rtype: TraceReference
        """

    def getReferenceCountFrom(self, snap: typing.Union[jpype.JLong, int], fromAddress: ghidra.program.model.address.Address) -> int:
        """
        Count the number of references from the given snapshot and address
        
        :param jpype.JLong or int snap: the snapshot key
        :param ghidra.program.model.address.Address fromAddress: the from address
        :return: the number of references
        :rtype: int
        """

    def getReferenceCountTo(self, snap: typing.Union[jpype.JLong, int], toAddress: ghidra.program.model.address.Address) -> int:
        """
        Count the number of references to the given snapshot and address
        
        :param jpype.JLong or int snap: the snapshot key
        :param ghidra.program.model.address.Address toAddress: the to address
        :return: the number of references
        :rtype: int
        """

    def getReferenceDestinations(self, span: ghidra.trace.model.Lifespan) -> ghidra.program.model.address.AddressSetView:
        """
        Get an address set of all "to" addresses in any reference intersecting the given lifespan
        
        :param ghidra.trace.model.Lifespan span: the lifespan to examine
        :return: a (lazily-computed) address set view of all "to" addresses
        :rtype: ghidra.program.model.address.AddressSetView
        """

    def getReferenceSources(self, span: ghidra.trace.model.Lifespan) -> ghidra.program.model.address.AddressSetView:
        """
        Get an address set of all "from" addresses in any reference intersecting the given lifespan
        
        :param ghidra.trace.model.Lifespan span: the lifespan to examine
        :return: a (lazily-computed) address set view of all "from" addresses
        :rtype: ghidra.program.model.address.AddressSetView
        """

    @typing.overload
    def getReferencesFrom(self, snap: typing.Union[jpype.JLong, int], fromAddress: ghidra.program.model.address.Address) -> java.util.Collection[TraceReference]:
        """
        Find all references from the given snapshot and address
        
        :param jpype.JLong or int snap: the snapshot key
        :param ghidra.program.model.address.Address fromAddress: the from address
        :return: the collection of results
        :rtype: java.util.Collection[TraceReference]
        """

    @typing.overload
    def getReferencesFrom(self, snap: typing.Union[jpype.JLong, int], fromAddress: ghidra.program.model.address.Address, operandIndex: typing.Union[jpype.JInt, int]) -> java.util.Collection[TraceReference]:
        """
        Find all references from the given snapshot, address, and operand index
        
        :param jpype.JLong or int snap: the snapshot key
        :param ghidra.program.model.address.Address fromAddress: the from address
        :param jpype.JInt or int operandIndex: the operand index for the "from" end, or -1
        :return: the collection of results
        :rtype: java.util.Collection[TraceReference]
        """

    def getReferencesFromRange(self, span: ghidra.trace.model.Lifespan, range: ghidra.program.model.address.AddressRange) -> java.util.Collection[TraceReference]:
        """
        Find all references with from addresses contained in the given lifespan and address range
        
        :param ghidra.trace.model.Lifespan span: the lifespan to examine
        :param ghidra.program.model.address.AddressRange range: the range to examine
        :return: the collection of results
        :rtype: java.util.Collection[TraceReference]
        """

    def getReferencesTo(self, snap: typing.Union[jpype.JLong, int], toAddress: ghidra.program.model.address.Address) -> java.util.Collection[TraceReference]:
        """
        Get all references whose to address (or range) contains the given snapshot and address
        
        :param jpype.JLong or int snap: the snapshot key
        :param ghidra.program.model.address.Address toAddress: the to address
        :return: the collection of results
        :rtype: java.util.Collection[TraceReference]
        """

    @typing.overload
    def getReferencesToRange(self, span: ghidra.trace.model.Lifespan, range: ghidra.program.model.address.AddressRange, order: ghidra.util.database.spatial.rect.Rectangle2DDirection) -> java.util.Collection[TraceReference]:
        """
        Get all references whose to address range intersects the given lifespan and address range
         
         
        
        The following iteration orders may be specified for the resulting (lazy) collection:
         
         
        * ``null`` - no particular order. This spares the cost of sorting.
        * :obj:`Rectangle2DDirection.TOPMOST` - most-recent (latest snapshot) first.
        * :obj:`Rectangle2DDirection.BOTTOMMOST` - least-recent (earliest including scratch
        snapshot first).
        * :obj:`Rectangle2DDirection.LEFTMOST` - smallest address first.
        * :obj:`Rectangle2DDirection.RIGHTMOST` - largest address first.
        
         
         
        
        "Secondary" sorting is not supported.
        
        :param ghidra.trace.model.Lifespan span: the lifespan to examine
        :param ghidra.program.model.address.AddressRange range: the range to examine
        :param ghidra.util.database.spatial.rect.Rectangle2DDirection order: the order of items in the collection.
        :return: the collection of results
        :rtype: java.util.Collection[TraceReference]
        """

    @typing.overload
    def getReferencesToRange(self, span: ghidra.trace.model.Lifespan, range: ghidra.program.model.address.AddressRange) -> java.util.Collection[TraceReference]:
        """
        Get all references whose to address range intersects the given lifespan and address range
        
        :param ghidra.trace.model.Lifespan span: the lifespan to examine
        :param ghidra.program.model.address.AddressRange range: the range to examine
        :return: the collection of results
        :rtype: java.util.Collection[TraceReference]
        """

    def hasFlowReferencesFrom(self, snap: typing.Union[jpype.JLong, int], fromAddress: ghidra.program.model.address.Address) -> bool:
        """
        Check if there exists a flow reference from the given snapshot and address
        
        :param jpype.JLong or int snap: the snapshot key
        :param ghidra.program.model.address.Address fromAddress: the from address
        :return: true if one or more flow references exist
        :rtype: bool
        """

    @typing.overload
    def hasReferencesFrom(self, snap: typing.Union[jpype.JLong, int], fromAddress: ghidra.program.model.address.Address) -> bool:
        """
        Check if there exists a reference from the given snapshot and address
        
        :param jpype.JLong or int snap: the snapshot key
        :param ghidra.program.model.address.Address fromAddress: the from address
        :return: true if one or more references exist
        :rtype: bool
        """

    @typing.overload
    def hasReferencesFrom(self, snap: typing.Union[jpype.JLong, int], fromAddress: ghidra.program.model.address.Address, operandIndex: typing.Union[jpype.JInt, int]) -> bool:
        """
        Check if there exists a reference from the given snapshot, address, and operand
        
        :param jpype.JLong or int snap: the snapshot key
        :param ghidra.program.model.address.Address fromAddress: the from address
        :param jpype.JInt or int operandIndex: the operand index, or -1
        :return: true if one or more references exist
        :rtype: bool
        """

    def hasReferencesTo(self, snap: typing.Union[jpype.JLong, int], toAddress: ghidra.program.model.address.Address) -> bool:
        """
        Check if there exists a reference to the given snapshot and address
        
        :param jpype.JLong or int snap: the snapshot key
        :param ghidra.program.model.address.Address toAddress: the to address
        :return: true if one or more references exists
        :rtype: bool
        """

    @property
    def referenceSources(self) -> ghidra.program.model.address.AddressSetView:
        ...

    @property
    def referenceDestinations(self) -> ghidra.program.model.address.AddressSetView:
        ...


class TraceClassSymbolView(TraceSymbolNoDuplicatesView[TraceClassSymbol]):
    """
    The class symbol view.
    """

    class_: typing.ClassVar[java.lang.Class]

    def add(self, name: typing.Union[java.lang.String, str], parent: TraceNamespaceSymbol, source: ghidra.program.model.symbol.SourceType) -> TraceClassSymbol:
        """
        Add a new class symbol.
        
        :param java.lang.String or str name: the name of the class
        :param TraceNamespaceSymbol parent: the parent namespace
        :param ghidra.program.model.symbol.SourceType source: the source
        :return: the new class symbol
        :rtype: TraceClassSymbol
        :raises DuplicateNameException: if the name is duplicated in the parent namespace
        :raises InvalidInputException: if the name is not valid
        :raises java.lang.IllegalArgumentException: if some other argument is not valid
        """


class TraceSymbolView(java.lang.Object, typing.Generic[T]):
    """
    A type-specific view in the trace symbol table
    
     
    
    The sub-interfaces of this handle the nuances for symbol types with more capabilities and/or
    restrictions.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getAll(self, includeDynamicSymbols: typing.Union[jpype.JBoolean, bool]) -> java.util.Collection[T]:
        """
        Get all the symbols in this view.
        
        :param jpype.JBoolean or bool includeDynamicSymbols: true to include dynamically-generated symbols
        :return: the symbols in this view satisfying the query
        :rtype: java.util.Collection[T]
        """

    def getChildren(self, parent: TraceNamespaceSymbol) -> java.util.Collection[T]:
        """
        Get all children of the given parent namespace in this view.
        
        :param TraceNamespaceSymbol parent: the parent namespace
        :return: the symbols in this view satisfying the query
        :rtype: java.util.Collection[T]
        """

    def getChildrenNamed(self, name: typing.Union[java.lang.String, str], parent: TraceNamespaceSymbol) -> java.util.Collection[T]:
        """
        Get all children of the given parent namespace having the given name in this view.
        
        :param java.lang.String or str name: the name of the symbols
        :param TraceNamespaceSymbol parent: the parent namespace
        :return: the symbols in this view satisfying the query
        :rtype: java.util.Collection[T]
        """

    def getGlobals(self) -> java.util.Collection[T]:
        """
        A shorthand for :meth:`getChildren(TraceNamespaceSymbol) <.getChildren>` where parent is the global
        namespace.
        
        :return: the symbols in this view satisfying the query
        :rtype: java.util.Collection[T]
        """

    def getGlobalsNamed(self, name: typing.Union[java.lang.String, str]) -> java.util.Collection[T]:
        """
        A shorthand for :meth:`getChildrenNamed(String, TraceNamespaceSymbol) <.getChildrenNamed>` where parent is the
        global namespace.
        
        :param java.lang.String or str name: the name of the symbols
        :return: the symbols in this view satisfying the query
        :rtype: java.util.Collection[T]
        """

    def getManager(self) -> TraceSymbolManager:
        """
        Get the symbol manager for the trace.
        
        :return: the symbol manager
        :rtype: TraceSymbolManager
        """

    def getNamed(self, name: typing.Union[java.lang.String, str]) -> java.util.Collection[T]:
        """
        Get symbols in this view with the given name, regardless of parent namespace
        
        :param java.lang.String or str name: the name of the symbols
        :return: the symbols in this view satisfying the query
        :rtype: java.util.Collection[T]
        """

    def getTrace(self) -> ghidra.trace.model.Trace:
        """
        Get the trace that contains this view
        
        :return: the trace
        :rtype: ghidra.trace.model.Trace
        """

    def getWithMatchingName(self, glob: typing.Union[java.lang.String, str], caseSensitive: typing.Union[jpype.JBoolean, bool]) -> java.util.Collection[T]:
        """
        Get symbols in this view whose names match the given glob, regardless of parent namespace
        
        :param java.lang.String or str glob: the glob (* matches zero-or-more, ? matches one character)
        :param jpype.JBoolean or bool caseSensitive: true to match case
        :return: the symbols in this view satisfying the query
        :rtype: java.util.Collection[T]
        """

    def scanByName(self, startName: typing.Union[java.lang.String, str]) -> java.util.Iterator[T]:
        """
        Scan symbols in this view lexicographically by name starting at the given lower bound
        
        :param java.lang.String or str startName: the starting lower bound
        :return: an iterator over symbols in this view satisfying the query
        :rtype: java.util.Iterator[T]
        """

    def size(self, includeDynamicSymbols: typing.Union[jpype.JBoolean, bool]) -> int:
        """
        Get the number of symbols in this view.
        
        :param jpype.JBoolean or bool includeDynamicSymbols: true to include dynamically-generated symbols
        :return: the number of symbols
        :rtype: int
        """

    @property
    def all(self) -> java.util.Collection[T]:
        ...

    @property
    def globalsNamed(self) -> java.util.Collection[T]:
        ...

    @property
    def trace(self) -> ghidra.trace.model.Trace:
        ...

    @property
    def named(self) -> java.util.Collection[T]:
        ...

    @property
    def manager(self) -> TraceSymbolManager:
        ...

    @property
    def children(self) -> java.util.Collection[T]:
        ...

    @property
    def globals(self) -> java.util.Collection[T]:
        ...


class TraceEquate(java.lang.Object):
    """
    TODO: Document me
     
    This is like :obj:`Equate`, except that extending it would prevent references with snaps. Thus,
    this interface is almost identical except where :obj:`Address`es are used, a snap is also used.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def addReference(self, lifespan: ghidra.trace.model.Lifespan, thread: ghidra.trace.model.thread.TraceThread, address: ghidra.program.model.address.Address, operandIndex: typing.Union[jpype.JInt, int]) -> TraceEquateReference:
        ...

    @typing.overload
    def addReference(self, lifespan: ghidra.trace.model.Lifespan, thread: ghidra.trace.model.thread.TraceThread, address: ghidra.program.model.address.Address, varnode: ghidra.program.model.pcode.Varnode) -> TraceEquateReference:
        ...

    def delete(self):
        ...

    def getDisplayName(self) -> str:
        ...

    def getDisplayValue(self) -> str:
        ...

    def getEnum(self) -> ghidra.program.model.data.Enum:
        ...

    def getName(self) -> str:
        ...

    @typing.overload
    def getReference(self, snap: typing.Union[jpype.JLong, int], thread: ghidra.trace.model.thread.TraceThread, address: ghidra.program.model.address.Address, operandIndex: typing.Union[jpype.JInt, int]) -> TraceEquateReference:
        ...

    @typing.overload
    def getReference(self, snap: typing.Union[jpype.JLong, int], thread: ghidra.trace.model.thread.TraceThread, address: ghidra.program.model.address.Address, varnode: ghidra.program.model.pcode.Varnode) -> TraceEquateReference:
        ...

    def getReferenceCount(self) -> int:
        ...

    def getReferences(self) -> java.util.Collection[TraceEquateReference]:
        ...

    def getValue(self) -> int:
        ...

    def hasValidEnum(self) -> bool:
        ...

    def isEnumBased(self) -> bool:
        ...

    def setName(self, newName: typing.Union[java.lang.String, str]):
        ...

    @property
    def displayValue(self) -> java.lang.String:
        ...

    @property
    def references(self) -> java.util.Collection[TraceEquateReference]:
        ...

    @property
    def displayName(self) -> java.lang.String:
        ...

    @property
    def referenceCount(self) -> jpype.JInt:
        ...

    @property
    def enumBased(self) -> jpype.JBoolean:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @name.setter
    def name(self, value: java.lang.String):
        ...

    @property
    def value(self) -> jpype.JLong:
        ...

    @property
    def enum(self) -> ghidra.program.model.data.Enum:
        ...


class TraceSymbolNoDuplicatesView(TraceSymbolView[T], typing.Generic[T]):
    """
    A symbol view where names cannot be duplicated within the same parent namespace
    """

    class_: typing.ClassVar[java.lang.Class]

    def getChildNamed(self, name: typing.Union[java.lang.String, str], parent: TraceNamespaceSymbol) -> T:
        """
        Get the child of the given parent having the given name.
        
        :param java.lang.String or str name: the name of the symbol
        :param TraceNamespaceSymbol parent: the parent namespace
        :return: the symbol, or null
        :rtype: T
        """

    def getGlobalNamed(self, name: typing.Union[java.lang.String, str]) -> T:
        """
        A shorthand for :meth:`getChildNamed(String, TraceNamespaceSymbol) <.getChildNamed>` where parent is the
        global namespace.
        
        :param java.lang.String or str name: the name of the symbol
        :return: the symbol, or null
        :rtype: T
        """

    @property
    def globalNamed(self) -> T:
        ...


class TraceSymbolWithAddressView(TraceSymbolView[T], typing.Generic[T]):
    """
    A symbol view for things with an address in stack or register space, but not associated with a
    trace thread.
    
     
    
    **NOTE:** This class is somewhat vestigial. It would be used to index parameters, locals, and
    global variables by their storage addresses. However, functions (and thus parameters and locals)
    are no longer supported. Furthermore, global variables are not fully implemented, yet.
    
    
    .. admonition:: Implementation Note
    
        If this is later used for global variables, we might need to consider that the variable
        is no longer implicitly bound in time by a parent function. We might remove this and
        use :obj:`TraceSymbolWithLocationView` instead. Even if we brought back function
        support, being able to query by those implicit bounds would probably be useful.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getAt(self, address: ghidra.program.model.address.Address, includeDynamicSymbols: typing.Union[jpype.JBoolean, bool]) -> java.util.Collection[T]:
        """
        Get symbols in this view containing the given address.
        
        :param ghidra.program.model.address.Address address: the address of the symbol
        :param jpype.JBoolean or bool includeDynamicSymbols: true to include dynamically-generated symbols
        :return: the symbols in this view satisfying the query
        :rtype: java.util.Collection[T]
        """

    def getChildWithNameAt(self, name: typing.Union[java.lang.String, str], address: ghidra.program.model.address.Address, parent: TraceNamespaceSymbol) -> T:
        """
        Get the child of the given parent having the given name at the given address.
        
        :param java.lang.String or str name: the name of the symbol
        :param ghidra.program.model.address.Address address: the address of the symbol
        :param TraceNamespaceSymbol parent: the parent namespace
        :return: the symbol, or null
        :rtype: T
        """

    def getGlobalWithNameAt(self, name: typing.Union[java.lang.String, str], address: ghidra.program.model.address.Address) -> T:
        """
        A shorthand for :meth:`getChildWithNameAt(String, Address, TraceNamespaceSymbol) <.getChildWithNameAt>` where
        parent is the global namespace.
        
        :param java.lang.String or str name: the name of the symbol
        :param ghidra.program.model.address.Address address: the address of the symbol
        :return: the symbol, or null
        :rtype: T
        """

    def getIntersecting(self, range: ghidra.program.model.address.AddressRange, includeDynamicSymbols: typing.Union[jpype.JBoolean, bool]) -> java.util.Collection[T]:
        """
        Get symbols in this view intersecting the given address range.
        
        :param ghidra.program.model.address.AddressRange range: the range
        :param jpype.JBoolean or bool includeDynamicSymbols: true to include dynamically-generated symbols
        :return: the symbols in this view satisfying the query
        :rtype: java.util.Collection[T]
        """

    def hasAt(self, address: ghidra.program.model.address.Address, includeDynamicSymbols: typing.Union[jpype.JBoolean, bool]) -> bool:
        """
        Check if this view contains any symbols at the given address.
        
        :param ghidra.program.model.address.Address address: the address of the symbol
        :param jpype.JBoolean or bool includeDynamicSymbols: true to include dynamically-generated symbols
        :return: true if any symbols in this view satisfy the query
        :rtype: bool
        """


class TraceLabelSymbolView(TraceSymbolWithLocationView[TraceLabelSymbol]):
    """
    The label symbol view.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def add(self, lifespan: ghidra.trace.model.Lifespan, address: ghidra.program.model.address.Address, name: typing.Union[java.lang.String, str], parent: TraceNamespaceSymbol, source: ghidra.program.model.symbol.SourceType) -> TraceLabelSymbol:
        """
        Add a new label symbol.
        
        :param ghidra.trace.model.Lifespan lifespan: the lifespan of the symbol
        :param ghidra.program.model.address.Address address: the address of the label
        :param java.lang.String or str name: the name of the label
        :param TraceNamespaceSymbol parent: the parent namespace
        :param ghidra.program.model.symbol.SourceType source: the source
        :return: the new label symbol
        :rtype: TraceLabelSymbol
        :raises InvalidInputException: if the name is not valid
        """

    @typing.overload
    def add(self, platform: ghidra.trace.model.guest.TracePlatform, lifespan: ghidra.trace.model.Lifespan, thread: ghidra.trace.model.thread.TraceThread, register: ghidra.program.model.lang.Register, name: typing.Union[java.lang.String, str], parent: TraceNamespaceSymbol, source: ghidra.program.model.symbol.SourceType) -> TraceLabelSymbol:
        """
        Add a new label symbol on a register for the given thread
        
        :param ghidra.trace.model.guest.TracePlatform platform: the platform defining the register
        :param ghidra.trace.model.Lifespan lifespan: the lifespan of the symbol
        :param ghidra.trace.model.thread.TraceThread thread: the thread
        :param ghidra.program.model.lang.Register register: the register
        :param java.lang.String or str name: the name of the label
        :param TraceNamespaceSymbol parent: the parent namespace
        :param ghidra.program.model.symbol.SourceType source: the source
        :return: the new label symbol
        :rtype: TraceLabelSymbol
        :raises InvalidInputException: if the name is not valid
        """

    @typing.overload
    def add(self, lifespan: ghidra.trace.model.Lifespan, thread: ghidra.trace.model.thread.TraceThread, register: ghidra.program.model.lang.Register, name: typing.Union[java.lang.String, str], parent: TraceNamespaceSymbol, source: ghidra.program.model.symbol.SourceType) -> TraceLabelSymbol:
        """
        Add new new label symbol on a register for the given thread
        
        :param ghidra.trace.model.Lifespan lifespan: the lifespan of the symbol
        :param ghidra.trace.model.thread.TraceThread thread: the thread
        :param ghidra.program.model.lang.Register register: the register
        :param java.lang.String or str name: the name of the label
        :param TraceNamespaceSymbol parent: the parent namespace
        :param ghidra.program.model.symbol.SourceType source: the source
        :return: the new label symbol
        :rtype: TraceLabelSymbol
        :raises InvalidInputException: if the name is not valid
        """

    @typing.overload
    def create(self, snap: typing.Union[jpype.JLong, int], address: ghidra.program.model.address.Address, name: typing.Union[java.lang.String, str], parent: TraceNamespaceSymbol, source: ghidra.program.model.symbol.SourceType) -> TraceLabelSymbol:
        """
        A shorthand for :meth:`add(Lifespan, Address, String, TraceNamespaceSymbol, SourceType) <.add>`
        where lifespan is from the given snap on.
        
        :param jpype.JLong or int snap: the starting snapshot key of the symbol
        :param ghidra.program.model.address.Address address: the address of the label
        :param java.lang.String or str name: the name of the label
        :param TraceNamespaceSymbol parent: the parent namespace
        :param ghidra.program.model.symbol.SourceType source: the source
        :return: the new label symbol
        :rtype: TraceLabelSymbol
        :raises InvalidInputException: if the name is not valid
        """

    @typing.overload
    def create(self, snap: typing.Union[jpype.JLong, int], thread: ghidra.trace.model.thread.TraceThread, register: ghidra.program.model.lang.Register, name: typing.Union[java.lang.String, str], parent: TraceNamespaceSymbol, source: ghidra.program.model.symbol.SourceType) -> TraceLabelSymbol:
        """
        A shorthand for
        :meth:`add(Lifespan, TraceThread, Register, String, TraceNamespaceSymbol, SourceType) <.add>` where
        lifespan is from the given snap on.
        
        :param jpype.JLong or int snap: the starting snapshot key of the symbol
        :param ghidra.trace.model.thread.TraceThread thread: the thread
        :param ghidra.program.model.lang.Register register: the register
        :param java.lang.String or str name: the name of the label
        :param TraceNamespaceSymbol parent: the parent namespace
        :param ghidra.program.model.symbol.SourceType source: the source
        :return: the new label symbol
        :rtype: TraceLabelSymbol
        :raises InvalidInputException: if the name is not valid
        """

    @typing.overload
    def create(self, platform: ghidra.trace.model.guest.TracePlatform, snap: typing.Union[jpype.JLong, int], thread: ghidra.trace.model.thread.TraceThread, register: ghidra.program.model.lang.Register, name: typing.Union[java.lang.String, str], parent: TraceNamespaceSymbol, source: ghidra.program.model.symbol.SourceType) -> TraceLabelSymbol:
        """
        A shorthand for
        :meth:`add(TracePlatform, Lifespan, TraceThread, Register, String, TraceNamespaceSymbol, SourceType) <.add>`
        where lifespan is from the given snap on.
        
        :param ghidra.trace.model.guest.TracePlatform platform: the platform defining the register
        :param jpype.JLong or int snap: the starting snapshot key of the symbol
        :param ghidra.trace.model.thread.TraceThread thread: the thread
        :param ghidra.program.model.lang.Register register: the register
        :param java.lang.String or str name: the name of the label
        :param TraceNamespaceSymbol parent: the parent namespace
        :param ghidra.program.model.symbol.SourceType source: the source
        :return: the new label symbol
        :rtype: TraceLabelSymbol
        :raises InvalidInputException: if the name is not valid
        """


class TraceEquateOperations(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def clearReferences(self, span: ghidra.trace.model.Lifespan, asv: ghidra.program.model.address.AddressSetView, monitor: ghidra.util.task.TaskMonitor):
        ...

    @typing.overload
    def clearReferences(self, span: ghidra.trace.model.Lifespan, range: ghidra.program.model.address.AddressRange, monitor: ghidra.util.task.TaskMonitor):
        ...

    @typing.overload
    def getReferenced(self, snap: typing.Union[jpype.JLong, int], address: ghidra.program.model.address.Address, operandIndex: typing.Union[jpype.JInt, int]) -> java.util.Collection[TraceEquate]:
        ...

    @typing.overload
    def getReferenced(self, snap: typing.Union[jpype.JLong, int], address: ghidra.program.model.address.Address) -> java.util.Collection[TraceEquate]:
        ...

    def getReferencedByValue(self, snap: typing.Union[jpype.JLong, int], address: ghidra.program.model.address.Address, operandIndex: typing.Union[jpype.JInt, int], value: typing.Union[jpype.JLong, int]) -> TraceEquate:
        ...

    def getReferringAddresses(self, span: ghidra.trace.model.Lifespan) -> ghidra.program.model.address.AddressSetView:
        ...

    @property
    def referringAddresses(self) -> ghidra.program.model.address.AddressSetView:
        ...


class TraceSymbolManager(java.lang.Object):
    """
    The symbol table for traces.
     
     
    
    Currently, functions are not supported, so effectively, the only symbol types possible in a trace
    are: labels, namespaces, and classes. Global variables are partially implemented, but as they are
    not finished, even in :obj:`Program`, they are not available in traces, either.
     
     
    
    This manager supports a "fluid" API syntax. The methods on this manager narrow the scope in terms
    of the symbol type. Each returns a view, the methods of which operate on that type specifically.
    For example, to get the label at a specific address:
     
     
    trace.getSymbolManager().labels().getAt(0, null, addr, false);
    """

    class_: typing.ClassVar[java.lang.Class]
    PRIMALITY_COMPARATOR: typing.Final[java.util.Comparator[TraceSymbol]]
    """
    A comparator that sorts primary symbols first.
    """


    def allNamespaces(self) -> TraceSymbolView[TraceNamespaceSymbol]:
        """
        Get a view of all the namespaces (including classes) in the trace.
        
        :return: the all-namespaces view
        :rtype: TraceSymbolView[TraceNamespaceSymbol]
        """

    def allSymbols(self) -> TraceSymbolView[TraceSymbol]:
        """
        Get a view of all symbols in the trace.
        
        :return: the all-symbols view
        :rtype: TraceSymbolView[TraceSymbol]
        """

    def classes(self) -> TraceClassSymbolView:
        """
        Get a view of the classes in the trace.
        
        :return: the classes view
        :rtype: TraceClassSymbolView
        """

    def getGlobalNamespace(self) -> TraceNamespaceSymbol:
        """
        Get the trace's global namespace.
        
        :return: the global namespace
        :rtype: TraceNamespaceSymbol
        """

    def getIDsAdded(self, from_: typing.Union[jpype.JLong, int], to: typing.Union[jpype.JLong, int]) -> java.util.Collection[java.lang.Long]:
        """
        Get the set of unique symbol IDs that are added going from one snapshot to another.
        
        :param jpype.JLong or int from: the first snapshot key
        :param jpype.JLong or int to: the second snapshot key
        :return: the set of IDs absent in the first but present in the second
        :rtype: java.util.Collection[java.lang.Long]
        """

    def getIDsRemoved(self, from_: typing.Union[jpype.JLong, int], to: typing.Union[jpype.JLong, int]) -> java.util.Collection[java.lang.Long]:
        """
        Get the set of unique symbol IDs that are removed going from one snapshot to another.
        
        :param jpype.JLong or int from: the first snapshot key
        :param jpype.JLong or int to: the second snapshot key
        :return: the set of IDs present in the first but absent in the second
        :rtype: java.util.Collection[java.lang.Long]
        """

    def getSymbolByID(self, symbolID: typing.Union[jpype.JLong, int]) -> TraceSymbol:
        """
        Get a symbol by its unique identifier.
         
         
        
        The identifier is only unique within this trace.
        
        :param jpype.JLong or int symbolID: the id
        :return: the symbol, or null
        :rtype: TraceSymbol
        """

    def getTrace(self) -> ghidra.trace.model.Trace:
        """
        Get the trace for this manager.
        
        :return: the trace
        :rtype: ghidra.trace.model.Trace
        """

    def labels(self) -> TraceLabelSymbolView:
        """
        Get a view of the labels in the trace.
        
        :return: the labels view
        :rtype: TraceLabelSymbolView
        """

    def namespaces(self) -> TraceNamespaceSymbolView:
        """
        Get a view of the namespaces in the trace.
        
        :return: the namespaces view
        :rtype: TraceNamespaceSymbolView
        """

    def notLabels(self) -> TraceSymbolNoDuplicatesView[TraceSymbol]:
        """
        Get a view of all the symbols except labels in the trace.
         
         
        
        **NOTE:** This method is somewhat vestigial. At one point, functions were partially
        implemented, so this would have contained functions, variables, etc. As the manager now only
        supports labels, namespaces, and classes, this is essentially the same as
        :meth:`allNamespaces() <.allNamespaces>`.
        
        :return: the not-labels view
        :rtype: TraceSymbolNoDuplicatesView[TraceSymbol]
        """

    @property
    def trace(self) -> ghidra.trace.model.Trace:
        ...

    @property
    def globalNamespace(self) -> TraceNamespaceSymbol:
        ...

    @property
    def symbolByID(self) -> TraceSymbol:
        ...


class TraceSymbolWithLocationView(TraceSymbolView[T], typing.Generic[T]):
    """
    A symbol view for things bound by an address range and lifespan.
    
     
    
    **NOTE:** We may eventually drop the ``thread`` parameter from these methods, as we
    transition to using register-space overlays.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def getAt(self, snap: typing.Union[jpype.JLong, int], address: ghidra.program.model.address.Address, includeDynamicSymbols: typing.Union[jpype.JBoolean, bool]) -> java.util.Collection[T]:
        """
        Get symbols in this view at the given point.
         
         
        
        The result will be ordered with the primary symbol first.
        
        :param jpype.JLong or int snap: the snapshot key
        :param ghidra.program.model.address.Address address: the address of the symbols
        :param jpype.JBoolean or bool includeDynamicSymbols: true to include dynamically-generated symbols
        :return: the symbols in this view satisfying the query
        :rtype: java.util.Collection[T]
        """

    @typing.overload
    def getAt(self, platform: ghidra.trace.model.guest.TracePlatform, snap: typing.Union[jpype.JLong, int], thread: ghidra.trace.model.thread.TraceThread, register: ghidra.program.model.lang.Register, includeDynamicSymbols: typing.Union[jpype.JBoolean, bool]) -> java.util.Collection[T]:
        """
        Get symbols in this view at the given register's min address.
         
         
        
        The result will be ordered with the primary symbol first.
        
        :param ghidra.trace.model.guest.TracePlatform platform: the platform defining the register
        :param jpype.JLong or int snap: the snapshot key
        :param ghidra.trace.model.thread.TraceThread thread: the thread
        :param ghidra.program.model.lang.Register register: the register
        :param jpype.JBoolean or bool includeDynamicSymbols: true to include dynamically-generated symbols
        :return: the symbols in this view satisfying the query
        :rtype: java.util.Collection[T]
        """

    @typing.overload
    def getAt(self, snap: typing.Union[jpype.JLong, int], thread: ghidra.trace.model.thread.TraceThread, register: ghidra.program.model.lang.Register, includeDynamicSymbols: typing.Union[jpype.JBoolean, bool]) -> java.util.Collection[T]:
        """
        Get symbols in this view at the given register's min address.
         
         
        
        The result will be ordered with the primary symbol first.
        
        :param jpype.JLong or int snap: the snapshot key
        :param ghidra.trace.model.thread.TraceThread thread: the thread
        :param ghidra.program.model.lang.Register register: the register
        :param jpype.JBoolean or bool includeDynamicSymbols: true to include dynamically-generated symbols
        :return: the symbols in this view satisfying the query
        :rtype: java.util.Collection[T]
        """

    @typing.overload
    def getChildWithNameAt(self, name: typing.Union[java.lang.String, str], snap: typing.Union[jpype.JLong, int], address: ghidra.program.model.address.Address, parent: TraceNamespaceSymbol) -> T:
        """
        Get the child of the given parent having the given name at the given point.
        
        :param java.lang.String or str name: the name of the symbol
        :param jpype.JLong or int snap: the snapshot key
        :param ghidra.program.model.address.Address address: the address of the symbol
        :param TraceNamespaceSymbol parent: the parent namespace
        :return: the symbol, or null
        :rtype: T
        """

    @typing.overload
    def getChildWithNameAt(self, name: typing.Union[java.lang.String, str], platform: ghidra.trace.model.guest.TracePlatform, snap: typing.Union[jpype.JLong, int], thread: ghidra.trace.model.thread.TraceThread, register: ghidra.program.model.lang.Register, parent: TraceNamespaceSymbol) -> T:
        """
        Get the child of the given parent having the given name at the given register's min address.
        
        :param java.lang.String or str name: the name of the symbol
        :param ghidra.trace.model.guest.TracePlatform platform: the platform defining the register
        :param jpype.JLong or int snap: the snapshot key
        :param ghidra.trace.model.thread.TraceThread thread: the thread
        :param ghidra.program.model.lang.Register register: the register whose min address to check
        :param TraceNamespaceSymbol parent: the parent namespace
        :return: the symbol, or null
        :rtype: T
        """

    @typing.overload
    def getChildWithNameAt(self, name: typing.Union[java.lang.String, str], snap: typing.Union[jpype.JLong, int], thread: ghidra.trace.model.thread.TraceThread, register: ghidra.program.model.lang.Register, parent: TraceNamespaceSymbol) -> T:
        """
        Get the child of the given parent having the given name at the given register's min address.
        
        :param java.lang.String or str name: the name of the symbol
        :param jpype.JLong or int snap: the snapshot key
        :param ghidra.trace.model.thread.TraceThread thread: the thread
        :param ghidra.program.model.lang.Register register: the register whose min address to check
        :param TraceNamespaceSymbol parent: the parent namespace
        :return: the symbol, or null
        :rtype: T
        """

    def getGlobalWithNameAt(self, name: typing.Union[java.lang.String, str], snap: typing.Union[jpype.JLong, int], address: ghidra.program.model.address.Address) -> T:
        """
        A shorthand for :meth:`getChildWithNameAt(String, long, Address, TraceNamespaceSymbol) <.getChildWithNameAt>`
        where parent is the global namespace.
        
        :param java.lang.String or str name: the name of the symbol
        :param jpype.JLong or int snap: the snapshot key
        :param ghidra.program.model.address.Address address: the address of the symbol
        :return: the symbol, or null
        :rtype: T
        """

    @typing.overload
    def getIntersecting(self, span: ghidra.trace.model.Lifespan, range: ghidra.program.model.address.AddressRange, includeDynamicSymbols: typing.Union[jpype.JBoolean, bool], forward: typing.Union[jpype.JBoolean, bool]) -> java.util.Collection[T]:
        """
        Get symbols in this view intersecting the given box.
        
        :param ghidra.trace.model.Lifespan span: the time bound of the box
        :param ghidra.program.model.address.AddressRange range: the address bound of the box
        :param jpype.JBoolean or bool includeDynamicSymbols: true to include dynamically-generated symbols
        :param jpype.JBoolean or bool forward: true if the collection should be ordered forward by address, false for
                    backward by address.
        :return: the symbols in this view satisfying the query
        :rtype: java.util.Collection[T]
        """

    @typing.overload
    def getIntersecting(self, platform: ghidra.trace.model.guest.TracePlatform, span: ghidra.trace.model.Lifespan, thread: ghidra.trace.model.thread.TraceThread, register: ghidra.program.model.lang.Register, includeDynamicSymbols: typing.Union[jpype.JBoolean, bool], forward: typing.Union[jpype.JBoolean, bool]) -> java.util.Collection[T]:
        """
        Get symbols in this view intersecting the given register.
        
        :param ghidra.trace.model.guest.TracePlatform platform: the platform defining the register
        :param ghidra.trace.model.Lifespan span: the time bound of the box
        :param ghidra.trace.model.thread.TraceThread thread: the thread
        :param ghidra.program.model.lang.Register register: the register
        :param jpype.JBoolean or bool includeDynamicSymbols: true to include dynamically-generated symbols
        :param jpype.JBoolean or bool forward: true if the collection should be ordered forward by address, false for
                    backward by address.
        :return: the symbols in this view satisfying the query
        :rtype: java.util.Collection[T]
        """

    @typing.overload
    def getIntersecting(self, span: ghidra.trace.model.Lifespan, thread: ghidra.trace.model.thread.TraceThread, register: ghidra.program.model.lang.Register, includeDynamicSymbols: typing.Union[jpype.JBoolean, bool], forward: typing.Union[jpype.JBoolean, bool]) -> java.util.Collection[T]:
        """
        Get symbols in this view intersecting the given register.
        
        :param ghidra.trace.model.Lifespan span: the time bound of the box
        :param ghidra.trace.model.thread.TraceThread thread: the thread
        :param ghidra.program.model.lang.Register register: the register
        :param jpype.JBoolean or bool includeDynamicSymbols: true to include dynamically-generated symbols
        :param jpype.JBoolean or bool forward: true if the collection should be ordered forward by address, false for
                    backward by address.
        :return: the symbols in this view satisfying the query
        :rtype: java.util.Collection[T]
        """

    def hasAt(self, snap: typing.Union[jpype.JLong, int], address: ghidra.program.model.address.Address, includeDynamicSymbols: typing.Union[jpype.JBoolean, bool]) -> bool:
        """
        Check if this view contains any symbols at the given point.
        
        :param jpype.JLong or int snap: the snapshot key
        :param ghidra.program.model.address.Address address: the address of the symbols
        :param jpype.JBoolean or bool includeDynamicSymbols: true to include dynamically-generated symbols
        :return: true if any symbols in this view satisfy the query
        :rtype: bool
        """


class TraceStackReference(TraceReference, ghidra.program.model.symbol.StackReference):
    ...
    class_: typing.ClassVar[java.lang.Class]


class TraceReferenceSpace(TraceReferenceOperations):

    class_: typing.ClassVar[java.lang.Class]

    def getAddressSpace(self) -> ghidra.program.model.address.AddressSpace:
        ...

    @property
    def addressSpace(self) -> ghidra.program.model.address.AddressSpace:
        ...


class TraceSymbolWithLifespan(TraceSymbol):
    """
    A trace symbol having a lifespan.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getEndSnap(self) -> int:
        """
        Get the maximum snapshot key in the lifespan
        
        :return: the maximum snapshot key
        :rtype: int
        """

    def getLifespan(self) -> ghidra.trace.model.Lifespan:
        """
        Get the lifespan of the symbol
        
        :return: the lifespan
        :rtype: ghidra.trace.model.Lifespan
        """

    def getStartSnap(self) -> int:
        """
        Get the minimum snapshot key in the lifespan
        
        :return: the minimum snapshot key
        :rtype: int
        """

    def setEndSnap(self, snap: typing.Union[jpype.JLong, int]):
        """
        Set the maximum snapshot key in the lifespan
        
        :param jpype.JLong or int snap: the new maximum snapshot key
        """

    @property
    def lifespan(self) -> ghidra.trace.model.Lifespan:
        ...

    @property
    def endSnap(self) -> jpype.JLong:
        ...

    @endSnap.setter
    def endSnap(self, value: jpype.JLong):
        ...

    @property
    def startSnap(self) -> jpype.JLong:
        ...


class TraceReference(ghidra.program.model.symbol.Reference):
    """
    A :obj:`Reference` within a :obj:`Trace`
    """

    class_: typing.ClassVar[java.lang.Class]

    def clearAssociatedSymbol(self):
        """
        Clear the associated symbol
        
        
        .. seealso::
        
            | :obj:`.getSymbolID()`
        """

    def delete(self):
        """
        Delete this reference
        """

    def getAssociatedSymbol(self) -> ghidra.program.model.symbol.Symbol:
        """
        Get the symbol associated with this reference
        
        :return: the symbol
        :rtype: ghidra.program.model.symbol.Symbol
        
        .. seealso::
        
            | :obj:`.getSymbolID()`
        """

    def getLifespan(self) -> ghidra.trace.model.Lifespan:
        """
        Get the lifespan for which this reference is effective
        
        :return: the lifespan
        :rtype: ghidra.trace.model.Lifespan
        """

    def getStartSnap(self) -> int:
        """
        Get the starting snapshot key of this reference's lifespan
        
        :return: the starting snapshot
        :rtype: int
        
        .. seealso::
        
            | :obj:`.getLifespan()`
        """

    def getToRange(self) -> ghidra.program.model.address.AddressRange:
        """
        Get the "to" range of this reference.
         
         
        
        Because references are often used in traces to indicate *actual* run-time writes, it
        is not sufficient to examine the code unit at a single "to" address and assume the reference
        is to the entire unit. For one, the read might be of a specific field in a structure data
        unit. For two, a read of a large unit may be implemented as a loop of several smaller reads.
        The trace could (and probably should) record each atomic read. In theory, one could examine
        the "from" instruction and operand index to derive the length, but that is onerous and not
        indexed. So instead, we record the exact "to" range in each reference and index it. This
        allows for easy implementation of, e.g., access breakpoints.
        
        :return: the to range
        :rtype: ghidra.program.model.address.AddressRange
        """

    def getTrace(self) -> ghidra.trace.model.Trace:
        """
        Get the trace containing this reference
        
        :return: the trace
        :rtype: ghidra.trace.model.Trace
        """

    def setAssociatedSymbol(self, symbol: ghidra.program.model.symbol.Symbol):
        """
        Set the symbol associated with this reference
        
        :param ghidra.program.model.symbol.Symbol symbol: the symbol
        
        .. seealso::
        
            | :obj:`.getSymbolID()`
        """

    def setPrimary(self, primary: typing.Union[jpype.JBoolean, bool]):
        """
        Make this reference primary.
         
        Only one reference at a given "from" location can be primary. If a primary reference already
        exists at this location, it will become a secondary reference.
        
        :param jpype.JBoolean or bool primary:
        """

    def setReferenceType(self, refType: ghidra.program.model.symbol.RefType):
        """
        Set the reference type
        
        :param ghidra.program.model.symbol.RefType refType: the new reference type
        """

    @property
    def trace(self) -> ghidra.trace.model.Trace:
        ...

    @property
    def lifespan(self) -> ghidra.trace.model.Lifespan:
        ...

    @property
    def startSnap(self) -> jpype.JLong:
        ...

    @property
    def toRange(self) -> ghidra.program.model.address.AddressRange:
        ...

    @property
    def associatedSymbol(self) -> ghidra.program.model.symbol.Symbol:
        ...

    @associatedSymbol.setter
    def associatedSymbol(self, value: ghidra.program.model.symbol.Symbol):
        ...


class TraceEquateReference(ghidra.program.model.symbol.EquateReference):

    class_: typing.ClassVar[java.lang.Class]

    def delete(self):
        ...

    def getLifespan(self) -> ghidra.trace.model.Lifespan:
        ...

    def getThread(self) -> ghidra.trace.model.thread.TraceThread:
        ...

    def getVarnode(self) -> ghidra.program.model.pcode.Varnode:
        ...

    @property
    def varnode(self) -> ghidra.program.model.pcode.Varnode:
        ...

    @property
    def lifespan(self) -> ghidra.trace.model.Lifespan:
        ...

    @property
    def thread(self) -> ghidra.trace.model.thread.TraceThread:
        ...


class TraceSymbol(ghidra.program.model.symbol.Symbol):
    """
    A trace symbol.
    
     
    
    This is essentially the equivalent concept of :obj:`Symbol` from a :obj:`Program`. One
    important distinction is that in the trace implementation, the symbol and the object it describes
    are the same. For example, in a :obj:`Program`, a :obj:`Namespace` and its symbol are two
    different things. To get the namespace, you would invoke :meth:`Symbol.getObject() <Symbol.getObject>`. That is
    unnecessary, though permissible, with a trace, because :obj:`TraceNamespaceSymbol` extends from
    both :obj:`Namespace` and :obj:`Symbol`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getReferenceCollection(self) -> java.util.Collection[TraceReference]:
        """
        Get all memory references to the address of this symbol.
        
        :return: the references
        :rtype: java.util.Collection[TraceReference]
        """

    def getThread(self) -> ghidra.trace.model.thread.TraceThread:
        """
        If in register space, get the thread associated with this symbol.
        
        :return: the thread
        :rtype: ghidra.trace.model.thread.TraceThread
        """

    def getTrace(self) -> ghidra.trace.model.Trace:
        """
        Get the trace to which this symbol belongs.
        
        :return: the trace
        :rtype: ghidra.trace.model.Trace
        """

    @property
    def trace(self) -> ghidra.trace.model.Trace:
        ...

    @property
    def referenceCollection(self) -> java.util.Collection[TraceReference]:
        ...

    @property
    def thread(self) -> ghidra.trace.model.thread.TraceThread:
        ...


class TraceNamespaceSymbolView(TraceSymbolNoDuplicatesView[TraceNamespaceSymbol]):
    """
    The namespace symbol view.
    """

    class_: typing.ClassVar[java.lang.Class]

    def add(self, name: typing.Union[java.lang.String, str], parent: TraceNamespaceSymbol, source: ghidra.program.model.symbol.SourceType) -> TraceNamespaceSymbol:
        """
        Add a new namespace symbol.
        
        :param java.lang.String or str name: the name of the namespace
        :param TraceNamespaceSymbol parent: the parent namespace
        :param ghidra.program.model.symbol.SourceType source: the source
        :return: the new namespace symbol
        :rtype: TraceNamespaceSymbol
        :raises DuplicateNameException: if the name is duplicated in the parent namespace
        :raises InvalidInputException: if the name is not valid
        """


class TraceReferenceManager(TraceReferenceOperations):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def getReferenceRegisterSpace(self, thread: ghidra.trace.model.thread.TraceThread, createIfAbsent: typing.Union[jpype.JBoolean, bool]) -> TraceReferenceSpace:
        ...

    @typing.overload
    def getReferenceRegisterSpace(self, frame: ghidra.trace.model.stack.TraceStackFrame, createIfAbsent: typing.Union[jpype.JBoolean, bool]) -> TraceReferenceSpace:
        ...

    def getReferenceSpace(self, space: ghidra.program.model.address.AddressSpace, createIfAbsent: typing.Union[jpype.JBoolean, bool]) -> TraceReferenceSpace:
        ...


class TraceEquateManager(TraceEquateOperations):
    """
    TODO: Document me
    """

    class_: typing.ClassVar[java.lang.Class]

    def create(self, name: typing.Union[java.lang.String, str], value: typing.Union[jpype.JLong, int]) -> TraceEquate:
        ...

    def getAll(self) -> java.util.Collection[TraceEquate]:
        ...

    def getByKey(self, key: typing.Union[jpype.JLong, int]) -> TraceEquate:
        ...

    def getByName(self, name: typing.Union[java.lang.String, str]) -> TraceEquate:
        ...

    def getByValue(self, value: typing.Union[jpype.JLong, int]) -> java.util.Collection[TraceEquate]:
        ...

    @typing.overload
    def getEquateRegisterSpace(self, thread: ghidra.trace.model.thread.TraceThread, createIfAbsent: typing.Union[jpype.JBoolean, bool]) -> TraceEquateSpace:
        ...

    @typing.overload
    def getEquateRegisterSpace(self, frame: ghidra.trace.model.stack.TraceStackFrame, createIfAbsent: typing.Union[jpype.JBoolean, bool]) -> TraceEquateSpace:
        ...

    def getEquateSpace(self, space: ghidra.program.model.address.AddressSpace, createIfAbsent: typing.Union[jpype.JBoolean, bool]) -> TraceEquateSpace:
        ...

    @staticmethod
    def validateName(name: typing.Union[java.lang.String, str]):
        ...

    @property
    def all(self) -> java.util.Collection[TraceEquate]:
        ...

    @property
    def byKey(self) -> TraceEquate:
        ...

    @property
    def byName(self) -> TraceEquate:
        ...

    @property
    def byValue(self) -> java.util.Collection[TraceEquate]:
        ...


class TraceOffsetReference(TraceReference, ghidra.program.model.symbol.OffsetReference):
    ...
    class_: typing.ClassVar[java.lang.Class]


class TraceClassSymbol(TraceNamespaceSymbol, ghidra.program.model.listing.GhidraClass):
    """
    A trace class symbol
    """

    class_: typing.ClassVar[java.lang.Class]


class TraceNamespaceSymbol(TraceSymbol, ghidra.program.model.symbol.Namespace):
    """
    A trace namespace symbol.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getChildren(self) -> java.util.Collection[TraceSymbol]:
        """
        Get the children of this namespace
        
        :return: the children
        :rtype: java.util.Collection[TraceSymbol]
        """

    @property
    def children(self) -> java.util.Collection[TraceSymbol]:
        ...



__all__ = ["TraceShiftedReference", "TraceSymbolWithAddressNoDuplicatesView", "TraceLabelSymbol", "TraceEquateSpace", "TraceReferenceOperations", "TraceClassSymbolView", "TraceSymbolView", "TraceEquate", "TraceSymbolNoDuplicatesView", "TraceSymbolWithAddressView", "TraceLabelSymbolView", "TraceEquateOperations", "TraceSymbolManager", "TraceSymbolWithLocationView", "TraceStackReference", "TraceReferenceSpace", "TraceSymbolWithLifespan", "TraceReference", "TraceEquateReference", "TraceSymbol", "TraceNamespaceSymbolView", "TraceReferenceManager", "TraceEquateManager", "TraceOffsetReference", "TraceClassSymbol", "TraceNamespaceSymbol"]
