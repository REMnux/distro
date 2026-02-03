from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import generic
import ghidra.framework.model
import ghidra.program.model.address
import ghidra.program.model.data
import ghidra.program.model.lang
import ghidra.program.model.listing
import ghidra.trace.model.bookmark
import ghidra.trace.model.breakpoint
import ghidra.trace.model.context
import ghidra.trace.model.data
import ghidra.trace.model.guest
import ghidra.trace.model.listing
import ghidra.trace.model.memory
import ghidra.trace.model.modules
import ghidra.trace.model.program
import ghidra.trace.model.property
import ghidra.trace.model.stack
import ghidra.trace.model.symbol
import ghidra.trace.model.target
import ghidra.trace.model.thread
import ghidra.trace.model.time
import ghidra.trace.util
import ghidra.util
import ghidra.util.database
import ghidra.util.database.spatial.rect
import java.lang # type: ignore
import java.util # type: ignore
import java.util.function # type: ignore
import javax.swing # type: ignore


T = typing.TypeVar("T")


class TraceUserData(ghidra.framework.model.UserData):
    ...
    class_: typing.ClassVar[java.lang.Class]


class TraceAddressSnapSpace(ghidra.util.database.spatial.rect.EuclideanSpace2D[ghidra.program.model.address.Address, java.lang.Long]):

    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def forAddressSpace(space: ghidra.program.model.address.AddressSpace) -> TraceAddressSnapSpace:
        """
        Get the trace-address-snap space for a given address space
         
         
        
        Because this synchronizes on a cache of spaces, it should only be called by space
        constructors, never by entry constructors.
        
        :param ghidra.program.model.address.AddressSpace space: the address space
        :return: the trace-address-snap space
        :rtype: TraceAddressSnapSpace
        """


class DefaultAddressSnap(AddressSnap):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, address: ghidra.program.model.address.Address, snap: typing.Union[jpype.JLong, int]):
        ...


class TraceClosedException(ghidra.framework.model.DomainObjectException):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, t: java.lang.Throwable):
        ...


class TraceChangeSet(ghidra.program.model.listing.DataTypeChangeSet):
    ...
    class_: typing.ClassVar[java.lang.Class]


class TraceUniqueObject(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def getObjectKey(self) -> ghidra.util.database.ObjectKey:
        """
        Get an opaque unique id for this object, whose hash is immutable
        
        :return: the opaque object id
        :rtype: ghidra.util.database.ObjectKey
        """

    def isDeleted(self) -> bool:
        """
        Check if this object is deleted
        
        :return: true if deleted
        :rtype: bool
        """

    @property
    def deleted(self) -> jpype.JBoolean:
        ...

    @property
    def objectKey(self) -> ghidra.util.database.ObjectKey:
        ...


class TraceOptionsManager(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def asMap(self) -> java.util.Map[java.lang.String, java.lang.String]:
        ...

    def getBaseLanguage(self) -> ghidra.program.model.lang.Language:
        ...

    def getBaseLanguageID(self) -> ghidra.program.model.lang.LanguageID:
        ...

    def getBaseLanguageIDName(self) -> str:
        ...

    def getCreationDate(self) -> java.util.Date:
        ...

    def getExecutablePath(self) -> str:
        ...

    def getName(self) -> str:
        ...

    def getPlatform(self) -> str:
        ...

    def setExecutablePath(self, path: typing.Union[java.lang.String, str]):
        ...

    def setName(self, name: typing.Union[java.lang.String, str]):
        ...

    def setPlatform(self, platform: typing.Union[java.lang.String, str]):
        ...

    @property
    def executablePath(self) -> java.lang.String:
        ...

    @executablePath.setter
    def executablePath(self, value: java.lang.String):
        ...

    @property
    def baseLanguageID(self) -> ghidra.program.model.lang.LanguageID:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @name.setter
    def name(self, value: java.lang.String):
        ...

    @property
    def baseLanguageIDName(self) -> java.lang.String:
        ...

    @property
    def baseLanguage(self) -> ghidra.program.model.lang.Language:
        ...

    @property
    def creationDate(self) -> java.util.Date:
        ...

    @property
    def platform(self) -> java.lang.String:
        ...

    @platform.setter
    def platform(self, value: java.lang.String):
        ...


class TraceTimeViewport(java.lang.Object):
    """
    A convenience for tracking the time structure of a trace and querying the trace accordingly.
    """

    class Occlusion(java.lang.Object, typing.Generic[T]):

        class_: typing.ClassVar[java.lang.Class]

        def occluded(self, object: T, range: ghidra.program.model.address.AddressRange, span: Lifespan) -> bool:
            ...

        def remove(self, object: T, remains: ghidra.program.model.address.AddressSet, span: Lifespan):
            ...


    class QueryOcclusion(TraceTimeViewport.Occlusion[T], typing.Generic[T]):

        class_: typing.ClassVar[java.lang.Class]

        def itemOccludes(self, range: ghidra.program.model.address.AddressRange, t: T, snap: typing.Union[jpype.JLong, int]) -> bool:
            ...

        def query(self, range: ghidra.program.model.address.AddressRange, span: Lifespan) -> java.lang.Iterable[T]:
            ...

        def removeItem(self, remains: ghidra.program.model.address.AddressSet, t: T, snap: typing.Union[jpype.JLong, int]):
            ...


    class RangeQueryOcclusion(TraceTimeViewport.QueryOcclusion[T], typing.Generic[T]):

        class_: typing.ClassVar[java.lang.Class]

        def range(self, t: T, snap: typing.Union[jpype.JLong, int]) -> ghidra.program.model.address.AddressRange:
            ...


    class SetQueryOcclusion(TraceTimeViewport.QueryOcclusion[T], typing.Generic[T]):

        class_: typing.ClassVar[java.lang.Class]

        def set(self, t: T, snap: typing.Union[jpype.JLong, int]) -> ghidra.program.model.address.AddressSetView:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def addChangeListener(self, l: java.lang.Runnable):
        """
        Add a listener for when the forking structure of this viewport changes
         
         
        
        This can occur when the snap changes or when any snapshot involved changes
        
        :param java.lang.Runnable l: the listener
        """

    def computeVisibleParts(self, set: ghidra.program.model.address.AddressSetView, lifespan: Lifespan, object: T, occlusion: TraceTimeViewport.Occlusion[T]) -> ghidra.program.model.address.AddressSet:
        """
        Compute the parts of a given object that are visible past more-recent objects
        
        :param T: the type of the object:param ghidra.program.model.address.AddressSetView set: the addresses comprising the object
        :param Lifespan lifespan: the lifespan of the object
        :param T object: the object to examine
        :param TraceTimeViewport.Occlusion[T] occlusion: a mechanism for query other like objects and removing occluded parts
        :return: the set of visible addresses
        :rtype: ghidra.program.model.address.AddressSet
        """

    def containsAnyUpper(self, lifespan: Lifespan) -> bool:
        """
        Check if the given lifespan contains any upper snap among the involved spans
        
        :param Lifespan lifespan: the lifespan to consider
        :return: true if it contains any upper snap, false otherwise.
        :rtype: bool
        """

    def getOrderedSnaps(self) -> java.util.List[java.lang.Long]:
        """
        Get the snaps involved in the view in most-recent-first order
         
         
        
        The first is always this view's snap. Following are the source snaps of each previous
        snapshot's schedule where applicable.
        
        :return: the list of snaps
        :rtype: java.util.List[java.lang.Long]
        """

    def getOrderedSpans(self) -> java.util.List[Lifespan]:
        """
        Get the spans involved in the view in most-recent-first order
        
        :return: the list of spans
        :rtype: java.util.List[Lifespan]
        """

    def getReversedSnaps(self) -> java.util.List[java.lang.Long]:
        """
        Get the snaps involved in the view in least-recent-first order
        
        :return: the list of snaps
        :rtype: java.util.List[java.lang.Long]
        """

    def getReversedSpans(self) -> java.util.List[Lifespan]:
        """
        Get the spans involved in the view in least-recent-first order
        
        :return: the list of spans
        :rtype: java.util.List[Lifespan]
        """

    def getTop(self, func: java.util.function.Function[java.lang.Long, T]) -> T:
        """
        Get the first non-null result of the function, applied to the most-recent snaps first
         
         
        
        Typically, func both retrieves an object and tests for its suitability.
        
        :param T: the type of object to retrieve:param java.util.function.Function[java.lang.Long, T] func: the function on a snap to retrieve an object
        :return: the first non-null result
        :rtype: T
        """

    def isCompletelyVisible(self, range: ghidra.program.model.address.AddressRange, lifespan: Lifespan, object: T, occlusion: TraceTimeViewport.Occlusion[T]) -> bool:
        """
        Check if any part of the given object is occluded by more-recent objects
        
        :param T: the type of the object:param ghidra.program.model.address.AddressRange range: the address range of the object
        :param Lifespan lifespan: the lifespan of the object
        :param T object: optionally, the object to examine. Used to avoid "self occlusion"
        :param TraceTimeViewport.Occlusion[T] occlusion: a mechanism for querying other like objects and checking for occlusion
        :return: true if completely visible, false if even partially occluded
        :rtype: bool
        """

    def isForked(self) -> bool:
        """
        Check if this view is forked
         
         
        
        The view is considered forked if any snap previous to this has a schedule with an initial
        snap other than the immediately-preceding one. Such forks "break" the linearity of the
        trace's usual time line.
        
        :return: true if forked, false otherwise
        :rtype: bool
        """

    def mergedIterator(self, iterFunc: java.util.function.Function[java.lang.Long, java.util.Iterator[T]], comparator: java.util.Comparator[T]) -> java.util.Iterator[T]:
        """
        Merge iterators from each involved snap into a single iterator
         
         
        
        Typically, the resulting iterator is passed through a filter to test each objects
        suitability.
        
        :param T: the type of objects in each iterator:param java.util.function.Function[java.lang.Long, java.util.Iterator[T]] iterFunc: a function on a snap to retrieve each iterator
        :param java.util.Comparator[T] comparator: the comparator for merging, which must yield the same order as each
                    iterator
        :return: the merged iterator
        :rtype: java.util.Iterator[T]
        """

    def removeChangeListener(self, l: java.lang.Runnable):
        """
        Remove a listener for forking structure changes
        
        :param java.lang.Runnable l: the listener
        
        .. seealso::
        
            | :obj:`.addChangeListener(Runnable)`
        """

    def setSnap(self, snap: typing.Union[jpype.JLong, int]):
        """
        Set the snapshot for this viewport
        
        :param jpype.JLong or int snap: the snap
        """

    def unionedAddresses(self, setFunc: java.util.function.Function[java.lang.Long, ghidra.program.model.address.AddressSetView]) -> ghidra.program.model.address.AddressSetView:
        """
        Union address sets from each involved snap
         
         
        
        The returned union is computed lazily.
        
        :param java.util.function.Function[java.lang.Long, ghidra.program.model.address.AddressSetView] setFunc: a function on a snap to retrieve the address set
        :return: the union
        :rtype: ghidra.program.model.address.AddressSetView
        """

    @property
    def top(self) -> T:
        ...

    @property
    def reversedSpans(self) -> java.util.List[Lifespan]:
        ...

    @property
    def reversedSnaps(self) -> java.util.List[java.lang.Long]:
        ...

    @property
    def orderedSpans(self) -> java.util.List[Lifespan]:
        ...

    @property
    def forked(self) -> jpype.JBoolean:
        ...

    @property
    def orderedSnaps(self) -> java.util.List[java.lang.Long]:
        ...


class TraceLocation(java.lang.Comparable[TraceLocation]):

    class_: typing.ClassVar[java.lang.Class]

    def getAddress(self) -> ghidra.program.model.address.Address:
        ...

    def getLifespan(self) -> Lifespan:
        ...

    def getThread(self) -> ghidra.trace.model.thread.TraceThread:
        ...

    def getTrace(self) -> Trace:
        ...

    @property
    def trace(self) -> Trace:
        ...

    @property
    def address(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def lifespan(self) -> Lifespan:
        ...

    @property
    def thread(self) -> ghidra.trace.model.thread.TraceThread:
        ...


class Lifespan(generic.Span[java.lang.Long, Lifespan], java.lang.Iterable[java.lang.Long]):
    """
    A closed range on snapshot keys, indicating a duration of time
     
     
    
    To attempt to avoid overuse of boxed :obj:`Long`s, we add primitive getters for the endpoints
    and re-define many of the interfaces' methods to work on those primitives directly. However,
    we've not done any performance testing to know whether the juice is worth the squeeze.
    """

    class Domain(java.lang.Enum[Lifespan.Domain], generic.Span.Domain[java.lang.Long, Lifespan]):
        """
        The domain of snapshot keys
        """

        class_: typing.ClassVar[java.lang.Class]
        INSTANCE: typing.Final[Lifespan.Domain]

        def atLeast(self, min: typing.Union[jpype.JLong, int]) -> Lifespan:
            ...

        def atMost(self, max: typing.Union[jpype.JLong, int]) -> Lifespan:
            ...

        def closed(self, min: typing.Union[jpype.JLong, int], max: typing.Union[jpype.JLong, int]) -> Lifespan:
            ...

        def compare(self, n1: typing.Union[jpype.JLong, int], n2: typing.Union[jpype.JLong, int]) -> int:
            ...

        def dec(self, n: typing.Union[jpype.JLong, int]) -> int:
            ...

        def inc(self, n: typing.Union[jpype.JLong, int]) -> int:
            ...

        def lmax(self) -> int:
            ...

        def lmin(self) -> int:
            ...

        def max(self, n1: typing.Union[jpype.JLong, int], n2: typing.Union[jpype.JLong, int]) -> int:
            ...

        def min(self, n1: typing.Union[jpype.JLong, int], n2: typing.Union[jpype.JLong, int]) -> int:
            ...

        def value(self, n: typing.Union[jpype.JLong, int]) -> Lifespan:
            ...

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> Lifespan.Domain:
            ...

        @staticmethod
        def values() -> jpype.JArray[Lifespan.Domain]:
            ...


    class Empty(Lifespan, generic.Span.Empty[java.lang.Long, Lifespan]):
        """
        The singleton empty lifespan of snapshot keys
        """

        class_: typing.ClassVar[java.lang.Class]
        INSTANCE: typing.Final[Lifespan.Empty]


    class Impl(java.lang.Record, Lifespan):
        """
        A non-empty lifespan of snapshot keys
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, lmin: typing.Union[jpype.JLong, int], lmax: typing.Union[jpype.JLong, int]):
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def lmax(self) -> int:
            ...

        def lmin(self) -> int:
            ...


    class LifeSet(generic.Span.SpanSet[java.lang.Long, Lifespan]):
        """
        A set of lifespans
        """

        class_: typing.ClassVar[java.lang.Class]


    class MutableLifeSet(Lifespan.LifeSet, generic.Span.MutableSpanSet[java.lang.Long, Lifespan]):
        """
        A mutable set of lifespans
        """

        class_: typing.ClassVar[java.lang.Class]


    class DefaultLifeSet(generic.Span.DefaultSpanSet[java.lang.Long, Lifespan], Lifespan.MutableLifeSet):
        """
        An interval tree implementing :obj:`MutableLifeSet`
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...

        @staticmethod
        def copyOf(set: Lifespan.LifeSet) -> Lifespan.DefaultLifeSet:
            ...


    class_: typing.ClassVar[java.lang.Class]
    DOMAIN: typing.Final[Lifespan.Domain]
    EMPTY: typing.Final[Lifespan.Empty]
    ALL: typing.Final[Lifespan.Impl]

    @staticmethod
    def at(snap: typing.Union[jpype.JLong, int]) -> Lifespan:
        """
        Get the lifespan for only the given snap.
        
        :param jpype.JLong or int snap: the snapshot key
        :return: the lifespan
        :rtype: Lifespan
        """

    @staticmethod
    def before(snap: typing.Union[jpype.JLong, int]) -> Lifespan:
        """
        Get the lifespan that excludes the given and all future snaps
        
        :param jpype.JLong or int snap: the snap
        :return: the lifespan
        :rtype: Lifespan
        """

    def contains(self, n: typing.Union[jpype.JLong, int]) -> bool:
        ...

    @staticmethod
    def isScratch(snap: typing.Union[jpype.JLong, int]) -> bool:
        """
        Check if a given snapshot key is designated as scratch space
         
         
        
        Conventionally, negative snaps are scratch space.
        
        :param jpype.JLong or int snap: the snap
        :return: true if scratch space
        :rtype: bool
        """

    def lmax(self) -> int:
        ...

    def lmin(self) -> int:
        ...

    @staticmethod
    def nowOn(snap: typing.Union[jpype.JLong, int]) -> Lifespan:
        """
        Get the lifespan from the given snap into the indefinite future
        
        :param jpype.JLong or int snap: the snapshot key
        :return: the lifespan
        :rtype: Lifespan
        """

    @staticmethod
    def nowOnMaybeScratch(snap: typing.Union[jpype.JLong, int]) -> Lifespan:
        """
        Get the lifespan from the given snap into the indefinite future, considering scratch space
         
         
        
        If the snapshot is in scratch space, then the span will have an upper endpoint of -1, the
        last scratch snapshot. Otherwise, this is the same as :meth:`nowOn(long) <.nowOn>`.
        
        :param jpype.JLong or int snap: 
        :return: the lifespan
        :rtype: Lifespan
        """

    @staticmethod
    def since(snap: typing.Union[jpype.JLong, int]) -> Lifespan:
        """
        Get the lifespan from 0 to the given snap.
         
         
        
        The lower bound is 0 to exclude scratch space.
        
        :param jpype.JLong or int snap: the snapshot key
        :return: the lifespan
        :rtype: Lifespan
        """

    @staticmethod
    def span(minSnap: typing.Union[jpype.JLong, int], maxSnap: typing.Union[jpype.JLong, int]) -> Lifespan:
        """
        Get the lifespan for the given snap bounds
        
        :param jpype.JLong or int minSnap: the minimum snap
        :param jpype.JLong or int maxSnap: the maximum snap
        :return: the lifespan
        :rtype: Lifespan
        """

    @staticmethod
    def toNow(snap: typing.Union[jpype.JLong, int]) -> Lifespan:
        """
        Get the lifespan from the given snap into the indefinite past, including scratch
        
        :param jpype.JLong or int snap: the snapshot key
        :return: the lifespan
        :rtype: Lifespan
        """

    def withMax(self, max: typing.Union[jpype.JLong, int]) -> Lifespan:
        ...

    def withMin(self, min: typing.Union[jpype.JLong, int]) -> Lifespan:
        ...


class TraceAddressSnapRange(ghidra.util.database.spatial.rect.Rectangle2D[ghidra.program.model.address.Address, java.lang.Long, TraceAddressSnapRange]):

    class_: typing.ClassVar[java.lang.Class]

    def getLifespan(self) -> Lifespan:
        ...

    def getRange(self) -> ghidra.program.model.address.AddressRange:
        ...

    @property
    def lifespan(self) -> Lifespan:
        ...

    @property
    def range(self) -> ghidra.program.model.address.AddressRange:
        ...


class DefaultTraceSpan(TraceSpan):
    """
    NOTE: This is used to mark (trace,snap) regardless of whether that snapshot is actually in the
    database.... Cannot just use TraceSnapshot here.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, trace: Trace, span: Lifespan):
        ...


class TraceDomainObjectListener(ghidra.trace.util.TypedEventDispatcher, ghidra.framework.model.DomainObjectListener):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class TraceSpan(java.lang.Comparable[TraceSpan]):

    class_: typing.ClassVar[java.lang.Class]

    def getSpan(self) -> Lifespan:
        ...

    def getTrace(self) -> Trace:
        ...

    @property
    def trace(self) -> Trace:
        ...

    @property
    def span(self) -> Lifespan:
        ...


class ImmutableTraceAddressSnapRange(TraceAddressSnapRange):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, minAddress: ghidra.program.model.address.Address, maxAddress: ghidra.program.model.address.Address, minSnap: typing.Union[jpype.JLong, int], maxSnap: typing.Union[jpype.JLong, int], space: TraceAddressSnapSpace):
        ...

    @typing.overload
    def __init__(self, minAddress: ghidra.program.model.address.Address, maxAddress: ghidra.program.model.address.Address, minSnap: typing.Union[jpype.JLong, int], maxSnap: typing.Union[jpype.JLong, int]):
        ...

    @typing.overload
    def __init__(self, range: ghidra.program.model.address.AddressRange, lifespan: Lifespan):
        ...

    @typing.overload
    def __init__(self, range: ghidra.program.model.address.AddressRange, snap: typing.Union[jpype.JLong, int]):
        ...

    @typing.overload
    def __init__(self, minAddress: ghidra.program.model.address.Address, maxAddress: ghidra.program.model.address.Address, lifespan: Lifespan, space: ghidra.util.database.spatial.rect.EuclideanSpace2D[ghidra.program.model.address.Address, java.lang.Long]):
        ...

    @typing.overload
    def __init__(self, minAddress: ghidra.program.model.address.Address, maxAddress: ghidra.program.model.address.Address, lifespan: Lifespan):
        ...

    @typing.overload
    def __init__(self, address: ghidra.program.model.address.Address, lifespan: Lifespan):
        ...

    @typing.overload
    def __init__(self, address: ghidra.program.model.address.Address, snap: typing.Union[jpype.JLong, int]):
        ...

    @staticmethod
    def centered(address: ghidra.program.model.address.Address, snap: typing.Union[jpype.JLong, int], addressBreadth: typing.Union[jpype.JInt, int], snapBreadth: typing.Union[jpype.JInt, int]) -> ImmutableTraceAddressSnapRange:
        ...

    @staticmethod
    def rangeCentered(address: ghidra.program.model.address.Address, breadth: typing.Union[jpype.JInt, int]) -> ghidra.program.model.address.AddressRange:
        ...

    @staticmethod
    def spanCentered(snap: typing.Union[jpype.JLong, int], breadth: typing.Union[jpype.JInt, int]) -> Lifespan:
        ...


class DefaultTraceLocation(TraceLocation):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, trace: Trace, thread: ghidra.trace.model.thread.TraceThread, lifespan: Lifespan, address: ghidra.program.model.address.Address):
        ...


class Trace(ghidra.program.model.data.DataTypeManagerDomainObject):
    """
    An indexed record of observations over the course of a target's execution
     
     
    
    Conceptually, this is the same as a :obj:`Program`, but multiplied by a concrete dimension of
    time and organized into :obj:`snapshots <TraceSnapshot>`. This also includes information about
    other objects not ordinarily of concern for static analysis, for example, :obj:`threads <TraceThread>`, :obj:`modules <TraceModule>`, and :obj:`breakpoints <TraceBreakpointLocation>`. To view a
    specific snapshot and/or manipulate the trace as if it were a program, use
    :meth:`getProgramView() <.getProgramView>`.
    """

    class TraceProgramViewListener(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        def viewCreated(self, view: ghidra.trace.model.program.TraceProgramView):
            ...


    class_: typing.ClassVar[java.lang.Class]
    TRACE_ICON: typing.Final[javax.swing.Icon]

    def addProgramViewListener(self, listener: Trace.TraceProgramViewListener):
        ...

    def createProgramView(self, snap: typing.Union[jpype.JLong, int]) -> ghidra.trace.model.program.TraceVariableSnapProgramView:
        ...

    def createTimeViewport(self) -> TraceTimeViewport:
        ...

    def getAddressPropertyManager(self) -> ghidra.trace.model.property.TraceAddressPropertyManager:
        ...

    def getAllProgramViews(self) -> java.util.Collection[ghidra.trace.model.program.TraceProgramView]:
        """
        Collect all program views, fixed or variable, of this trace.
        
        :return: the current set of program views
        :rtype: java.util.Collection[ghidra.trace.model.program.TraceProgramView]
        """

    def getBaseAddressFactory(self) -> ghidra.program.model.address.AddressFactory:
        ...

    def getBaseCompilerSpec(self) -> ghidra.program.model.lang.CompilerSpec:
        ...

    def getBaseDataTypeManager(self) -> ghidra.trace.model.data.TraceBasedDataTypeManager:
        ...

    def getBaseLanguage(self) -> ghidra.program.model.lang.Language:
        ...

    def getBookmarkManager(self) -> ghidra.trace.model.bookmark.TraceBookmarkManager:
        ...

    def getBreakpointManager(self) -> ghidra.trace.model.breakpoint.TraceBreakpointManager:
        ...

    def getCodeManager(self) -> ghidra.trace.model.listing.TraceCodeManager:
        ...

    def getEmulatorCacheVersion(self) -> int:
        ...

    def getEquateManager(self) -> ghidra.trace.model.symbol.TraceEquateManager:
        ...

    def getFixedProgramView(self, snap: typing.Union[jpype.JLong, int]) -> ghidra.trace.model.program.TraceProgramView:
        ...

    def getMemoryManager(self) -> ghidra.trace.model.memory.TraceMemoryManager:
        ...

    def getModuleManager(self) -> ghidra.trace.model.modules.TraceModuleManager:
        ...

    def getObjectManager(self) -> ghidra.trace.model.target.TraceObjectManager:
        ...

    def getPlatformManager(self) -> ghidra.trace.model.guest.TracePlatformManager:
        ...

    def getProgramView(self) -> ghidra.trace.model.program.TraceVariableSnapProgramView:
        """
        Get the "canonical" program view for this trace
         
         
        
        This view is the view returned, e.g., by :meth:`TraceCodeUnit.getProgram() <TraceCodeUnit.getProgram>`, no matter which
        view was actually used to retrieve that unit.
        
        :return: the canonical program view
        :rtype: ghidra.trace.model.program.TraceVariableSnapProgramView
        """

    def getReferenceManager(self) -> ghidra.trace.model.symbol.TraceReferenceManager:
        ...

    def getRegisterContextManager(self) -> ghidra.trace.model.context.TraceRegisterContextManager:
        ...

    def getStackManager(self) -> ghidra.trace.model.stack.TraceStackManager:
        ...

    def getStaticMappingManager(self) -> ghidra.trace.model.modules.TraceStaticMappingManager:
        ...

    def getSymbolManager(self) -> ghidra.trace.model.symbol.TraceSymbolManager:
        ...

    def getThreadManager(self) -> ghidra.trace.model.thread.TraceThreadManager:
        ...

    def getTimeManager(self) -> ghidra.trace.model.time.TraceTimeManager:
        ...

    def lockRead(self) -> ghidra.util.LockHold:
        ...

    def lockWrite(self) -> ghidra.util.LockHold:
        ...

    def removeProgramViewListener(self, listener: Trace.TraceProgramViewListener):
        ...

    def setEmulatorCacheVersion(self, version: typing.Union[jpype.JLong, int]):
        ...

    @property
    def addressPropertyManager(self) -> ghidra.trace.model.property.TraceAddressPropertyManager:
        ...

    @property
    def threadManager(self) -> ghidra.trace.model.thread.TraceThreadManager:
        ...

    @property
    def fixedProgramView(self) -> ghidra.trace.model.program.TraceProgramView:
        ...

    @property
    def baseCompilerSpec(self) -> ghidra.program.model.lang.CompilerSpec:
        ...

    @property
    def emulatorCacheVersion(self) -> jpype.JLong:
        ...

    @emulatorCacheVersion.setter
    def emulatorCacheVersion(self, value: jpype.JLong):
        ...

    @property
    def symbolManager(self) -> ghidra.trace.model.symbol.TraceSymbolManager:
        ...

    @property
    def referenceManager(self) -> ghidra.trace.model.symbol.TraceReferenceManager:
        ...

    @property
    def equateManager(self) -> ghidra.trace.model.symbol.TraceEquateManager:
        ...

    @property
    def memoryManager(self) -> ghidra.trace.model.memory.TraceMemoryManager:
        ...

    @property
    def baseAddressFactory(self) -> ghidra.program.model.address.AddressFactory:
        ...

    @property
    def allProgramViews(self) -> java.util.Collection[ghidra.trace.model.program.TraceProgramView]:
        ...

    @property
    def moduleManager(self) -> ghidra.trace.model.modules.TraceModuleManager:
        ...

    @property
    def registerContextManager(self) -> ghidra.trace.model.context.TraceRegisterContextManager:
        ...

    @property
    def breakpointManager(self) -> ghidra.trace.model.breakpoint.TraceBreakpointManager:
        ...

    @property
    def bookmarkManager(self) -> ghidra.trace.model.bookmark.TraceBookmarkManager:
        ...

    @property
    def objectManager(self) -> ghidra.trace.model.target.TraceObjectManager:
        ...

    @property
    def staticMappingManager(self) -> ghidra.trace.model.modules.TraceStaticMappingManager:
        ...

    @property
    def programView(self) -> ghidra.trace.model.program.TraceVariableSnapProgramView:
        ...

    @property
    def baseLanguage(self) -> ghidra.program.model.lang.Language:
        ...

    @property
    def timeManager(self) -> ghidra.trace.model.time.TraceTimeManager:
        ...

    @property
    def platformManager(self) -> ghidra.trace.model.guest.TracePlatformManager:
        ...

    @property
    def codeManager(self) -> ghidra.trace.model.listing.TraceCodeManager:
        ...

    @property
    def stackManager(self) -> ghidra.trace.model.stack.TraceStackManager:
        ...

    @property
    def baseDataTypeManager(self) -> ghidra.trace.model.data.TraceBasedDataTypeManager:
        ...


class TraceExecutionState(java.lang.Enum[TraceExecutionState]):
    """
    The execution state of a debug target object
    """

    class_: typing.ClassVar[java.lang.Class]
    INACTIVE: typing.Final[TraceExecutionState]
    """
    The object has been created, but it not yet alive
     
     
    
    This may apply, e.g., to a GDB "Inferior," which has no yet been used to launch or attach to
    a process.
    """

    ALIVE: typing.Final[TraceExecutionState]
    """
    The object is alive, but its execution state is unspecified
     
     
    
    Implementations should use :obj:`.STOPPED` and :obj:`.RUNNING` whenever possible. For some
    objects, e.g., a process, this is conventionally determined by its parts, e.g., threads: A
    process is running when *any* of its threads are running. It is stopped when
    *all* of its threads are stopped. For the clients' sakes, all models should implement
    these conventions internally.
    """

    STOPPED: typing.Final[TraceExecutionState]
    """
    The object is alive, but not executing
    """

    RUNNING: typing.Final[TraceExecutionState]
    """
    The object is alive and executing
     
     
    
    "Running" is loosely defined. For example, with respect to a thread, it may indicate the
    thread is currently executing, waiting on an event, or scheduled for execution. It does not
    necessarily mean it is executing on a CPU at this exact moment.
    """

    TERMINATED: typing.Final[TraceExecutionState]
    """
    The object is no longer alive
     
     
    
    The object still exists but no longer represents something alive. This could be used for
    stale handles to objects which may still be queried (e.g., for a process exit code), or e.g.,
    a GDB "Inferior," which could be re-used to launch or attach to another process.
    """


    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> TraceExecutionState:
        ...

    @staticmethod
    def values() -> jpype.JArray[TraceExecutionState]:
        ...


class AddressSnap(java.lang.Comparable[AddressSnap]):

    class_: typing.ClassVar[java.lang.Class]

    def getAddress(self) -> ghidra.program.model.address.Address:
        ...

    def getSnap(self) -> int:
        ...

    @property
    def address(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def snap(self) -> jpype.JLong:
        ...



__all__ = ["TraceUserData", "TraceAddressSnapSpace", "DefaultAddressSnap", "TraceClosedException", "TraceChangeSet", "TraceUniqueObject", "TraceOptionsManager", "TraceTimeViewport", "TraceLocation", "Lifespan", "TraceAddressSnapRange", "DefaultTraceSpan", "TraceDomainObjectListener", "TraceSpan", "ImmutableTraceAddressSnapRange", "DefaultTraceLocation", "Trace", "TraceExecutionState", "AddressSnap"]
