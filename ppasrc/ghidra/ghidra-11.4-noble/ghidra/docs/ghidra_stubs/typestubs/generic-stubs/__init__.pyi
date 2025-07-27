from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import generic.stl
import java.lang # type: ignore
import java.util # type: ignore
import java.util.function # type: ignore
import java.util.stream # type: ignore


D = typing.TypeVar("D")
E = typing.TypeVar("E")
K = typing.TypeVar("K")
N = typing.TypeVar("N")
R = typing.TypeVar("R")
S = typing.TypeVar("S")
T = typing.TypeVar("T")
V = typing.TypeVar("V")


class ULongSpan(Span[java.lang.Long, ULongSpan]):
    """
    A span of unsigned longs
     
     
    
    While the type of endpoint is :obj:`Long`, the domain imposes unsigned behavior. To ensure
    consistent behavior in client code, comparisons and manipulations should be performed via
    :obj:`.DOMAIN`, where applicable.
    """

    class Domain(java.lang.Enum[ULongSpan.Domain], Span.Domain[java.lang.Long, ULongSpan]):
        """
        The domain of unsigned longs
        """

        class_: typing.ClassVar[java.lang.Class]
        INSTANCE: typing.Final[ULongSpan.Domain]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> ULongSpan.Domain:
            ...

        @staticmethod
        def values() -> jpype.JArray[ULongSpan.Domain]:
            ...


    class Empty(ULongSpan, Span.Empty[java.lang.Long, ULongSpan]):
        """
        The singleton empty span of unsigned longs
        """

        class_: typing.ClassVar[java.lang.Class]


    class Impl(java.lang.Record, ULongSpan):
        """
        A non-empty span of unsigned longs
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, min: typing.Union[java.lang.Long, int], max: typing.Union[java.lang.Long, int]):
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def max(self) -> int:
            ...

        def min(self) -> int:
            ...


    class ULongSpanMap(Span.SpanMap[java.lang.Long, ULongSpan, V], typing.Generic[V]):
        """
        A map of unsigned long spans to values
        """

        class_: typing.ClassVar[java.lang.Class]


    class MutableULongSpanMap(ULongSpan.ULongSpanMap[V], Span.MutableSpanMap[java.lang.Long, ULongSpan, V], typing.Generic[V]):
        """
        A mutable map of unsigned long spans to values
        """

        class_: typing.ClassVar[java.lang.Class]


    class DefaultULongSpanMap(Span.DefaultSpanMap[java.lang.Long, ULongSpan, V], ULongSpan.MutableULongSpanMap[V], typing.Generic[V]):
        """
        An interval tree implementing :obj:`MutableULongSpanMap`
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class ULongSpanSet(Span.SpanSet[java.lang.Long, ULongSpan]):
        """
        A set of unsigned long spans
        """

        class_: typing.ClassVar[java.lang.Class]

        @staticmethod
        def of(*spans: ULongSpan) -> ULongSpan.ULongSpanSet:
            ...


    class MutableULongSpanSet(ULongSpan.ULongSpanSet, Span.MutableSpanSet[java.lang.Long, ULongSpan]):
        """
        A mutable set of unsigned long spans
        """

        class_: typing.ClassVar[java.lang.Class]


    class DefaultULongSpanSet(Span.DefaultSpanSet[java.lang.Long, ULongSpan], ULongSpan.MutableULongSpanSet):
        """
        An interval tree implementing :obj:`MutableULongSpanSet`
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class_: typing.ClassVar[java.lang.Class]
    DOMAIN: typing.Final[ULongSpan.Domain]
    EMPTY: typing.Final[ULongSpan.Empty]
    ALL: typing.Final[ULongSpan.Impl]

    @staticmethod
    @typing.overload
    def extent(min: typing.Union[jpype.JLong, int], length: typing.Union[jpype.JLong, int]) -> ULongSpan:
        """
        Create a closed interval of unsigned longs having a given length
        
        :param jpype.JLong or int min: the lower bound
        :param jpype.JLong or int length: the length
        :return: the span
        :rtype: ULongSpan
        :raises IllegalArgumentException: if the upper endpoint would exceed :meth:`Domain.max() <Domain.max>`
        """

    @staticmethod
    @typing.overload
    def extent(min: typing.Union[jpype.JLong, int], length: typing.Union[jpype.JInt, int]) -> ULongSpan:
        """
        Create a closed interval of unsigned longs having the given (unsigned) length
         
         
        
        This operates the same as :meth:`extent(long, int) <.extent>`, but ensures the given length is treated
        as an unsigned integer.
        
        :param jpype.JLong or int min: 
        :param jpype.JInt or int length: 
        :return: the span
        :rtype: ULongSpan
        :raises IllegalArgumentException: if the upper endpoint would exceed :meth:`Domain.max() <Domain.max>`
        """

    def length(self) -> int:
        """
        Get the length of the span
        
        :return: the length
        :rtype: int
        """

    @staticmethod
    def span(min: typing.Union[jpype.JLong, int], max: typing.Union[jpype.JLong, int]) -> ULongSpan:
        """
        Create a closed interval of unsigned longs
        
        :param jpype.JLong or int min: the lower bound
        :param jpype.JLong or int max: the upper bound
        :return: the span
        :rtype: ULongSpan
        :raises IllegalArgumentException: if ``max < min``
        """


class RangeMapSetter(java.lang.Object, typing.Generic[E, D, R, V]):
    """
    A method outline for setting an entry in a range map where coalescing is desired
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @typing.overload
    def set(self, range: R, value: V) -> E:
        """
        Entry point: Set the given range to the given value, coalescing where possible
        
        :param R range: the range
        :param V value: the value
        :return: the entry containing the value
        :rtype: E
        """

    @typing.overload
    def set(self, lower: D, upper: D, value: V) -> E:
        """
        Entry point: Set the given range to the given value, coalescing where possible
        
        :param D lower: the lower bound
        :param D upper: the upper bound
        :param V value: the value
        :return: the entry containing the value
        :rtype: E
        """


class Span(java.lang.Comparable[S], typing.Generic[N, S]):
    """
    A (closed) interval
    
     
    
    An interval-like type may implement this interface in order to obtain a near out-of-box
    implementation of a map and/or set of spans. Common operations, such as computing intersections
    and bounds, are provided. Similarly, spans are automatically coalesced when present in sets and
    maps. The main requirement is that the span define the domain of its endpoints. The domain can
    impose behaviors and properties that aren't otherwise present on the type of endpoints. For
    example, the domain may be :obj:`Long`s, but using unsigned attributes. The domain also provides
    a factory for new spans. While nominally, this only supports closed intervals, the domain can
    define a custom endpoint type to obtain mixed intervals.
    """

    class Domain(java.lang.Object, typing.Generic[N, S]):
        """
        The (discrete) domain of endpoints for a span
        
         
        
        This defines the domain, which may introduce behaviors different than those naturally
        acquired from the type. For example, a domain may impose unsigned comparison on a (boxed)
        primitive type.
        
        
        .. admonition:: Implementation Note
        
            each domain should be a singleton class
        """

        class_: typing.ClassVar[java.lang.Class]

        def all(self) -> S:
            """
            Get the span containing all values in the domain
            
            
            .. admonition:: Implementation Note
            
                It is recommended to return a static object
            
            
            :return: the span
            :rtype: S
            """

        def atLeast(self, min: N) -> S:
            """
            Construct a new span with the given lower endpoint, inclusive.
             
             
            
            The upper endpoint becomes the maximum value in the domain
            
            :param N min: the lower endpoint
            :return: the span
            :rtype: S
            """

        def atMost(self, max: N) -> S:
            """
            Construct a new span with the given upper endpoint, inclusive.
             
             
            
            The lower endpoint becomes the minimum value in the domain
            
            :param N max: the upper endpoint
            :return: the span
            :rtype: S
            """

        def bound(self, s1: S, s2: S) -> S:
            """
            Compute the smallest span which contains two spans
            
            :param S s1: a span
            :param S s2: another span
            :return: the bounding span
            :rtype: S
            """

        def closed(self, min: N, max: N) -> S:
            """
            Create a new span with the given endpoints, inclusive.
            
            :param N min: the lower endpoint
            :param N max: the upper endpoint
            :return: the span
            :rtype: S
            :raises IllegalArgumentException: if max is less than min
            """

        def compare(self, n1: N, n2: N) -> int:
            """
            Compare two values
            
            :param N n1: a value
            :param N n2: another value
            :return: the result, as in :meth:`Comparator.compare(Object, Object) <Comparator.compare>`
            :rtype: int
            """

        def dec(self, n: N) -> N:
            """
            Get a given value, decremented by 1
             
             
            
            If the resulting value would exceed :meth:`min() <.min>`, this should wrap to :meth:`max() <.max>`.
            
            :param N n: the value
            :return: the value decremented
            :rtype: N
            """

        def empty(self) -> S:
            """
            Get the span that contains no value, nor has any endpoints
             
             
            
            This span is returned when the result doesn't exist, e.g., when finding the intersection
            of spans which do not intersect.
            
            
            .. admonition:: Implementation Note
            
                It is recommended to implement :obj:`Empty` as a singleton class and return
                its instance
            
            
            :return: the empty span
            :rtype: S
            """

        def encloses(self, s1: S, s2: S) -> bool:
            """
            Check if one span encloses another
            
            :param S s1: a span
            :param S s2: another span
            :return: true if s1 encloses s2
            :rtype: bool
            """

        def inc(self, n: N) -> N:
            """
            Get a given value, incremented by 1
             
             
            
            If the resulting value would exceed :meth:`max() <.max>`, this should wrap to :meth:`min() <.min>`.
            
            :param N n: the value
            :return: the value incremented
            :rtype: N
            """

        def intersect(self, s1: S, s2: S) -> S:
            """
            Compute the intersection of two spans
            
            :param S s1: a span
            :param S s2: another span
            :return: the intersection, possibly empty
            :rtype: S
            """

        def intersects(self, s1: S, s2: S) -> bool:
            """
            Check if two spans intersect
            
            :param S s1: a span
            :param S s2: another span
            :return: true if they intersect
            :rtype: bool
            """

        @typing.overload
        def max(self) -> N:
            """
            Get the maximum value in the domain
             
             
            
            This value can also represent positive infinity.
            
            :return: the maximum value
            :rtype: N
            """

        @typing.overload
        def max(self, n1: N, n2: N) -> N:
            """
            Get the greater of two values
             
             
            
            If the values are equal, then either may be chosen
            
            :param N n1: a value
            :param N n2: another value
            :return: the greater
            :rtype: N
            """

        @typing.overload
        def min(self) -> N:
            """
            Get the minimum value in the domain
             
             
            
            This value can also represent negative infinity.
            
            :return: the minimum value
            :rtype: N
            """

        @typing.overload
        def min(self, n1: N, n2: N) -> N:
            """
            Get the lesser of two values
             
             
            
            If the values are equal, then either may be chosen
            
            :param N n1: a value
            :param N n2: another value
            :return: the lesser
            :rtype: N
            """

        def newSpan(self, min: N, max: N) -> S:
            """
            Factory method for a new span after arguments are validated
            
            :param N min: the lower endpoint
            :param N max: the upper endpoint
            :return: the span
            :rtype: S
            """

        def subtract(self, s1: S, s2: S) -> java.util.List[S]:
            """
            Subtract two spans
             
             
            
            If the first span is empty, this returns 0 spans.
            
            :param S s1: a span
            :param S s2: another span
            :return: 0, 1, or 2 spans
            :rtype: java.util.List[S]
            """

        def toMaxString(self, max: N, nToString: java.util.function.Function[N, java.lang.String]) -> str:
            """
            Render the upper bound of a span
            
            :param N max: the upper bound
            :param java.util.function.Function[N, java.lang.String] nToString: a function to convert n to a string
            :return: the string
            :rtype: str
            """

        def toMinString(self, min: N, nToString: java.util.function.Function[N, java.lang.String]) -> str:
            """
            Render the lower bound of a span
            
            :param N min: the lower bound
            :param java.util.function.Function[N, java.lang.String] nToString: a function to convert n to a string
            :return: the string
            :rtype: str
            """

        @typing.overload
        def toString(self, n: N) -> str:
            """
            Render the given value as a string
            
            :param N n: the value
            :return: the string
            :rtype: str
            """

        @typing.overload
        def toString(self, s: S) -> str:
            """
            Render the given span as a string
            
            :param S s: the span
            :return: the string
            :rtype: str
            """

        @typing.overload
        def toString(self, s: S, nToString: java.util.function.Function[N, java.lang.String]) -> str:
            """
            Render the given span as a string
            
            :param S s: the span
            :param java.util.function.Function[N, java.lang.String] nToString: a function to convert n to a string
            :return: the string
            :rtype: str
            """

        def value(self, n: N) -> S:
            """
            Construct a span containing only the given value
            
            :param N n: the value
            :return: the span
            :rtype: S
            """


    class Empty(Span[N, S], typing.Generic[N, S]):
        """
        A mix-in interface for empty spans
        
        
        .. admonition:: Implementation Note
        
            It is recommended to implement this as a singleton class
        """

        class_: typing.ClassVar[java.lang.Class]


    class SpanMap(java.lang.Object, typing.Generic[N, S, V]):
        """
        An abstract interface for an immutable map of spans to values
         
         
        
        Spans are not allowed to overlap, and connected spans are automatically coalesced when mapped
        to the same value. For example, the entries ``[1..5]='A'`` and ``[6..10]='A'`` become
        one entry ``[1..10]='A'``. When an entry is added that overlaps other entries, the
        existing entries are truncated or deleted (or coalesced if they share the same value as the
        new entry) so that the new entry can fit.
        
        
        .. admonition:: Implementation Note
        
            It is recommended to create an interface (having only the ``<V>`` parameter)
            extending this one specific to your domain and span type, then implement it using
            an extension of :obj:`DefaultSpanMap`. See :obj:`ULongSpanMap` for an example.
        """

        class_: typing.ClassVar[java.lang.Class]

        def bound(self) -> S:
            """
            Get a span which encloses all spans in the map
            
            :return: the bounding span
            :rtype: S
            """

        def entries(self) -> java.util.Set[java.util.Map.Entry[S, V]]:
            """
            Get the entries in this map
             
            
            Note that the behavior regarding a copy versus a view is not specified. Clients should
            not rely on one or the other.
            
            :return: the set of entries
            :rtype: java.util.Set[java.util.Map.Entry[S, V]]
            """

        def get(self, n: N) -> V:
            """
            Get the value of the given key
             
             
            
            Note that a null return could indicate either that no entry has a span containing the
            given key, or that the entry whose span contains it has the null value. To distinguish
            the two, consider using :meth:`getEntry(Object) <.getEntry>`.
            
            :param N n: the key
            :return: the value, or null
            :rtype: V
            """

        def getEntry(self, n: N) -> java.util.Map.Entry[S, V]:
            """
            Get the entry whose span contains the given key
            
            :param N n: the key
            :return: the entry, or null
            :rtype: java.util.Map.Entry[S, V]
            """

        def intersectingEntries(self, s: S) -> java.lang.Iterable[java.util.Map.Entry[S, V]]:
            """
            Iterate over all entries whose spans intersect the given span
            
            :param S s: the span
            :return: an iterable of entries
            :rtype: java.lang.Iterable[java.util.Map.Entry[S, V]]
            """

        def intersectingSpans(self, s: S) -> java.lang.Iterable[S]:
            """
            Iterate over all spans in the map that intersect the given span
            
            :param S s: the span
            :return: an iterable of spans
            :rtype: java.lang.Iterable[S]
            """

        def intersects(self, s: S) -> bool:
            """
            Check if any span in the map intersects the given span
            
            :param S s: the span
            :return: true if any span in the map intersects it
            :rtype: bool
            """

        def isEmpty(self) -> bool:
            """
            Check if this map has any entries
            
            :return: true if empty
            :rtype: bool
            """

        def spans(self) -> java.util.NavigableSet[S]:
            """
            Get the spans in this map
             
             
            
            Note that the behavior regarding a copy versus a view is not specified. Clients should
            not rely on one or the other.
            
            :return: the set of spans
            :rtype: java.util.NavigableSet[S]
            """

        def values(self) -> java.util.Collection[V]:
            """
            Get the values in this map
             
             
            
            Note that the behavior regarding a copy versus a view is not specified. Clients should
            not rely on one of the other.
            
            :return: the collection of values
            :rtype: java.util.Collection[V]
            """

        @property
        def entry(self) -> java.util.Map.Entry[S, V]:
            ...

        @property
        def empty(self) -> jpype.JBoolean:
            ...


    class MutableSpanMap(Span.SpanMap[N, S, V], typing.Generic[N, S, V]):
        """
        An abstract interface for a mutable :obj:`SpanMap`
        """

        class_: typing.ClassVar[java.lang.Class]

        def clear(self):
            """
            Remove all entries from the map
            """

        def put(self, s: S, v: V):
            """
            Put an entry, mapping all keys contains in the span to the given value
             
             
            
            Each key can only be mapped to a single value. Thus existing entries having the same
            value may be coalesced to this new entry. Existing entries having a different value will
            be truncated or deleted to make room for this entry.
            
            :param S s: the span
            :param V v: the value
            """

        def putAll(self, map: Span.SpanMap[N, S, V]):
            """
            Copy all entries from the given map into this one
             
             
            
            The entries from both maps may be coalesced when entered into this one. (The given map
            remains unmodified.) The entries in this map may be truncated or deleted to make room for
            those in the given map.
            
            :param Span.SpanMap[N, S, V] map: the other map
            """

        def remove(self, s: S):
            """
            Delete all keys in the given span
             
             
            
            Entries which intersect the given span are truncated. Entries which are enclosed are
            deleted, such that every key in the given span is no longer mapped to a value.
            
            :param S s: the span
            """


    class SpanSet(java.lang.Object, typing.Generic[N, S]):
        """
        An abstract interface for a set of spans
        
         
        
        Connected spans in the set are automatically coalesced. For example, the set
        ``[[0..5],[6..10]]`` becomes ``[[0..10]]``.
        
        
        .. admonition:: Implementation Note
        
            It is recommended to create an unparameterized interface extending this one
            specific to your domain and span type, then implement it using an extension of
            :obj:`DefaultSpanSet`. See :obj:`ULongSpanSet` for an example.
        """

        class_: typing.ClassVar[java.lang.Class]

        def bound(self) -> S:
            """
            Get a span which encloses all spans in the set
            
            :return: the bounding span
            :rtype: S
            """

        def complement(self, s: S) -> java.lang.Iterable[S]:
            """
            Iterate over the spans which are absent from the set but enclosed by the given span
            
            :param S s: the span
            :return: the iterable of spans
            :rtype: java.lang.Iterable[S]
            """

        def contains(self, n: N) -> bool:
            """
            Check if the set contains the given value
            
            :param N n: the value
            :return: true if contained by any span in the set
            :rtype: bool
            """

        def encloses(self, s: S) -> bool:
            """
            Check if any span in the set encloses the given span
            
            :param S s: the span
            :return: true if any span in the set encloses it
            :rtype: bool
            """

        def intersecting(self, s: S) -> java.lang.Iterable[S]:
            """
            Iterate over all spans in the set that intersect the given span
            
            :param S s: the span
            :return: the iterable of spans
            :rtype: java.lang.Iterable[S]
            """

        def intersects(self, s: S) -> bool:
            """
            Check if any span in the set intersects the given span
            
            :param S s: the span
            :return: true if any span in the set intersects it
            :rtype: bool
            """

        def isEmpty(self) -> bool:
            """
            Check if this set has any spans
            
            :return: true if empty
            :rtype: bool
            """

        def spanContaining(self, n: N) -> S:
            """
            Get the span containing the given value
            
            :param N n: the value
            :return: the span or null
            :rtype: S
            """

        def spans(self) -> java.util.NavigableSet[S]:
            """
            Iterate the spans in this set
            
            :return: the iterable
            :rtype: java.util.NavigableSet[S]
            """

        def toString(self, nToString: java.util.function.Function[N, java.lang.String]) -> str:
            """
            Render this set as a string, using the given endpoint-to-string function
            
            :param java.util.function.Function[N, java.lang.String] nToString: the endpoint-to-string function
            :return: the string
            :rtype: str
            """

        @property
        def empty(self) -> jpype.JBoolean:
            ...


    class MutableSpanSet(Span.SpanSet[N, S], typing.Generic[N, S]):
        """
        An abstract interface for a mutable :obj:`SpanSet`
        """

        class_: typing.ClassVar[java.lang.Class]

        def add(self, s: S):
            """
            Add a span to the set
             
             
            
            Any connected spans will be coalesced.
            
            :param S s: the span
            """

        def addAll(self, set: Span.SpanSet[N, S]):
            """
            Add all spans from the given set into this one
             
             
            
            The spans from both maps amy be coalesced when entered into this one. (The given map
            remains unmodified.)
            
            :param Span.SpanSet[N, S] set: the other set
            """

        def clear(self):
            """
            Remove all spans from the set
            """

        def remove(self, s: S):
            """
            Remove a span from the set
             
             
            
            Spans which intersect the given span are truncated. Spans which are enclosed are deleted,
            such that no value in the given span remains in the set.
            
            :param S s: the span
            """


    class SpanMapSetter(RangeMapSetter[E, N, S, V], typing.Generic[E, N, S, V]):
        """
        A partial implementation of :obj:`RangeMapSetter` for :obj:`Span`s.
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class DefaultSpanMap(Span.MutableSpanMap[N, S, V], typing.Generic[N, S, V]):
        """
        The default implementation of :obj:`SpanMap` and :obj:`MutableSpanMap` using an interval
        tree
        
         
        
        The interfaces can prevent accidental mutation of a map where it shouldn't be allowed;
        however, nothing prevents a client from casting to the mutable interface. If proper
        immutability is required, this will need to be wrapped or extended to prevent mutation.
        
        
        .. admonition:: Implementation Note
        
            While this map is concrete and can be used as is for spans in the given domain, it
            is recommended to create your own extension implementing an interface specific to
            your span type and domain.
        """

        @typing.type_check_only
        class Setter(Span.SpanMapSetter[java.util.Map.Entry[N, java.util.Map.Entry[S, V]], N, S, V]):
            """
            The setter, which handles coalescing and truncating entries
            """

            class_: typing.ClassVar[java.lang.Class]

            def __init__(self, domain: Span.Domain[N, S]):
                """
                Create a setter for the given domain
                
                :param Span.Domain[N, S] domain: the domain
                """


        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, domain: Span.Domain[N, S]):
            """
            Create a span map on the given domain
             
             
            
            Extensions should invoke this as a super constructor with a fixed domain. See
            :obj:`DefaultULongSpanMap` for an example.
            
            :param Span.Domain[N, S] domain: the domain
            """

        def toString(self, nToString: java.util.function.Function[N, java.lang.String]) -> str:
            ...


    class DefaultSpanSet(Span.MutableSpanSet[N, S], typing.Generic[N, S]):
        """
        The default implementation of :obj:`SpanSet` and :obj:`MutableSpanSet` using an interval
        tree
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, domain: Span.Domain[N, S]):
            """
            Create a span set on the given domain
             
             
            
            Extensions should invoke this as a super constructor with a fixed domain. See
            :obj:`DefaultULongSpanSet` for an example.
            
            :param Span.Domain[N, S] domain: the domain
            """


    class_: typing.ClassVar[java.lang.Class]

    def bound(self, s: S) -> S:
        """
        Compute the bound of this span and another
        
        :param S s: another span
        :return: the bound
        :rtype: S
        
        .. seealso::
        
            | :obj:`Domain.bound(Span, Span)`
        """

    def contains(self, n: N) -> bool:
        """
        Check if this span contains the given value
        
        :param N n: the value
        :return: true if n is contained in this span
        :rtype: bool
        """

    def domain(self) -> Span.Domain[N, S]:
        """
        Get the domain of this span's endpoints
        
        
        .. admonition:: Implementation Note
        
            a span implementation should probably return a fixed singleton instance for its
            domain.
        
        
        :return: the domain
        :rtype: Span.Domain[N, S]
        """

    def encloses(self, s: S) -> bool:
        """
        Check if this span encloses a given span
        
        :param S s: another span
        :return: true if this encloses the given span
        :rtype: bool
        """

    def intersect(self, s: S) -> S:
        """
        Compute the intersection of this span and another
        
        :param S s: another span
        :return: the intersection, possibly empty
        :rtype: S
        
        .. seealso::
        
            | :obj:`Domain.intersect(Span, Span)`
        """

    def intersects(self, s: S) -> bool:
        """
        Check if this span intersects a given span
        
        :param S s: another span
        :return: true if they intersect
        :rtype: bool
        
        .. seealso::
        
            | :obj:`Domain.intersects(Span, Span)`
        """

    def isEmpty(self) -> bool:
        """
        Check if this span is empty
        
        :return: true if empty
        :rtype: bool
        """

    def max(self) -> N:
        """
        Get the upper endpoint
        
        :return: the upper endpoint
        :rtype: N
        :raises NoSuchElementException: if the span is empty
        
        .. seealso::
        
            | :obj:`.isEmpty()`
        """

    def maxIsFinite(self) -> bool:
        """
        Check if the upper endpoint excludes the domain maximum
        
        :return: true if max is not the domain max
        :rtype: bool
        """

    def min(self) -> N:
        """
        Get the lower enpdoint
        
        :return: the lower endpoint
        :rtype: N
        :raises NoSuchElementException: if the span is empty
        
        .. seealso::
        
            | :obj:`.isEmpty()`
        """

    def minIsFinite(self) -> bool:
        """
        Check if the lower endpoint excludes the domain minimum
        
        :return: true if min is not the domain min
        :rtype: bool
        """

    def subtract(self, s: S) -> java.util.List[S]:
        """
        Subtract a span from this span
        
        :param S s: the span to subtract
        :return: 0, 1, or 2 spans resulting from the subtraction
        :rtype: java.util.List[S]
        """

    def toString(self, nToString: java.util.function.Function[N, java.lang.String]) -> str:
        """
        Provides a default :obj:`Object.toString` implementation
        
        :param java.util.function.Function[N, java.lang.String] nToString: the endpoint-to-string function
        :return: the string
        :rtype: str
        """

    @property
    def empty(self) -> jpype.JBoolean:
        ...


class Unique(java.lang.Object):
    """
    Some utilities for when singleton collections are expected
    """

    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    @typing.overload
    def assertAtMostOne(arr: jpype.JArray[T]) -> T:
        ...

    @staticmethod
    @typing.overload
    def assertAtMostOne(col: collections.abc.Sequence) -> T:
        """
        Assert that at most one element is in an iterable and get that element or ``null``
        
        :param T: the type of element:param collections.abc.Sequence col: the iterable
        :return: the element or ``null`` if empty
        :rtype: T
        :raises AssertionError: if many elements exist in the iterable
        """

    @staticmethod
    @typing.overload
    def assertOne(col: collections.abc.Sequence) -> T:
        """
        Assert that exactly one element is in an iterable and get that element
        
        :param T: the type of element:param collections.abc.Sequence col: the iterable
        :return: the element
        :rtype: T
        :raises AssertionError: if no element or many elements exist in the iterable
        """

    @staticmethod
    @typing.overload
    def assertOne(st: java.util.stream.Stream[T]) -> T:
        """
        Assert that exactly one element is in a stream and get that element
        
        :param T: the type of element:param java.util.stream.Stream[T] st: the stream
        :return: the element
        :rtype: T
        :raises AssertionError: if no element or many elements exist in the stream
        """


class FilteredIterator(java.util.Iterator[T], java.lang.Iterable[T], typing.Generic[T]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, it: java.util.Iterator[T], filter: java.util.function.Predicate[T]):
        """
        Construct a new FilteredIterator.
        
        :param java.util.Iterator[T] it: the iterator to filter
        :param java.util.function.Predicate[T] filter: the filter on T
        """


class DominantPair(generic.stl.Pair[K, V], typing.Generic[K, V]):
    """
    DominantPair is a pair where the key is responsible for equality and hashCode (and the value of
    the pair doesn't matter at all).  This is useful when you need the pair itself to function as a
    key in a Map or value in a Set.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, key: K, value: V):
        ...



__all__ = ["ULongSpan", "RangeMapSetter", "Span", "Unique", "FilteredIterator", "DominantPair"]
