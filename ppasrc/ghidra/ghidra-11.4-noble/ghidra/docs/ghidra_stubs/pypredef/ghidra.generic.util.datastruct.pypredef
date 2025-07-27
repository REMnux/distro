from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import java.lang # type: ignore
import java.util # type: ignore
import org.apache.commons.collections4.multimap # type: ignore


E = typing.TypeVar("E")
K = typing.TypeVar("K")
V = typing.TypeVar("V")


class SemisparseByteArray(java.lang.Object):
    """
    A sparse byte array characterized by contiguous dense regions
     
     
    
    Notionally, the array is 2 to the power 64 bytes in size. Only the initialized values are
    actually stored. Uninitialized indices are assumed to have the value 0. Naturally, this
    implementation works best when the array is largely uninitialized. For efficient use, isolated
    initialized values should be avoided. Rather, an entire range should be initialized at the same
    time.
     
     
    
    On a number line, the initialized indices of a semisparse array might be depicted:
     
     
    -----   --------- - ------         ---
     
     
     
    
    In contrast, the same for a sparse array might be depicted:
     
     
    -    --  -  - -    ---     --     -         -
     
     
     
    
    This implementation is well-suited for memory caches where the memory is accessed by reading
    ranges instead of individual bytes. Because consecutive reads and writes tend to occur in a
    common locality, caches using a semisparse array may perform well.
     
     
    
    This implementation is also thread-safe. Any thread needing exclusive access for multiple reads
    and/or writes, e.g., to implement a compare-and-set operation, must apply additional
    synchronization.
    """

    class_: typing.ClassVar[java.lang.Class]
    BLOCK_SIZE: typing.Final = 4096
    """
    The size of blocks used internally to store array values
    """


    def __init__(self):
        ...

    def clear(self):
        """
        Clear the array
         
         
        
        All indices will be uninitialized after this call, just as it was immediately after
        construction
        """

    def contiguousAvailableAfter(self, loc: typing.Union[jpype.JLong, int]) -> int:
        """
        Check how many contiguous bytes are available starting at the given address
        
        :param jpype.JLong or int loc: the starting offset
        :return: the number of contiguous defined bytes following
        :rtype: int
        """

    def fork(self) -> SemisparseByteArray:
        ...

    @typing.overload
    def getData(self, loc: typing.Union[jpype.JLong, int], data: jpype.JArray[jpype.JByte]):
        """
        Copy a range of data from the semisparse array into the given byte array
        
        :param jpype.JLong or int loc: the index to begin copying data out
        :param jpype.JArray[jpype.JByte] data: the array to copy data into
        
        .. seealso::
        
            | :obj:`.getData(long, byte[], int, int)`
        """

    @typing.overload
    def getData(self, loc: typing.Union[jpype.JLong, int], data: jpype.JArray[jpype.JByte], offset: typing.Union[jpype.JInt, int], length: typing.Union[jpype.JInt, int]):
        """
        Copy a range of data from the semisparse array into a portion of the given byte array
         
         
        
        Copies ``length`` bytes of data from the semisparse array starting at index ``loc``
        into ``data`` starting at index ``offset``. All initialized portions within the
        requested region are copied. The uninitialized portions may be treated as zeroes or not
        copied at all. Typically, the destination array has been initialized to zero by the caller,
        such that all uninitialized portions are zero. To avoid fetching uninitialized data, use
        :meth:`contiguousAvailableAfter(long) <.contiguousAvailableAfter>` as an upper bound on the length.
        
        :param jpype.JLong or int loc: the index to begin copying data out
        :param jpype.JArray[jpype.JByte] data: the array to copy data into
        :param jpype.JInt or int offset: the offset into the destination array
        :param jpype.JInt or int length: the length of data to read
        """

    def getDirect(self, loc: typing.Union[jpype.JLong, int]) -> jpype.JArray[jpype.JByte]:
        ...

    def getInitialized(self, a: typing.Union[jpype.JLong, int], b: typing.Union[jpype.JLong, int]) -> generic.ULongSpan.ULongSpanSet:
        """
        Enumerate the initialized ranges within the given range
         
         
        
        The given range is interpreted as closed, i.e., [a, b].
        
        :param jpype.JLong or int a: the lower-bound, inclusive, of the range
        :param jpype.JLong or int b: the upper-bound, inclusive, of the range
        :return: the set of initialized ranges
        :rtype: generic.ULongSpan.ULongSpanSet
        """

    def getUninitialized(self, a: typing.Union[jpype.JLong, int], b: typing.Union[jpype.JLong, int]) -> generic.ULongSpan.ULongSpanSet:
        """
        Enumerate the uninitialized ranges within the given range
         
         
        
        The given range is interpreted as closed, i.e., [a, b].
        
        :param jpype.JLong or int a: the lower-bound, inclusive, of the range
        :param jpype.JLong or int b: the upper-bound, inclusive, of the range
        :return: the set of uninitialized ranges
        :rtype: generic.ULongSpan.ULongSpanSet
        """

    @typing.overload
    def isInitialized(self, a: typing.Union[jpype.JLong, int], b: typing.Union[jpype.JLong, int]) -> bool:
        """
        Check if a range is completely initialized
         
         
        
        The given range is interpreted as closed, i.e., [a, b].
        
        :param jpype.JLong or int a: the lower-bound, inclusive, of the range
        :param jpype.JLong or int b: the upper-bound, inclusive, of the range
        :return: true if all indices in the range are initialized, false otherwise
        :rtype: bool
        """

    @typing.overload
    def isInitialized(self, a: typing.Union[jpype.JLong, int]) -> bool:
        """
        Check if an index is initialized
        
        :param jpype.JLong or int a: the index to check
        :return: true if the index is initialized, false otherwise
        :rtype: bool
        """

    def putAll(self, from_: SemisparseByteArray):
        """
        Copy the contents on another semisparse array into this one
        
        :param SemisparseByteArray from: the source array
        """

    @typing.overload
    def putData(self, loc: typing.Union[jpype.JLong, int], data: jpype.JArray[jpype.JByte]):
        """
        Initialize or modify a range of the array by copying from a given array
        
        :param jpype.JLong or int loc: the index of the semisparse array to begin copying into
        :param jpype.JArray[jpype.JByte] data: the data to copy
        
        .. seealso::
        
            | :obj:`.putData(long, byte[], int, int)`
        """

    @typing.overload
    def putData(self, loc: typing.Union[jpype.JLong, int], data: jpype.JArray[jpype.JByte], offset: typing.Union[jpype.JInt, int], length: typing.Union[jpype.JInt, int]):
        """
        Initialize or modify a range of the array by copying a portion from a given array
        
        :param jpype.JLong or int loc: the index of the semisparse array to begin copying into
        :param jpype.JArray[jpype.JByte] data: the source array to copy from
        :param jpype.JInt or int offset: the offset of the source array to begin copying from
        :param jpype.JInt or int length: the length of data to copy
        """

    @property
    def direct(self) -> jpype.JArray[jpype.JByte]:
        ...

    @property
    def initialized(self) -> jpype.JBoolean:
        ...


class SortedList(ValueSortedMap.LesserList[E], typing.Generic[E]):
    """
    An interface for sorted lists
    
     
    
    This might be better described as a NavigableMultiset; however, I wish for the elements to be
    retrievable by index, though insertion and mutation is not permitted by index. This implies that
    though unordered, the underlying implementation has sorted the elements in some way and wishes to
    expose that ordering to its clients.
    """

    class_: typing.ClassVar[java.lang.Class]

    def ceilingIndex(self, element: E) -> int:
        """
        Returns the least index in this list whose element is greater than or equal to the specified
        element
         
         
        
        If multiples of the specified element exist, this returns the greatest index of that element.
        
        :param E element: the element to search for
        :return: the index of the found element, or -1
        :rtype: int
        """

    def floorIndex(self, element: E) -> int:
        """
        Returns the greatest index in this list whose element is less than or equal to the specified
        element
         
         
        
        If multiples of the specified element exist, this returns the least index of that element.
        
        :param E element: the element to search for
        :return: the index of the found element, or -1
        :rtype: int
        """

    def higherIndex(self, element: E) -> int:
        """
        Returns the least index in this list whose element is strictly greater the specified element
        
        :param E element: the element to search for
        :return: the index of the found element, or -1
        :rtype: int
        """

    def lowerIndex(self, element: E) -> int:
        """
        Returns the greatest index in this list whose element is strictly less than the specified
        element
        
        :param E element: the element to search for
        :return: the index of the found element, or -1
        :rtype: int
        """


class RestrictedValueSortedMap(ValueSortedMap[K, V], typing.Generic[K, V]):
    """
    A view of the value-sorted map for implementing
    :meth:`subMapByValue(Object, boolean, Object, boolean) <.subMapByValue>`, etc.
    """

    class RestrictedEntryListIterator(java.util.ListIterator[java.util.Map.Entry[K, V]]):
        """
        A list iterator suitable for :meth:`List.listIterator() <List.listIterator>`, etc., on the entries of a
        :obj:`RestrictedValueSortedMap`
        """

        class_: typing.ClassVar[java.lang.Class]

        @typing.overload
        def __init__(self):
            """
            Construct an iterator
            """

        @typing.overload
        def __init__(self, start: typing.Union[jpype.JInt, int]):
            """
            Construct an iterator starting at a given index of the *sub* list.
            
            :param jpype.JInt or int start: initial iterator position
            """


    class RestrictedKeyListIterator(java.util.ListIterator[K]):
        """
        A list iterator suitable for :meth:`List.listIterator() <List.listIterator>`, etc., on the keys of a
        :obj:`RestrictedValueSortedMap`
        """

        class_: typing.ClassVar[java.lang.Class]

        @typing.overload
        def __init__(self):
            """
            Construct an iterator
            """

        @typing.overload
        def __init__(self, start: typing.Union[jpype.JInt, int]):
            """
            Construct an iterator starting at a given index of the *sub* list.
            
            :param jpype.JInt or int start: initial iterator position
            """


    class RestrictedValueListIterator(java.util.ListIterator[V]):
        """
        A list iterator suitable for :meth:`List.listIterator() <List.listIterator>`, etc., on the values of a
        :obj:`RestrictedValueSortedMap`
        """

        class_: typing.ClassVar[java.lang.Class]

        @typing.overload
        def __init__(self):
            """
            Construct an iterator
            """

        @typing.overload
        def __init__(self, start: typing.Union[jpype.JInt, int]):
            """
            Construct an iterator starting at a given index of the *sub* list.
            
            :param jpype.JInt or int start: initial iterator position
            """


    class RestrictedValueSortedMapEntryList(ValueSortedMap.ValueSortedMapEntryList[K, V]):
        """
        A list view suitable for :meth:`ValueSortedMap.entrySet() <ValueSortedMap.entrySet>` of
        :obj:`RestrictedValueSortedMap`
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class RestrictedValueSortedMapKeyList(ValueSortedMap.ValueSortedMapKeyList[K]):
        """
        A list view suitable for :meth:`ValueSortedMap.keySet() <ValueSortedMap.keySet>` of :obj:`RestrictedValueSortedMap`
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class RestrictedSortedList(SortedList[V]):
        """
        A list view suitable for :meth:`ValueSortedMap.values() <ValueSortedMap.values>` of :obj:`RestrictedValueSortedMap`
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class_: typing.ClassVar[java.lang.Class]


class TreeValueSortedMap(java.util.AbstractMap[K, V], ValueSortedMap[K, V], typing.Generic[K, V]):
    """
    A tree-based implementation of a value-sorted map
    
    The underlying implementation is currently an unbalanced binary tree whose nodes also comprise a
    doubly-linked list. Currently, it is not thread safe.
    
    Note this implementation isn't terribly smart, as it makes no efforts to balance the tree. It is
    also not thread safe.
    """

    @typing.type_check_only
    class EntryListIterator(java.util.ListIterator[java.util.Map.Entry[K, V]]):
        """
        An iterator of the entries
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class KeyListIterator(java.util.ListIterator[K]):
        """
        An iterator of the keys
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class Node(java.util.Map.Entry[K, V]):
        """
        An entry in the map.
         
        Nodes are elements of a binary tree and a doubly-linked list.
        """

        class_: typing.ClassVar[java.lang.Class]

        def computeIndex(self) -> int:
            """
            Compute this node's index.
             
            This uses the :obj:`.sizeLeft` field to compute the index in O(log n) on average.
            
            :return: the index
            :rtype: int
            """


    @typing.type_check_only
    class BoundType(java.lang.Enum[TreeValueSortedMap.BoundType]):

        class_: typing.ClassVar[java.lang.Class]
        CLOSED: typing.Final[TreeValueSortedMap.BoundType]
        OPEN: typing.Final[TreeValueSortedMap.BoundType]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> TreeValueSortedMap.BoundType:
            ...

        @staticmethod
        def values() -> jpype.JArray[TreeValueSortedMap.BoundType]:
            ...


    @typing.type_check_only
    class Comp(java.lang.Enum[TreeValueSortedMap.Comp]):

        class_: typing.ClassVar[java.lang.Class]
        NONE: typing.Final[TreeValueSortedMap.Comp]
        LT: typing.Final[TreeValueSortedMap.Comp]
        GT: typing.Final[TreeValueSortedMap.Comp]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> TreeValueSortedMap.Comp:
            ...

        @staticmethod
        def values() -> jpype.JArray[TreeValueSortedMap.Comp]:
            ...


    @typing.type_check_only
    class SearchMode(java.lang.Enum[TreeValueSortedMap.SearchMode]):
        """
        When searching for values, identifies which instance to find
        """

        class_: typing.ClassVar[java.lang.Class]
        ANY: typing.Final[TreeValueSortedMap.SearchMode]
        """
        Find any occurrence
        """

        FIRST: typing.Final[TreeValueSortedMap.SearchMode]
        """
        Find the first occurrence
        """

        LAST: typing.Final[TreeValueSortedMap.SearchMode]
        """
        Find the last occurrence
        """

        LOWER: typing.Final[TreeValueSortedMap.SearchMode]
        """
        Find the nearest match less than
        """

        FLOOR: typing.Final[TreeValueSortedMap.SearchMode]
        """
        Find the nearest match less than or equal
        """

        CEILING: typing.Final[TreeValueSortedMap.SearchMode]
        """
        Find the nearest match greater than or equal
        """

        HIGHER: typing.Final[TreeValueSortedMap.SearchMode]
        """
        Find the nearest match greater than
        """


        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> TreeValueSortedMap.SearchMode:
            ...

        @staticmethod
        def values() -> jpype.JArray[TreeValueSortedMap.SearchMode]:
            ...


    @typing.type_check_only
    class ValueListIterator(java.util.ListIterator[V]):
        """
        An iterator of the values
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ValueSortedTreeMapEntrySet(java.util.AbstractSet[java.util.Map.Entry[K, V]], ValueSortedMap.ValueSortedMapEntryList[K, V]):
        """
        A public view of the map as a set of entries
         
        In addition to :obj:`Set`, this view implements :obj:`List` and :obj:`Deque`, since an
        ordered set ought to behave like a list, and since this implementation is meant to be used as
        a dynamic-cost priority queue.
         
        Generally, all of the mutation methods are supported.
        """

        class_: typing.ClassVar[java.lang.Class]

        def add(self, e: java.util.Map.Entry[K, V]) -> bool:
            """
            Inserts (by copy) the entry into the owning map
            """


    @typing.type_check_only
    class ValueSortedTreeMapKeySet(java.util.AbstractSet[K], ValueSortedMap.ValueSortedMapKeyList[K]):
        """
        A public view of the map as a set of keys
         
        In addition to :obj:`Set`, this view implements :obj:`List` and :obj:`Deque`, since an
        ordered set ought to behave like a list, and since this implementation is meant to be used as
        a dynamic-cost priority queue.
         
        Generally, only the removal mutation methods are supported, all others are not supported.
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ValueSortedTreeMapValues(java.util.AbstractCollection[V], SortedList[V]):
        """
        A public view of the map as a list of values
         
        This view implements :obj:`SortedList` and :obj:`Deque`, since an ordered collection ought
        to behave like a list, and since this implementation is meant to be used as a dynamic-cost
        priority queue.
         
        Generally, only the removal mutation methods are supported, all others are not supported.
        """

        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def createWithComparator(comparator: java.util.Comparator[V]) -> TreeValueSortedMap[K, V]:
        """
        Create a tree using a custom comparator to order the values
        
        :param java.util.Comparator[V] comparator: the comparator, providing a total ordering of the values
        """

    @staticmethod
    def createWithNaturalOrder() -> TreeValueSortedMap[K, V]:
        """
        Create a tree using the values' natural ordering
        """


class TreeSetValuedTreeMap(org.apache.commons.collections4.multimap.AbstractSetValuedMap[K, V], typing.Generic[K, V]):
    """
    A multi-valued map using a tree map of tree sets
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class ValueSortedMap(java.lang.Object, typing.Generic[K, V]):
    """
    A map that is sorted by value.
     
     
    
    This is an extension of :obj:`Map` where entries are sorted by value, rather than by key. Such a
    map may be useful as a priority queue where the cost of an entry may change over time. As such,
    the collections returned by :meth:`entrySet() <.entrySet>`, :meth:`keySet() <.keySet>`, and :meth:`values() <.values>` all
    extend :obj:`Deque`. The order of the entries will be updated on any call to
    :meth:`Map.put(Object, Object) <Map.put>`, or a call to :meth:`Collection.add(Object) <Collection.add>` on the entry set.
    Additionally, if the values are mutable objects, whose order may change, there is an
    :meth:`update(Object) <.update>` method, which notifies the map that the given key may need to be
    repositioned. The associated collections also extend the :obj:`List` interface, providing fairly
    efficient implementations of :meth:`List.get(int) <List.get>` and :meth:`List.indexOf(Object) <List.indexOf>`. Sequential
    access is best performed via :meth:`Collection.iterator() <Collection.iterator>`, since this will use a linked list.
    """

    class LesserList(java.lang.Iterable[E], typing.Generic[E]):
        """
        An interface with a subset of methods from :obj:`List`.
         
         
        
        We've opted to implement this instead of :obj:`List` so that newer JDKs do not impose new
        requirements on our implementations.
        """

        class_: typing.ClassVar[java.lang.Class]

        def contains(self, o: java.lang.Object) -> bool:
            ...

        def get(self, i: typing.Union[jpype.JInt, int]) -> E:
            """
            Get the element at the given index
            
            :param jpype.JInt or int i: the index
            :return: the element
            :rtype: E
            """

        def indexOf(self, o: java.lang.Object) -> int:
            """
            Get the index of a given element
             
             
            
            Returns the index of the element, or -1 if not found
            
            :param java.lang.Object o: the object
            :return: the index or -1
            :rtype: int
            """

        def isEmpty(self) -> bool:
            ...

        def listIterator(self, index: typing.Union[jpype.JInt, int]) -> java.util.ListIterator[E]:
            ...

        def poll(self) -> E:
            """
            Get and remove the first element
            
            :return: the first element, or null if empty
            :rtype: E
            """

        def remove(self, o: java.lang.Object) -> bool:
            ...

        def removeAll(self, col: collections.abc.Sequence) -> bool:
            ...

        def size(self) -> int:
            ...

        def toList(self) -> java.util.List[E]:
            """
            Copy this to a new list
            
            :return: the list
            :rtype: java.util.List[E]
            """

        @property
        def empty(self) -> jpype.JBoolean:
            ...


    class ValueSortedMapEntryList(ValueSortedMap.LesserList[java.util.Map.Entry[K, V]], typing.Generic[K, V]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class ValueSortedMapKeyList(ValueSortedMap.LesserList[K], typing.Generic[K]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def ceilingEntryByValue(self, value: V) -> java.util.Map.Entry[K, V]:
        """
        Returns a key-value mapping associated with the least value greater than or equal to the
        given value, or ``null`` if there is no such value.
        
        :param V value: the value
        :return: the found entry, or ``null``
        :rtype: java.util.Map.Entry[K, V]
        """

    def clear(self):
        ...

    def containsKey(self, key: java.lang.Object) -> bool:
        ...

    def containsValue(self, value: java.lang.Object) -> bool:
        ...

    def entrySet(self) -> ValueSortedMap.ValueSortedMapEntryList[K, V]:
        ...

    def floorEntryByValue(self, value: V) -> java.util.Map.Entry[K, V]:
        """
        Returns a key-value mapping associated with the greatest value less than or equal to the
        given value, or ``null`` if there is no such value.
        
        :param V value: the value
        :return: the found entry, or ``null``
        :rtype: java.util.Map.Entry[K, V]
        """

    def get(self, key: java.lang.Object) -> V:
        ...

    def headMapByValue(self, toValue: V, inclusive: typing.Union[jpype.JBoolean, bool]) -> ValueSortedMap[K, V]:
        """
        Returns a view of the portion of this map whose values are less than (or equal to, if
        ``inclusive`` is true) ``toValue``. The returned map is an unmodifiable view.
        
        :param V toValue: high endpoint of the values in the returned map
        :param jpype.JBoolean or bool inclusive: ``true`` if the high endpoint is to be included in the returned view
        :return: the view
        :rtype: ValueSortedMap[K, V]
        """

    def higherEntryByValue(self, value: V) -> java.util.Map.Entry[K, V]:
        """
        Returns a key-value mapping associated with the least value strictly greater than the given
        value, or ``null`` if there is no such value.
        
        :param V value: the value
        :return: the found entry, or ``null``
        :rtype: java.util.Map.Entry[K, V]
        """

    def isEmpty(self) -> bool:
        ...

    def keySet(self) -> ValueSortedMap.ValueSortedMapKeyList[K]:
        ...

    def lowerEntryByValue(self, value: V) -> java.util.Map.Entry[K, V]:
        """
        Returns a key-value mapping associated with the greatest value strictly less than the given
        value, or ``null`` if there is no such value.
        
        :param V value: the value
        :return: the found entry, or ``null``
        :rtype: java.util.Map.Entry[K, V]
        """

    def put(self, key: K, value: V) -> V:
        ...

    def remove(self, key: K) -> V:
        ...

    def size(self) -> int:
        ...

    def subMapByValue(self, fromValue: V, fromInclusive: typing.Union[jpype.JBoolean, bool], toValue: V, toInclusive: typing.Union[jpype.JBoolean, bool]) -> ValueSortedMap[K, V]:
        """
        Returns a view of the portion of this map whose values range from ``fromValue`` to
        ``toValue``. The returned map is an unmodifiable view.
        
        :param V fromValue: low endpoint of the values in the returned map
        :param jpype.JBoolean or bool fromInclusive: ``true`` if the low endpoint is to be included in the returned view
        :param V toValue: high endpoint of the values in the returned map
        :param jpype.JBoolean or bool toInclusive: ``true`` if the high endpoint is to be included in the returned view
        :return: the view
        :rtype: ValueSortedMap[K, V]
        """

    def tailMapByValue(self, fromValue: V, inclusive: typing.Union[jpype.JBoolean, bool]) -> ValueSortedMap[K, V]:
        """
        Returns a view of the portion of this map whose values are greater than (or equal to, if
        ``inclusive`` is true) ``toValue``. The returned map is an unmodifiable view.
        
        :param V fromValue: low endpoint of the values in the returned map
        :param jpype.JBoolean or bool inclusive: ``true`` if the low endpoint is to be included in the returned view
        :return: the view
        :rtype: ValueSortedMap[K, V]
        """

    def update(self, key: K) -> bool:
        """
        Notify the map of an external change to the cost of a key's associated value
         
         
        
        This is meant to update the entry's position after a change in cost. The position may not
        necessarily change, however, if the cost did not change significantly.
        
        :param K key: the key whose associated value has changed in cost
        :return: true if the entry's position changed
        :rtype: bool
        """

    def values(self) -> SortedList[V]:
        ...

    @property
    def empty(self) -> jpype.JBoolean:
        ...



__all__ = ["SemisparseByteArray", "SortedList", "RestrictedValueSortedMap", "TreeValueSortedMap", "TreeSetValuedTreeMap", "ValueSortedMap"]
