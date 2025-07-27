from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import generic.cache
import ghidra.util
import ghidra.util.exception
import ghidra.util.map
import java.io # type: ignore
import java.lang # type: ignore
import java.lang.ref # type: ignore
import java.lang.reflect # type: ignore
import java.util # type: ignore
import java.util.function # type: ignore
import java.util.stream # type: ignore
import org.apache.commons.lang3.mutable # type: ignore


E = typing.TypeVar("E")
K = typing.TypeVar("K")
T = typing.TypeVar("T")
V = typing.TypeVar("V")


class DoubleArray(Array, java.io.Serializable):
    """
    Array of doubles that grows as needed.
    """

    class_: typing.ClassVar[java.lang.Class]
    MIN_SIZE: typing.Final = 4

    def __init__(self):
        """
        Creates new doubleArray
        """

    def copyDataTo(self, index: typing.Union[jpype.JInt, int], table: DataTable, toIndex: typing.Union[jpype.JInt, int], toCol: typing.Union[jpype.JInt, int]):
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.util.datastruct.Array.copyDataTo(int, DataTable, int, int)`
        """

    def get(self, index: typing.Union[jpype.JInt, int]) -> float:
        """
        Returns the int at the given index
        
        :param jpype.JInt or int index: index into the array
        :return: The int value at the given index. A 0 will
        be return for any index not initialized to
        another value.
        :rtype: float
        :raises IndexOutOfBoundsException: if the index is negative
        """

    def getLastNonEmptyIndex(self) -> int:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.util.datastruct.Array.getLastNonEmptyIndex()`
        """

    def put(self, index: typing.Union[jpype.JInt, int], value: typing.Union[jpype.JDouble, float]):
        """
        Puts the given double value in the double array at
        the given index
        
        :param jpype.JInt or int index: Index into the array.
        :param jpype.JDouble or float value: value to store
        :raises IndexOutOfBoundsException: if the index is negative
        """

    def remove(self, index: typing.Union[jpype.JInt, int]):
        """
        Sets the value at the given index to 0.
        
        :param jpype.JInt or int index: the index to set to 0.
        :raises IndexOutOfBoundsException: if the index is negative
        """

    @property
    def lastNonEmptyIndex(self) -> jpype.JInt:
        ...


class LongArrayList(java.util.List[java.lang.Long], java.util.RandomAccess):
    """
    An ArrayList for longs.
    """

    @typing.type_check_only
    class LongArraySubList(java.util.List[java.lang.Long]):

        class_: typing.ClassVar[java.lang.Class]

        @typing.overload
        def add(self, value: typing.Union[jpype.JLong, int]):
            ...

        @typing.overload
        def add(self, index: typing.Union[jpype.JInt, int], value: typing.Union[jpype.JLong, int]):
            ...

        def getIndex(self, value: typing.Union[jpype.JLong, int]) -> int:
            ...

        def set(self, index: typing.Union[jpype.JInt, int], value: typing.Union[jpype.JLong, int]):
            ...

        @property
        def index(self) -> jpype.JInt:
            ...


    class_: typing.ClassVar[java.lang.Class]
    MIN_SIZE: typing.Final = 4

    @typing.overload
    def __init__(self):
        """
        Creates a new LongArrayList
        """

    @typing.overload
    def __init__(self, arr: jpype.JArray[jpype.JLong]):
        """
        Creates a new Long ArrayList using the values in the given array
        
        :param jpype.JArray[jpype.JLong] arr: array of longs to initialize to.
        """

    @typing.overload
    def __init__(self, list: LongArrayList):
        """
        Creates a new LongArrayList that is equivalent to the specified LongArrayList.
        It creates a copy of the specified list.
        
        :param LongArrayList list: the list to be copied.
        """

    @typing.overload
    def add(self, value: typing.Union[jpype.JLong, int]):
        ...

    @typing.overload
    def add(self, index: typing.Union[jpype.JInt, int], value: typing.Union[jpype.JLong, int]):
        ...

    def getLongValue(self, index: typing.Union[jpype.JInt, int]) -> int:
        ...

    def reverse(self):
        ...

    def toArray(self, a: jpype.JArray[java.lang.Long]) -> jpype.JArray[java.lang.Long]:
        ...

    @typing.overload
    def toLongArray(self) -> jpype.JArray[jpype.JLong]:
        ...

    @typing.overload
    def toLongArray(self, start: typing.Union[jpype.JInt, int], length: typing.Union[jpype.JInt, int]) -> jpype.JArray[jpype.JLong]:
        ...

    @property
    def longValue(self) -> jpype.JLong:
        ...


class ObjectCache(java.lang.Object, typing.Generic[T]):
    """
    ``ObjectClass`` provides a fixed-size long-key-based object cache.
    Both a hard and weak cache are maintained, where the weak cache is only
    limited by available memory.  This cache mechanism is useful in ensuring that
    only a single object instance for a given key exists.
     
    
    The weak cache is keyed, while the hard cache simply maintains the presence of
    an object in the weak cache.
    """

    @typing.type_check_only
    class KeyedSoftReference(java.lang.ref.WeakReference[T], typing.Generic[T]):
        """
        Provides a weak wrapper for a keyed-object
        """

        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, hardCacheSize: typing.Union[jpype.JInt, int]):
        """
        Construct a keyed-object cache of size hardCacheSize.
        
        :param jpype.JInt or int hardCacheSize: hard cache size.
        """

    def computeIfAbsent(self, key: typing.Union[jpype.JLong, int], mappingFunction: java.util.function.Function[java.lang.Long, T]) -> T:
        """
        Get the current cached object which corresponds to specified ``key`` if contained in
        cache, otherwise the ``mappingFunction`` will be invoked to instantiate a new object
        where that object will be added to the cache and returned.  If the ``mappingFunction``
        returns null nothing will be added to the cache and null will be returned by this method.
        
        :param jpype.JLong or int key: object key
        :param java.util.function.Function[java.lang.Long, T] mappingFunction: function used to obtain a new object if not currently present
        in cache.
        :return: cached object
        :rtype: T
        """

    def contains(self, key: typing.Union[jpype.JLong, int]) -> bool:
        """
        Determine if the keyed-object exists in the cache.
        
        :param jpype.JLong or int key: object key
        :return: true if object is cached
        :rtype: bool
        """

    def get(self, key: typing.Union[jpype.JLong, int]) -> T:
        """
        Get the object from cache which corresponds to the specified key.
        
        :param jpype.JLong or int key: object key
        :return: cached object
        :rtype: T
        """

    def put(self, key: typing.Union[jpype.JLong, int], obj: T):
        """
        Add an object to the cache
        
        :param jpype.JLong or int key: object key
        :param T obj: the object
        """

    def remove(self, key: typing.Union[jpype.JLong, int]):
        """
        Remove the specified keyed object from both hard and weak caches.
        An object should be removed from the cache when it becomes invalid.
        
        :param jpype.JLong or int key: object key
        """

    def setHardCacheSize(self, size: typing.Union[jpype.JInt, int]):
        """
        Adjust the hard cache size
        
        :param jpype.JInt or int size: new hard cache size
        """

    def size(self) -> int:
        """
        Return the hard cache size
        
        :return: the hard cache size
        :rtype: int
        """


class IntArrayArray(Array, java.io.Serializable):
    """
    Array of int[] that grows as needed.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        """
        Creates new intArrayArray
        """

    def copyDataTo(self, index: typing.Union[jpype.JInt, int], table: DataTable, toIndex: typing.Union[jpype.JInt, int], toCol: typing.Union[jpype.JInt, int]):
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.util.datastruct.Array.copyDataTo(int, ghidra.util.datastruct.DataTable, int, int)`
        """

    def get(self, index: typing.Union[jpype.JInt, int]) -> jpype.JArray[jpype.JInt]:
        """
        Returns the int at the given index
        
        :param jpype.JInt or int index: index into the array
        :return: The int value at the given index. A 0 will
        be returned for any index not initialized to
        another value.
        :rtype: jpype.JArray[jpype.JInt]
        :raises IndexOutOfBoundsException: if the index is negative
        """

    def getLastNonEmptyIndex(self) -> int:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.util.datastruct.Array.getLastNonEmptyIndex()`
        """

    def put(self, index: typing.Union[jpype.JInt, int], value: jpype.JArray[jpype.JInt]):
        """
        Puts the given int value in the int array at
        the given index
        
        :param jpype.JInt or int index: Index into the array.
        :param jpype.JArray[jpype.JInt] value: value to store
        :raises IndexOutOfBoundsException: if the index is negative
        """

    def remove(self, index: typing.Union[jpype.JInt, int]):
        """
        Removes the array at the given index
        
        :param jpype.JInt or int index: index of the array to be removed
        :raises IndexOutOfBoundsException: if the index is negative
        """

    @property
    def lastNonEmptyIndex(self) -> jpype.JInt:
        ...


class Accumulator(java.lang.Iterable[T], java.util.function.Consumer[T], typing.Generic[T]):
    """
    The interface provides a mechanism for clients to pass around an object that is effectively
    a 'results object', into which data can be placed as it is discovered. 
     
     
    Historically, clients that load data will return results, once fully loaded, in a 
    :obj:`Collection`.  This has the drawback that the discovered data cannot be used until
    all searching is complete.  This interface can now be passed into such a method (as opposed
    to be returned by it) so that the client can make use of data as it is discovered.   This 
    allows for long searching processes to report data as they work.
    """

    class_: typing.ClassVar[java.lang.Class]

    def add(self, t: T):
        ...

    def addAll(self, collection: collections.abc.Sequence):
        ...

    def contains(self, t: T) -> bool:
        ...

    def get(self) -> java.util.Collection[T]:
        ...

    def isEmpty(self) -> bool:
        ...

    def size(self) -> int:
        ...

    def stream(self) -> java.util.stream.Stream[T]:
        ...

    @property
    def empty(self) -> jpype.JBoolean:
        ...


class ByteArrayArray(Array, java.io.Serializable):
    """
    Array of byte[] that grows as needed.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        """
        Creates new ByteArrayArray
        """

    def copyDataTo(self, index: typing.Union[jpype.JInt, int], table: DataTable, toIndex: typing.Union[jpype.JInt, int], toCol: typing.Union[jpype.JInt, int]):
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.util.datastruct.Array.copyDataTo(int, DataTable, int, int)`
        """

    def get(self, index: typing.Union[jpype.JInt, int]) -> jpype.JArray[jpype.JByte]:
        """
        Returns the byte array at the given index
        
        :param jpype.JInt or int index: index into the array
        :return: The byte array at the given index. An empty array will
        be returned for any index not initialized to
        another value.
        :rtype: jpype.JArray[jpype.JByte]
        :raises IndexOutOfBoundsException: if the index is negative
        """

    def getLastNonEmptyIndex(self) -> int:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.util.datastruct.Array.getLastNonEmptyIndex()`
        """

    def put(self, index: typing.Union[jpype.JInt, int], value: jpype.JArray[jpype.JByte]):
        """
        Puts the given byte array in the ByteArrayArray at
        the given index
        
        :param jpype.JInt or int index: Index into the array.
        :param jpype.JArray[jpype.JByte] value: value to store
        :raises IndexOutOfBoundsException: if the index is negative
        """

    def remove(self, index: typing.Union[jpype.JInt, int]):
        """
        Removes the array at the given index
        
        :param jpype.JInt or int index: index of the array to be removed
        :raises IndexOutOfBoundsException: if the index is negative
        """

    @property
    def lastNonEmptyIndex(self) -> jpype.JInt:
        ...


class CallbackAccumulator(Accumulator[T], typing.Generic[T]):
    """
    An implementation of :obj:`Accumulator` that allows clients to easily process items as
    they arrive. 
     
     
    This class is different than normal accumulators in that the values are **not** 
    stored internally.  As such, calls to :meth:`get() <.get>`, :meth:`iterator() <.iterator>` and 
    :meth:`size() <.size>` will reflect having no data.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, consumer: java.util.function.Consumer[T]):
        """
        Constructor
        
        :param java.util.function.Consumer[T] consumer: the consumer that will get called each time an item is added
        """


class ObjectRangeMap(java.lang.Object, typing.Generic[T]):
    """
    Associates objects with long index ranges.
    """

    @typing.type_check_only
    class SimpleIndexRangeIterator(IndexRangeIterator):

        class_: typing.ClassVar[java.lang.Class]

        def hasNext(self) -> bool:
            ...

        def next(self) -> IndexRange:
            ...


    @typing.type_check_only
    class RestrictedIndexRangeIterator(IndexRangeIterator):

        class_: typing.ClassVar[java.lang.Class]

        def hasNext(self) -> bool:
            ...

        def next(self) -> IndexRange:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        """
        Constructs a new ObjectRangeMap
        """

    def clearRange(self, start: typing.Union[jpype.JLong, int], end: typing.Union[jpype.JLong, int]):
        """
        Clears any object associations within the given range.
        
        :param jpype.JLong or int start: the first index in the range to be cleared.
        :param jpype.JLong or int end: the last index in the range to be cleared.
        """

    def contains(self, index: typing.Union[jpype.JLong, int]) -> bool:
        """
        Returns true if the associated index has an associated object even if the assocated object
        is null.
        
        :param jpype.JLong or int index: the index to check for an association.
        :return: true if the associated index has an associated object even if the assocated object
        is null.
        :rtype: bool
        """

    @typing.overload
    def getIndexRangeIterator(self) -> IndexRangeIterator:
        """
        Returns an :obj:`IndexRangeIterator` over all ranges that have associated objects.
        
        :return: an :obj:`IndexRangeIterator` over all ranges that have associated objects.
        :rtype: IndexRangeIterator
        """

    @typing.overload
    def getIndexRangeIterator(self, start: typing.Union[jpype.JLong, int], end: typing.Union[jpype.JLong, int]) -> IndexRangeIterator:
        """
        Returns an :obj:`IndexRangeIterator` over all ranges that have associated objects within
        the given range.  Object Ranges that overlap the beginning or end of the given range are
        included, but have thier start or end index adjusted to be in the given range.
        
        :param jpype.JLong or int start: the first index in the range to find all index ranges that have associated values.
        :param jpype.JLong or int end: the last index(inclusive) in the range to find all index ranges that have associated
        values.
        :return: an :obj:`IndexRangeIterator` over all ranges that have associated objects within the
        given range.
        :rtype: IndexRangeIterator
        """

    def getObject(self, index: typing.Union[jpype.JLong, int]) -> T:
        """
        Returns the object associated with the given index or null if no object is associated with
        the given index.  Note that null is a valid association so a null result could be either
        no association or an actual association of the index to null.  Use the contains() method
        first if the distinction is important.  If the contains() method returns true, the result
        is cached so the next call to getObject() will be fast.
        
        :param jpype.JLong or int index: the index at which to retrieve an assocated object.
        :return: the object (which can be null) associated with the given index or null if no such
        association exists.
        :rtype: T
        """

    def setObject(self, start: typing.Union[jpype.JLong, int], end: typing.Union[jpype.JLong, int], object: T):
        """
        Associates the given object with all indices in the given range. The object may be null,
        but an assocition is still established.  Use the clearRange() method to remove associations.
        
        :param jpype.JLong or int start: the start of the range.
        :param jpype.JLong or int end: the end (inclusive) of the range.
        :param T object: the object to associate with the given range.
        """

    @property
    def indexRangeIterator(self) -> IndexRangeIterator:
        ...

    @property
    def object(self) -> T:
        ...


class IntKeyIndexer(java.io.Serializable):
    """
    This class converts arbitrary int keys into compacted int indexes suitable
    for use as indexes into an array or table.  Whenever a new key is added,
    the smallest unused index is allocated and associated with that key.
    Basically hashes the keys into linked lists using the IntListIndexer class,
    where all values in a list have
    the same hashcode.  Does most of the work in implementing a separate chaining
    version of a hashtable - the only thing missing is the values which are stored
    in the individual implementations of the various hashtables.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        Constructs an IntKeyIndexer with a default capacity.
        """

    @typing.overload
    def __init__(self, capacity: typing.Union[jpype.JInt, int]):
        """
        Constructs an IntKeyIndexer with a given initial capacity.
        
        :param jpype.JInt or int capacity: the initial capacity.
        """

    def clear(self):
        """
        Remove all keys.
        """

    def get(self, key: typing.Union[jpype.JInt, int]) -> int:
        """
        Returns the index for the given key, or
        -1 if key is not in the table.
        
        :param jpype.JInt or int key: the key for which to find an index.
        """

    def getCapacity(self) -> int:
        """
        Returns the current size of the key table.
        """

    def getKeys(self) -> jpype.JArray[jpype.JInt]:
        """
        Returns a array containing all the keys stored in this object.
        """

    def getSize(self) -> int:
        """
        Returns the number of keys stored in the table.
        """

    def put(self, key: typing.Union[jpype.JInt, int]) -> int:
        """
        Returns an index that will always be associated to the given key as long as
        the key remains in the table. If the key already exists, then the index where
        that key is stored is returned.  If the key is new, then a new index is allocated,
        the key is stored at that index, and the new index is returned.
        
        :param jpype.JInt or int key: the key to be stored.
        :return: index for key, or -1 if there was no room to put the key.
        :rtype: int
        :raises IndexOutOfBoundsException: thrown if this object is at maximum capacity.
        """

    def remove(self, key: typing.Union[jpype.JInt, int]) -> int:
        """
        Removes the key from the table.
        
        :param jpype.JInt or int key: the key to remove.
        :return: index of the key if the key was found, -1 if
        key did not exist in the table
        :rtype: int
        """

    @property
    def size(self) -> jpype.JInt:
        ...

    @property
    def keys(self) -> jpype.JArray[jpype.JInt]:
        ...

    @property
    def capacity(self) -> jpype.JInt:
        ...


class SetAccumulator(Accumulator[T], typing.Generic[T]):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, set: java.util.Set[T]):
        ...

    def asSet(self) -> java.util.Set[T]:
        ...


class ListenerErrorHandler(java.lang.Object):
    """
    A simple interface that allows listener structures to use different error handling
    """

    class_: typing.ClassVar[java.lang.Class]

    def handleError(self, listener: java.lang.Object, t: java.lang.Throwable):
        """
        Handles the given error
        
        :param java.lang.Object listener: the listener that generated the error
        :param java.lang.Throwable t: the error
        """


class BooleanArray(Array, java.io.Serializable):
    """
    Data structure to set bits to indicate in use.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        """
        Constructor
        """

    def copyDataTo(self, index: typing.Union[jpype.JInt, int], table: DataTable, toIndex: typing.Union[jpype.JInt, int], toCol: typing.Union[jpype.JInt, int]):
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.util.datastruct.Array.copyDataTo(int, ghidra.util.datastruct.DataTable, int, int)`
        """

    def get(self, index: typing.Union[jpype.JInt, int]) -> bool:
        """
        Returns the boolean at the given index
        
        :param jpype.JInt or int index: index into the array
        :return: The boolean value at the given index. A false will
        be return for any non-negative index not initialized to
        another value.
        :rtype: bool
        :raises IndexOutOfBoundsException: if the index is negative
        """

    def getLastNonEmptyIndex(self) -> int:
        """
        Returns the index of the last non-null or non-zero element in the array.
        """

    def put(self, index: typing.Union[jpype.JInt, int], value: typing.Union[jpype.JBoolean, bool]):
        """
        Puts the given boolean value in the boolean array at
        the given index
        
        :param jpype.JInt or int index: Index into the array.
        :param jpype.JBoolean or bool value: value to store
        :raises IndexOutOfBoundsException: if the index is negative
        """

    def remove(self, index: typing.Union[jpype.JInt, int]):
        """
        Sets the value at the given index to 0.
        
        :param jpype.JInt or int index: the index to set to 0.
        """

    @property
    def lastNonEmptyIndex(self) -> jpype.JInt:
        ...


class IntIntHashtable(java.lang.Object):
    """
    Class that implements a hashtable with int keys and int values.
        Because this class uses array of primitives
        to store the information, it serializes very fast.  This implementation uses
        separate chaining to resolve collisions.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        Default constructor creates a table with an initial default capacity.
        """

    @typing.overload
    def __init__(self, capacity: typing.Union[jpype.JInt, int]):
        """
        Constructor creates a table with an initial given capacity.  The capacity
        will be adjusted to the next highest prime in the PRIMES table.
        
        :param jpype.JInt or int capacity: the initial capacity.
        """

    def contains(self, key: typing.Union[jpype.JInt, int]) -> bool:
        """
        Return true if the given key is in the hashtable.
        
        :param jpype.JInt or int key: the key to be tested for existence in the hashtable.
        """

    def get(self, key: typing.Union[jpype.JInt, int]) -> int:
        """
        Returns the value for the given key.
        
        :param jpype.JInt or int key: the key for which to retrieve a value.
        :raises NoValueException: thrown if there is no value for the given key.
        """

    def getKeys(self) -> jpype.JArray[jpype.JInt]:
        """
        Returns an array containing all the int keys.
        """

    def put(self, key: typing.Union[jpype.JInt, int], value: typing.Union[jpype.JInt, int]):
        """
        Adds a key/value pair to the hashtable. If the key is already in the table,
        the old value is replaced with the new value.  If the hashtable is already
        full, the hashtable will attempt to approximately double in size
        (it will use a prime number), and all the current entries will
        be rehashed.
        
        :param jpype.JInt or int key: the key for the new entry.
        :param jpype.JInt or int value: the value for the new entry.
        :raises ArrayIndexOutOfBoundsException: thrown if the maximum capacity is
        reached.
        """

    def remove(self, key: typing.Union[jpype.JInt, int]) -> int:
        """
        Removes a key/value from the hashtable
        
        :param jpype.JInt or int key: the key to remove from the hashtable.
        :return: true if key is found and removed, false otherwise.
        :rtype: int
        :raises NoValueException: 
        :raises NoValueException: thrown if there is no value for the given key.
        """

    def removeAll(self):
        """
        Remove all entries from the hashtable.
        """

    def size(self) -> int:
        """
        Return the number of key/value pairs stored in the hashtable.
        """

    @property
    def keys(self) -> jpype.JArray[jpype.JInt]:
        ...


class CaseInsensitiveDuplicateStringComparator(java.util.Comparator[java.lang.String]):
    """
    Comparator for sorting Strings in a case insensitive way except that case insensitive duplicates
    are then sub-sorted by reverse case so that lower case is before upper case.
    
    Example:   the strings "abc", "bob", "Bob", "zzz" would always sort as shown.  In a normal case 
    insensitive sort, the "bob" and "Bob" order would be arbitrary.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class AbstractWeakValueMap(java.util.Map[K, V], typing.Generic[K, V]):
    """
    Class to provide a map with weak values, backed by a given map
    """

    @typing.type_check_only
    class GeneratedEntry(java.util.Map.Entry[K, V]):
        """
        An entry for the "entrySet" method, since internally, entries are of weak-referenced values.
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class WeakValueRef(java.lang.ref.WeakReference[V], typing.Generic[K, V]):
        """
        A weak value ref that also knows its key in the map.
         
         
        
        Used for processing the reference queue, so we know which keys to remove.
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class WeakValuesCollection(java.util.AbstractCollection[V]):
        """
        Wrapper that provides a Collection view of the values in this map. 
        The collection is backed by the map, so changes to the map are
        reflected in the collection, and vice-versa. This collection has
        weak values and all the magic to handle that is in the :obj:`WeakValuesIterator`
        implementation.
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class WeakValuesIterator(java.util.Iterator[V]):
        """
        Iterator that handles iterating over weak values. This iterator will find the next 
        non-null value by checking each WeakReference to find a value that has not been garbage
        collected. The next non-null value is found during the :meth:`hasNext() <.hasNext>` call and is
        held onto via a strong reference to guarantee that if hasNext returns true, you will get
        a non-null value on the call to :meth:`next() <.next>`.
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    @typing.type_check_only
    class EntryIterator(java.util.Iterator[java.util.Map.Entry[K, V]]):
        """
        This iterator works much like the :obj:`WeakValuesIterator`, except that this iterator
        works on Map Entry objects.
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    @typing.type_check_only
    class EntrySet(java.util.AbstractSet[java.util.Map.Entry[K, V]]):
        """
        Class that provides a :obj:`Set` view of the entry set of this map that is backed live
        by this map. Its main job is to translate from ``Map.Entry<K, WeakValueRef<V>>`` to 
        ``Map.Entry<K,V>``. The heavy lifting is done by the :obj:`EntryIterator`. The super 
        class implements all the rest of the methods by leveraging the iterator. We implement
        contains, remove, and clear as they can be implemented much more efficiently than the 
        default implementation which iterates over all the values to do those operations.
        """

        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def values(self) -> java.util.Collection[V]:
        """
        Returns a :obj:`Collection` view of the values contained in this map.
        The collection is backed by the map, so changes to the map are
        reflected in the collection, and vice-versa. However, since values in this map
        are held via weak references, the collection returned is effectively weak in that
        any time, values may disappear from the collection. To get a static view of the values
        in this map, you should construct another collection class (List, Set, etc.) and pass
        this collection to it in its constructor.
        """


class WeakValueTreeMap(AbstractWeakValueNavigableMap[K, V], typing.Generic[K, V]):
    """
    Class to provide a tree map with weak values.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        Constructs a new weak map
        """

    @typing.overload
    def __init__(self, comparator: java.util.Comparator[K]):
        """
        Constructs a new weak map with keys ordered according to the given comparator
        
        :param java.util.Comparator[K] comparator: the comparator, or ``null`` for the natural ordering
        """


class ShortArray(Array, java.io.Serializable):
    """
    Array of shorts that grows as needed.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        """
        Creates new shortArray
        """

    def copyDataTo(self, index: typing.Union[jpype.JInt, int], table: DataTable, toIndex: typing.Union[jpype.JInt, int], toCol: typing.Union[jpype.JInt, int]):
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.util.datastruct.Array.copyDataTo(int, ghidra.util.datastruct.DataTable, int, int)`
        """

    def get(self, index: typing.Union[jpype.JInt, int]) -> int:
        """
        Returns the short at the given index
        
        :param jpype.JInt or int index: index into the array
        :return: The short value at the given index. A 0 will
        be return for any index not initialized to
        another value.
        :rtype: int
        :raises IndexOutOfBoundsException: if the index is negative
        """

    def getLastNonEmptyIndex(self) -> int:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.util.datastruct.Array.getLastNonEmptyIndex()`
        """

    def put(self, index: typing.Union[jpype.JInt, int], value: typing.Union[jpype.JShort, int]):
        """
        Puts the given short value into the short array at
        the given index
        
        :param jpype.JInt or int index: Index into the array.
        :param jpype.JShort or int value: value to store
        :raises IndexOutOfBoundsException: if the index is negative
        """

    def remove(self, index: typing.Union[jpype.JInt, int]):
        """
        Sets the value at the given index to 0.
        
        :param jpype.JInt or int index: the index to set to 0.
        :raises IndexOutOfBoundsException: if the index is negative
        """

    @property
    def lastNonEmptyIndex(self) -> jpype.JInt:
        ...


@typing.type_check_only
class ThreadUnsafeWeakSet(WeakSet[T], typing.Generic[T]):
    ...
    class_: typing.ClassVar[java.lang.Class]


class Array(java.lang.Object):
    """
    Base interface for Defining methods for managing a "virtual" array of some data type.
    Any access of an Array with an index that has never been set will return 0 
    (or something like that depending on the data type)
    """

    class_: typing.ClassVar[java.lang.Class]

    def copyDataTo(self, index: typing.Union[jpype.JInt, int], table: DataTable, toIndex: typing.Union[jpype.JInt, int], toCol: typing.Union[jpype.JInt, int]):
        """
        Copies the underlying value for this array at the given index to the
        data table at the given index and column.  The data type at the column in
        the data table must be the same as the data in this array.
        
        :param jpype.JInt or int index: index into this array to copy the value from.
        :param DataTable table: the data table object to copy the data to.
        :param jpype.JInt or int toIndex: the index into the destination data table to copy the
        value.
        :param jpype.JInt or int toCol: the data table column to store the value.  Must be the same
        type as this array.
        """

    def getLastNonEmptyIndex(self) -> int:
        """
        Returns the index of the last non-null or non-zero element in the array.
        """

    def remove(self, index: typing.Union[jpype.JInt, int]):
        """
        Removes the value at that index.  If the array is of primitive type (int, short, etc),
        then "removing" the value is equivilent to setting the value to 0;
        
        :param jpype.JInt or int index: int index into the array to remove.
        """

    @property
    def lastNonEmptyIndex(self) -> jpype.JInt:
        ...


class BitTree(ShortKeySet, java.io.Serializable):
    """
    The BitTree class maintains a set of ordered keys between the values of
    0 and N.  It can quickly (O(log(n))) add keys, remove keys, find the next key
    greater than some value , and find the prev key less than some value.  It can
    determine if a key is in the set in O(1) time. This implementation has been
    limited to short keys so that it can implement the ShortKeySet interface.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, maxKey: typing.Union[jpype.JShort, int]):
        """
        The BitTree constructor takes the maximum key value. The legal
        keys for this set range from 0 to maxKey.
        
        :param jpype.JShort or int maxKey: the maximum key that will ever be put into this BitTree.
        """

    @typing.overload
    def __init__(self, maxKey: typing.Union[jpype.JShort, int], isFull: typing.Union[jpype.JBoolean, bool]):
        """
        The BitTree constructor takes the maximum key value. The legal
        keys for this set range from 0 to maxKey.
        
        :param jpype.JShort or int maxKey: the maximum key value.
        :param jpype.JBoolean or bool isFull: if true, then the set is initilized to contain all legal keys.
        """

    def containsKey(self, key: typing.Union[jpype.JShort, int]) -> bool:
        """
        Determines if a given key is in the set.
        
        :param jpype.JShort or int key: the key to check if it is in this set.
        :return: true if the key is in the set.
        :rtype: bool
        """

    def getFirst(self) -> int:
        """
        Returns the first (lowest) key in the set.
        """

    def getLast(self) -> int:
        """
        Returns the last (highest) key in the set.
        """

    def getNext(self, key: typing.Union[jpype.JShort, int]) -> int:
        """
        finds the next key that is in the set that is greater than the given key.
        
        :param jpype.JShort or int key: from which to search forward.
        :return: the next key greater than the given key or -1 if there is no key
        greater than the given key.
        :rtype: int
        :raises IndexOutOfBoundsException: if the given key is not
        in the range [0, size-1].
        """

    def getPrevious(self, key: typing.Union[jpype.JShort, int]) -> int:
        """
        Finds the next key that is in the set that is less than the given key.
        
        :param jpype.JShort or int key: the key to search before.
        :return: the next key less than the given key or -1 if there is no key
        less than the given key.
        :rtype: int
        :raises IndexOutOfBoundsException: if the given key is not
        in the range [0, size-1].
        """

    def isEmpty(self) -> bool:
        """
        Checks if the set is empty.
        
        :return: true if the set is empty.
        :rtype: bool
        """

    def put(self, key: typing.Union[jpype.JShort, int]):
        """
        Adds a key to the set.
        
        :param jpype.JShort or int key: to be added.
        :raises IndexOutOfBoundsException: if the given key is not
        in the range [0, size-1].
        """

    def remove(self, key: typing.Union[jpype.JShort, int]) -> bool:
        """
        Removes the key from the set.
        
        :param jpype.JShort or int key: The key to remove.
        :raises IndexOutOfBoundsException: if the given key is not
        in the range [0, size-1].
        """

    def removeAll(self):
        """
        Removes all keys from the set.
        """

    def size(self) -> int:
        """
        Returns the number of keys currently in the set.
        """

    @property
    def next(self) -> jpype.JShort:
        ...

    @property
    def previous(self) -> jpype.JShort:
        ...

    @property
    def last(self) -> jpype.JShort:
        ...

    @property
    def first(self) -> jpype.JShort:
        ...

    @property
    def empty(self) -> jpype.JBoolean:
        ...


@typing.type_check_only
class CopyOnReadWeakSet(WeakSet[T], typing.Generic[T]):
    """
    A copy on read set that will create a copy of its internal data for iteration operations.  This
    allows clients to avoid concurrency issue by allowing mutates during reads.  All operations
    of this class are synchronized to allow clients to use non-iterative methods without the need
    for a copy operation.
    """

    class_: typing.ClassVar[java.lang.Class]


class Stack(java.lang.Iterable[E], typing.Generic[E]):
    """
    
    
    The Stack class represents a last-in-first-out (LIFO) stack of objects.
    It extends class ArrayList with five operations that allow an array list
    to be treated as a stack. The usual push and pop operations are provided,
    as well as a method to peek at the top item on the stack, a
    method to test for whether the stack is empty, and a method to search
    the stack for an item and discover how far it is from the top.
     
    
     
    
    When a stack is first created, it contains no items.
     
    
     
    
    **Note: This implementation is not synchronized!**
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        Creates an empty Stack.
        """

    @typing.overload
    def __init__(self, initialCapacity: typing.Union[jpype.JInt, int]):
        """
        Creates an empty Stack with specified capacity.
        
        :param jpype.JInt or int initialCapacity: the initial capacity.
        """

    @typing.overload
    def __init__(self, stack: Stack[E]):
        """
        Copy Constructor.
        Creates a new stack using the items of the given stack.
        Only a shallow copy is performed.
        
        :param Stack[E] stack: the stack to copy
        """

    def add(self, item: E):
        """
        Appends the given item to the top of the stack.
        
        :param E item: the new top of the stack
        """

    def clear(self):
        """
        Clears the stack. All items will be removed.
        """

    def get(self, depth: typing.Union[jpype.JInt, int]) -> E:
        """
        Returns the element at the specified depth in this stack.
        0 indicates the bottom of the stack.
        size()-1 indicates the top of the stack.
        
        :param jpype.JInt or int depth: the depth in the stack.
        :return: the element at the specified depth in this stack
        :rtype: E
        """

    def isEmpty(self) -> bool:
        """
        Tests if this stack is empty.
        """

    def iterator(self) -> java.util.Iterator[E]:
        """
        Returns an iterator over the items of the stack.
        The iterator starts from the bottom of the stack.
        
        :return: an iterator over the items of the stack
        :rtype: java.util.Iterator[E]
        """

    def peek(self) -> E:
        """
        Looks at the object at the top of this stack without removing it from the stack.
        """

    def pop(self) -> E:
        """
        Removes the object at the top of this stack and returns that object as the value of this function.
        """

    def push(self, item: E) -> E:
        """
        Pushes an item onto the top of this stack.
        
        :param E item: the object to push onto the stack.
        """

    def search(self, o: E) -> int:
        """
        Returns the position where an object is on this stack.
        
        :param E o: the object to search for.
        """

    def size(self) -> int:
        """
        Returns the number of elements in this stack.
        
        :return: the number of elements in this stack
        :rtype: int
        """

    def stream(self) -> java.util.stream.Stream[E]:
        """
        Returns a stream over this collection.
        
        :return: a stream over this collection.
        :rtype: java.util.stream.Stream[E]
        """

    @property
    def empty(self) -> jpype.JBoolean:
        ...


class WeakSet(java.util.Set[T], typing.Generic[T]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def add(self, t: T) -> bool:
        """
        Add the given object to the set
        
        :param T t: the object to add
        """

    def clear(self):
        """
        Remove all elements from this data structure
        """

    def contains(self, t: java.lang.Object) -> bool:
        """
        Returns true if the given object is in this data structure
        
        :param java.lang.Object t: the object
        :return: true if the given object is in this data structure
        :rtype: bool
        """

    def isEmpty(self) -> bool:
        """
        Return whether this data structure is empty
        
        :return: whether this data structure is empty
        :rtype: bool
        """

    def remove(self, t: java.lang.Object) -> bool:
        """
        Remove the given object from the data structure
        
        :param java.lang.Object t: the object to remove
        """

    def size(self) -> int:
        """
        Return the number of objects contained within this data structure
        
        :return: the size
        :rtype: int
        """

    def stream(self) -> java.util.stream.Stream[T]:
        """
        Returns a stream of the values of this collection.
        
        :return: a stream of the values of this collection.
        :rtype: java.util.stream.Stream[T]
        """

    def values(self) -> java.util.Collection[T]:
        """
        Returns a Collection view of this set.  The returned Collection is backed by this set.
        
        :return: a Collection view of this set.  The returned Collection is backed by this set.
        :rtype: java.util.Collection[T]
        """

    @property
    def empty(self) -> jpype.JBoolean:
        ...


class ValueRange(java.lang.Comparable[ValueRange]):
    """
    Associates an integer value with a numeric range.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, start: typing.Union[jpype.JLong, int], end: typing.Union[jpype.JLong, int], value: typing.Union[jpype.JInt, int]):
        """
        Constructor for numeric range with an associated value.
        
        :param jpype.JLong or int start: beginning of the range
        :param jpype.JLong or int end: end of the range
        :param jpype.JInt or int value: the value to associate with the range.
        """

    def contains(self, index: typing.Union[jpype.JLong, int]) -> bool:
        """
        Determines whether or not the indicated index is in the range.
        
        :param jpype.JLong or int index: the index to check
        :return: true if the index is in this range.
        :rtype: bool
        """

    def getEnd(self) -> int:
        """
        Returns the end of the range.
        """

    def getStart(self) -> int:
        """
        Returns the beginning of the range.
        """

    def getValue(self) -> int:
        """
        Returns the value associated with the range.
        """

    @property
    def start(self) -> jpype.JLong:
        ...

    @property
    def end(self) -> jpype.JLong:
        ...

    @property
    def value(self) -> jpype.JInt:
        ...


class IndexRange(java.lang.Object):
    """
    Class for holding a begin and end index.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, start: typing.Union[jpype.JLong, int], end: typing.Union[jpype.JLong, int]):
        """
        Constructor for IndexRange.
        
        :param jpype.JLong or int start: the starting index of the range.
        :param jpype.JLong or int end: the ending index of the range.
        """

    def getEnd(self) -> int:
        """
        Returns the ending index of the range.
        
        :return: the ending index of the range.
        :rtype: int
        """

    def getStart(self) -> int:
        """
        Returns the starting index of the range.
        
        :return: the starting index of the range.
        :rtype: int
        """

    @property
    def start(self) -> jpype.JLong:
        ...

    @property
    def end(self) -> jpype.JLong:
        ...


class IntObjectHashtable(java.io.Serializable, typing.Generic[T]):
    """
    Class that implements a hashtable with int keys and Object values.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        Default constructor creates a table with an initial default capacity.
        """

    @typing.overload
    def __init__(self, capacity: typing.Union[jpype.JInt, int]):
        """
        Constructor creates a table with an initial given capacity.  The capacity
        will be adjusted to the next highest prime in the PRIMES table.
        
        :param jpype.JInt or int capacity: the initial capacity.
        """

    def contains(self, key: typing.Union[jpype.JInt, int]) -> bool:
        """
        Return true if the given key is in the hashtable.
        
        :param jpype.JInt or int key: the key whose presence in this map is to be tested.
        """

    def get(self, key: typing.Union[jpype.JInt, int]) -> T:
        """
        Returns the value for the given key.
        
        :param jpype.JInt or int key: the key whose associated value is to be returned.
        """

    def getKeys(self) -> jpype.JArray[jpype.JInt]:
        """
        Returns an array containing all the int keys.
        """

    def put(self, key: typing.Union[jpype.JInt, int], value: T):
        """
        Adds a key/value pair to the hashtable. If the key is already in the table,
        the old value is replaced with the new value.  If the hashtable is already
        full, the hashtable will attempt to approximately double in size
        (it will use a prime number), and all the current entries will
        be rehashed.
        
        :param jpype.JInt or int key: the key to associate with the given value.
        :param T value: the value to associate with the given key.
        :raises ArrayIndexOutOfBoundsException: thrown if the maximum capacity is
        reached.
        """

    def remove(self, key: typing.Union[jpype.JInt, int]) -> bool:
        """
        Removes a key from the hashtable
        
        :param jpype.JInt or int key: key to be removed from the hashtable.
        :return: true if key is found and removed, false otherwise.
        :rtype: bool
        """

    def removeAll(self):
        """
        Remove all entries from the hashtable.
        """

    def size(self) -> int:
        """
        Return the number of key/value pairs stored in the hashtable.
        """

    @property
    def keys(self) -> jpype.JArray[jpype.JInt]:
        ...


class AccumulatorSizeException(java.lang.RuntimeException):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, maxSize: typing.Union[jpype.JInt, int]):
        ...

    def getMaxSize(self) -> int:
        ...

    @property
    def maxSize(self) -> jpype.JInt:
        ...


class RedBlackEntry(java.util.Map.Entry[K, V], typing.Generic[K, V]):

    @typing.type_check_only
    class NodeColor(java.lang.Enum[RedBlackEntry.NodeColor]):

        class_: typing.ClassVar[java.lang.Class]
        RED: typing.Final[RedBlackEntry.NodeColor]
        BLACK: typing.Final[RedBlackEntry.NodeColor]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> RedBlackEntry.NodeColor:
            ...

        @staticmethod
        def values() -> jpype.JArray[RedBlackEntry.NodeColor]:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def getPredecessor(self) -> RedBlackEntry[K, V]:
        ...

    def getSuccessor(self) -> RedBlackEntry[K, V]:
        ...

    def isDisposed(self) -> bool:
        ...

    @property
    def successor(self) -> RedBlackEntry[K, V]:
        ...

    @property
    def disposed(self) -> jpype.JBoolean:
        ...

    @property
    def predecessor(self) -> RedBlackEntry[K, V]:
        ...


class RedBlackKeySet(ShortKeySet, java.io.Serializable):
    """
    A RedBlack Tree implementation of the ShortKeySet interface.
    """

    @typing.type_check_only
    class RBNode(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]
    NODESIZE: typing.Final = 15
    """
    the number of bytes in a RedBlackKeySet node
    """


    def __init__(self, n: typing.Union[jpype.JShort, int]):
        """
        Creates a new RedBlackKeySet that can store keys between 0 and n.
        
        :param jpype.JShort or int n: the maximum key for this set.
        """

    def containsKey(self, key: typing.Union[jpype.JShort, int]) -> bool:
        """
        Returns true if the key is in the set.
        
        :param jpype.JShort or int key: the key whose presence is to be tested.
        :raises IndexOutOfBoundsException: thrown if the given key is not
        in the range [0, maxKey].
        """

    def getFirst(self) -> int:
        """
        Returns the first key in this set.
        """

    def getLast(self) -> int:
        """
        Returns the last key in this set.
        """

    def getNext(self, key: typing.Union[jpype.JShort, int]) -> int:
        """
        Returns the smallest key in the set that is greater than the given key.  Returns
        -1 if there are no keys greater than the given key.
        
        :param jpype.JShort or int key: the key for which to find the next key after.
        :raises IndexOutOfBoundsException: thrown if the given key is not
        in the range [0, maxKey].
        """

    def getPrevious(self, key: typing.Union[jpype.JShort, int]) -> int:
        """
        Returns the largest key in the set that is less than the given key. Returns -1 if
        there are not keys less than the given key.
        
        :param jpype.JShort or int key: the key for which to find the previous key.
        :raises IndexOutOfBoundsException: thrown if the given key is not
        in the range [0, maxKey].
        """

    def isEmpty(self) -> bool:
        """
        Test if the set is empty.
        
        :return: true if the set is empty.
        :rtype: bool
        """

    def put(self, key: typing.Union[jpype.JShort, int]):
        """
        Adds the given key to the set.
        
        :param jpype.JShort or int key: the key to add to the set.
        :raises IndexOutOfBoundsException: thrown if the given key is not
        in the range [0, maxKey].
        """

    def remove(self, key: typing.Union[jpype.JShort, int]) -> bool:
        """
        Removes the given key from the set.
        
        :param jpype.JShort or int key: the key to remove from the set.
        :raises IndexOutOfBoundsException: thrown if the given key is not
        in the range [0, maxKey].
        """

    def removeAll(self):
        """
        Removes all keys from the set.
        """

    def size(self) -> int:
        """
        Returns the number keys in this set.
        """

    @property
    def next(self) -> jpype.JShort:
        ...

    @property
    def previous(self) -> jpype.JShort:
        ...

    @property
    def last(self) -> jpype.JShort:
        ...

    @property
    def first(self) -> jpype.JShort:
        ...

    @property
    def empty(self) -> jpype.JBoolean:
        ...


class ListAccumulator(Accumulator[T], typing.Generic[T]):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, list: java.util.List[T]):
        ...

    def asList(self) -> java.util.List[T]:
        ...


class LongArrayArray(Array, java.io.Serializable):
    """
    Array of long[] that grows as needed.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        """
        Creates new LongArrayArray
        """

    def copyDataTo(self, index: typing.Union[jpype.JInt, int], table: DataTable, toIndex: typing.Union[jpype.JInt, int], toCol: typing.Union[jpype.JInt, int]):
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.util.datastruct.Array.copyDataTo(int, ghidra.util.datastruct.DataTable, int, int)`
        """

    def get(self, index: typing.Union[jpype.JInt, int]) -> jpype.JArray[jpype.JLong]:
        """
        Returns the long array at the given index in the LongArrayArray.
        
        :param jpype.JInt or int index: index into the array
        :return: The long array value at the given index. An empty array will
        be returned for any index not initialized to
        another value.
        :rtype: jpype.JArray[jpype.JLong]
        :raises IndexOutOfBoundsException: if the index is negative
        """

    def getLastNonEmptyIndex(self) -> int:
        """
        Returns the index of the last non-null or non-zero element in the array.
        """

    def put(self, index: typing.Union[jpype.JInt, int], value: jpype.JArray[jpype.JLong]):
        """
        Puts the given long array in the long array array at
        the given index
        
        :param jpype.JInt or int index: Index into the array.
        :param jpype.JArray[jpype.JLong] value: value to store
        :raises IndexOutOfBoundsException: if the index is negative
        """

    def remove(self, index: typing.Union[jpype.JInt, int]):
        """
        Removes the long array at the given index
        
        :param jpype.JInt or int index: index of the array to be removed
        :raises IndexOutOfBoundsException: if the index is negative
        """

    @property
    def lastNonEmptyIndex(self) -> jpype.JInt:
        ...


class DoubleArrayArray(Array, java.io.Serializable):
    """
    Array of double[] that grows as needed.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        """
        Creates new doubleArrayArray
        """

    def copyDataTo(self, index: typing.Union[jpype.JInt, int], table: DataTable, toIndex: typing.Union[jpype.JInt, int], toCol: typing.Union[jpype.JInt, int]):
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.util.datastruct.Array.copyDataTo(int, DataTable, int, int)`
        """

    def get(self, index: typing.Union[jpype.JInt, int]) -> jpype.JArray[jpype.JDouble]:
        """
        Returns the double at the given index
        
        :param jpype.JInt or int index: index into the array
        :return: The double array at the given index. An empty array will
        be returned for any index not initialized to
        another value.
        :rtype: jpype.JArray[jpype.JDouble]
        """

    def getLastNonEmptyIndex(self) -> int:
        """
        Returns the index of the last non-null or non-zero element in the array.
        """

    def put(self, index: typing.Union[jpype.JInt, int], value: jpype.JArray[jpype.JDouble]):
        """
        Puts the given double value in the double array at
        the given index
        
        :param jpype.JInt or int index: Index into the array.
        :param jpype.JArray[jpype.JDouble] value: value to store
        :raises IndexOutOfBoundsException: if the index is negative
        """

    def remove(self, index: typing.Union[jpype.JInt, int]):
        """
        Removes the array at the given index
        
        :param jpype.JInt or int index: index of the array to be removed
        """

    @property
    def lastNonEmptyIndex(self) -> jpype.JInt:
        ...


@typing.type_check_only
class ThreadSafeListenerStorage(java.lang.Object, typing.Generic[T]):
    """
    A very specific data structure that provides 'copy on write' behavior while the client is
    iterating the elements.
     
    
    This class is meant for a very narrow and specific use case that includes: having a relatively
    small number of listeners and the need for only basic adding, removing and iterating.
     
    
    This class will create a new copy of its internal storage for any write operation, but only if
    that happens while the elements in this class are being iterated.  This avoids unnecessary
    copying.
    """

    @typing.type_check_only
    class WeakSetFactory(generic.cache.Factory[java.util.Set[T], java.util.Set[T]], typing.Generic[T]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class StrongSetFactory(generic.cache.Factory[java.util.Set[T], java.util.Set[T]], typing.Generic[T]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]


class ShortStringHashtable(java.io.Serializable):
    """
    Class that implements a hashtable with short keys and String values.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        Default constructor creates a table with an initial default capacity.
        """

    @typing.overload
    def __init__(self, capacity: typing.Union[jpype.JShort, int]):
        """
        Constructor creates a table with an initial given capacity.  The capacity
        will be adjusted to the next highest prime in the PRIMES table.
        
        :param jpype.JShort or int capacity: the initial capacity.
        """

    def contains(self, key: typing.Union[jpype.JShort, int]) -> bool:
        """
        Return true if the given key is in the hashtable.
        
        :param jpype.JShort or int key: the key whose presence is this map is to be tested.
        """

    def get(self, key: typing.Union[jpype.JShort, int]) -> str:
        """
        Returns the value for the given key.
        
        :param jpype.JShort or int key: the key whose associated value is to be returned.
        """

    def getKeys(self) -> jpype.JArray[jpype.JShort]:
        """
        Returns an array containing all the short keys.
        """

    def put(self, key: typing.Union[jpype.JShort, int], value: typing.Union[java.lang.String, str]):
        """
        Adds a key/value pair to the hashtable. If the key is already in the table,
        the old value is replaced with the new value.  If the hashtable is already
        full, the hashtable will attempt to approximately double in size
        (it will use a prime number), and all the current entries will
        be rehashed.
        
        :param jpype.JShort or int key: the key to associate with the given value.
        :param java.lang.String or str value: the value to associate with the given key.
        :raises ArrayIndexOutOfBoundsException: thrown if the maximum capacity is
        reached.
        """

    def remove(self, key: typing.Union[jpype.JShort, int]) -> bool:
        """
        Removes a key from the hashtable
        
        :param jpype.JShort or int key: key to be removed from the hashtable.
        :return: true if key is found and removed, false otherwise.
        :rtype: bool
        """

    def removeAll(self):
        """
        Remove all entries from the hashtable.
        """

    def size(self) -> int:
        """
        Return the number of key/value pairs stored in the hashtable.
        """

    @property
    def keys(self) -> jpype.JArray[jpype.JShort]:
        ...


class DataTable(java.io.Serializable):
    """
    Table for managing rows and columns of data.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        """
        Creates a new DataTable.
        """

    def copyRowTo(self, row: typing.Union[jpype.JInt, int], table: DataTable, toRow: typing.Union[jpype.JInt, int]):
        """
        Copy one row to another row.
        
        :param jpype.JInt or int row: source row
        :param DataTable table: table containing the data
        :param jpype.JInt or int toRow: destination row
        """

    def getBoolean(self, row: typing.Union[jpype.JInt, int], col: typing.Union[jpype.JInt, int]) -> bool:
        """
        Returns the boolean at the given row, column.
        
        :param jpype.JInt or int row: the row in the table
        :param jpype.JInt or int col: the column in the table (field num)
        :return: the boolean value in the table
        :rtype: bool
        """

    def getByte(self, row: typing.Union[jpype.JInt, int], col: typing.Union[jpype.JInt, int]) -> int:
        """
        Returns the byte at the given row, column.
        
        :param jpype.JInt or int row: the row in the table
        :param jpype.JInt or int col: the column in the table (field num)
        :return: the byte value in the table
        :rtype: int
        """

    def getByteArray(self, row: typing.Union[jpype.JInt, int], col: typing.Union[jpype.JInt, int]) -> jpype.JArray[jpype.JByte]:
        """
        Returns the byte array at the given row, column.
        
        :param jpype.JInt or int row: The row into the table (specifies which object)
        :param jpype.JInt or int col: The column of the table.  (specifies which field)
        :return: the int value.
        :rtype: jpype.JArray[jpype.JByte]
        """

    def getDouble(self, row: typing.Union[jpype.JInt, int], col: typing.Union[jpype.JInt, int]) -> float:
        """
        Returns the double at the given row, column.
        
        :param jpype.JInt or int row: The row into the table (specifies which object)
        :param jpype.JInt or int col: The column of the table.  (specifies which field)
        :return: the double value.
        :rtype: float
        """

    def getDoubleArray(self, row: typing.Union[jpype.JInt, int], col: typing.Union[jpype.JInt, int]) -> jpype.JArray[jpype.JDouble]:
        """
        Returns the double array at the given row, column.
        
        :param jpype.JInt or int row: The row into the table (specifies which object)
        :param jpype.JInt or int col: The column of the table.  (specifies which field)
        :return: the int value.
        :rtype: jpype.JArray[jpype.JDouble]
        """

    def getFloat(self, row: typing.Union[jpype.JInt, int], col: typing.Union[jpype.JInt, int]) -> float:
        """
        Returns the float at the given row, column.
        
        :param jpype.JInt or int row: The row into the table (specifies which object)
        :param jpype.JInt or int col: The column of the table.  (specifies which field)
        :return: the float value.
        :rtype: float
        """

    def getFloatArray(self, row: typing.Union[jpype.JInt, int], col: typing.Union[jpype.JInt, int]) -> jpype.JArray[jpype.JFloat]:
        """
        Returns the float array at the given row, column.
        
        :param jpype.JInt or int row: The row into the table (specifies which object)
        :param jpype.JInt or int col: The column of the table.  (specifies which field)
        :return: the float[] value.
        :rtype: jpype.JArray[jpype.JFloat]
        """

    def getInt(self, row: typing.Union[jpype.JInt, int], col: typing.Union[jpype.JInt, int]) -> int:
        """
        Returns the int at the given row, column.
        
        :param jpype.JInt or int row: The row into the table (specifies which object)
        :param jpype.JInt or int col: The column of the table.  (specifies which field)
        :return: the int value.
        :rtype: int
        """

    def getIntArray(self, row: typing.Union[jpype.JInt, int], col: typing.Union[jpype.JInt, int]) -> jpype.JArray[jpype.JInt]:
        """
        Returns the int array at the given row, column.
        
        :param jpype.JInt or int row: The row into the table (specifies which object)
        :param jpype.JInt or int col: The column of the table.  (specifies which field)
        :return: the int value.
        :rtype: jpype.JArray[jpype.JInt]
        """

    def getLong(self, row: typing.Union[jpype.JInt, int], col: typing.Union[jpype.JInt, int]) -> int:
        """
        Returns the long at the given row, column.
        
        :param jpype.JInt or int row: The row into the table (specifies which object)
        :param jpype.JInt or int col: The column of the table.  (specifies which field)
        :return: the long value.
        :rtype: int
        """

    def getLongArray(self, row: typing.Union[jpype.JInt, int], col: typing.Union[jpype.JInt, int]) -> jpype.JArray[jpype.JLong]:
        """
        Returns the long array at the given row, column.
        
        :param jpype.JInt or int row: The row into the table (specifies which object)
        :param jpype.JInt or int col: The column of the table.  (specifies which field)
        :return: the long[] value.
        :rtype: jpype.JArray[jpype.JLong]
        """

    def getObject(self, row: typing.Union[jpype.JInt, int], col: typing.Union[jpype.JInt, int]) -> java.lang.Object:
        """
        Returns the Object at the given row, column.
        
        :param jpype.JInt or int row: The row into the table (specifies which object)
        :param jpype.JInt or int col: The column of the table.  (specifies which field)
        :return: the Object value.
        :rtype: java.lang.Object
        """

    def getShort(self, row: typing.Union[jpype.JInt, int], col: typing.Union[jpype.JInt, int]) -> int:
        """
        Returns the short at the given row, column.
        
        :param jpype.JInt or int row: The row into the table (specifies which object)
        :param jpype.JInt or int col: The column of the table.  (specifies which field)
        :return: the short value.
        :rtype: int
        """

    def getShortArray(self, row: typing.Union[jpype.JInt, int], col: typing.Union[jpype.JInt, int]) -> jpype.JArray[jpype.JShort]:
        """
        Returns the short array at the given row, column.
        
        :param jpype.JInt or int row: The row into the table (specifies which object)
        :param jpype.JInt or int col: The column of the table.  (specifies which field)
        :return: the int value.
        :rtype: jpype.JArray[jpype.JShort]
        """

    def getString(self, row: typing.Union[jpype.JInt, int], col: typing.Union[jpype.JInt, int]) -> str:
        """
        Returns the string at the given row, column.
        
        :param jpype.JInt or int row: The row into the table (specifies which object)
        :param jpype.JInt or int col: The column of the table.  (specifies which field)
        :return: the int value.
        :rtype: str
        """

    def getStringArray(self, row: typing.Union[jpype.JInt, int], col: typing.Union[jpype.JInt, int]) -> jpype.JArray[java.lang.String]:
        """
        Returns the String array at the given row, column.
        
        :param jpype.JInt or int row: The row into the table (specifies which object)
        :param jpype.JInt or int col: The column of the table.  (specifies which field)
        :return: the String[] value.
        :rtype: jpype.JArray[java.lang.String]
        """

    def putBoolean(self, row: typing.Union[jpype.JInt, int], col: typing.Union[jpype.JInt, int], value: typing.Union[jpype.JBoolean, bool]):
        """
        Stores a boolean value in the table at the given row
        and column.  Note - all values in a given column must be
        of the same type.
        
        :param jpype.JInt or int row: The row into the table (specifies which object)
        :param jpype.JInt or int col: The column of the table.  (specifies which field)
        :param jpype.JBoolean or bool value: The value to store.
        """

    def putByte(self, row: typing.Union[jpype.JInt, int], col: typing.Union[jpype.JInt, int], value: typing.Union[jpype.JByte, int]):
        """
        Stores a byte value in the table at the given row
        and column.  Note - all values in a given column must be
        of the same type.
        
        :param jpype.JInt or int row: The row into the table (specifies which object)
        :param jpype.JInt or int col: The column of the table.  (specifies which field)
        :param jpype.JByte or int value: The value to store.
        """

    def putByteArray(self, row: typing.Union[jpype.JInt, int], col: typing.Union[jpype.JInt, int], value: jpype.JArray[jpype.JByte]):
        """
        Stores an byte array in the table at the given row
        and column.  Note - all values in a given column must be
        of the same type.
        
        :param jpype.JInt or int row: The row into the table (specifies which object)
        :param jpype.JInt or int col: The column of the table.  (specifies which field)
        :param jpype.JArray[jpype.JByte] value: The value to store.
        """

    def putDouble(self, row: typing.Union[jpype.JInt, int], col: typing.Union[jpype.JInt, int], value: typing.Union[jpype.JDouble, float]):
        """
        Stores a double value in the table at the given row
        and column.  Note - all values in a given column must be
        of the same type.
        
        :param jpype.JInt or int row: The row into the table (specifies which object)
        :param jpype.JInt or int col: The column of the table.  (specifies which field)
        :param jpype.JDouble or float value: The value to store.
        """

    def putDoubleArray(self, row: typing.Union[jpype.JInt, int], col: typing.Union[jpype.JInt, int], value: jpype.JArray[jpype.JDouble]):
        """
        Stores a double array in the table at the given row
        and column.  Note - all values in a given column must be
        of the same type.
        
        :param jpype.JInt or int row: The row into the table (specifies which object)
        :param jpype.JInt or int col: The column of the table.  (specifies which field)
        :param jpype.JArray[jpype.JDouble] value: The value to store.
        """

    def putFloat(self, row: typing.Union[jpype.JInt, int], col: typing.Union[jpype.JInt, int], value: typing.Union[jpype.JFloat, float]):
        """
        Stores a float value in the table at the given row
        and column.  Note - all values in a given column must be
        of the same type.
        
        :param jpype.JInt or int row: The row into the table (specifies which object)
        :param jpype.JInt or int col: The column of the table.  (specifies which field)
        :param jpype.JFloat or float value: The value to store.
        """

    def putFloatArray(self, row: typing.Union[jpype.JInt, int], col: typing.Union[jpype.JInt, int], value: jpype.JArray[jpype.JFloat]):
        """
        Stores a float array in the table at the given row
        and column.  Note - all values in a given column must be
        of the same type.
        
        :param jpype.JInt or int row: The row into the table (specifies which object)
        :param jpype.JInt or int col: The column of the table.  (specifies which field)
        :param jpype.JArray[jpype.JFloat] value: The value to store.
        """

    def putInt(self, row: typing.Union[jpype.JInt, int], col: typing.Union[jpype.JInt, int], value: typing.Union[jpype.JInt, int]):
        """
        Stores an int value in the table at the given row
        and column.  Note - all values in a given column must be
        of the same type.
        
        :param jpype.JInt or int row: The row into the table (specifies which object)
        :param jpype.JInt or int col: The column of the table.  (specifies which field)
        :param jpype.JInt or int value: The value to store.
        """

    def putIntArray(self, row: typing.Union[jpype.JInt, int], col: typing.Union[jpype.JInt, int], value: jpype.JArray[jpype.JInt]):
        """
        Stores an int array in the table at the given row
        and column.  Note - all values in a given column must be
        of the same type.
        
        :param jpype.JInt or int row: The row into the table (specifies which object)
        :param jpype.JInt or int col: The column of the table.  (specifies which field)
        :param jpype.JArray[jpype.JInt] value: The value to store.
        """

    def putLong(self, row: typing.Union[jpype.JInt, int], col: typing.Union[jpype.JInt, int], value: typing.Union[jpype.JLong, int]):
        """
        Stores a long value in the table at the given row
        and column.  Note - all values in a given column must be
        of the same type.
        
        :param jpype.JInt or int row: The row into the table (specifies which object)
        :param jpype.JInt or int col: The column of the table.  (specifies which field)
        :param jpype.JLong or int value: The value to store.
        """

    def putLongArray(self, row: typing.Union[jpype.JInt, int], col: typing.Union[jpype.JInt, int], value: jpype.JArray[jpype.JLong]):
        """
        Stores an long array in the table at the given row
        and column.  Note - all values in a given column must be
        of the same type.
        
        :param jpype.JInt or int row: The row into the table (specifies which object)
        :param jpype.JInt or int col: The column of the table.  (specifies which field)
        :param jpype.JArray[jpype.JLong] value: The value to store.
        """

    def putObject(self, row: typing.Union[jpype.JInt, int], col: typing.Union[jpype.JInt, int], value: java.lang.Object):
        """
        Stores an Object in the table at the given row
        and column.  Note - all values in a given column must be
        of the same type.
        
        :param jpype.JInt or int row: The row into the table (specifies which object)
        :param jpype.JInt or int col: The column of the table.  (specifies which field)
        :param java.lang.Object value: The value to store.
        """

    def putShort(self, row: typing.Union[jpype.JInt, int], col: typing.Union[jpype.JInt, int], value: typing.Union[jpype.JShort, int]):
        """
        Stores a short value in the table at the given row
        and column.  Note - all values in a given column must be
        of the same type.
        
        :param jpype.JInt or int row: The row into the table (specifies which object)
        :param jpype.JInt or int col: The column of the table.  (specifies which field)
        :param jpype.JShort or int value: The value to store.
        """

    def putShortArray(self, row: typing.Union[jpype.JInt, int], col: typing.Union[jpype.JInt, int], value: jpype.JArray[jpype.JShort]):
        """
        Stores an short array in the table at the given row
        and column.  Note - all values in a given column must be
        of the same type.
        
        :param jpype.JInt or int row: The row into the table (specifies which object)
        :param jpype.JInt or int col: The column of the table.  (specifies which field)
        :param jpype.JArray[jpype.JShort] value: The value to store.
        """

    def putString(self, row: typing.Union[jpype.JInt, int], col: typing.Union[jpype.JInt, int], value: typing.Union[java.lang.String, str]):
        """
        Stores a String in the table at the given row
        and column.  Note - all values in a given column must be
        of the same type.
        
        :param jpype.JInt or int row: The row into the table (specifies which object)
        :param jpype.JInt or int col: The column of the table.  (specifies which field)
        :param java.lang.String or str value: The value to store.
        """

    def putStringArray(self, row: typing.Union[jpype.JInt, int], col: typing.Union[jpype.JInt, int], value: jpype.JArray[java.lang.String]):
        """
        Stores a String array in the table at the given row
        and column.  Note - all values in a given column must be
        of the same type.
        
        :param jpype.JInt or int row: The row into the table (specifies which object)
        :param jpype.JInt or int col: The column of the table.  (specifies which field)
        :param jpype.JArray[java.lang.String] value: The value to store.
        """

    def removeRow(self, row: typing.Union[jpype.JInt, int]):
        """
        Removes the given row from the table.
        
        :param jpype.JInt or int row: The row to be removed
        """


class FilteringAccumulatorWrapper(Accumulator[T], typing.Generic[T]):
    """
    A class that allows clients to wrap a given accumulator, only adding elements that pass the
    given filter.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, accumulator: Accumulator[T], passesFilterPredicate: java.util.function.Predicate[T]):
        """
        Constructor.
        
        :param Accumulator[T] accumulator: the accumulator to pass items to
        :param java.util.function.Predicate[T] passesFilterPredicate: the predicate that will return true for items that should be
                allowed to pass
        """


class FixedSizeHashMap(java.util.LinkedHashMap[K, V], typing.Generic[K, V]):
    """
    A simple implementation of a LRU map that will throw away entries that exceed the given
    maximum size.
    
     
    If you would like a LRU based upon *access-order*, then use the :obj:`LRUMap`.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, maxSize: typing.Union[jpype.JInt, int]):
        ...

    @typing.overload
    def __init__(self, initialSize: typing.Union[jpype.JInt, int], maxSize: typing.Union[jpype.JInt, int]):
        ...


class RedBlackLongKeySet(java.io.Serializable):
    """
    A RedBlack Tree implementation of a long key set.
    """

    @typing.type_check_only
    class RBNode(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]
    NODESIZE: typing.Final = 15
    """
    the number of bytes in a RedBlackLongKeySet node
    """


    def __init__(self):
        """
        Creates a new RedBlackLongKeySet that can store keys between 0 and n.
        """

    def containsKey(self, key: typing.Union[jpype.JLong, int]) -> bool:
        """
        Returns true if the key is in the set.
        
        :param jpype.JLong or int key: the key whose presence is to be tested.
        :raises IndexOutOfBoundsException: thrown if the given key is not
        in the range [0, maxKey].
        """

    def getFirst(self) -> int:
        """
        Returns the first key in this set.
        """

    def getLast(self) -> int:
        """
        Returns the last key in this set.
        """

    def getNext(self, key: typing.Union[jpype.JLong, int]) -> int:
        """
        Returns the smallest key in the set that is greater than the given key.  Returns
        -1 if there are no keys greater than the given key.
        
        :param jpype.JLong or int key: the key for which to find the next key after.
        :raises IndexOutOfBoundsException: thrown if the given key is not
        in the range [0, maxKey].
        """

    def getPrevious(self, key: typing.Union[jpype.JLong, int]) -> int:
        """
        Returns the largest key in the set that is less than the given key. Returns -1 if
        there are not keys less than the given key.
        
        :param jpype.JLong or int key: the key for which to find the previous key.
        :raises IndexOutOfBoundsException: thrown if the given key is not
        in the range [0, maxKey].
        """

    def isEmpty(self) -> bool:
        """
        Test if the set is empty.
        
        :return: true if the set is empty.
        :rtype: bool
        """

    def put(self, key: typing.Union[jpype.JLong, int]):
        """
        Adds the given key to the set.
        
        :param jpype.JLong or int key: the key to add to the set.
        :raises IndexOutOfBoundsException: thrown if the given key is not
        in the range [0, maxKey].
        """

    def remove(self, key: typing.Union[jpype.JLong, int]) -> bool:
        """
        Removes the given key from the set.
        
        :param jpype.JLong or int key: the key to remove from the set.
        :raises IndexOutOfBoundsException: thrown if the given key is not
        in the range [0, maxKey].
        """

    def removeAll(self):
        """
        Removes all keys from the set.
        """

    def size(self) -> int:
        """
        Returns the number keys in this set.
        """

    @property
    def next(self) -> jpype.JLong:
        ...

    @property
    def previous(self) -> jpype.JLong:
        ...

    @property
    def last(self) -> jpype.JLong:
        ...

    @property
    def first(self) -> jpype.JLong:
        ...

    @property
    def empty(self) -> jpype.JBoolean:
        ...


class ByteArray(Array, java.io.Serializable):
    """
    Array of bytes that grows as needed.
    """

    class_: typing.ClassVar[java.lang.Class]
    MIN_SIZE: typing.Final = 4

    def __init__(self):
        """
        Creates new ByteArray
        """

    def copyDataTo(self, index: typing.Union[jpype.JInt, int], table: DataTable, toIndex: typing.Union[jpype.JInt, int], toCol: typing.Union[jpype.JInt, int]):
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.util.datastruct.Array.copyDataTo(int, DataTable, int, int)`
        """

    def get(self, index: typing.Union[jpype.JInt, int]) -> int:
        """
        Returns the byte at the given index
        
        :param jpype.JInt or int index: index into the array
        :return: The byte value at the given index. A 0 will
        be returned for any index not initialized to
        another value.
        :rtype: int
        :raises IndexOutOfBoundsException: if the index is negative
        """

    def getLastNonEmptyIndex(self) -> int:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.util.datastruct.Array.getLastNonEmptyIndex()`
        """

    def put(self, index: typing.Union[jpype.JInt, int], value: typing.Union[jpype.JByte, int]):
        """
        Puts the given byte value in the byte array at
        the given index
        
        :param jpype.JInt or int index: Index into the array.
        :param jpype.JByte or int value: value to store
        :raises IndexOutOfBoundsException: if the index is negative
        """

    def remove(self, index: typing.Union[jpype.JInt, int]):
        """
        Sets the value at the given index to 0.
        
        :param jpype.JInt or int index: the index to set to 0.
        :raises IndexOutOfBoundsException: if the index is negative
        """

    @property
    def lastNonEmptyIndex(self) -> jpype.JInt:
        ...


class RedBlackTree(java.lang.Iterable[RedBlackEntry[K, V]], typing.Generic[K, V]):
    """
    A RedBlack Tree implementation with K type keys and place to store V type values.
    """

    @typing.type_check_only
    class RedBlackTreeIterator(java.util.ListIterator[RedBlackEntry[K, V]]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        """
        Creates a new RedBlackKeySet that can store keys between 0 and n.
        """

    def containsKey(self, key: K) -> bool:
        """
        Returns true if the key is in the set.
        
        :param K key: the key whose presence is to be tested.
        """

    def deleteEntry(self, p: RedBlackEntry[K, V]):
        """
        Delete node p, and then rebalance the tree.
        """

    def getEntry(self, key: K) -> RedBlackEntry[K, V]:
        ...

    def getEntryGreaterThanEqual(self, key: K) -> RedBlackEntry[K, V]:
        """
        Returns the node with largest key in the set that is less or equal to the given key.
        Returns null if there are no keys less than or equal to the given key.
        
        :param K key: the search key
        """

    def getEntryLessThanEqual(self, key: K) -> RedBlackEntry[K, V]:
        """
        Returns the node with largest key in the set that is less or equal to the given key.
        Returns null if there are no keys less than or equal to the given key.
        
        :param K key: the search key
        """

    def getFirst(self) -> RedBlackEntry[K, V]:
        """
        Returns the first entry in this set.
        """

    def getLast(self) -> RedBlackEntry[K, V]:
        """
        Returns the last entry in this set.
        """

    def getOrCreateEntry(self, key: K) -> RedBlackEntry[K, V]:
        ...

    def isEmpty(self) -> bool:
        """
        Test if the set is empty.
        
        :return: true if the set is empty.
        :rtype: bool
        """

    @typing.overload
    def iterator(self, forward: typing.Union[jpype.JBoolean, bool]) -> java.util.ListIterator[RedBlackEntry[K, V]]:
        ...

    @typing.overload
    def iterator(self, firstEntry: RedBlackEntry[K, V], forward: typing.Union[jpype.JBoolean, bool]) -> java.util.ListIterator[RedBlackEntry[K, V]]:
        ...

    @typing.overload
    def iterator(self, key: K, forward: typing.Union[jpype.JBoolean, bool]) -> java.util.ListIterator[RedBlackEntry[K, V]]:
        ...

    def put(self, key: K, value: V) -> V:
        """
        Adds the given key,value to the map. If the map does not allow duplicate keys and a key
        already exists, the old value will be replaced by the new value and the old value will be
        returned.
        
        :param K key: the key to add to the set.
        :return: the old value associated with the key, or null if the key was not previously in the map.
        :rtype: V
        """

    def remove(self, key: K) -> V:
        """
        Removes the given key (first if duplicates are allowed) from the set.
        
        :param K key: the key to remove from the set.
        :return: the value associated with the key removed or null if the key not found.
        :rtype: V
        """

    def removeAll(self):
        """
        Removes all entries from the set.
        """

    def removeNode(self, node: RedBlackEntry[K, V]):
        ...

    def size(self) -> int:
        """
        Returns the number keys in this set.
        """

    @property
    def entry(self) -> RedBlackEntry[K, V]:
        ...

    @property
    def last(self) -> RedBlackEntry[K, V]:
        ...

    @property
    def orCreateEntry(self) -> RedBlackEntry[K, V]:
        ...

    @property
    def entryGreaterThanEqual(self) -> RedBlackEntry[K, V]:
        ...

    @property
    def entryLessThanEqual(self) -> RedBlackEntry[K, V]:
        ...

    @property
    def first(self) -> RedBlackEntry[K, V]:
        ...

    @property
    def empty(self) -> jpype.JBoolean:
        ...


class ObjectValueRange(java.lang.Comparable[ObjectValueRange[T]], typing.Generic[T]):
    """
    Associates an integer value with a numeric range.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, start: typing.Union[jpype.JLong, int], end: typing.Union[jpype.JLong, int], value: T):
        """
        Constructor for numeric range with an associated value.
        
        :param jpype.JLong or int start: beginning of the range
        :param jpype.JLong or int end: end of the range
        :param T value: the value to associate with the range.
        """

    def compareTo(self, otherRange: ObjectValueRange[T]) -> int:
        """
        
        
        
        .. seealso::
        
            | :obj:`java.lang.Comparable.compareTo(java.lang.Object)`
        """

    def contains(self, index: typing.Union[jpype.JLong, int]) -> bool:
        """
        Determines whether or not the indicated index is in the range.
        
        :param jpype.JLong or int index: the index to check
        :return: true if the index is in this range.
        :rtype: bool
        """

    def getEnd(self) -> int:
        """
        Returns the end of the range.
        """

    def getStart(self) -> int:
        """
        Returns the beginning of the range.
        """

    def getValue(self) -> T:
        """
        Returns the value associated with the range.
        """

    @property
    def start(self) -> jpype.JLong:
        ...

    @property
    def end(self) -> jpype.JLong:
        ...

    @property
    def value(self) -> T:
        ...


class LongKeyIndexer(java.io.Serializable):
    """
    This class converts arbitrary long keys into compacted int indexes suitable
    for use as indexes into an array or table.  Whenever a new key is added,
    the smallest unused index is allocated and associated with that key.
    Basically hashes the keys into linked lists using the IntListIndexer class,
    where all values in a list have
    the same hashcode.  Does most of the work in implementing a separate chaining
    version of a hashtable - the only thing missing is the values which are stored
    in the individual implementations of the various hashtables.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        Constructs a LongKeyIndexer with a default capacity.
        """

    @typing.overload
    def __init__(self, capacity: typing.Union[jpype.JInt, int]):
        """
        Constructs a LongKeyIndexer with a given initial capacity.
        
        :param jpype.JInt or int capacity: the initial capacity.
        """

    def clear(self):
        """
        Remove all keys.
        """

    def get(self, key: typing.Union[jpype.JLong, int]) -> int:
        """
        Returns the index for the given key, or
        -1 if key is not in the table.
        
        :param jpype.JLong or int key: the key for which to find an index.
        """

    def getCapacity(self) -> int:
        """
        Returns the current size of the key table.
        """

    def getKeys(self) -> jpype.JArray[jpype.JLong]:
        """
        Returns an array containing all the keys stored in this object.
        """

    def getSize(self) -> int:
        """
        Returns the number of keys stored in the table.
        """

    def put(self, key: typing.Union[jpype.JLong, int]) -> int:
        """
        Returns an index that will always be associated to the given key as long as
        the key remains in the table. If the key already exists, then the index where
        that key is stored is returned.  If the key is new, then a new index is allocated,
        the key is stored at that index, and the new index is returned.
        
        :param jpype.JLong or int key: the key to be stored.
        :return: index for key, or -1 if there was no room to put the key.
        :rtype: int
        :raises IndexOutOfBoundsException: thrown if this object is at maximum capacity.
        """

    def remove(self, key: typing.Union[jpype.JLong, int]) -> int:
        """
        Removes the key from the table.
        
        :param jpype.JLong or int key: the key to remove.
        :return: index of the key if the key was found, -1 if
        key did not exist in the table
        :rtype: int
        """

    @property
    def size(self) -> jpype.JInt:
        ...

    @property
    def keys(self) -> jpype.JArray[jpype.JLong]:
        ...

    @property
    def capacity(self) -> jpype.JInt:
        ...


class Prime(java.lang.Object):
    """
    Class that provides a static nextPrime method that gives out prime numbers
    that are useful in a buffer doubling strategy with all buffer sizes being prime.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def nextPrime(n: typing.Union[jpype.JInt, int]) -> int:
        """
        Finds the next prime number greater than or equal to n.
        
        :param jpype.JInt or int n: the number from which to find the next higher prime number.
        """


class IndexRangeIterator(java.lang.Object):
    """
    Iterator interface for index ranges.
    """

    class_: typing.ClassVar[java.lang.Class]

    def hasNext(self) -> bool:
        """
        Returns true if there are more index ranges.
        
        :return: true if there are more index ranges.
        :rtype: bool
        """

    def next(self) -> IndexRange:
        """
        Returns the next index range.
        
        :return: the next index range.
        :rtype: IndexRange
        """


class ShortObjectHashtable(java.io.Serializable):
    """
    Class that implements a hashtable with short keys and Object values.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        Default constructor creates a table with an initial default capacity.
        """

    @typing.overload
    def __init__(self, capacity: typing.Union[jpype.JShort, int]):
        """
        Constructor creates a table with an initial given capacity.  The capacity
        will be adjusted to the next highest prime in the PRIMES table.
        
        :param jpype.JShort or int capacity: the initial capacity.
        """

    def contains(self, key: typing.Union[jpype.JShort, int]) -> bool:
        """
        Return true if the given key is in the hashtable.
        
        :param jpype.JShort or int key: the key whose presence in this map is to be tested.
        """

    def get(self, key: typing.Union[jpype.JShort, int]) -> java.lang.Object:
        """
        Returns the value for the given key.
        
        :param jpype.JShort or int key: the key whose assocated value is to be returned.
        """

    def getKeys(self) -> jpype.JArray[jpype.JShort]:
        """
        Returns an array containing all the short keys.
        """

    def put(self, key: typing.Union[jpype.JShort, int], value: java.lang.Object):
        """
        Adds a key/value pair to the hashtable. If the key is already in the table,
        the old value is replaced with the new value.  If the hashtable is already
        full, the hashtable will attempt to approximately double in size
        (it will use a prime number), and all the current entries will
        be rehashed.
        
        :param jpype.JShort or int key: the key to associated with the given value.
        :param java.lang.Object value: the value to associate with the given key.
        :raises ArrayIndexOutOfBoundsException: thrown if the maximum capacity is
        reached.
        """

    def remove(self, key: typing.Union[jpype.JShort, int]) -> bool:
        """
        Removes a key from the hashtable
        
        :param jpype.JShort or int key: key to be removed from the hashtable.
        :return: true if key is found and removed, false otherwise.
        :rtype: bool
        """

    def removeAll(self):
        """
        Remove all entries from the hashtable.
        """

    def size(self) -> int:
        """
        Return the number of key/value pairs stored in the hashtable.
        """

    @property
    def keys(self) -> jpype.JArray[jpype.JShort]:
        ...


class ShortLongHashtable(java.io.Serializable):
    """
    Class that implements a hashtable with Short keys and long values.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        Default constructor creates a table with an initial default capacity.
        """

    @typing.overload
    def __init__(self, capacity: typing.Union[jpype.JShort, int]):
        """
        Constructor creates a table with an initial given capacity.  The capacity
        will be adjusted to the next highest prime in the PRIMES table.
        
        :param jpype.JShort or int capacity: the initial capacity.
        """

    def contains(self, key: typing.Union[jpype.JShort, int]) -> bool:
        """
        Return true if the given key is in the hashtable.
        
        :param jpype.JShort or int key: the key whose presence is this map is to be tested.
        """

    def get(self, key: typing.Union[jpype.JShort, int]) -> int:
        """
        Returns the value for the given key.
        
        :param jpype.JShort or int key: the key whose assocated value is to be returned.
        """

    def getKeys(self) -> jpype.JArray[jpype.JShort]:
        """
        Returns an array containing all the short keys.
        """

    def put(self, key: typing.Union[jpype.JShort, int], value: typing.Union[jpype.JLong, int]):
        """
        Adds a key/value pair to the hashtable. If the key is already in the table,
        the old value is replaced with the new value.  If the hashtable is already
        full, the hashtable will attempt to approximately double in size
        (it will use a prime number), and all the current entries will
        be rehashed.
        
        :param jpype.JShort or int key: the key to associated with the given value.
        :param jpype.JLong or int value: the value to associate with the given key.
        :raises ArrayIndexOutOfBoundsException: thrown if the maximum capacity is
        reached.
        """

    def remove(self, key: typing.Union[jpype.JShort, int]) -> bool:
        """
        Removes a key from the hashtable
        
        :param jpype.JShort or int key: key to be removed from the hashtable.
        :return: true if key is found and removed, false otherwise.
        :rtype: bool
        """

    def removeAll(self):
        """
        Remove all entries from the hashtable.
        """

    def size(self) -> int:
        """
        Return the number of key/value pairs stored in the hashtable.
        """

    @property
    def keys(self) -> jpype.JArray[jpype.JShort]:
        ...


class IntArrayList(java.io.Serializable, ghidra.util.Saveable):
    """
    An ArrayList type object for ints.
    """

    class_: typing.ClassVar[java.lang.Class]
    MIN_SIZE: typing.Final = 4

    @typing.overload
    def __init__(self):
        """
        Creates new intArrayList
        """

    @typing.overload
    def __init__(self, useZeroSize: typing.Union[jpype.JBoolean, bool]):
        ...

    @typing.overload
    def __init__(self, arr: jpype.JArray[jpype.JInt]):
        """
        Creates a new intArrayList using the values in the given array
        
        :param jpype.JArray[jpype.JInt] arr: array of ints to initialize to.
        """

    @typing.overload
    def add(self, value: typing.Union[jpype.JInt, int]):
        """
        Adds a new int value at the end of the list.
        
        :param jpype.JInt or int value: the int value to add.
        """

    @typing.overload
    def add(self, index: typing.Union[jpype.JInt, int], value: typing.Union[jpype.JInt, int]):
        """
        Puts the given int value in the int array at
        the given index
        
        :param jpype.JInt or int index: Index into the array.
        :param jpype.JInt or int value: value to store
        :raises IndexOutOfBoundsException: if the index is negative OR index > size
        """

    def clear(self):
        """
        Clears the entire array of data.
        """

    def get(self, index: typing.Union[jpype.JInt, int]) -> int:
        """
        Returns the int at the given index
        
        :param jpype.JInt or int index: index into the array
        :return: The int value at the given index. A 0 will
        be returned for any index not initialized to
        another value.
        :rtype: int
        :raises IndexOutOfBoundsException: if the index is negative or greater than the list size.
        """

    def isEmpty(self) -> bool:
        ...

    def removeValue(self, value: typing.Union[jpype.JInt, int]):
        """
        Removes the first occurrence of the given
        value.
        
        :param jpype.JInt or int value: the value to be removed.
        """

    def removeValueAt(self, index: typing.Union[jpype.JInt, int]):
        """
        Removes the value at the given index decreasing the array list size by 1.
        
        :param jpype.JInt or int index: the index to remove.
        :raises IndexOutOfBoundsException: if the index is negative
        """

    def set(self, index: typing.Union[jpype.JInt, int], value: typing.Union[jpype.JInt, int]):
        """
        Sets the array value at index to value.
        
        :param jpype.JInt or int index: the index to set.
        :param jpype.JInt or int value: the value to store.
        """

    def size(self) -> int:
        """
        Returns the size of this virtual array.
        
        :return: int the size of this virtual array.
        :rtype: int
        """

    def toArray(self) -> jpype.JArray[jpype.JInt]:
        """
        Converts to a primitive array.
        
        :return: int[] int array for results.
        :rtype: jpype.JArray[jpype.JInt]
        """

    @property
    def empty(self) -> jpype.JBoolean:
        ...


class ObjectLongHashtable(java.lang.Object, typing.Generic[T]):
    """
    Class that implements a hashtable with Object keys and long values.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        Default constructor creates a table with an initial default capacity.
        """

    @typing.overload
    def __init__(self, capacity: typing.Union[jpype.JInt, int]):
        """
        Constructor creates a table with an initial given capacity.  The capacity
        will be adjusted to the next highest prime in the PRIMES table.
        
        :param jpype.JInt or int capacity: the initial capacity.
        """

    def contains(self, key: java.lang.Object) -> bool:
        """
        Return true if the given key is in the hashtable.
        
        :param java.lang.Object key: the key whose presence in this map is to be tested.
        """

    def get(self, key: T) -> int:
        """
        Returns the value for the given key.
        
        :param T key: the key whose associated value is to be returned.
        :raises NoValueException: thrown if there is no value for the given key.
        """

    def getKeys(self, keyArray: jpype.JArray[T]) -> jpype.JArray[T]:
        """
        Returns an array containing all the key objects.
        """

    def put(self, key: T, value: typing.Union[jpype.JLong, int]):
        """
        Adds a key/value pair to the hashtable. If the key is already in the table,
        the old value is replaced with the new value.  If the hashtable is already
        full, the hashtable will attempt to approximately double in size
        (it will use a prime number), and all the current entries will
        be rehashed.
        
        :param T key: the key to associate with the given value.
        :param jpype.JLong or int value: the value to associate with the given key.
        :raises ArrayIndexOutOfBoundsException: thrown if the maximum capacity is
        reached.
        """

    def remove(self, key: java.lang.Object) -> bool:
        """
        Removes a key from the hashtable
        
        :param java.lang.Object key: key to be removed from the hashtable.
        :return: true if key is found and removed, false otherwise.
        :rtype: bool
        """

    def removeAll(self):
        """
        Remove all entries from the hashtable.
        """

    def size(self) -> int:
        """
        Return the number of key/value pairs stored in the hashtable.
        """

    @property
    def keys(self) -> jpype.JArray[T]:
        ...


class LongIntHashtable(java.io.Serializable):
    """
    Class that implements a hashtable with long keys and int values.
        Because this class uses array of primitives
        to store the information, it serializes very fast.  This implementation uses
        separate chaining to resolve collisions.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        Default constructor creates a table with an initial default capacity.
        """

    @typing.overload
    def __init__(self, capacity: typing.Union[jpype.JInt, int]):
        """
        Constructor creates a table with an initial given capacity.  The capacity
        will be adjusted to the next highest prime in the PRIMES table.
        
        :param jpype.JInt or int capacity: the initial capacity.
        """

    def contains(self, key: typing.Union[jpype.JLong, int]) -> bool:
        """
        Return true if the given key is in the hashtable.
        
        :param jpype.JLong or int key: the key whose presence in this map is to be tested.
        """

    def get(self, key: typing.Union[jpype.JLong, int]) -> int:
        """
        Returns the value for the given key.
        
        :param jpype.JLong or int key: the key whose associated value is to be returned.
        :raises NoValueException: thrown if there is no value for the given key.
        """

    def getKeys(self) -> jpype.JArray[jpype.JLong]:
        """
        Returns an array containing all the long keys.
        """

    def put(self, key: typing.Union[jpype.JLong, int], value: typing.Union[jpype.JInt, int]):
        """
        Adds a key/value pair to the hashtable. If the key is already in the table,
        the old value is replaced with the new value.  If the hashtable is already
        full, the hashtable will attempt to approximately double in size
        (it will use a prime number), and all the current entries will
        be rehashed.
        
        :param jpype.JLong or int key: the key to associate with the given value.
        :param jpype.JInt or int value: the value to associate with the given key.
        :raises ArrayIndexOutOfBoundsException: thrown if the maximum capacity is
        reached.
        """

    def remove(self, key: typing.Union[jpype.JLong, int]) -> bool:
        """
        Removes a key from the hashtable
        
        :param jpype.JLong or int key: key to be removed from the hashtable.
        :return: true if key is found and removed, false otherwise.
        :rtype: bool
        """

    def removeAll(self):
        """
        Remove all entries from the hashtable.
        """

    def size(self) -> int:
        """
        Return the number of key/value pairs stored in the hashtable.
        """

    @property
    def keys(self) -> jpype.JArray[jpype.JLong]:
        ...


class FixedSizeStack(Stack[E], typing.Generic[E]):
    """
    Creates a fixed size stack.
    The oldest (or deepest) item on the stack
    will be removed when the max size is achieved.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, maxSize: typing.Union[jpype.JInt, int]):
        """
        Creates a fixed size stack with the specified
        max size.
        
        :param jpype.JInt or int maxSize: the max size of the stack
        """

    def remove(self, index: typing.Union[jpype.JInt, int]) -> E:
        ...


class IntSet(java.lang.Object):
    """
    Class for storing a set of integers
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, capacity: typing.Union[jpype.JInt, int]):
        """
        Constructs a new empty int set
        
        :param jpype.JInt or int capacity: the initial storage size, the set will grow if needed.
        """

    @typing.overload
    def __init__(self, values: jpype.JArray[jpype.JInt]):
        """
        Constructs a new IntSet and populates it with the given array of ints.
        
        :param jpype.JArray[jpype.JInt] values: the array if ints to add to the set.
        """

    def add(self, value: typing.Union[jpype.JInt, int]):
        """
        Add the int value to the set.
        
        :param jpype.JInt or int value: the value to add to the set.
        """

    def clear(self):
        """
        Removes all values from the set.
        """

    def contains(self, value: typing.Union[jpype.JInt, int]) -> bool:
        """
        Returns true if the set contains the given value.
        
        :param jpype.JInt or int value: the value to test if it is in the set.
        :return: true if the value is in the set.
        :rtype: bool
        """

    def getValues(self) -> jpype.JArray[jpype.JInt]:
        """
        Returns an array with all the values in the set.
        """

    def isEmpty(self) -> bool:
        """
        Returns true if the set is empty
        """

    def remove(self, value: typing.Union[jpype.JInt, int]) -> bool:
        """
        Removes the int value from the set.
        
        :param jpype.JInt or int value: the value to remove from the set.
        :return: true if the value was in the set, false otherwise.
        :rtype: bool
        """

    def size(self) -> int:
        """
        Returns the number of ints in the set.
        
        :return: the number of ints in the set.
        :rtype: int
        """

    @property
    def values(self) -> jpype.JArray[jpype.JInt]:
        ...

    @property
    def empty(self) -> jpype.JBoolean:
        ...


class LongObjectHashtable(java.io.Serializable, typing.Generic[T]):
    """
    Class that implements a hashtable with long keys and Object values.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        Default constructor creates a table with an initial default capacity.
        """

    @typing.overload
    def __init__(self, capacity: typing.Union[jpype.JInt, int]):
        """
        Constructor creates a table with an initial given capacity.  The capacity
        will be adjusted to the next highest prime in the PRIMES table.
        
        :param jpype.JInt or int capacity: the initial capacity.
        """

    def contains(self, key: typing.Union[jpype.JLong, int]) -> bool:
        """
        Return true if the given key is in the hashtable.
        
        :param jpype.JLong or int key: the key whose presence in this map is to be tested.
        """

    def get(self, key: typing.Union[jpype.JLong, int]) -> T:
        """
        Returns the value for the given key.
        
        :param jpype.JLong or int key: the key whose associated value is to be returned.
        """

    def getKeys(self) -> jpype.JArray[jpype.JLong]:
        """
        Returns an array containing all the long keys.
        """

    def put(self, key: typing.Union[jpype.JLong, int], value: T):
        """
        Adds a key/value pair to the hashtable. If the key is already in the table,
        the old value is replaced with the new value.  If the hashtable is already
        full, the hashtable will attempt to approximately double in size
        (it will use a prime number), and all the current entries will
        be rehashed.
        
        :param jpype.JLong or int key: the key to associate with the given value.
        :param T value: the value to associate with the given key.
        :raises ArrayIndexOutOfBoundsException: thrown if the maximum capacity is
        reached.
        """

    def remove(self, key: typing.Union[jpype.JLong, int]) -> T:
        """
        Removes a key from the hashtable
        
        :param jpype.JLong or int key: key to be removed from the hashtable.
        :return: Object removed from cache.  A null could be returned if either
        the key was not found or a null had been stored for the specified key.
        :rtype: T
        """

    def removeAll(self):
        """
        Remove all entries from the hashtable.
        """

    def size(self) -> int:
        """
        Return the number of key/value pairs stored in the hashtable.
        """

    @property
    def keys(self) -> jpype.JArray[jpype.JLong]:
        ...


class NoSuchIndexException(ghidra.util.exception.UsrException):
    """
    Exception thrown if a requested index does not exist.
    """

    class_: typing.ClassVar[java.lang.Class]
    noSuchIndexException: typing.Final[NoSuchIndexException]
    """
    Static constructor for this exception with a generic message. 
    Use this for efficiency when the actual stack information isn't needed.
    """


    @typing.overload
    def __init__(self):
        """
        Default constructor
        """

    @typing.overload
    def __init__(self, msg: typing.Union[java.lang.String, str]):
        """
        Constructor
        
        :param java.lang.String or str msg: detailed message
        """


class SynchronizedListAccumulator(Accumulator[T], typing.Generic[T]):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, list: java.util.List[T]):
        ...

    def asList(self) -> java.util.List[T]:
        ...

    def clear(self):
        ...


class LongDoubleHashtable(java.io.Serializable):
    """
    Class that implements a hashtable with long keys and double values.
        Because this class uses array of primitives
        to store the information, it serializes very fast.  This implementation uses
        separate chaining to resolve collisions.
    
        My local change of LongShortHashtable (SCP 4/13/00)
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        Default constructor creates a table with an initial default capacity.
        """

    @typing.overload
    def __init__(self, capacity: typing.Union[jpype.JInt, int]):
        """
        Constructor creates a table with an initial given capacity.  The capacity
        will be adjusted to the next highest prime in the PRIMES table.
        
        :param jpype.JInt or int capacity: the initial capacity.
        """

    def contains(self, key: typing.Union[jpype.JLong, int]) -> bool:
        """
        Return true if the given key is in the hashtable.
        
        :param jpype.JLong or int key: the key whose presence in this map is to be tested.
        """

    def get(self, key: typing.Union[jpype.JLong, int]) -> float:
        """
        Returns the value for the given key.
        
        :param jpype.JLong or int key: the key whose associated value is to be returned.
        :raises NoValueException: thrown if there is no value for the given key.
        """

    def getKeys(self) -> jpype.JArray[jpype.JLong]:
        """
        Returns an array containing all the long keys.
        """

    def put(self, key: typing.Union[jpype.JLong, int], value: typing.Union[jpype.JDouble, float]):
        """
        Adds a key/value pair to the hashtable. If the key is already in the table,
        the old value is replaced with the new value.  If the hashtable is already
        full, the hashtable will attempt to approximately double in size
        (it will use a prime number), and all the current entries will
        be rehashed.
        
        :param jpype.JLong or int key: the key to associate with the given value.
        :param jpype.JDouble or float value: the value to associate with the given key.
        :raises ArrayIndexOutOfBoundsException: thrown if the maximum capacity is
        reached.
        """

    def remove(self, key: typing.Union[jpype.JLong, int]) -> bool:
        """
        Removes a key from the hashtable
        
        :param jpype.JLong or int key: key to be removed from the hashtable.
        :return: true if key is found and removed, false otherwise.
        :rtype: bool
        """

    def removeAll(self):
        """
        Remove all entries from the hashtable.
        """

    def size(self) -> int:
        """
        Return the number of key/value pairs stored in the hashtable.
        """

    @property
    def keys(self) -> jpype.JArray[jpype.JLong]:
        ...


class ListenerErrorHandlerFactory(java.lang.Object):
    """
    A simple interface for creating listener error handlers
    """

    class_: typing.ClassVar[java.lang.Class]

    def createErrorHandler(self) -> ListenerErrorHandler:
        """
        Creates the error handler
        
        :return: the error handler
        :rtype: ListenerErrorHandler
        """


class ShortListIndexer(java.io.Serializable):
    """
    Class to manage multiple linked lists of short indexes. Users can add indexes
    to a list, remove indexes from a list, remove all indexes from a list, and
    retrieve all indexes within a given list.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, numLists: typing.Union[jpype.JShort, int], capacity: typing.Union[jpype.JShort, int]):
        """
        The constructor
        
        :param jpype.JShort or int numLists: - The initial number of lists to be managed.
        :param jpype.JShort or int capacity: - The current size of the pool of possible indexes.  All indexes
        begin on the free list.
        """

    def add(self, listID: typing.Union[jpype.JShort, int]) -> int:
        """
        Allocates a new index resource and adds it to the front of the linked list
        indexed by listID.
        
        :param jpype.JShort or int listID: the id of the list to add to.
        :raises IndexOutOfBoundsException: thrown if the listID is not in the
        the range [0, numLists).
        """

    def append(self, listID: typing.Union[jpype.JShort, int]) -> int:
        """
        Allocates a new index resource and adds it to the end of the linked list
        indexed by listID.
        
        :param jpype.JShort or int listID: the id of the list to add to.
        :raises IndexOutOfBoundsException: thrown if the listID is not in the
        the range [0, numLists).
        """

    def clear(self):
        """
        Removes all indexes from all lists.
        """

    def first(self, listID: typing.Union[jpype.JShort, int]) -> int:
        """
        Returns the first index resource on the linked list indexed by listID.
        
        :raises IndexOutOfBoundsException: thrown if the listID is not in the
        the range [0, numLists].
        """

    def getCapacity(self) -> int:
        """
        Returns the current index capacity.
        """

    def getListSize(self, listID: typing.Union[jpype.JShort, int]) -> int:
        """
        Returns the number of indexes in the specified list.
        
        :raises IndexOutOfBoundsException: thrown if the listID is not in the
        the range [0, numLists).
        """

    def getNewCapacity(self) -> int:
        """
        Computes the next size that should be used to grow the index capacity.
        """

    def getNumLists(self) -> int:
        """
        Returns the number of linked list being managed.
        """

    def getSize(self) -> int:
        """
        Returns the current number of used index resources.
        """

    def growCapacity(self, newCapacity: typing.Union[jpype.JShort, int]):
        """
        Increases the index resource pool.
        
        :param jpype.JShort or int newCapacity: the new number of resource indexes to manage.  if this number
        is smaller than the current number of resource indexes, then nothing changes.
        """

    def growNumLists(self, newListSize: typing.Union[jpype.JShort, int]):
        """
        Increases the number of managed linked lists.
        
        :param jpype.JShort or int newListSize: the new number of linked lists.  If this number is
        smaller than the current number of linked lists, then nothing changes.
        """

    def next(self, index: typing.Union[jpype.JShort, int]) -> int:
        """
        Returns the next index resource that follows the given index in a linked list.
        The index should be an index that is in some linked list.  Otherwise, the
        results are undefined( probably give you the next index on the free list )
        
        :param jpype.JShort or int index: to search after to find the next index.
        :raises IndexOutOfBoundsException: thrown if the index is not in the
        the range [0, capacity].
        """

    def remove(self, listID: typing.Union[jpype.JShort, int], index: typing.Union[jpype.JShort, int]):
        """
        Remove the index resource from the linked list indexed by listID.
        
        :param jpype.JShort or int listID: the id of the list from which to removed the value at index.
        :param jpype.JShort or int index: the index of the value to be removed from the specified list.
        :raises IndexOutOfBoundsException: thrown if the listID is not in the
        the range [0, numLists).
        """

    def removeAll(self, listID: typing.Union[jpype.JShort, int]):
        """
        Removes all indexes from the specified list.
        
        :param jpype.JShort or int listID: the list to be emptied.
        """

    @property
    def size(self) -> jpype.JShort:
        ...

    @property
    def numLists(self) -> jpype.JShort:
        ...

    @property
    def newCapacity(self) -> jpype.JShort:
        ...

    @property
    def listSize(self) -> jpype.JInt:
        ...

    @property
    def capacity(self) -> jpype.JShort:
        ...


class AbstractWeakValueNavigableMap(AbstractWeakValueMap[K, V], java.util.NavigableMap[K, V], typing.Generic[K, V]):
    """
    Class to provide a navigable, e.g., tree-, map with weak values
    """

    @typing.type_check_only
    class NavigableView(AbstractWeakValueNavigableMap[K, V], typing.Generic[K, V]):
        """
        A view of this same map that limits or changes the order of the keys
        
         
        
        TODO: By virtue of extending (indirectly) :obj:`AbstractWeakValueMap`, this view inherits a
        unique, but totally unused, :obj:`AbstractWeakValueMap.refQueue`. This is a small and
        harmless, but unnecessary waste.
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, map: AbstractWeakValueNavigableMap[K, V], sub: java.util.NavigableMap[K, AbstractWeakValueMap.WeakValueRef[K, V]]):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class ObjectArray(Array, java.io.Serializable):
    """
    Array of objects that grows as needed.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        Creates a new Object array of a default size.
        """

    @typing.overload
    def __init__(self, size: typing.Union[jpype.JInt, int]):
        """
        Creates a new object array that is initially the size specified.
        
        :param jpype.JInt or int size: the initial size of the Object array.
        """

    def copyDataTo(self, index: typing.Union[jpype.JInt, int], table: DataTable, toIndex: typing.Union[jpype.JInt, int], toCol: typing.Union[jpype.JInt, int]):
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.util.datastruct.Array.copyDataTo(int, ghidra.util.datastruct.DataTable, int, int)`
        """

    def get(self, index: typing.Union[jpype.JInt, int]) -> java.lang.Object:
        """
        Returns the Object at the given index
        
        :param jpype.JInt or int index: index into the array
        :return: The Object value at the given index. A null will
        be return for any index not initialized to
        another value.
        :rtype: java.lang.Object
        :raises IndexOutOfBoundsException: if the index is negative
        """

    def getLastNonEmptyIndex(self) -> int:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.util.datastruct.Array.getLastNonEmptyIndex()`
        """

    def put(self, index: typing.Union[jpype.JInt, int], value: java.lang.Object):
        """
        Puts the given Object in the Object array at
        the given index
        
        :param jpype.JInt or int index: Index into the array.
        :param java.lang.Object value: value to store
        :raises IndexOutOfBoundsException: if the index is negative
        """

    def remove(self, index: typing.Union[jpype.JInt, int]):
        """
        Sets the value at the given index to null.
        
        :param jpype.JInt or int index: the index to set to null.
        :raises IndexOutOfBoundsException: if the index is negative
        """

    @property
    def lastNonEmptyIndex(self) -> jpype.JInt:
        ...


class ShortKeyIndexer(java.io.Serializable):
    """
    This class converts arbitrary short keys into compacted short indexes suitable
    for use as indexes into an array or table.  Whenever a new key is added,
    the smallest unused index is allocated and associated with that key.
    Basically hashes the keys into linked lists using the ShortListIndexer class,
    where all values in a list have
    the same hashcode.  Does most of the work in implementing a separate chaining
    version of a hashtable - the only thing missing is the values which are stored
    in the individual implementations of the various hashtables.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        Constructs a ShortKeyIndexer with a default capacity.
        """

    @typing.overload
    def __init__(self, capacity: typing.Union[jpype.JShort, int]):
        """
        Constructs a ShortKeyIndexer with a given initial capacity.
        
        :param jpype.JShort or int capacity: the initial capacity.
        """

    def clear(self):
        """
        Remove all keys.
        """

    def get(self, key: typing.Union[jpype.JShort, int]) -> int:
        """
        Returns the index for the given key, or
        -1 if key is not in the table.
        
        :param jpype.JShort or int key: the key for which to find an index.
        """

    def getCapacity(self) -> int:
        """
        Returns the current size of the key table.
        """

    def getKeys(self) -> jpype.JArray[jpype.JShort]:
        """
        Returns an array containing all the keys stored in this object.
        """

    def getSize(self) -> int:
        """
        Returns the number of keys stored in the table.
        """

    def put(self, key: typing.Union[jpype.JShort, int]) -> int:
        """
        Returns an index that will always be associated to the given key as long as
        the key remains in the table. If the key already exists, then the index where
        that key is stored is returned.  If the key is new, then a new index is allocated,
        the key is stored at that index, and the new index is returned.
        
        :param jpype.JShort or int key: the key to be stored.
        :return: index for key, or -1 if there was no room to put the key.
        :rtype: int
        :raises IndexOutOfBoundsException: thrown if this object is at maximum capacity.
        """

    def remove(self, key: typing.Union[jpype.JShort, int]) -> int:
        """
        Removes the key from the table.
        
        :param jpype.JShort or int key: the key to remove.
        :return: index of the key if the key was found, -1 if
        key did not exist in the table
        :rtype: int
        """

    @property
    def size(self) -> jpype.JShort:
        ...

    @property
    def keys(self) -> jpype.JArray[jpype.JShort]:
        ...

    @property
    def capacity(self) -> jpype.JShort:
        ...


class PropertySetIndexRangeIterator(IndexRangeIterator):
    """
    Iterator over Property Set Index ranges that have the same value
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, set: ghidra.util.map.ValueMap, start: typing.Union[jpype.JLong, int]):
        """
        Constructor for PropertySetIndexRangeIterator.
        """

    def hasNext(self) -> bool:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.util.datastruct.IndexRangeIterator.hasNext()`
        """

    def next(self) -> IndexRange:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.util.datastruct.IndexRangeIterator.next()`
        """


class WeakStore(java.lang.Object, typing.Generic[T]):
    """
    Class for storing a weak reference to object instances. Objects of type T can be placed in this 
    store and they will remain there until there are no references to that object. Note 
    that this is not a Set and you can have multiple instances that are "equal" in this store.The 
    main purpose of this store is to be able to get all objects in the store that are still 
    referenced.  This is useful when you need to visit all in use items.   
     
    
    This class is thread safe.
    """

    @typing.type_check_only
    class Link(java.lang.ref.WeakReference[T], typing.Generic[T]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, previous: WeakStore.Link[T], value: T, next: WeakStore.Link[T], refQueue: java.lang.ref.ReferenceQueue[T]):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def add(self, value: T):
        """
        Adds the given value to the store
        
        :param T value: the instance being added to the store
        """

    def getValues(self) -> java.util.List[T]:
        """
        returns a list of all the objects in this store
        
        :return: a list of all the objects in this store
        :rtype: java.util.List[T]
        """

    def size(self) -> int:
        """
        Returns the number of objects of type T remaining in the store. Those that are remaining
        are either still referenced
        
        :return: the number of objects still in the store that haven't yet been garbage collected
        :rtype: int
        """

    @property
    def values(self) -> java.util.List[T]:
        ...


@typing.type_check_only
class LongArrayListIterator(java.util.ListIterator[java.lang.Long]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, list: java.util.List[java.lang.Long], startIndex: typing.Union[jpype.JInt, int]):
        ...


class SizeLimitedAccumulatorWrapper(Accumulator[T], typing.Generic[T]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, accumulator: Accumulator[T], maxSize: typing.Union[jpype.JInt, int]):
        """
        Constructor.
        
        :param Accumulator[T] accumulator: the accumulator to pass items to
        :param jpype.JInt or int maxSize: the maximum number of items this accumulator will hold
        """

    def hasReachedSizeLimit(self) -> bool:
        """
        Returns true if this size of this accumulator is greater than or equal to the given 
        maximum size
        
        :return: true if the max size has been reachged
        :rtype: bool
        """


class ShortKeySet(java.lang.Object):
    """
    The ShortKeySet provides an interface for managing a set of ordered short keys
    between the values of 0 and N.  It can add keys, remove keys, find the next key
    greater than some value , and find the previous key less than some value.
    """

    class_: typing.ClassVar[java.lang.Class]

    def containsKey(self, key: typing.Union[jpype.JShort, int]) -> bool:
        """
        Determines if a given key is in the set.
        
        :param jpype.JShort or int key: the key whose presence is to be tested.
        :return: true if the key is in the set.
        :rtype: bool
        """

    def getFirst(self) -> int:
        """
        Returns the first (lowest) key in the set.
        """

    def getLast(self) -> int:
        """
        Returns the last (highest) key in the set.
        """

    def getNext(self, key: typing.Union[jpype.JShort, int]) -> int:
        """
        finds the next key that is in the set that is greater than the given key.
        
        :param jpype.JShort or int key: the key for which to find the next key after.
        """

    def getPrevious(self, key: typing.Union[jpype.JShort, int]) -> int:
        """
        finds the previous key that is in the set that is less than the given key.
        
        :param jpype.JShort or int key: the key for which to find the previous key.
        """

    def isEmpty(self) -> bool:
        """
        Checks if the set is empty.
        
        :return: true if the set is empty.
        :rtype: bool
        """

    def put(self, key: typing.Union[jpype.JShort, int]):
        """
        Adds a key to the set.
        
        :param jpype.JShort or int key: the key to add to the set.
        """

    def remove(self, key: typing.Union[jpype.JShort, int]) -> bool:
        """
        Removes the key from the set.
        
        :param jpype.JShort or int key: the key to remove from the set.
        """

    def removeAll(self):
        """
        Removes all keys from the set.
        """

    def size(self) -> int:
        """
        Returns the number of keys currently in the set.
        """

    @property
    def next(self) -> jpype.JShort:
        ...

    @property
    def previous(self) -> jpype.JShort:
        ...

    @property
    def last(self) -> jpype.JShort:
        ...

    @property
    def first(self) -> jpype.JShort:
        ...

    @property
    def empty(self) -> jpype.JBoolean:
        ...


class RangeMap(java.lang.Object):
    """
    Stores ranges of int values throughout "long" space. Every "long" index has
    an associated int value (initially 0). Users can paint (set) ranges of
    indexes to a given integer value, overwriting any value that currently exists
    in that range.
     
    This class is implemented using an IntPropertyMap.  The first index
    (0) will always contain a value.  The value at any other given
    index will either be the value stored at that index, or if no
    value stored there, then the value stored at the nearest previous index
    that contains a value.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        Constructor for RangeMap with a default value of 0.
        """

    @typing.overload
    def __init__(self, defaultValue: typing.Union[jpype.JInt, int]):
        """
        Creates a new range map with spcified default value.
        
        :param jpype.JInt or int defaultValue: the default value
        """

    def clear(self):
        """
        Clears all current values from the range map and resets the default value.
        """

    def getChangePointIterator(self, start: typing.Union[jpype.JLong, int], end: typing.Union[jpype.JLong, int]) -> ghidra.util.LongIterator:
        """
        Returns an iterator over all indexes where the value changes.
        
        :param jpype.JLong or int start: the starting index to search.
        :param jpype.JLong or int end: the ending index to search.
        :return: an iterator over all indexes where the value changes.
        :rtype: ghidra.util.LongIterator
        """

    def getIndexRangeIterator(self, index: typing.Union[jpype.JLong, int]) -> IndexRangeIterator:
        """
        Returns an iterator over all occupied ranges in the map.
        
        :param jpype.JLong or int index: the index to start the iterator
        :return: an iterator over all occupied ranges in the map.
        :rtype: IndexRangeIterator
        """

    def getNumRanges(self) -> int:
        """
        Get the total number of ranges in map.
        
        :return: number of ranges
        :rtype: int
        """

    def getValue(self, index: typing.Union[jpype.JLong, int]) -> int:
        """
        Returns the int value associated with the given index.
        
        :param jpype.JLong or int index: the index at which to get the value.
        """

    def getValueRange(self, index: typing.Union[jpype.JLong, int]) -> ValueRange:
        """
        Returns the value range containing the given index. The value range indicates
        the int value and the start and end index for the range.
        
        :param jpype.JLong or int index: the index at which to get the associated value range
        :return: the value range
        :rtype: ValueRange
        """

    def paintRange(self, start: typing.Union[jpype.JLong, int], end: typing.Union[jpype.JLong, int], value: typing.Union[jpype.JInt, int]):
        """
        Associates the given value with every index from start to end (inclusive)
        Any previous associates are overwritten.
        
        :param jpype.JLong or int start: the start index of the range to fill.
        :param jpype.JLong or int end: the end index of the range to fill
        :param jpype.JInt or int value: the value to put at every index in the range.
        """

    @property
    def valueRange(self) -> ValueRange:
        ...

    @property
    def numRanges(self) -> jpype.JInt:
        ...

    @property
    def value(self) -> jpype.JInt:
        ...

    @property
    def indexRangeIterator(self) -> IndexRangeIterator:
        ...


class ShortArrayArray(Array, java.io.Serializable):
    """
    Array of byte[] that grows as needed.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        """
        Creates new shortArrayArray
        """

    def copyDataTo(self, index: typing.Union[jpype.JInt, int], table: DataTable, toIndex: typing.Union[jpype.JInt, int], toCol: typing.Union[jpype.JInt, int]):
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.util.datastruct.Array.copyDataTo(int, ghidra.util.datastruct.DataTable, int, int)`
        """

    def get(self, index: typing.Union[jpype.JInt, int]) -> jpype.JArray[jpype.JShort]:
        """
        Returns the short array at the given index
        
        :param jpype.JInt or int index: index into the array
        :return: The short array value at the given index. An empty array will
        be return for any index not initialized to
        another value.
        :rtype: jpype.JArray[jpype.JShort]
        :raises IndexOutOfBoundsException: if the index is negative
        """

    def getLastNonEmptyIndex(self) -> int:
        """
        Returns the index of the last non-null or non-zero element in the array.
        """

    def put(self, index: typing.Union[jpype.JInt, int], value: jpype.JArray[jpype.JShort]):
        """
        Puts the given short array value in the short array array at
        the given index
        
        :param jpype.JInt or int index: Index into the array.
        :param jpype.JArray[jpype.JShort] value: value to store
        :raises IndexOutOfBoundsException: if the index is negative
        """

    def remove(self, index: typing.Union[jpype.JInt, int]):
        """
        Removes the short array at the given index
        
        :param jpype.JInt or int index: index of the array to be removed
        :raises IndexOutOfBoundsException: if the index is negative
        """

    @property
    def lastNonEmptyIndex(self) -> jpype.JInt:
        ...


class IntIndexManager(java.io.Serializable):
    """
    Class to generate int indexes to be used for arrays or tables.  If a location
    or entry in a table becomes available, the index for that location is released.
    This class manages the use and reuse of those indexes.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        """
        Constructs an IntIndexManager.
        """

    def allocate(self) -> int:
        """
        Returns the smallest unused index value.
        
        :raises IndexOutOfBoundsException: thrown if there are no unused
        indexes.
        """

    def clear(self):
        """
        frees all index values.
        """

    def deallocate(self, index: typing.Union[jpype.JInt, int]):
        """
        Returns the index value so that it can be reused.
        
        :param jpype.JInt or int index: the index to be free'd for reuse.
        """


class StringArrayArray(Array, java.io.Serializable):
    """
    Array of String[] that grows as needed.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        """
        Constructor for StringArrayArray.
        """

    def copyDataTo(self, index: typing.Union[jpype.JInt, int], table: DataTable, toIndex: typing.Union[jpype.JInt, int], toCol: typing.Union[jpype.JInt, int]):
        """
        
        
        
        .. seealso::
        
            | :obj:`Array.copyDataTo(int, DataTable, int, int)`
        """

    def get(self, index: typing.Union[jpype.JInt, int]) -> jpype.JArray[java.lang.String]:
        """
        Retrieves the String array stored at the given index.
        
        :param jpype.JInt or int index: the index at which to retrieve the array.
        :return: String[] the String array at the index.
        :rtype: jpype.JArray[java.lang.String]
        """

    def getLastNonEmptyIndex(self) -> int:
        """
        
        
        
        .. seealso::
        
            | :obj:`Array.getLastNonEmptyIndex()`
        """

    def put(self, index: typing.Union[jpype.JInt, int], value: jpype.JArray[java.lang.String]):
        """
        Stores the string array at the given index.
        
        :param jpype.JInt or int index: the index to store the array
        :param jpype.JArray[java.lang.String] value: the array to store
        """

    def remove(self, index: typing.Union[jpype.JInt, int]):
        """
        
        
        
        .. seealso::
        
            | :obj:`Array.remove(int)`
        """

    @property
    def lastNonEmptyIndex(self) -> jpype.JInt:
        ...


class Counter(org.apache.commons.lang3.mutable.MutableInt):
    """
    Simple class used to avoid immutable objects and autoboxing when storing changing integer 
    primitives in a collection.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        Construct a new counter with an initial value of 0.
        """

    @typing.overload
    def __init__(self, value: typing.Union[jpype.JInt, int]):
        """
        Construct a new Counter with the given initial value.
        
        :param jpype.JInt or int value: the initial value
        """

    def count(self) -> int:
        """
        Returns the value of this counter.
        
        :return: the value of this counter
        :rtype: int
        """


class ObjectIntHashtable(java.lang.Object, typing.Generic[T]):
    """
    Class that implements a hashtable with Object keys and int values.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        Default constructor creates a table with an initial default capacity.
        """

    @typing.overload
    def __init__(self, capacity: typing.Union[jpype.JInt, int]):
        """
        Constructor creates a table with an initial given capacity.  The capacity
        will be adjusted to the next highest prime in the PRIMES table.
        
        :param jpype.JInt or int capacity: the initial capacity.
        """

    def contains(self, key: java.lang.Object) -> bool:
        """
        Return true if the given key is in the hashtable.
        
        :param java.lang.Object key: the key whose presence in this map is to be tested.
        """

    def get(self, key: T) -> int:
        """
        Returns the value for the given key.
        
        :param T key: the key whose associated value is to be returned.
        :raises NoValueException: thrown if there is no value for the given key.
        """

    def getKeys(self, keyArray: jpype.JArray[T]) -> jpype.JArray[T]:
        """
        Returns an array containing all the key objects.
        """

    def put(self, key: T, value: typing.Union[jpype.JInt, int]):
        """
        Adds a key/value pair to the hashtable. If the key is already in the table,
        the old value is replaced with the new value.  If the hashtable is already
        full, the hashtable will attempt to approximately double in size
        (it will use a prime number), and all the current entries will
        be rehashed.
        
        :param T key: the key to associate with the given value.
        :param jpype.JInt or int value: the value to associate with the given key.
        :raises ArrayIndexOutOfBoundsException: thrown if the maximum capacity is
        reached.
        """

    def remove(self, key: T) -> bool:
        """
        Removes a key from the hashtable
        
        :param T key: key to be removed from the hashtable.
        :return: true if key is found and removed, false otherwise.
        :rtype: bool
        """

    def removeAll(self):
        """
        Remove all entries from the hashtable.
        """

    def size(self) -> int:
        """
        Return the number of key/value pairs stored in the hashtable.
        """

    @property
    def keys(self) -> jpype.JArray[T]:
        ...


class ManagedDataTable(DataTable):
    """
    Data table that keeps track of rows that are occupied.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def getMaxRow(self) -> int:
        """
        Returns the max row that contains data.
        """

    def hasRow(self, row: typing.Union[jpype.JInt, int]) -> bool:
        """
        returns true if the given row contains an object
        
        :param jpype.JInt or int row: the row in the table
        :return: true if the given row contains an object
        :rtype: bool
        """

    def putBoolean(self, row: typing.Union[jpype.JInt, int], col: typing.Union[jpype.JInt, int], value: typing.Union[jpype.JBoolean, bool]):
        """
        Stores a boolean value in the table at the given row
        and column.  Note - all values in a given column must be
        of the same type.
        
        :param jpype.JInt or int row: The row into the table (specifies which object)
        :param jpype.JInt or int col: The column of the table.  (specifies which field)
        :param jpype.JBoolean or bool value: The value to store.
        """

    def putByte(self, row: typing.Union[jpype.JInt, int], col: typing.Union[jpype.JInt, int], value: typing.Union[jpype.JByte, int]):
        """
        Stores a byte value in the table at the given row
        and column.  Note - all values in a given column must be
        of the same type.
        
        :param jpype.JInt or int row: The row into the table (specifies which object)
        :param jpype.JInt or int col: The column of the table.  (specifies which field)
        :param jpype.JByte or int value: The value to store.
        """

    def putByteArray(self, row: typing.Union[jpype.JInt, int], col: typing.Union[jpype.JInt, int], value: jpype.JArray[jpype.JByte]):
        """
        Stores an byte array in the table at the given row
        and column.  Note - all values in a given column must be
        of the same type.
        
        :param jpype.JInt or int row: The row into the table (specifies which object)
        :param jpype.JInt or int col: The column of the table.  (specifies which field)
        :param jpype.JArray[jpype.JByte] value: The value to store.
        """

    def putDouble(self, row: typing.Union[jpype.JInt, int], col: typing.Union[jpype.JInt, int], value: typing.Union[jpype.JDouble, float]):
        """
        Stores a double value in the table at the given row
        and column.  Note - all values in a given column must be
        of the same type.
        
        :param jpype.JInt or int row: The row into the table (specifies which object)
        :param jpype.JInt or int col: The column of the table.  (specifies which field)
        :param jpype.JDouble or float value: The value to store.
        """

    def putDoubleArray(self, row: typing.Union[jpype.JInt, int], col: typing.Union[jpype.JInt, int], value: jpype.JArray[jpype.JDouble]):
        """
        Stores a double array in the table at the given row
        and column.  Note - all values in a given column must be
        of the same type.
        
        :param jpype.JInt or int row: The row into the table (specifies which object)
        :param jpype.JInt or int col: The column of the table.  (specifies which field)
        :param jpype.JArray[jpype.JDouble] value: The value to store.
        """

    def putFloat(self, row: typing.Union[jpype.JInt, int], col: typing.Union[jpype.JInt, int], value: typing.Union[jpype.JFloat, float]):
        """
        Stores a float value in the table at the given row
        and column.  Note - all values in a given column must be
        of the same type.
        
        :param jpype.JInt or int row: The row into the table (specifies which object)
        :param jpype.JInt or int col: The column of the table.  (specifies which field)
        :param jpype.JFloat or float value: The value to store.
        """

    def putFloatArray(self, row: typing.Union[jpype.JInt, int], col: typing.Union[jpype.JInt, int], value: jpype.JArray[jpype.JFloat]):
        """
        Stores a float array in the table at the given row
        and column.  Note - all values in a given column must be
        of the same type.
        
        :param jpype.JInt or int row: The row into the table (specifies which object)
        :param jpype.JInt or int col: The column of the table.  (specifies which field)
        :param jpype.JArray[jpype.JFloat] value: The value to store.
        """

    def putInt(self, row: typing.Union[jpype.JInt, int], col: typing.Union[jpype.JInt, int], value: typing.Union[jpype.JInt, int]):
        """
        Stores an int value in the table at the given row
        and column.  Note - all values in a given column must be
        of the same type.
        
        :param jpype.JInt or int row: The row into the table (specifies which object)
        :param jpype.JInt or int col: The column of the table.  (specifies which field)
        :param jpype.JInt or int value: The value to store.
        """

    def putIntArray(self, row: typing.Union[jpype.JInt, int], col: typing.Union[jpype.JInt, int], value: jpype.JArray[jpype.JInt]):
        """
        Stores an int array in the table at the given row
        and column.  Note - all values in a given column must be
        of the same type.
        
        :param jpype.JInt or int row: The row into the table (specifies which object)
        :param jpype.JInt or int col: The column of the table.  (specifies which field)
        :param jpype.JArray[jpype.JInt] value: The value to store.
        """

    def putLong(self, row: typing.Union[jpype.JInt, int], col: typing.Union[jpype.JInt, int], value: typing.Union[jpype.JLong, int]):
        """
        Stores a long value in the table at the given row
        and column.  Note - all values in a given column must be
        of the same type.
        
        :param jpype.JInt or int row: The row into the table (specifies which object)
        :param jpype.JInt or int col: The column of the table.  (specifies which field)
        :param jpype.JLong or int value: The value to store.
        """

    def putLongArray(self, row: typing.Union[jpype.JInt, int], col: typing.Union[jpype.JInt, int], value: jpype.JArray[jpype.JLong]):
        """
        Stores an long array in the table at the given row
        and column.  Note - all values in a given column must be
        of the same type.
        
        :param jpype.JInt or int row: The row into the table (specifies which object)
        :param jpype.JInt or int col: The column of the table.  (specifies which field)
        :param jpype.JArray[jpype.JLong] value: The value to store.
        """

    def putShort(self, row: typing.Union[jpype.JInt, int], col: typing.Union[jpype.JInt, int], value: typing.Union[jpype.JShort, int]):
        """
        Stores a short value in the table at the given row
        and column.  Note - all values in a given column must be
        of the same type.
        
        :param jpype.JInt or int row: The row into the table (specifies which object)
        :param jpype.JInt or int col: The column of the table.  (specifies which field)
        :param jpype.JShort or int value: The value to store.
        """

    def putShortArray(self, row: typing.Union[jpype.JInt, int], col: typing.Union[jpype.JInt, int], value: jpype.JArray[jpype.JShort]):
        """
        Stores an short array in the table at the given row
        and column.  Note - all values in a given column must be
        of the same type.
        
        :param jpype.JInt or int row: The row into the table (specifies which object)
        :param jpype.JInt or int col: The column of the table.  (specifies which field)
        :param jpype.JArray[jpype.JShort] value: The value to store.
        """

    def putString(self, row: typing.Union[jpype.JInt, int], col: typing.Union[jpype.JInt, int], value: typing.Union[java.lang.String, str]):
        """
        Stores an String in the table at the given row
        and column.  Note - all values in a given column must be
        of the same type.
        
        :param jpype.JInt or int row: The row into the table (specifies which object)
        :param jpype.JInt or int col: The column of the table.  (specifies which field)
        :param java.lang.String or str value: The value to store.
        """

    def removeRow(self, row: typing.Union[jpype.JInt, int]):
        """
        Removes the given row from the table.
        
        :param jpype.JInt or int row: The row to be removed
        """

    @property
    def maxRow(self) -> jpype.JInt:
        ...


class StringKeyIndexer(java.io.Serializable):
    """
    This class converts arbitrary Strings into compacted int indexes suitable
    for use as indexes into an array or table.  Whenever a new key is added,
    the smallest unused index is allocated and associated with that key.
    Basically hashes the keys into linked lists using the IntListIndexer class,
    where all values in a list have
    the same hashcode.  Does most of the work in implementing a separate chaining
    version of a hashtable - the only thing missing is the values which are stored
    in the individual implementations of the various hashtables.
    """

    @typing.type_check_only
    class KeyIterator(java.util.Iterator[java.lang.String]):

        class_: typing.ClassVar[java.lang.Class]

        def hasNext(self) -> bool:
            ...

        def next(self) -> str:
            ...

        def remove(self):
            ...


    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        Constructs a StringKeyIndexer with a default capacity.
        """

    @typing.overload
    def __init__(self, capacity: typing.Union[jpype.JInt, int]):
        """
        Constructs a StringKeyIndexer with a given initial capacity.
        
        :param jpype.JInt or int capacity: the initial capacity.
        """

    def clear(self):
        """
        Remove all keys.
        """

    def get(self, key: typing.Union[java.lang.String, str]) -> int:
        """
        Returns the index for the given key, or
        -1 if key is not in the table.
        
        :param java.lang.String or str key: the key for which to find an index.
        """

    def getCapacity(self) -> int:
        """
        Returns the current size of the key table.
        """

    def getKeyIterator(self) -> java.util.Iterator[java.lang.String]:
        """
        Returns an iterator over all the keys.
        
        :return: an iterator over all the keys.
        :rtype: java.util.Iterator[java.lang.String]
        """

    def getKeys(self) -> jpype.JArray[java.lang.String]:
        """
        Returns an array containing all the keys stored in this object.
        """

    def getSize(self) -> int:
        """
        Returns the number of keys stored in the table.
        """

    def put(self, key: typing.Union[java.lang.String, str]) -> int:
        """
        Returns an index that will always be associated to the given key as long as
        the key remains in the table. If the key already exists, then the index where
        that key is stored is returned.  If the key is new, then a new index is allocated,
        the key is stored at that index, and the new index is returned.
        
        :param java.lang.String or str key: the key to be stored.
        :return: index for key, or -1 if there was no room to put the key.
        :rtype: int
        :raises IndexOutOfBoundsException: thrown if this object is at maximum capacity.
        """

    def remove(self, key: typing.Union[java.lang.String, str]) -> int:
        """
        Removes the key from the table.
        
        :param java.lang.String or str key: the key to remove.
        :return: index of the key if the key was found, -1 if
        key did not exist in the table
        :rtype: int
        """

    @property
    def keyIterator(self) -> java.util.Iterator[java.lang.String]:
        ...

    @property
    def size(self) -> jpype.JInt:
        ...

    @property
    def keys(self) -> jpype.JArray[java.lang.String]:
        ...

    @property
    def capacity(self) -> jpype.JInt:
        ...


class PriorityQueue(java.lang.Object, typing.Generic[T]):
    """
    Maintains a list of objects in priority order where priority is just 
    an integer value.  The object with the lowest
    priority number can be retrieved using getFirst() and the object with the highest
    priority number can be retrieved using getLast().
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def add(self, obj: T, priority: typing.Union[jpype.JInt, int]):
        """
        Adds the given object to the queue at the appropriate insertion point based
        on the given priority.
        
        :param T obj: the object to be added.
        :param jpype.JInt or int priority: the priority assigned to the object.
        """

    def clear(self):
        """
        Removes all objects from the queue.
        """

    def getFirst(self) -> T:
        """
        Returns the object with the lowest priority number in the queue.
        If more than one object has the same priority, then the object that
        was added to the queue first is considered to have the lower priority value.
        Null is returned if the queue is empty.
        """

    def getFirstPriority(self) -> int:
        """
        Returns the priority of the object with the lowest priority in the queue.
        Null returned if the queue is empty.
        """

    def getLast(self) -> T:
        """
        Returns the object with the highest priority number in the queue.
        If more than one object has the same priority, then the object that
        was added to the queue last is considered to have the higher priority value.
        Null is returned if the queue is empty.
        """

    def getLastPriority(self) -> int:
        """
        Returns the priority of the object with the highest priority in the queue.
        Null returned if the queue is empty.
        """

    def isEmpty(self) -> bool:
        """
        Returns true if the queue is empty.
        """

    def removeFirst(self) -> T:
        """
        Removes and returns the object with the lowest priority number in the queue.
        If more than one object has the same priority, then the object that
        was added to the queue first is considered to have the lower priority value.
        Null is returned if the queue is empty.
        
        :return: the object with the lowest priority number or null if the list is empty.
        :rtype: T
        """

    def removeLast(self) -> T:
        """
        Removes and returns the object with the highest priority number in the queue.
        If more than one object has the same priority, then the object that
        was added to the queue last is considered to have the higher priority value.
        Null is returned if the queue is empty.
        
        :return: the object with the highest priority number or null if the list is empty.
        :rtype: T
        """

    def size(self) -> int:
        """
        Returns the number of objects in the queue.
        """

    @property
    def last(self) -> T:
        ...

    @property
    def lastPriority(self) -> jpype.JInt:
        ...

    @property
    def firstPriority(self) -> jpype.JInt:
        ...

    @property
    def first(self) -> T:
        ...

    @property
    def empty(self) -> jpype.JBoolean:
        ...


class SoftCacheMap(java.util.Map[K, V], typing.Generic[K, V]):
    """
    Class to manage a "soft" HaspMap that keeps its keys as soft references so
    they can be reclaimed if needed. Useful for caching.
    """

    @typing.type_check_only
    class MySoftReference(java.lang.ref.SoftReference[V]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, cacheSize: typing.Union[jpype.JInt, int]):
        """
        Constructs a new SoftCacheMap that has at most cacheSize entries.
        
        :param jpype.JInt or int cacheSize: the max number of entries to cache.
        """


class FloatArray(Array, java.io.Serializable):
    """
    Array of floats that grows as needed.
    """

    class_: typing.ClassVar[java.lang.Class]
    MIN_SIZE: typing.Final = 4

    def __init__(self):
        """
        Creates new FloatArray
        """

    def copyDataTo(self, index: typing.Union[jpype.JInt, int], table: DataTable, toIndex: typing.Union[jpype.JInt, int], toCol: typing.Union[jpype.JInt, int]):
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.util.datastruct.Array.copyDataTo(int, DataTable, int, int)`
        """

    def get(self, index: typing.Union[jpype.JInt, int]) -> float:
        """
        Returns the int at the given index
        
        :param jpype.JInt or int index: index into the array
        :return: The int value at the given index. A 0 will
        be return for any index not initialized to
        another value.
        :rtype: float
        :raises IndexOutOfBoundsException: if the index is negative
        """

    def getLastNonEmptyIndex(self) -> int:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.util.datastruct.Array.getLastNonEmptyIndex()`
        """

    def put(self, index: typing.Union[jpype.JInt, int], value: typing.Union[jpype.JFloat, float]):
        """
        Puts the given float value in the float array at
        the given index
        
        :param jpype.JInt or int index: Index into the array.
        :param jpype.JFloat or float value: value to store
        :raises IndexOutOfBoundsException: if the index is negative
        """

    def remove(self, index: typing.Union[jpype.JInt, int]):
        """
        Sets the value at the given index to 0.
        
        :param jpype.JInt or int index: the index to set to 0.
        :raises IndexOutOfBoundsException: if the index is negative
        """

    @property
    def lastNonEmptyIndex(self) -> jpype.JInt:
        ...


class SortedRangeList(java.lang.Iterable[Range]):
    """
    Provides a list of integer ranges that are maintained in sorted order.  When a range is added
    any ranges that overlap or are adjacent to one another will coalesce into a single range.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        Creates a new empty sorted range list.
        """

    @typing.overload
    def __init__(self, list: SortedRangeList):
        """
        Creates a new sorted range list with ranges equivalent to those in the specified list.
        
        :param SortedRangeList list: the sorted range list to make an equivalent copy of.
        """

    def addRange(self, min: typing.Union[jpype.JInt, int], max: typing.Union[jpype.JInt, int]):
        """
        Adds the range from min to max to this sorted range list.  If the range is adjacent to or
        overlaps any other existing ranges,  then those ranges will coalesce.
        
        :param jpype.JInt or int min: the range minimum
        :param jpype.JInt or int max: the range maximum (inclusive)
        """

    def clear(self):
        ...

    @typing.overload
    def contains(self, value: typing.Union[jpype.JInt, int]) -> bool:
        """
        Returns true if the value is contained in any ranges within this list.
        
        :param jpype.JInt or int value: the value to check for.
        :return: true if the value is contained in any ranges within this list.
        :rtype: bool
        """

    @typing.overload
    def contains(self, min: typing.Union[jpype.JInt, int], max: typing.Union[jpype.JInt, int]) -> bool:
        """
        Returns true if a single range contains all the values from min to max.
        
        :param jpype.JInt or int min: the minimum value
        :param jpype.JInt or int max: the maximum value
        :return: true if a single range contains all the values from min to max.
        :rtype: bool
        """

    def getMax(self) -> int:
        """
        Returns the maximum int value in this sorted range list.
        
        :return: the max value
        :rtype: int
        :raises NoSuchElementException: if the list is empty.
        """

    def getMin(self) -> int:
        """
        Returns the minimum int value in this sorted range list.
        
        :return: the min value
        :rtype: int
        :raises NoSuchElementException: if the list is empty.
        """

    def getNumRanges(self) -> int:
        """
        Returns the number of ranges in the list.
        
        :return: the number of ranges
        :rtype: int
        """

    def getNumValues(self) -> int:
        """
        Gets the total number of int values in this range.
        
        :return: the number of int values.
        :rtype: int
        """

    def getRange(self, index: typing.Union[jpype.JInt, int]) -> Range:
        """
        Gets the nth range in this list as indicated by the value of index.
        
        :param jpype.JInt or int index: value indicating which nth range to get.
        :return: the range or null if there is no such range in this list.
        :rtype: Range
        """

    def getRangeIndex(self, value: typing.Union[jpype.JInt, int]) -> int:
        """
        Gets the range index for the range containing the specified value.
        
        :param jpype.JInt or int value: the value to look for.
        :return: the range index or a negative value if the range list doesn't contain the value.
        :rtype: int
        """

    @typing.overload
    def getRanges(self) -> java.util.Iterator[Range]:
        """
        Returns an iterator over all the ranges in this list.
        
        :return: the iterator
        :rtype: java.util.Iterator[Range]
        """

    @typing.overload
    def getRanges(self, forward: typing.Union[jpype.JBoolean, bool]) -> java.util.Iterator[Range]:
        """
        Returns an iterator over all the ranges in this list that iterates in the direction
        specified.
        
        :param jpype.JBoolean or bool forward: true indicates to iterate forward from minimum to maximum range; false
        indicates backward iteration form maximum to minimum.
        :return: the iterator
        :rtype: java.util.Iterator[Range]
        """

    def intersect(self, other: SortedRangeList) -> SortedRangeList:
        """
        Creates a new SortedRangeList that is the intersection of this range list and the other
        range list specified.
        
        :param SortedRangeList other: the other range list
        :return: the new SortedRangeList representing the intersection.
        :rtype: SortedRangeList
        """

    def intersects(self, min: typing.Union[jpype.JInt, int], max: typing.Union[jpype.JInt, int]) -> bool:
        """
        Returns true if the range from min to max intersects (overlaps) any ranges in this sorted
        range list.
        
        :param jpype.JInt or int min: the range minimum value.
        :param jpype.JInt or int max: the range maximum value.
        :return: true if the range from min to max intersects (overlaps) any ranges in this sorted
        range list.
        :rtype: bool
        """

    def isEmpty(self) -> bool:
        """
        Returns true if the range list is empty.
        
        :return: true if the range list is empty.
        :rtype: bool
        """

    def remove(self, other: SortedRangeList):
        """
        Removes all the ranges that are in the specified other list from this list.
        
        :param SortedRangeList other: the other sorted range list.
        """

    def removeRange(self, min: typing.Union[jpype.JInt, int], max: typing.Union[jpype.JInt, int]):
        """
        Removes the indicated range of values from the list. This will remove
        any ranges or portion of ranges that overlap the indicated range.
        
        :param jpype.JInt or int min: the minimum value for the range to remove.
        :param jpype.JInt or int max: the maximum value for the range to remove.
        """

    @property
    def rangeIndex(self) -> jpype.JInt:
        ...

    @property
    def min(self) -> jpype.JInt:
        ...

    @property
    def ranges(self) -> java.util.Iterator[Range]:
        ...

    @property
    def max(self) -> jpype.JInt:
        ...

    @property
    def range(self) -> Range:
        ...

    @property
    def numValues(self) -> jpype.JLong:
        ...

    @property
    def numRanges(self) -> jpype.JInt:
        ...

    @property
    def empty(self) -> jpype.JBoolean:
        ...


class ObjectKeyIndexer(java.lang.Object, typing.Generic[T]):
    """
    This class converts arbitrary Objects into compacted int indexes suitable
    for use as indexes into an array or table.  Whenever a new key is added,
    the smallest unused index is allocated and associated with that key.
    Basically hashes the keys into linked lists using the IntListIndexer class,
    where all values in a list have
    the same hashcode.  Does most of the work in implementing a separate chaining
    version of a hashtable - the only thing missing is the values which are stored
    in the individual implementations of the various hashtables.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        Constructs an ObjectKeyIndexer with a default capacity.
        """

    @typing.overload
    def __init__(self, capacity: typing.Union[jpype.JInt, int]):
        """
        Constructs an ObjectKeyIndexer with a given initial capacity.
        
        :param jpype.JInt or int capacity: the initial capacity.
        """

    def clear(self):
        """
        Remove all keys.
        """

    def get(self, key: java.lang.Object) -> int:
        """
        Returns the index for the given key, or
        -1 if key is not in the table.
        
        :param java.lang.Object key: the key for which to find an index.
        """

    def getCapacity(self) -> int:
        """
        Returns the current size of the key table.
        """

    def getKeys(self, keyArray: jpype.JArray[T]) -> jpype.JArray[T]:
        ...

    def getSize(self) -> int:
        """
        Returns the number of keys stored in the table.
        """

    def put(self, key: T) -> int:
        """
        Returns an index that will always be associated to the given key as long as
        the key remains in the table. If the key already exists, then the index where
        that key is stored is returned.  If the key is new, then a new index is allocated,
        the key is stored at that index, and the new index is returned.
        
        :param T key: the key to be stored.
        :return: index for key, or -1 if there was no room to put the key.
        :rtype: int
        :raises IndexOutOfBoundsException: thrown if this object is at maximum capacity.
        """

    def remove(self, key: java.lang.Object) -> int:
        """
        Removes the key from the table.
        
        :param java.lang.Object key: the key to remove.
        :return: index of the key if the key was found, -1 if
        key did not exist in the table
        :rtype: int
        """

    @property
    def size(self) -> jpype.JInt:
        ...

    @property
    def keys(self) -> jpype.JArray[T]:
        ...

    @property
    def capacity(self) -> jpype.JInt:
        ...


class StringIntHashtable(java.io.Serializable):
    """
    Class that implements a hashtable with String keys and int values.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        Default constructor creates a table with an initial default capacity.
        """

    @typing.overload
    def __init__(self, capacity: typing.Union[jpype.JInt, int]):
        """
        Constructor creates a table with an initial given capacity.  The capacity
        will be adjusted to the next highest prime in the PRIMES table.
        
        :param jpype.JInt or int capacity: the initial capacity.
        """

    def contains(self, key: typing.Union[java.lang.String, str]) -> bool:
        """
        Return true if the given key is in the hashtable.
        
        :param java.lang.String or str key: the key whose presence in this map is to be tested.
        """

    def get(self, key: typing.Union[java.lang.String, str]) -> int:
        """
        Returns the value for the given key.
        
        :param java.lang.String or str key: the key whose associated value is to be returned.
        :raises NoValueException: thrown if there is no value for the given key.
        """

    def getKeyIterator(self) -> java.util.Iterator[java.lang.String]:
        """
        Returns an iterator over the strings in 
        this hash table.
        """

    def getKeys(self) -> jpype.JArray[java.lang.String]:
        """
        Returns an array containing all the String keys.
        """

    def put(self, key: typing.Union[java.lang.String, str], value: typing.Union[jpype.JInt, int]):
        """
        Adds a key/value pair to the hashtable. If the key is already in the table,
        the old value is replaced with the new value.  If the hashtable is already
        full, the hashtable will attempt to approximately double in size
        (it will use a prime number), and all the current entries will
        be rehashed.
        
        :param java.lang.String or str key: the key to associate with the given value.
        :param jpype.JInt or int value: the value to associate with the given key.
        :raises ArrayIndexOutOfBoundsException: thrown if the maximum capacity is
        reached.
        """

    def remove(self, key: typing.Union[java.lang.String, str]) -> bool:
        """
        Removes a key from the hashtable
        
        :param java.lang.String or str key: key to be removed from the hashtable.
        :return: true if key is found and removed, false otherwise.
        :rtype: bool
        """

    def removeAll(self):
        """
        Remove all entries from the hashtable.
        """

    def size(self) -> int:
        """
        Return the number of key/value pairs stored in the hashtable.
        """

    @property
    def keyIterator(self) -> java.util.Iterator[java.lang.String]:
        ...

    @property
    def keys(self) -> jpype.JArray[java.lang.String]:
        ...


class StringArray(Array, java.io.Serializable):
    """
    Array of Strings that grows as needed.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        """
        Creates new StringArray
        """

    def copyDataTo(self, index: typing.Union[jpype.JInt, int], table: DataTable, toIndex: typing.Union[jpype.JInt, int], toCol: typing.Union[jpype.JInt, int]):
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.util.datastruct.Array.copyDataTo(int, ghidra.util.datastruct.DataTable, int, int)`
        """

    def get(self, index: typing.Union[jpype.JInt, int]) -> str:
        """
        Returns the String at the given index
        
        :param jpype.JInt or int index: index into the array
        :return: The String  at the given index. A null will
        be return for any index not initialized to
        another value.
        :rtype: str
        """

    def getLastNonEmptyIndex(self) -> int:
        """
        Returns the index of the last non-null or non-zero element in the array.
        """

    def put(self, index: typing.Union[jpype.JInt, int], value: typing.Union[java.lang.String, str]):
        """
        Puts the given String value in the String array at
        the given index
        
        :param jpype.JInt or int index: Index into the array.
        :param java.lang.String or str value: value to store
        """

    def remove(self, index: typing.Union[jpype.JInt, int]):
        """
        Removes the string at the given index
        
        :param jpype.JInt or int index: index of the string to be removed
        """

    @property
    def lastNonEmptyIndex(self) -> jpype.JInt:
        ...


class FullKeySet(ShortKeySet, java.io.Serializable):
    """
    Implementation of the ShortKeySet interface that always contains
    all the possible keys.  Used to save storage when sets are full.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, numKeys: typing.Union[jpype.JInt, int]):
        """
        Construct a new FullKeySet
        
        :param jpype.JInt or int numKeys: the number of keys in the set.
        """

    def containsKey(self, key: typing.Union[jpype.JShort, int]) -> bool:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.util.datastruct.ShortKeySet.containsKey(short)`
        """

    def getFirst(self) -> int:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.util.datastruct.ShortKeySet.getFirst()`
        """

    def getLast(self) -> int:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.util.datastruct.ShortKeySet.getLast()`
        """

    def getNext(self, key: typing.Union[jpype.JShort, int]) -> int:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.util.datastruct.ShortKeySet.getNext(short)`
        """

    def getPrevious(self, key: typing.Union[jpype.JShort, int]) -> int:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.util.datastruct.ShortKeySet.getPrevious(short)`
        """

    def isEmpty(self) -> bool:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.util.datastruct.ShortKeySet.isEmpty()`
        """

    def put(self, key: typing.Union[jpype.JShort, int]):
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.util.datastruct.ShortKeySet.put(short)`
        """

    def remove(self, key: typing.Union[jpype.JShort, int]) -> bool:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.util.datastruct.ShortKeySet.remove(short)`
        """

    def removeAll(self):
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.util.datastruct.ShortKeySet.removeAll()`
        """

    def size(self) -> int:
        """
        Returns the number of keys currently in the set.
        """

    @property
    def next(self) -> jpype.JShort:
        ...

    @property
    def previous(self) -> jpype.JShort:
        ...

    @property
    def last(self) -> jpype.JShort:
        ...

    @property
    def first(self) -> jpype.JShort:
        ...

    @property
    def empty(self) -> jpype.JBoolean:
        ...


class QueueStub(java.util.Queue[E], typing.Generic[E]):
    """
    A do-nothing, stubbed version of the :obj:`Queue` interface.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class LongLongHashtable(java.io.Serializable):
    """
    Class that implements a hashtable with long keys and long values.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        Default constructor creates a table with an initial default capacity.
        """

    @typing.overload
    def __init__(self, capacity: typing.Union[jpype.JInt, int]):
        """
        Constructor creates a table with an initial given capacity.  The capacity
        will be adjusted to the next highest prime in the PRIMES table.
        
        :param jpype.JInt or int capacity: the initial capacity.
        """

    def contains(self, key: typing.Union[jpype.JLong, int]) -> bool:
        """
        Return true if the given key is in the hashtable.
        
        :param jpype.JLong or int key: the key whose presence in this map is to be tested.
        """

    def get(self, key: typing.Union[jpype.JLong, int]) -> int:
        """
        Returns the value for the given key.
        
        :param jpype.JLong or int key: the key whose associated value is to be returned.
        :raises NoValueException: thrown if there is no value for the given key.
        """

    def getKeys(self) -> jpype.JArray[jpype.JLong]:
        """
        Returns an array containing all the long keys.
        """

    def put(self, key: typing.Union[jpype.JLong, int], value: typing.Union[jpype.JLong, int]):
        """
        Adds a key/value pair to the hashtable. If the key is already in the table,
        the old value is replaced with the new value.  If the hashtable is already
        full, the hashtable will attempt to approximately double in size
        (it will use a prime number), and all the current entries will
        be rehashed.
        
        :param jpype.JLong or int key: the key to associate with the given value.
        :param jpype.JLong or int value: the value to associate with the given key.
        :raises ArrayIndexOutOfBoundsException: thrown if the maximum capacity is
        reached.
        """

    def remove(self, key: typing.Union[jpype.JLong, int]) -> bool:
        """
        Removes a key from the hashtable
        
        :param jpype.JLong or int key: key to be removed from the hashtable.
        :return: true if key is found and removed, false otherwise.
        :rtype: bool
        """

    def removeAll(self):
        """
        Remove all entries from the hashtable.
        """

    def size(self) -> int:
        """
        Return the number of key/value pairs stored in the hashtable.
        """

    @property
    def keys(self) -> jpype.JArray[jpype.JLong]:
        ...


class LongComparator(java.lang.Object):
    """
    Interface that defines a method for comparing two long values.
    """

    class_: typing.ClassVar[java.lang.Class]

    def compare(self, a: typing.Union[jpype.JLong, int], b: typing.Union[jpype.JLong, int]) -> int:
        """
        Compares the long values a and b.
        
        :param jpype.JLong or int a: the first value
        :param jpype.JLong or int b: the second value
        :return: 0 if a equals b; a number greater than 0 if a is greater than b;
        a number less than 0 if a is less than b.
        :rtype: int
        """


class DataStructureErrorHandlerFactory(java.lang.Object):
    """
    A class data structures can use to delegate error handling responsibilities to system-level
    decision making.  This allows for specialized error handling in testing mode.
    """

    @typing.type_check_only
    class DefaultListenerErrorHandler(ListenerErrorHandler):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def createListenerErrorHandler() -> ListenerErrorHandler:
        """
        Creates a :obj:`ListenerErrorHandler`
        
        :return: the error handler
        :rtype: ListenerErrorHandler
        """


class LRUMap(java.util.Map[K, V], typing.Generic[K, V]):
    """
    A LRU (Least Recently Used) map that maintains *access-order* (newest to oldest)
    iteration over the elements.
    This map is limited to the given size.
    As new items are added, the older items will be removed from this map.
     
    
    If you need to be notified of removals, then you can override
    :meth:`eldestEntryRemoved(java.util.Map.Entry) <.eldestEntryRemoved>`.
     
    
    If you don't want the eldest removed, override
    :meth:`removeEldestEntry(java.util.Map.Entry) <.removeEldestEntry>` and return false;
     
    
    If you would like to have the iteration order of your LRU structure be based upon access,
    but want it to iterate from least recently used to most recently used, then you should see
    :obj:`FixedSizeHashMap`.
     
    
    Note: this class is not thread safe.
    
    
    .. seealso::
    
        | :obj:`LinkedHashMap`
    
        | :obj:`FixedSizeHashMap`
    """

    @typing.type_check_only
    class LinkedIterator(java.util.Iterator[T], typing.Generic[T]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class KeyIterator(LRUMap.LinkedIterator[K]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ValueIterator(LRUMap.LinkedIterator[V]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class EntryIterator(LRUMap.LinkedIterator[java.util.Map.Entry[K, V]]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class Entry(java.util.Map.Entry[K, V], typing.Generic[K, V]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, cacheSize: typing.Union[jpype.JInt, int]):
        ...


class WeakDataStructureFactory(java.lang.Object):
    """
    Factory for creating containers to use in various threading environments
    
    Other non-weak listeners:
     
    * :obj:`ConcurrentListenerSet`
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def createCopyOnReadWeakSet() -> WeakSet[T]:
        """
        Use when mutations outweigh iterations.
        
        :return: a new WeakSet
        :rtype: WeakSet[T]
        
        .. seealso::
        
            | :obj:`CopyOnReadWeakSet`
        """

    @staticmethod
    def createCopyOnWriteWeakSet() -> WeakSet[T]:
        """
        Use when iterations outweigh mutations.
        
        :return: a new WeakSet
        :rtype: WeakSet[T]
        
        .. seealso::
        
            | :obj:`CopyOnWriteWeakSet`
        """

    @staticmethod
    def createSingleThreadAccessWeakSet() -> WeakSet[T]:
        """
        Use when all access are on a single thread, such as the Swing thread.
        
        :return: a new WeakSet
        :rtype: WeakSet[T]
        """


class IntArray(Array, java.io.Serializable):
    """
    Array of ints that grows as needed.
    """

    class_: typing.ClassVar[java.lang.Class]
    MIN_SIZE: typing.Final = 4

    def __init__(self):
        """
        Creates new intArray
        """

    def copyDataTo(self, index: typing.Union[jpype.JInt, int], table: DataTable, toIndex: typing.Union[jpype.JInt, int], toCol: typing.Union[jpype.JInt, int]):
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.util.datastruct.Array.copyDataTo(int, DataTable, int, int)`
        """

    def get(self, index: typing.Union[jpype.JInt, int]) -> int:
        """
        Returns the int at the given index
        
        :param jpype.JInt or int index: index into the array
        :return: The int value at the given index. A 0 will
        be return for any index not initialized to
        another value.
        :rtype: int
        :raises IndexOutOfBoundsException: if the index is negative
        """

    def getLastNonEmptyIndex(self) -> int:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.util.datastruct.Array.getLastNonEmptyIndex()`
        """

    def put(self, index: typing.Union[jpype.JInt, int], value: typing.Union[jpype.JInt, int]):
        """
        Puts the given int value in the int array at
        the given index
        
        :param jpype.JInt or int index: Index into the array.
        :param jpype.JInt or int value: value to store
        :raises IndexOutOfBoundsException: if the index is negative
        """

    def remove(self, index: typing.Union[jpype.JInt, int]):
        """
        Sets the value at the given index to 0.
        
        :param jpype.JInt or int index: the index to set to 0.
        :raises IndexOutOfBoundsException: if the index is negative
        """

    @property
    def lastNonEmptyIndex(self) -> jpype.JInt:
        ...


class FloatArrayArray(Array, java.io.Serializable):
    """
    Array of float[] that grows as needed.
    """

    class_: typing.ClassVar[java.lang.Class]
    serialVersionUID: typing.Final = 1

    def __init__(self):
        """
        Creates new floatArrayArray
        """

    def copyDataTo(self, index: typing.Union[jpype.JInt, int], table: DataTable, toIndex: typing.Union[jpype.JInt, int], toCol: typing.Union[jpype.JInt, int]):
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.util.datastruct.Array.copyDataTo(int, DataTable, int, int)`
        """

    def get(self, index: typing.Union[jpype.JInt, int]) -> jpype.JArray[jpype.JFloat]:
        """
        Returns the float at the given index
        
        :param jpype.JInt or int index: index into the array
        :return: The float array at the given index. An empty array will
        be returned for any index not initialized to
        another value.
        :rtype: jpype.JArray[jpype.JFloat]
        :raises IndexOutOfBoundsException: if the index is negative
        """

    def getLastNonEmptyIndex(self) -> int:
        """
        Returns the index of the last non-null or non-zero element in the array.
        """

    def put(self, index: typing.Union[jpype.JInt, int], value: jpype.JArray[jpype.JFloat]):
        """
        Puts the given float value in the float array at
        the given index
        
        :param jpype.JInt or int index: Index into the array.
        :param jpype.JArray[jpype.JFloat] value: value to store
        :raises IndexOutOfBoundsException: if the index is negative
        """

    def remove(self, index: typing.Union[jpype.JInt, int]):
        """
        Removes the array at the given index
        
        :param jpype.JInt or int index: index of the array to be removed
        :raises IndexOutOfBoundsException: if the index is negative
        """

    @property
    def lastNonEmptyIndex(self) -> jpype.JInt:
        ...


class ListenerSet(java.lang.Object, typing.Generic[T]):
    """
    A data structure meant to be used to hold listeners.  This class has a few benefits:
     
    * Clients supply the class of the listeners being stored.  Then, clients make use of a Java
    :obj:`Proxy` object to sends events by calling the desired method directly on the proxy.
    
    * This class is thread safe, allowing adding and removing listeners while events are being
        fired.
    
    * Weak or strong references may be used seamlessly by passing the correct constructor value.
    
    
    
     
    
    Some restrictions:
     
    * Exception handling is currently done by storing the first exception encountered while
        processing events.   Any exception encountered while notifying a listener does not stop
        follow-on listeners from getting notified.
    
    * Listener classes are restricted to using methods with a void return type, as there is
        currently no way to return values back to the client when notifying.
    
    * The insertion order of listeners is not maintained, which means that event notification may
        take place in an arbitrary order.
    
    
    
     
    
    An example use of this class to fire events could look like this:
     
        ListenerSet<ActionListener> listeners = new ListenerSet(ActionListener.class);
        ActionEvent event = new ActionEvent(this, 1, "Event");
        listeners.invoke().actionPerformed(event);
    """

    @typing.type_check_only
    class ListenerHandler(java.lang.reflect.InvocationHandler):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, iface: java.lang.Class[T], isWeak: typing.Union[jpype.JBoolean, bool]):
        """
        Constructs a listener set that is backed by weak references.
        
        :param java.lang.Class[T] iface: the listener class type.
        :param jpype.JBoolean or bool isWeak: true signals to use weak storage for the listeners.  If using weak storage,
                clients must keep a reference to the listener or it will eventually be removed from
                this data structure when garbage collected.
        """

    def add(self, e: T) -> bool:
        ...

    def clear(self):
        ...

    def getProxy(self) -> T:
        """
        Returns the proxy used by this class.  Using :meth:`invoke() <.invoke>` is preferred for better
        readability.
        
        :return: the proxy
        :rtype: T
        """

    def invoke(self) -> T:
        """
        Returns the proxy object.  Using this is the same as calling :meth:`getProxy() <.getProxy>`. Use this
        method to make the client call more readable.
        
        :return: the proxy
        :rtype: T
        """

    def remove(self, e: T) -> bool:
        ...

    def setErrorHandler(self, errorHandler: ListenerErrorHandler):
        ...

    def size(self) -> int:
        ...

    @property
    def proxy(self) -> T:
        ...


class LongArray(Array, java.io.Serializable):
    """
    Array of longs that grows as needed.
    """

    class_: typing.ClassVar[java.lang.Class]
    serialVersionUID: typing.Final = 1
    MIN_SIZE: typing.Final = 4

    def __init__(self):
        """
        Creates new LongArray
        """

    def copyDataTo(self, index: typing.Union[jpype.JInt, int], table: DataTable, toIndex: typing.Union[jpype.JInt, int], toCol: typing.Union[jpype.JInt, int]):
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.util.datastruct.Array.copyDataTo(int, ghidra.util.datastruct.DataTable, int, int)`
        """

    def get(self, index: typing.Union[jpype.JInt, int]) -> int:
        """
        Returns the long at the given index
        
        :param jpype.JInt or int index: index into the array
        :return: The long value at the given index. A 0 will
        be returned for any index not initialized to
        another value.
        :rtype: int
        :raises IndexOutOfBoundsException: if the index is negative
        """

    def getLastNonEmptyIndex(self) -> int:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.util.datastruct.Array.getLastNonEmptyIndex()`
        """

    def put(self, index: typing.Union[jpype.JInt, int], value: typing.Union[jpype.JLong, int]):
        """
        Puts the given long value in the long array at
        the given index
        
        :param jpype.JInt or int index: Index into the array.
        :param jpype.JLong or int value: value to store
        :raises IndexOutOfBoundsException: if the index is negative
        """

    def remove(self, index: typing.Union[jpype.JInt, int]):
        """
        Sets the value at the given index to 0.
        
        :param jpype.JInt or int index: the index to set to 0.
        :raises IndexOutOfBoundsException: if the index is negative
        """

    @property
    def lastNonEmptyIndex(self) -> jpype.JInt:
        ...


class SizeRestrictedAccumulatorWrapper(Accumulator[T], typing.Generic[T]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, accumulator: Accumulator[T], maxSize: typing.Union[jpype.JInt, int]):
        """
        Constructor.
        
        :param Accumulator[T] accumulator: the accumulator to pass items to
        :param jpype.JInt or int maxSize: the maximum number of items this accumulator will hold
        """


class WeakValueHashMap(AbstractWeakValueMap[K, V], typing.Generic[K, V]):
    """
    Class to provide a hash map with weak values.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        Constructs a new weak map
        """

    @typing.overload
    def __init__(self, initialSize: typing.Union[jpype.JInt, int]):
        """
        Constructs a new weak map with the given initial size
        
        :param jpype.JInt or int initialSize: the initial size of the backing map
        """


@typing.type_check_only
class CopyOnWriteWeakSet(WeakSet[T], typing.Generic[T]):
    """
    A set that avoids :obj:`ConcurrentModificationException`s by copying the internal storage
    **for every mutation operation**.  Thus, this data structure is only efficient when the
    number of event notification operations significantly out numbers mutations to this structure
    (e.g., adding and removing items.
     
    
    An example use case where using this class is a good fit would be a listener list where
    listeners are added during initialization, but not after that.   Further, this hypothetical
    list is used to fire a large number of events.
     
    
    A bad use of this class would be as a container to store widgets where the container the
    contents are changed often, but iterated very little.
     
    
    Finally, if this structure is only ever used from a single thread, like the Swing thread, then
    you do not need the overhead of this class, as the Swing thread synchronous access guarantees
    that the structure cannot be mutated while it is being iterated.  See
    :meth:`WeakDataStructureFactory.createSingleThreadAccessWeakSet() <WeakDataStructureFactory.createSingleThreadAccessWeakSet>`.
    
    
    .. seealso::
    
        | :obj:`WeakSet`
    """

    class_: typing.ClassVar[java.lang.Class]

    def addAll(self, c: collections.abc.Sequence) -> bool:
        """
        Adds all items to this set.
         
        
        Note: calling this method will only result in one copy operation.  If :meth:`add(Object) <.add>`
        were called instead for each item of the iterator, then each call would copy this set.
        
        :param collections.abc.Sequence c: the items
        """


class IntListIndexer(java.io.Serializable):
    """
    Class to manage multiple linked lists of int indexes. Users can add indexes
    to a list, remove indexes from a list, remove all indexes from a list, and
    retrieve all indexes within a given list.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, numLists: typing.Union[jpype.JInt, int], capacity: typing.Union[jpype.JInt, int]):
        """
        The constructor
        
        :param jpype.JInt or int numLists: - The initial number of lists to be managed.
        :param jpype.JInt or int capacity: - The current size of the pool of possible indexes.  All indexes
        begin on the free list.
        """

    def add(self, listID: typing.Union[jpype.JInt, int]) -> int:
        """
        Allocates a new index resource and adds it to the front of the linked list
        indexed by listID.
        
        :param jpype.JInt or int listID: the id of the list to add to.
        :raises IndexOutOfBoundsException: thrown if the listID is not in the
        the range [0, numLists).
        """

    def append(self, listID: typing.Union[jpype.JInt, int]) -> int:
        """
        Allocates a new index resource and adds it to the end of the linked list
        indexed by listID.
        
        :param jpype.JInt or int listID: the id of the list to add to.
        :raises IndexOutOfBoundsException: thrown if the listID is not in the
        the range [0, numLists).
        """

    def clear(self):
        """
        Removes all indexes from all lists.
        """

    def first(self, listID: typing.Union[jpype.JInt, int]) -> int:
        """
        Returns the first index resource on the linked list indexed by listID.
        
        :raises IndexOutOfBoundsException: thrown if the listID is not in the
        the range [0, numLists].
        """

    def getCapacity(self) -> int:
        """
        Returns the current index capacity.
        """

    def getListSize(self, listID: typing.Union[jpype.JInt, int]) -> int:
        """
        Returns the number of indexes in the specified list.
        
        :param jpype.JInt or int listID: the id of the list from which to get the number of indexes.
        :raises IndexOutOfBoundsException: thrown if the listID is not in the
        the range [0, numLists).
        """

    def getNewCapacity(self) -> int:
        """
        Computes the next size that should be used to grow the index capacity.
        """

    def getNumLists(self) -> int:
        """
        Returns the number of linked list being managed.
        """

    def getSize(self) -> int:
        """
        Returns the current number of used index resources.
        """

    def growCapacity(self, newCapacity: typing.Union[jpype.JInt, int]):
        """
        Increases the index resource pool.
        
        :param jpype.JInt or int newCapacity: the new number of resource indexes to manage.  if this number
        is smaller than the current number of resource indexes, then nothing changes.
        """

    def growNumLists(self, newListSize: typing.Union[jpype.JInt, int]):
        """
        Increases the number of managed linked lists.
        
        :param jpype.JInt or int newListSize: the new number of linked lists.  If this number is
        smaller than the current number of linked lists, then nothing changes.
        """

    def next(self, index: typing.Union[jpype.JInt, int]) -> int:
        """
        Returns the next index resource that follows the given index in a linked list.
        The index should be an index that is in some linked list.  Otherwise, the
        results are undefined( probably give you the next index on the free list )
        
        :param jpype.JInt or int index: the index to search after for the next index.
        :raises IndexOutOfBoundsException: thrown if the index is not in the
        the range [0, capacity].
        """

    def remove(self, listID: typing.Union[jpype.JInt, int], index: typing.Union[jpype.JInt, int]):
        """
        Remove the index resource from the linked list indexed by listID.
        
        :param jpype.JInt or int listID: the id of the list from which to removed the value at index.
        :param jpype.JInt or int index: the index of the value to be removed from the specified list.
        :raises IndexOutOfBoundsException: thrown if the listID is not in the
        the range [0, numLists).
        """

    def removeAll(self, listID: typing.Union[jpype.JInt, int]):
        """
        Removes all indexes from the specified list.
        
        :param jpype.JInt or int listID: the list to be emptied.
        """

    @property
    def size(self) -> jpype.JInt:
        ...

    @property
    def numLists(self) -> jpype.JInt:
        ...

    @property
    def newCapacity(self) -> jpype.JInt:
        ...

    @property
    def listSize(self) -> jpype.JInt:
        ...

    @property
    def capacity(self) -> jpype.JInt:
        ...


class LRUSet(LRUMap[T, T], java.lang.Iterable[T], typing.Generic[T]):
    """
    An ordered set-like data structure.   
     
    
    Use this when you need a collection of unique items (hence set) that are also ordered by 
    insertion time.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, size: typing.Union[jpype.JInt, int]):
        """
        Constructs this set with the given size.  As elements are added, the oldest elements 
        (by access time) will fall off the bottom of the set.
         
        
        If you do not wish to have a set bounded by size, then you can override 
        :meth:`removeEldestEntry(java.util.Map.Entry) <.removeEldestEntry>` to do nothing.
        
        :param jpype.JInt or int size: The size to which this set will be restricted.
        """

    def add(self, t: T):
        ...


class Range(java.lang.Comparable[Range], java.lang.Iterable[java.lang.Integer]):
    """
    A class for holding a minimum and maximum signed int values that define a range.
    """

    class_: typing.ClassVar[java.lang.Class]
    min: jpype.JInt
    """
    The range's minimum extent.
    """

    max: jpype.JInt
    """
    The range's maximum extent (inclusive).
    """


    def __init__(self, min: typing.Union[jpype.JInt, int], max: typing.Union[jpype.JInt, int]):
        """
        Creates a range whose extent is from min to max.
        
        :param jpype.JInt or int min: the minimum extent.
        :param jpype.JInt or int max: the maximum extent (inclusive).
        :raises IllegalArgumentException: if max is less than min.
        """

    def contains(self, value: typing.Union[jpype.JInt, int]) -> bool:
        """
        Returns true if the value is within the ranges extent.
        
        :param jpype.JInt or int value: the value to check.
        :return: true if the value is within the ranges extent.
        :rtype: bool
        """

    def size(self) -> int:
        """
        Returns the range's size.
        
        :return: the size
        :rtype: int
        """


class Duo(java.lang.Object, typing.Generic[T]):
    """
    Class for holding two objects of the same type. We are using the idiom of LEFT and RIGHT to 
    refer to each item in this pair of objects.
    The enum "Side" is used to represent either the LEFT (or first) or RIGHT (or second) item.
    """

    class Side(java.lang.Enum[Duo.Side]):

        class_: typing.ClassVar[java.lang.Class]
        LEFT: typing.Final[Duo.Side]
        RIGHT: typing.Final[Duo.Side]

        def otherSide(self) -> Duo.Side:
            ...

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> Duo.Side:
            ...

        @staticmethod
        def values() -> jpype.JArray[Duo.Side]:
            ...


    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        Constructor with no values.
        """

    @typing.overload
    def __init__(self, left: T, right: T):
        """
        Constructor with a left and right value.
        
        :param T left: the left value
        :param T right: the right value
        """

    def each(self, c: java.util.function.Consumer[T]):
        """
        Invokes the given consumer on both the left and right values.
        
        :param java.util.function.Consumer[T] c: the consumer to invoke on both values
        """

    def equals(self, otherLeft: T, otherRight: T) -> bool:
        """
        Returns true if both values are equals to this objects values.
        
        :param T otherLeft: the value to compare to our left side value
        :param T otherRight: the value to compare to our right side value
        :return: true if both values are equals to this objects values
        :rtype: bool
        """

    def get(self, side: Duo.Side) -> T:
        """
        Gets the value for the given side.
        
        :param Duo.Side side: LEFT or RIGHT
        :return: the value for the given side
        :rtype: T
        """

    def with_(self, side: Duo.Side, newValue: T) -> Duo[T]:
        """
        Creates a new Duo, replacing the value for just one side. The other side uses the value 
        from this Duo.
        
        :param Duo.Side side: the side that gets a new value
        :param T newValue: the new value for the given side
        :return: the new Duo
        value as this
        :rtype: Duo[T]
        """



__all__ = ["DoubleArray", "LongArrayList", "ObjectCache", "IntArrayArray", "Accumulator", "ByteArrayArray", "CallbackAccumulator", "ObjectRangeMap", "IntKeyIndexer", "SetAccumulator", "ListenerErrorHandler", "BooleanArray", "IntIntHashtable", "CaseInsensitiveDuplicateStringComparator", "AbstractWeakValueMap", "WeakValueTreeMap", "ShortArray", "ThreadUnsafeWeakSet", "Array", "BitTree", "CopyOnReadWeakSet", "Stack", "WeakSet", "ValueRange", "IndexRange", "IntObjectHashtable", "AccumulatorSizeException", "RedBlackEntry", "RedBlackKeySet", "ListAccumulator", "LongArrayArray", "DoubleArrayArray", "ThreadSafeListenerStorage", "ShortStringHashtable", "DataTable", "FilteringAccumulatorWrapper", "FixedSizeHashMap", "RedBlackLongKeySet", "ByteArray", "RedBlackTree", "ObjectValueRange", "LongKeyIndexer", "Prime", "IndexRangeIterator", "ShortObjectHashtable", "ShortLongHashtable", "IntArrayList", "ObjectLongHashtable", "LongIntHashtable", "FixedSizeStack", "IntSet", "LongObjectHashtable", "NoSuchIndexException", "SynchronizedListAccumulator", "LongDoubleHashtable", "ListenerErrorHandlerFactory", "ShortListIndexer", "AbstractWeakValueNavigableMap", "ObjectArray", "ShortKeyIndexer", "PropertySetIndexRangeIterator", "WeakStore", "LongArrayListIterator", "SizeLimitedAccumulatorWrapper", "ShortKeySet", "RangeMap", "ShortArrayArray", "IntIndexManager", "StringArrayArray", "Counter", "ObjectIntHashtable", "ManagedDataTable", "StringKeyIndexer", "PriorityQueue", "SoftCacheMap", "FloatArray", "SortedRangeList", "ObjectKeyIndexer", "StringIntHashtable", "StringArray", "FullKeySet", "QueueStub", "LongLongHashtable", "LongComparator", "DataStructureErrorHandlerFactory", "LRUMap", "WeakDataStructureFactory", "IntArray", "FloatArrayArray", "ListenerSet", "LongArray", "SizeRestrictedAccumulatorWrapper", "WeakValueHashMap", "CopyOnWriteWeakSet", "IntListIndexer", "LRUSet", "Range", "Duo"]
