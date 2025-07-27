from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import java.lang # type: ignore
import java.util # type: ignore


K = typing.TypeVar("K")
T = typing.TypeVar("T")
T1 = typing.TypeVar("T1")
T2 = typing.TypeVar("T2")
T3 = typing.TypeVar("T3")
T4 = typing.TypeVar("T4")
V = typing.TypeVar("V")


class ListIterator(IteratorSTL[T], typing.Generic[T]):

    class_: typing.ClassVar[java.lang.Class]
    stackUse: jpype.JArray[java.lang.StackTraceElement]

    def assign(self, otherIterator: IteratorSTL[T]):
        ...

    def copy(self) -> IteratorSTL[T]:
        ...

    @typing.overload
    def decrement(self) -> IteratorSTL[T]:
        ...

    @typing.overload
    def decrement(self, n: typing.Union[jpype.JInt, int]) -> IteratorSTL[T]:
        ...

    def get(self) -> T:
        ...

    @typing.overload
    def increment(self) -> IteratorSTL[T]:
        ...

    @typing.overload
    def increment(self, count: typing.Union[jpype.JInt, int]) -> IteratorSTL[T]:
        ...

    def insert(self, value: T):
        ...

    def isBegin(self) -> bool:
        ...

    def isEnd(self) -> bool:
        ...

    def set(self, value: T):
        ...

    @property
    def end(self) -> jpype.JBoolean:
        ...

    @property
    def begin(self) -> jpype.JBoolean:
        ...


class ComparableSetSTL(SetSTL[T], typing.Generic[T]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class RedBlackNode(java.lang.Object, typing.Generic[K, V]):

    @typing.type_check_only
    class NodeColor(java.lang.Enum[RedBlackNode.NodeColor]):

        class_: typing.ClassVar[java.lang.Class]
        RED: typing.Final[RedBlackNode.NodeColor]
        BLACK: typing.Final[RedBlackNode.NodeColor]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> RedBlackNode.NodeColor:
            ...

        @staticmethod
        def values() -> jpype.JArray[RedBlackNode.NodeColor]:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def getKey(self) -> K:
        ...

    def getPredecessor(self) -> RedBlackNode[K, V]:
        ...

    def getSuccessor(self) -> RedBlackNode[K, V]:
        ...

    def getValue(self) -> V:
        ...

    def setValue(self, value: V):
        ...

    @property
    def successor(self) -> RedBlackNode[K, V]:
        ...

    @property
    def predecessor(self) -> RedBlackNode[K, V]:
        ...

    @property
    def value(self) -> V:
        ...

    @value.setter
    def value(self, value: V):
        ...

    @property
    def key(self) -> K:
        ...


class VectorSTL(java.lang.Iterable[T], typing.Generic[T]):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, initialCapacity: typing.Union[jpype.JInt, int]):
        ...

    @typing.overload
    def __init__(self, initialCapacity: typing.Union[jpype.JInt, int], value: T):
        ...

    @typing.overload
    def __init__(self, other: VectorSTL[T]):
        ...

    def appendAll(self, vector: VectorSTL[T]):
        ...

    def assign(self, otherVector: VectorSTL[T]):
        ...

    def back(self) -> T:
        ...

    def begin(self) -> IteratorSTL[T]:
        ...

    def clear(self):
        ...

    def copy(self) -> VectorSTL[T]:
        ...

    def empty(self) -> bool:
        ...

    def end(self) -> IteratorSTL[T]:
        ...

    @typing.overload
    def erase(self, index: typing.Union[jpype.JInt, int]) -> T:
        ...

    @typing.overload
    def erase(self, it: IteratorSTL[T]) -> IteratorSTL[T]:
        ...

    @typing.overload
    def erase(self, start: IteratorSTL[T], end: IteratorSTL[T]):
        ...

    def front(self) -> T:
        ...

    def get(self, index: typing.Union[jpype.JInt, int]) -> T:
        ...

    @typing.overload
    def insert(self, index: typing.Union[jpype.JInt, int], value: T):
        ...

    @typing.overload
    def insert(self, iterator: IteratorSTL[T], value: T):
        ...

    @typing.overload
    def insert(self, pos: IteratorSTL[T], list: jpype.JArray[T]):
        ...

    def insertAll(self, pos: IteratorSTL[T], vector: VectorSTL[T]):
        ...

    @typing.overload
    def lower_bound(self, key: T, comparator: java.util.Comparator[T]) -> IteratorSTL[T]:
        """
        Returns an iterator postioned at the item in the vector that is the smallest key less or equal than
        the given key.  This method assumes the vector is sorted in ascending order.
        
        :param T key: the key for which to find the lower bound
        :return: an iterator postioned at the item in the vector that is the smallest key less or equal than
        the given key.
        :rtype: IteratorSTL[T]
        :raises UnsupportedOperationException: if T is not comparable
        """

    @typing.overload
    def lower_bound(self, key: T) -> IteratorSTL[T]:
        """
        Returns an iterator postioned at the item in the vector that is the smallest key less or equal than
        the given key.  This method assumes the vector is sorted in ascending order.
        
        :param T key: the key for which to find the lower bound
        :return: an iterator postioned at the item in the vector that is the smallest key less or equal than
        the given key.
        :rtype: IteratorSTL[T]
        """

    @staticmethod
    @typing.overload
    def merge(v1: VectorSTL[K], v2: VectorSTL[K], destination: VectorSTL[K]):
        ...

    @staticmethod
    @typing.overload
    def merge(v1: VectorSTL[K], v2: VectorSTL[K], destination: VectorSTL[K], comparator: java.util.Comparator[K]):
        ...

    def pop_back(self) -> T:
        ...

    def push_back(self, value: T):
        ...

    def rBegin(self) -> IteratorSTL[T]:
        ...

    def rEnd(self) -> IteratorSTL[T]:
        ...

    def reserve(self, capacity: typing.Union[jpype.JInt, int]):
        ...

    def resize(self, size: typing.Union[jpype.JInt, int], value: T):
        ...

    @typing.overload
    def set(self, index: typing.Union[jpype.JInt, int], value: T):
        ...

    @typing.overload
    def set(self, iter: IteratorSTL[T], value: T):
        ...

    def setBack(self, value: T):
        ...

    def size(self) -> int:
        ...

    @typing.overload
    def sort(self):
        """
        Sorts the vector. To use this method T must be comparable.
        
        :raises UnsupportedOperationException: if T is not comparable;
        """

    @typing.overload
    def sort(self, comparator: java.util.Comparator[T]):
        ...

    @typing.overload
    def upper_bound(self, key: T) -> IteratorSTL[T]:
        """
        Returns an iterator postioned at the item in the vector that is the smallest key less than
        the given key.  This method assumes the vector is sorted in ascending order.
        
        :param T key: the key for which to find the upper bound
        :return: an iterator postioned at the item in the vector that is the smallest key less than
        the given key.
        :rtype: IteratorSTL[T]
        :raises UnsupportedOperationException: if T is not comparable
        """

    @typing.overload
    def upper_bound(self, key: T, comparator: java.util.Comparator[T]) -> IteratorSTL[T]:
        """
        Returns an iterator postioned at the item in the vector that is the smallest key less than
        the given key.  This method assumes the vector is sorted in ascending order.
        
        :param T key: the key for which to find the upper bound
        :return: an iterator postioned at the item in the vector that is the smallest key less than
        the given key.
        :rtype: IteratorSTL[T]
        :raises UnsupportedOperationException: if T is not comparable
        """


class IteratorSTL(java.lang.Object, typing.Generic[T]):

    class_: typing.ClassVar[java.lang.Class]

    def assign(self, otherIterator: IteratorSTL[T]):
        """
        'Assigns' this iterator to be equivalent to the given iterator.  This is equivalent to
        C++'s '=' overloading mechanism
        
        :param IteratorSTL[T] otherIterator: The iterator to copy
        """

    def copy(self) -> IteratorSTL[T]:
        """
        Creates a copy of this iterator.
        
        :return: a copy of this iterator.
        :rtype: IteratorSTL[T]
        """

    @typing.overload
    def decrement(self) -> IteratorSTL[T]:
        """
        Devance the iterator to the previous position.  This method is only supported in 
        bidirectional iterators.
        
        :return: a reference to the iterator itself
        :rtype: IteratorSTL[T]
        """

    @typing.overload
    def decrement(self, n: typing.Union[jpype.JInt, int]) -> IteratorSTL[T]:
        """
        Devances the iterator n positions.
        
        :return: a reference to the iterator itself
        :rtype: IteratorSTL[T]
        :raises IndexOutOfBoundsException: if the n value pushes past the beginning of the collection
        """

    def get(self) -> T:
        """
        Returns the current value of the iterator.
        
        :return: the current value of the iterator.
        :rtype: T
        :raises IndexOutOfBoundsException: if the iterator is positioned before the first value or
        after the last value.
        """

    @typing.overload
    def increment(self) -> IteratorSTL[T]:
        """
        Advances the iterator to the next position.
        
        :return: a reference to the iterator itself
        :rtype: IteratorSTL[T]
        :raises IndexOutOfBoundsException: if the iterator is already past the last element.
        """

    @typing.overload
    def increment(self, n: typing.Union[jpype.JInt, int]) -> IteratorSTL[T]:
        """
        Advances the iterator n positions.
        
        :return: a reference to the iterator itself
        :rtype: IteratorSTL[T]
        :raises IndexOutOfBoundsException: if the n value pushes past the end of the collection.
        """

    def insert(self, value: T):
        """
        Inserts the given value at the current position (the current value will be pushed to the next value).
        The iterator will be positioned on the new value.
        
        :param T value: the value to insert into the collection.
        :raises IndexOutOfBoundsException: if the iterator is positioned before the first item.
        """

    def isBegin(self) -> bool:
        """
        Returns true if the iterator is positioned on the first element of the collection.  If the
        collection is empty, this will always return false.
        
        :return: true if the iterator is positioned on the first element of the collection.
        :rtype: bool
        """

    def isEnd(self) -> bool:
        """
        Returns true if the iterator is positioned past the last element of the collection.  If the
        collection is empty, this will always return true.
        
        :return: true if the iterator is positioned past the last element of the collection.
        :rtype: bool
        """

    def set(self, value: T):
        """
        Sets the current value of the iterator to the given value.
        
        :param T value: the value to set at the iterator position
        :raises IndexOutOfBoundsException: if the iterator is positioned befor the first value or
        after the last value.
        """

    @property
    def end(self) -> jpype.JBoolean:
        ...

    @property
    def begin(self) -> jpype.JBoolean:
        ...


class MultiSetSTL(java.lang.Object, typing.Generic[K]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, comparator: java.util.Comparator[K]):
        ...

    def begin(self) -> IteratorSTL[K]:
        ...

    def contains(self, key: K) -> bool:
        ...

    def end(self) -> IteratorSTL[K]:
        ...

    def erase(self, position: IteratorSTL[K]):
        ...

    @typing.overload
    def insert(self, key: K):
        ...

    @typing.overload
    def insert(self, low: IteratorSTL[K], key: K) -> IteratorSTL[K]:
        ...

    def lower_bound(self, key: K) -> IteratorSTL[K]:
        ...

    @staticmethod
    def main(args: jpype.JArray[java.lang.String]):
        ...

    def rBegin(self) -> IteratorSTL[K]:
        ...

    def rEnd(self) -> IteratorSTL[K]:
        ...

    def remove(self, key: K) -> bool:
        ...

    def upper_bound(self, key: K) -> IteratorSTL[K]:
        ...


class MapSTL(java.lang.Object, typing.Generic[K, V]):

    class_: typing.ClassVar[java.lang.Class]
    EOL: typing.Final[java.lang.String]

    def __init__(self, comparator: java.util.Comparator[K]):
        ...

    def add(self, key: K, value: V) -> bool:
        ...

    def begin(self) -> IteratorSTL[Pair[K, V]]:
        ...

    def clear(self):
        ...

    def contains(self, key: K) -> bool:
        ...

    def empty(self) -> bool:
        ...

    def end(self) -> IteratorSTL[Pair[K, V]]:
        ...

    @typing.overload
    def erase(self, key: K) -> V:
        ...

    @typing.overload
    def erase(self, iter: IteratorSTL[Pair[K, V]]):
        ...

    @typing.overload
    def erase(self, start: IteratorSTL[Pair[K, V]], end: IteratorSTL[Pair[K, V]]):
        ...

    def find(self, key: K) -> IteratorSTL[Pair[K, V]]:
        ...

    def get(self, key: K) -> V:
        ...

    def insert(self, start: IteratorSTL[Pair[K, V]], end: IteratorSTL[Pair[K, V]]):
        ...

    def isEmpty(self) -> bool:
        ...

    def lower_bound(self, key: K) -> IteratorSTL[Pair[K, V]]:
        ...

    def put(self, key: K, value: V):
        ...

    def rBegin(self) -> IteratorSTL[Pair[K, V]]:
        ...

    def rEnd(self) -> IteratorSTL[Pair[K, V]]:
        ...

    def remove(self, key: K) -> V:
        ...

    def size(self) -> int:
        ...

    def upper_bound(self, key: K) -> IteratorSTL[Pair[K, V]]:
        ...


class ComparableMultiMapSTL(MultiMapSTL[K, V], typing.Generic[K, V]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class Pair(java.lang.Object, typing.Generic[T1, T2]):

    class_: typing.ClassVar[java.lang.Class]
    first: typing.Final[T1]
    second: typing.Final[T2]

    def __init__(self, key: T1, value: T2):
        ...

    @staticmethod
    def emptyPair() -> Pair[T1, T2]:
        ...


class ReverseSetIterator(SetIterator[T], typing.Generic[T]):

    class_: typing.ClassVar[java.lang.Class]

    def delete(self):
        ...


class ComparableMultiSetSTL(MultiSetSTL[T], typing.Generic[T]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class RedBlackTree(java.lang.Object, typing.Generic[K, V]):
    """
    A RedBlack Tree implementation with K type keys and place to store V type values.
    """

    class_: typing.ClassVar[java.lang.Class]
    EOL: typing.Final[java.lang.String]

    @typing.overload
    def __init__(self, comparator: java.util.Comparator[K], allowDuplicateKeys: typing.Union[jpype.JBoolean, bool]):
        """
        Creates a new RedBlackTree
        
        :param java.util.Comparator[K] comparator: the comparator for this tree
        :param jpype.JBoolean or bool allowDuplicateKeys: true to allow duplicate keys
        """

    @typing.overload
    def __init__(self, tree: RedBlackTree[K, V]):
        """
        Creates a copy of an existing RedBlackTree
        
        :param RedBlackTree[K, V] tree: the existing tree to copy
        """

    def containsKey(self, key: K) -> bool:
        """
        Returns true if the key is in the set.
        
        :param K key: the key whose presence is to be tested.
        """

    def deleteEntry(self, p: RedBlackNode[K, V]):
        """
        Delete node p, and then rebalance the tree.
        """

    def findFirstNode(self, key: K) -> RedBlackNode[K, V]:
        ...

    def findLastNode(self, key: K) -> RedBlackNode[K, V]:
        ...

    def getFirst(self) -> RedBlackNode[K, V]:
        """
        Returns the first entry in this set.
        """

    def getLast(self) -> RedBlackNode[K, V]:
        """
        Returns the last entry in this set.
        """

    def isEmpty(self) -> bool:
        """
        Test if the set is empty.
        
        :return: true if the set is empty.
        :rtype: bool
        """

    def lowerBound(self, key: K) -> RedBlackNode[K, V]:
        """
        Finds the node with the lowest key that is >= to the given key.  Returns null if all nodes
        in the tree have keys less than the given key.
        
        :param K key: the key to search for.
        :return: the node with the lowest key that is >= to the given key or null if no such key exists.
        :rtype: RedBlackNode[K, V]
        """

    def put(self, key: K, value: V) -> Pair[RedBlackNode[K, V], java.lang.Boolean]:
        """
        Adds the given key,value to the map. If the map does not allow duplicate keys and a key
        already exists, the old value will be replaced by the new value and the old value will be
        returned.
        
        :param K key: the key to add to the set.
        :param V value: the key's value.
        :return: the old value associated with the key, or null if the key was not previously in the map.
        :rtype: Pair[RedBlackNode[K, V], java.lang.Boolean]
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
        Removes all entrys from the set.
        """

    def size(self) -> int:
        """
        Returns the number keys in this set.
        """

    def upperBound(self, key: K) -> RedBlackNode[K, V]:
        """
        Finds the node with the lowest key that is > the given key.  Returns null if all nodes
        in the tree have keys less than or equal to the given key.
        
        :param K key: the key to search for.
        :return: the node with the lowest key that is > to the given key or null if no such key exists.
        :rtype: RedBlackNode[K, V]
        """

    @property
    def last(self) -> RedBlackNode[K, V]:
        ...

    @property
    def first(self) -> RedBlackNode[K, V]:
        ...

    @property
    def empty(self) -> jpype.JBoolean:
        ...


class SetSTL(java.lang.Object, typing.Generic[K]):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, comparator: java.util.Comparator[K]):
        ...

    @typing.overload
    def __init__(self, set: SetSTL[K]):
        ...

    def begin(self) -> IteratorSTL[K]:
        ...

    def clear(self):
        ...

    def contains(self, key: K) -> bool:
        ...

    def end(self) -> IteratorSTL[K]:
        ...

    @typing.overload
    def erase(self, iterator: IteratorSTL[K]):
        ...

    @typing.overload
    def erase(self, key: K):
        ...

    def find(self, key: K) -> IteratorSTL[K]:
        ...

    def insert(self, key: K) -> Pair[IteratorSTL[K], java.lang.Boolean]:
        ...

    def isEmpty(self) -> bool:
        ...

    def lower_bound(self, key: K) -> IteratorSTL[K]:
        ...

    def rBegin(self) -> IteratorSTL[K]:
        ...

    def rEnd(self) -> IteratorSTL[K]:
        ...

    def remove(self, key: K) -> bool:
        ...

    def upper_bound(self, key: K) -> IteratorSTL[K]:
        ...

    @property
    def empty(self) -> jpype.JBoolean:
        ...


class MultiMapSTL(java.lang.Object, typing.Generic[K, V]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, comparator: java.util.Comparator[K]):
        ...

    def add(self, key: K, value: V):
        ...

    def begin(self) -> IteratorSTL[Pair[K, V]]:
        ...

    def contains(self, key: K) -> bool:
        ...

    def end(self) -> IteratorSTL[Pair[K, V]]:
        ...

    def erase(self, iter: IteratorSTL[Pair[K, V]]):
        ...

    def lower_bound(self, key: K) -> IteratorSTL[Pair[K, V]]:
        ...

    @staticmethod
    def main(args: jpype.JArray[java.lang.String]):
        ...

    def rBegin(self) -> IteratorSTL[Pair[K, V]]:
        ...

    def rEnd(self) -> IteratorSTL[Pair[K, V]]:
        ...

    def remove(self, key: K) -> V:
        ...

    def upper_bound(self, key: K) -> IteratorSTL[Pair[K, V]]:
        ...


class ComparableMapSTL(MapSTL[K, V], typing.Generic[K, V]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class Algorithms(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def lower_bound(start: IteratorSTL[T], end: IteratorSTL[T], key: T) -> IteratorSTL[T]:
        ...

    @staticmethod
    def upper_bound(start: IteratorSTL[T], end: IteratorSTL[T], key: T) -> IteratorSTL[T]:
        ...


class SetIterator(IteratorSTL[T], typing.Generic[T]):

    class_: typing.ClassVar[java.lang.Class]
    erased: jpype.JBoolean

    def assign(self, otherIterator: IteratorSTL[T]):
        ...

    def copy(self) -> IteratorSTL[T]:
        ...

    @typing.overload
    def decrement(self) -> IteratorSTL[T]:
        ...

    @typing.overload
    def decrement(self, n: typing.Union[jpype.JInt, int]) -> IteratorSTL[T]:
        ...

    def get(self) -> T:
        ...

    @typing.overload
    def increment(self) -> IteratorSTL[T]:
        ...

    @typing.overload
    def increment(self, n: typing.Union[jpype.JInt, int]) -> IteratorSTL[T]:
        ...

    def insert(self, value: T):
        ...

    def isBegin(self) -> bool:
        ...

    def isEnd(self) -> bool:
        ...

    def set(self, value: T):
        ...

    @property
    def end(self) -> jpype.JBoolean:
        ...

    @property
    def begin(self) -> jpype.JBoolean:
        ...


class ReverseMapIteratorSTL(MapIteratorSTL[K, V], typing.Generic[K, V]):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def delete(self):
        ...

    @typing.overload
    def delete(self, count: typing.Union[jpype.JInt, int]):
        ...


class VectorIterator(IteratorSTL[T], typing.Generic[T]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, data: java.util.ArrayList[T], index: typing.Union[jpype.JInt, int]):
        ...

    def assign(self, otherIterator: IteratorSTL[T]):
        ...

    def copy(self) -> IteratorSTL[T]:
        ...

    @typing.overload
    def decrement(self) -> IteratorSTL[T]:
        ...

    @typing.overload
    def decrement(self, count: typing.Union[jpype.JInt, int]) -> IteratorSTL[T]:
        ...

    @typing.overload
    def get(self) -> T:
        ...

    @typing.overload
    def get(self, offset: typing.Union[jpype.JInt, int]) -> T:
        ...

    def getIndex(self) -> int:
        ...

    @typing.overload
    def increment(self) -> IteratorSTL[T]:
        ...

    @typing.overload
    def increment(self, count: typing.Union[jpype.JInt, int]) -> IteratorSTL[T]:
        ...

    def insert(self, value: T):
        ...

    def isBegin(self) -> bool:
        ...

    def isEnd(self) -> bool:
        ...

    def set(self, value: T):
        ...

    @property
    def index(self) -> jpype.JInt:
        ...

    @property
    def end(self) -> jpype.JBoolean:
        ...

    @property
    def begin(self) -> jpype.JBoolean:
        ...


class MapIteratorSTL(IteratorSTL[Pair[K, V]], typing.Generic[K, V]):

    class_: typing.ClassVar[java.lang.Class]

    def assign(self, otherIterator: IteratorSTL[Pair[K, V]]):
        ...

    def copy(self) -> IteratorSTL[Pair[K, V]]:
        ...

    @typing.overload
    def decrement(self) -> IteratorSTL[Pair[K, V]]:
        ...

    @typing.overload
    def decrement(self, n: typing.Union[jpype.JInt, int]) -> IteratorSTL[Pair[K, V]]:
        ...

    def get(self) -> Pair[K, V]:
        ...

    @typing.overload
    def increment(self) -> IteratorSTL[Pair[K, V]]:
        ...

    @typing.overload
    def increment(self, n: typing.Union[jpype.JInt, int]) -> IteratorSTL[Pair[K, V]]:
        ...

    def insert(self, value: Pair[K, V]):
        ...

    def isBegin(self) -> bool:
        ...

    def isEnd(self) -> bool:
        ...

    def set(self, value: Pair[K, V]):
        ...

    @property
    def end(self) -> jpype.JBoolean:
        ...

    @property
    def begin(self) -> jpype.JBoolean:
        ...


@typing.type_check_only
class ReverseVectorIterator(VectorIterator[T], typing.Generic[T]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, data: java.util.ArrayList[T], index: typing.Union[jpype.JInt, int]):
        ...

    def delete(self, count: typing.Union[jpype.JInt, int]):
        ...


@typing.type_check_only
class ReverseListIterator(ListIterator[T], typing.Generic[T]):
    ...
    class_: typing.ClassVar[java.lang.Class]


class UnmodifiableListIteratorSTL(ListIterator[T], typing.Generic[T]):
    """
    This wrapper class is used to detect cases where code is 
    modifying iterators that shouldn't change.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, iterator: ListIterator[T]):
        ...

    @typing.overload
    def delete(self):
        ...

    @typing.overload
    def delete(self, count: typing.Union[jpype.JInt, int]):
        ...


class Quad(java.lang.Object, typing.Generic[T1, T2, T3, T4]):

    class_: typing.ClassVar[java.lang.Class]
    first: T1
    second: T2
    third: T3
    fourth: T4

    def __init__(self, first: T1, second: T2, third: T3, fourth: T4):
        ...


class ListSTL(java.lang.Object, typing.Generic[T]):

    class_: typing.ClassVar[java.lang.Class]
    EOL: typing.Final[java.lang.String]

    def __init__(self):
        ...

    def back(self) -> T:
        ...

    def begin(self) -> IteratorSTL[T]:
        ...

    def clear(self):
        ...

    def end(self) -> IteratorSTL[T]:
        ...

    def erase(self, position: IteratorSTL[T]):
        ...

    def front(self) -> T:
        ...

    def insert(self, position: IteratorSTL[T], value: T) -> IteratorSTL[T]:
        ...

    def isEmpty(self) -> bool:
        ...

    def pop_back(self) -> T:
        ...

    def pop_front(self) -> T:
        ...

    def printDebug(self):
        ...

    def push_back(self, value: T):
        ...

    def push_front(self, value: T):
        ...

    def rBegin(self) -> IteratorSTL[T]:
        ...

    def rEnd(self) -> IteratorSTL[T]:
        ...

    def size(self) -> int:
        ...

    def sort(self, comparator: java.util.Comparator[T]):
        ...

    def splice(self, position: IteratorSTL[T], list: ListSTL[T], listPosition: IteratorSTL[T]):
        """
        moves a single element, decreasing the length of list by 1 and increasing this list by 1.
        
        :param IteratorSTL[T] position: the position into this list where the element is to be inserted
        :param ListSTL[T] list: the list from which the element is removed.
        :param IteratorSTL[T] listPosition: the postion of the element to be removed.
        """

    @property
    def empty(self) -> jpype.JBoolean:
        ...


class EmptyIteratorSTL(IteratorSTL[T], typing.Generic[T]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def assign(self, otherIterator: IteratorSTL[T]):
        ...

    def copy(self) -> IteratorSTL[T]:
        ...

    @typing.overload
    def decrement(self) -> IteratorSTL[T]:
        ...

    @typing.overload
    def decrement(self, n: typing.Union[jpype.JInt, int]) -> IteratorSTL[T]:
        ...

    @typing.overload
    def delete(self):
        ...

    @typing.overload
    def delete(self, count: typing.Union[jpype.JInt, int]):
        ...

    def get(self) -> T:
        ...

    @typing.overload
    def increment(self) -> IteratorSTL[T]:
        ...

    @typing.overload
    def increment(self, n: typing.Union[jpype.JInt, int]) -> IteratorSTL[T]:
        ...

    def insert(self, value: T):
        ...

    def isBegin(self) -> bool:
        ...

    def isEnd(self) -> bool:
        ...

    def isRBegin(self) -> bool:
        ...

    def isREnd(self) -> bool:
        ...

    def set(self, value: T):
        ...

    @property
    def end(self) -> jpype.JBoolean:
        ...

    @property
    def rEnd(self) -> jpype.JBoolean:
        ...

    @property
    def begin(self) -> jpype.JBoolean:
        ...

    @property
    def rBegin(self) -> jpype.JBoolean:
        ...


class ListNodeSTL(java.lang.Object, typing.Generic[T]):

    class_: typing.ClassVar[java.lang.Class]
    value: T
    stackUse: jpype.JArray[java.lang.StackTraceElement]

    @typing.overload
    def __init__(self, prev: ListNodeSTL[T], next: ListNodeSTL[T], value: T):
        ...

    @typing.overload
    def __init__(self):
        ...


class SelfComparator(java.util.Comparator[T], typing.Generic[T]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...



__all__ = ["ListIterator", "ComparableSetSTL", "RedBlackNode", "VectorSTL", "IteratorSTL", "MultiSetSTL", "MapSTL", "ComparableMultiMapSTL", "Pair", "ReverseSetIterator", "ComparableMultiSetSTL", "RedBlackTree", "SetSTL", "MultiMapSTL", "ComparableMapSTL", "Algorithms", "SetIterator", "ReverseMapIteratorSTL", "VectorIterator", "MapIteratorSTL", "ReverseVectorIterator", "ReverseListIterator", "UnmodifiableListIteratorSTL", "Quad", "ListSTL", "EmptyIteratorSTL", "ListNodeSTL", "SelfComparator"]
