from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.pcodeCPort.space
import ghidra.sleigh.grammar
import java.lang # type: ignore
import java.lang.ref # type: ignore
import java.util # type: ignore


K = typing.TypeVar("K")
V = typing.TypeVar("V")
Z = typing.TypeVar("Z")


class WeakHashMap2(java.util.AbstractMap[K, V], typing.Generic[K, V]):
    """
    A hashtable-based ``Map`` implementation with *weak values*.
     
     
    This implementation uses two maps internally, which nearly doubles the memory requirements
    over a traditional map.
    """

    @typing.type_check_only
    class WeakValue(java.lang.ref.WeakReference[Z], typing.Generic[Z]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class Entry(java.util.Map.Entry[K, V], typing.Generic[K, V]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class EntrySet(java.util.AbstractSet[java.util.Map.Entry[K, V]]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, initialCapacity: typing.Union[jpype.JInt, int], loadFactor: typing.Union[jpype.JFloat, float]):
        """
        Constructs a new, empty ``WeakHashMap2`` with the given
        initial capacity and the given load factor.
        
        :param jpype.JInt or int initialCapacity: The initial capacity of the
                                ``WeakHashMap2``
        :param jpype.JFloat or float loadFactor: The load factor of the ``WeakHashMap2``
        :raises IllegalArgumentException: If the initial capacity is less than
                                        zero, or if the load factor is
                                        nonpositive
        """

    @typing.overload
    def __init__(self, initialCapacity: typing.Union[jpype.JInt, int]):
        """
        Constructs a new, empty ``WeakHashMap2`` with the given
        initial capacity and the default load factor, which is
        ``0.75``.
        
        :param jpype.JInt or int initialCapacity: The initial capacity of the
                                ``WeakHashMap2``
        :raises IllegalArgumentException: If the initial capacity is less than
                                        zero
        """

    @typing.overload
    def __init__(self):
        """
        Constructs a new, empty ``WeakHashMap2`` with the default
        initial capacity and the default load factor, which is
        ``0.75``.
        """

    @typing.overload
    def __init__(self, t: collections.abc.Mapping):
        """
        Constructs a new ``WeakHashMap2`` with the same mappings as the
        specified ``Map``.  The ``WeakHashMap2`` is created with an
        initial capacity of twice the number of mappings in the specified map
        or 11 (whichever is greater), and a default load factor, which is
        ``0.75``.
        
        :param collections.abc.Mapping t: the map whose mappings are to be placed in this map.
        
        .. versionadded:: 1.3
        """

    def clear(self):
        """
        Removes all mappings from this map.
        """

    def containsKey(self, key: java.lang.Object) -> bool:
        """
        Returns ``true`` if this map contains a mapping for the
        specified key.
        
        :param java.lang.Object key: The key whose presence in this map is to be tested
        """

    def entrySet(self) -> java.util.Set[java.util.Map.Entry[K, V]]:
        """
        Returns a ``Set`` view of the mappings in this map.
        """

    def get(self, key: java.lang.Object) -> V:
        """
        Returns the value to which this map maps the specified ``key``.
        If this map does not contain a value for this key, then return
        ``null``.
        
        :param java.lang.Object key: The key whose associated value, if any, is to be returned
        """

    def isEmpty(self) -> bool:
        """
        Returns ``true`` if this map contains no key-value mappings.
        """

    def put(self, key: K, value: V) -> V:
        """
        Updates this map so that the given ``key`` maps to the given
        ``value``.  If the map previously contained a mapping for
        ``key`` then that mapping is replaced and the previous value is
        returned.
        
        :param K key: The key that is to be mapped to the given
                        ``value``
        :param V value: The value to which the given ``key`` is to be
                        mapped
        :return: The previous value to which this key was mapped, or
                ``null`` if there was no mapping for the key
        :rtype: V
        """

    def remove(self, key: java.lang.Object) -> V:
        """
        Removes the mapping for the given ``key`` from this map, if
        present.
        
        :param java.lang.Object key: The key whose mapping is to be removed
        :return: The value to which this key was mapped, or ``null`` if
                there was no mapping for the key
        :rtype: V
        """

    def reverseGet(self, value: V) -> K:
        ...

    def size(self) -> int:
        """
        Returns the number of key-value mappings in this map.
        **Note:** *In contrast with most implementations of the
        ``Map`` interface, the time required by this operation is
        linear in the size of the map.*
        """

    @property
    def empty(self) -> jpype.JBoolean:
        ...


class MutableLong(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, value: typing.Union[jpype.JLong, int]):
        ...

    @typing.overload
    def __init__(self):
        ...

    def add(self, amount: typing.Union[jpype.JLong, int]):
        ...

    def get(self) -> int:
        ...

    def increment(self):
        ...

    def set(self, i: typing.Union[jpype.JLong, int]):
        ...


class AddrSpaceToIdSymmetryMap(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def getID(space: ghidra.pcodeCPort.space.AddrSpace) -> int:
        ...

    @staticmethod
    def getSpace(ID: typing.Union[jpype.JLong, int]) -> ghidra.pcodeCPort.space.AddrSpace:
        ...


class MutableInt(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, value: typing.Union[jpype.JInt, int]):
        ...

    @typing.overload
    def __init__(self):
        ...

    def add(self, amount: typing.Union[jpype.JInt, int]):
        ...

    def get(self) -> int:
        ...

    def increment(self):
        ...

    def set(self, i: typing.Union[jpype.JInt, int]):
        ...


class Utils(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    endl: typing.Final[java.lang.String]

    def __init__(self):
        ...

    @staticmethod
    def ashiftRight(a: typing.Union[jpype.JLong, int], b: typing.Union[jpype.JLong, int]) -> int:
        ...

    @staticmethod
    def byte_swap(val: typing.Union[jpype.JLong, int], size: typing.Union[jpype.JInt, int]) -> int:
        ...

    @staticmethod
    def bytesToInt(bytes: jpype.JArray[jpype.JByte], bigEndian: typing.Union[jpype.JBoolean, bool]) -> int:
        ...

    @staticmethod
    def bytesToLong(byteBuf: jpype.JArray[jpype.JByte]) -> int:
        ...

    @staticmethod
    def calc_mask(size: typing.Union[jpype.JInt, int]) -> int:
        ...

    @staticmethod
    def calc_maskword(location: ghidra.sleigh.grammar.Location, sbit: typing.Union[jpype.JInt, int], ebit: typing.Union[jpype.JInt, int], num: MutableInt, shift: MutableInt, mask: MutableInt):
        ...

    @staticmethod
    def coveringmask(val: typing.Union[jpype.JLong, int]) -> int:
        ...

    @staticmethod
    def isascii(c: typing.Union[jpype.JInt, int]) -> bool:
        ...

    @staticmethod
    def isprint(c: typing.Union[jpype.JInt, int]) -> bool:
        ...

    @staticmethod
    def leastsigbit_set(val: typing.Union[jpype.JLong, int]) -> int:
        ...

    @staticmethod
    def lshiftRight(a: typing.Union[jpype.JLong, int], b: typing.Union[jpype.JLong, int]) -> int:
        ...

    @staticmethod
    def main(args: jpype.JArray[java.lang.String]):
        ...

    @staticmethod
    def mostsigbit_set(val: typing.Union[jpype.JLong, int]) -> int:
        ...

    @staticmethod
    def paddedHexString(value: typing.Union[jpype.JLong, int], padLength: typing.Union[jpype.JInt, int]) -> str:
        ...

    @staticmethod
    def pcode_left(val: typing.Union[jpype.JLong, int], sa: typing.Union[jpype.JInt, int]) -> int:
        ...

    @staticmethod
    def pcode_right(val: typing.Union[jpype.JLong, int], sa: typing.Union[jpype.JInt, int]) -> int:
        ...

    @staticmethod
    def shiftLeft(a: typing.Union[jpype.JLong, int], b: typing.Union[jpype.JLong, int]) -> int:
        ...

    @staticmethod
    def sign_extend(in_: typing.Union[jpype.JLong, int], sizein: typing.Union[jpype.JInt, int], sizeout: typing.Union[jpype.JInt, int]) -> int:
        ...

    @staticmethod
    def signbit_negative(val: typing.Union[jpype.JLong, int], size: typing.Union[jpype.JInt, int]) -> bool:
        ...

    @staticmethod
    def toUnsignedIntHex(n: typing.Union[jpype.JInt, int]) -> str:
        ...

    @staticmethod
    def uintb_negate(in_: typing.Union[jpype.JLong, int], size: typing.Union[jpype.JInt, int]) -> int:
        ...

    @staticmethod
    @typing.overload
    def unsignedCompare(v1: typing.Union[jpype.JLong, int], v2: typing.Union[jpype.JLong, int]) -> int:
        ...

    @staticmethod
    @typing.overload
    def unsignedCompare(v1: typing.Union[jpype.JInt, int], v2: typing.Union[jpype.JInt, int]) -> int:
        ...

    @staticmethod
    def unsignedDivide(a: typing.Union[jpype.JInt, int], b: typing.Union[jpype.JInt, int]) -> int:
        ...

    @staticmethod
    def unsignedInt(a: typing.Union[jpype.JInt, int]) -> int:
        ...

    @staticmethod
    def unsignedModulo(a: typing.Union[jpype.JInt, int], b: typing.Union[jpype.JInt, int]) -> int:
        ...

    @staticmethod
    def zzz_sign_extend(val: typing.Union[jpype.JLong, int], bit: typing.Union[jpype.JInt, int]) -> int:
        ...

    @staticmethod
    def zzz_zero_extend(val: typing.Union[jpype.JLong, int], bit: typing.Union[jpype.JInt, int]) -> int:
        ...



__all__ = ["WeakHashMap2", "MutableLong", "AddrSpaceToIdSymmetryMap", "MutableInt", "Utils"]
