from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.util
import ghidra.util.datastruct
import java.io # type: ignore
import java.lang # type: ignore


T = typing.TypeVar("T")


@typing.type_check_only
class LongIteratorImpl(ghidra.util.LongIterator):
    """
    Class to iterate over indexes of a PropertyMap.
    """

    class_: typing.ClassVar[java.lang.Class]

    def hasNext(self) -> bool:
        """
        Returns true if the iterator has more indexes.
        """

    def hasPrevious(self) -> bool:
        """
        Return true if the iterator has a previous index.
        """

    def next(self) -> int:
        """
        Returns the next index in the iterator.
        """

    def previous(self) -> int:
        """
        Returns the previous index in the iterator.
        """


class IntValueMap(ValueMap[java.lang.Integer]):
    """
    Handles general storage and retrieval of int values indexed by long keys.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, name: typing.Union[java.lang.String, str]):
        """
        Constructor for IntValueMap.
        
        :param java.lang.String or str name: the name associated with this property set
        """

    def getInt(self, index: typing.Union[jpype.JLong, int]) -> int:
        """
        Retrieves the int value stored at the given index.
        
        :param jpype.JLong or int index: the index at which to retrieve the int value.
        :return: int the value stored at the given index.
        :rtype: int
        :raises NoValueException: if there is no int value stored at the index.
        """

    def putInt(self, index: typing.Union[jpype.JLong, int], value: typing.Union[jpype.JInt, int]):
        """
        Stores an int value at the given index.  Any value currently at that
        index will be replaced by the new value.
        
        :param jpype.JLong or int index: the index at which to store the int value.
        :param jpype.JInt or int value: the int value to store.
        """

    @property
    def int(self) -> jpype.JInt:
        ...


class TypeMismatchException(java.lang.RuntimeException):
    """
    Exception thrown when a PropertyPage does not support a
    requested data type.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        Constructor
        """

    @typing.overload
    def __init__(self, msg: typing.Union[java.lang.String, str]):
        """
        Constructor
        
        :param java.lang.String or str msg: detailed message
        """


class ValueMap(java.io.Serializable, typing.Generic[T]):
    """
    Base class for managing data values that are accessed by an ordered long index key. Specific
    data value types are determined by the derived class.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getDataSize(self) -> int:
        """
        Returns the size (in bytes) of the data that is stored in this property
        set.
        
        :return: the size (in bytes) of the data that is stored in this property
        set.
        :rtype: int
        """

    def getFirstPropertyIndex(self) -> int:
        """
        Get the first index where a property value exists.
        
        :raises NoSuchIndexException: when there is no property value for any index.
        """

    def getLastPropertyIndex(self) -> int:
        """
        Get the last index where a property value exists.
        
        :raises NoSuchIndexException: thrown if there is no address having the property value.
        """

    def getName(self) -> str:
        """
        Get the name for this property manager.
        """

    def getNextPropertyIndex(self, index: typing.Union[jpype.JLong, int]) -> int:
        """
        Get the next index where the property value exists.
        
        :param jpype.JLong or int index: the address from which to begin the search (exclusive).
        :raises NoSuchIndexException: thrown if there is no address with
        a property value after the given address.
        """

    def getObjectClass(self) -> java.lang.Class[T]:
        """
        Returns property object class associated with this set.
        """

    def getPreviousPropertyIndex(self, index: typing.Union[jpype.JLong, int]) -> int:
        """
        Get the previous index where a property value exists.
        
        :param jpype.JLong or int index: the long representation of an address from which
                to begin the search (exclusive).
        :raises NoSuchIndexException: when there is no index
                with a property value before the given address.
        """

    @typing.overload
    def getPropertyIterator(self, start: typing.Union[jpype.JLong, int], end: typing.Union[jpype.JLong, int]) -> ghidra.util.LongIterator:
        """
        Creates an iterator over all the indexes that have this property within
        the given range.
        
        :param jpype.JLong or int start: The start address to search
        :param jpype.JLong or int end: The end address to search
        :return: LongIterator Iterator over indexes that have properties.
        :rtype: ghidra.util.LongIterator
        """

    @typing.overload
    def getPropertyIterator(self, start: typing.Union[jpype.JLong, int], end: typing.Union[jpype.JLong, int], atStart: typing.Union[jpype.JBoolean, bool]) -> ghidra.util.LongIterator:
        """
        Creates an iterator over all the indexes that have this property within
        the given range.
        
        :param jpype.JLong or int start: The start address to search
        :param jpype.JLong or int end: The end address to search
        :param jpype.JBoolean or bool atStart: indicates if the iterator should begin at the start
        address, otherwise it will start at the last address.  Set this flag to
        false if you want to iterate backwards through the properties.
        :return: LongIterator Iterator over indexes that have properties.
        :rtype: ghidra.util.LongIterator
        """

    @typing.overload
    def getPropertyIterator(self) -> ghidra.util.LongIterator:
        """
        Returns an iterator over the indices having the given property
        value.
        """

    @typing.overload
    def getPropertyIterator(self, start: typing.Union[jpype.JLong, int]) -> ghidra.util.LongIterator:
        """
        Returns an iterator over the indices having the given property
        value.
        
        :param jpype.JLong or int start: the starting index for the iterator.
        """

    @typing.overload
    def getPropertyIterator(self, start: typing.Union[jpype.JLong, int], before: typing.Union[jpype.JBoolean, bool]) -> ghidra.util.LongIterator:
        """
        Returns an iterator over the indices having the given property
        value.
        
        :param jpype.JLong or int start: the starting index for the iterator.
        :param jpype.JBoolean or bool before: if true the iterator will be positioned before the start value.
        """

    def getSize(self) -> int:
        """
        Get the number of properties in the set.
        
        :return: the number of properties
        :rtype: int
        """

    def hasProperty(self, index: typing.Union[jpype.JLong, int]) -> bool:
        """
        returns whether there is a property value at index.
        
        :param jpype.JLong or int index: the long representation of an address.
        """

    def intersects(self, start: typing.Union[jpype.JLong, int], end: typing.Union[jpype.JLong, int]) -> bool:
        """
        Given two indices it indicates whether there is an index in
        that range (inclusive) having the property.
        
        :param jpype.JLong or int start: the start of the index range.
        :param jpype.JLong or int end: the end of the index range.
        :return: boolean true if at least one index in the range
        has the property, false otherwise.
        :rtype: bool
        """

    def moveRange(self, start: typing.Union[jpype.JLong, int], end: typing.Union[jpype.JLong, int], newStart: typing.Union[jpype.JLong, int]):
        """
        Move the range of properties to the newStart index.
        
        :param jpype.JLong or int start: the beginning of the property range to move
        :param jpype.JLong or int end: the end of the property range to move
        :param jpype.JLong or int newStart: the new beginning of the property range after the move
        """

    def remove(self, index: typing.Union[jpype.JLong, int]) -> bool:
        """
        Remove the property value at the given index.
        
        :return: true if the property value was removed, false
        otherwise.
        :rtype: bool
        :param jpype.JLong or int index: the long representation of an address.
        """

    def removeRange(self, start: typing.Union[jpype.JLong, int], end: typing.Union[jpype.JLong, int]) -> bool:
        """
        Removes all property values within a given range.
        
        :param jpype.JLong or int start: begin range
        :param jpype.JLong or int end: end range, inclusive
        :return: true if any property value was removed; return
                false otherwise.
        :rtype: bool
        """

    def restoreProperties(self, ois: java.io.ObjectInputStream):
        """
        Restores all the properties from the input stream.  Any existing
        properties will first be removed.
        
        :param java.io.ObjectInputStream ois: the input stream.
        :raises IOException: if I/O error occurs.
        :raises java.lang.ClassNotFoundException: if the a class cannot be determined for
        the property value.
        """

    def saveProperties(self, oos: java.io.ObjectOutputStream, start: typing.Union[jpype.JLong, int], end: typing.Union[jpype.JLong, int]):
        """
        Saves all property values between start and end to the output stream
        
        :param java.io.ObjectOutputStream oos: the output stream
        :param jpype.JLong or int start: the first index in the range to save.
        :param jpype.JLong or int end: the last index in the range to save.
        :raises IOException: if an I/O error occurs on the write.
        """

    @property
    def size(self) -> jpype.JInt:
        ...

    @property
    def propertyIterator(self) -> ghidra.util.LongIterator:
        ...

    @property
    def lastPropertyIndex(self) -> jpype.JLong:
        ...

    @property
    def objectClass(self) -> java.lang.Class[T]:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def firstPropertyIndex(self) -> jpype.JLong:
        ...

    @property
    def dataSize(self) -> jpype.JInt:
        ...

    @property
    def nextPropertyIndex(self) -> jpype.JLong:
        ...

    @property
    def previousPropertyIndex(self) -> jpype.JLong:
        ...


@typing.type_check_only
class ValueStoragePageIndex(java.io.Serializable):
    """
    PropertyPageIndex is used to find the property pages before and
    after a given property page.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def add(self, pageID: typing.Union[jpype.JLong, int]):
        """
        Add the given pageID to the table.
        """

    def getNext(self, pageID: typing.Union[jpype.JLong, int]) -> int:
        """
        Get the ID of the page after pageID.
        """

    def getNumPages(self) -> int:
        """
        Get the number of pages in the table.
        """

    def getPrevious(self, pageID: typing.Union[jpype.JLong, int]) -> int:
        """
        Get the ID of the page before pageID.
        """

    def hasPage(self, pageID: typing.Union[jpype.JLong, int]) -> bool:
        """
        Return whether the pageID exists in the table.
        """

    def remove(self, pageID: typing.Union[jpype.JLong, int]) -> bool:
        """
        Remove pageID from the table.
        
        :return: true if the pageID was removed
        :rtype: bool
        """

    @property
    def next(self) -> jpype.JLong:
        ...

    @property
    def numPages(self) -> jpype.JInt:
        ...

    @property
    def previous(self) -> jpype.JLong:
        ...


class ObjectStorageAdapter(ghidra.util.ObjectStorage):
    """
    Convenience adapter implementation for saving and restoring Strings and 
    Java primitives or arrays of Strings and primitives for a row of a data table.
    The order in which the puts are done must the same order in which the gets are done.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, table: ghidra.util.datastruct.DataTable, row: typing.Union[jpype.JInt, int]):
        """
        Constructor for ObjectStorageAdapter.
        """

    def getBoolean(self) -> bool:
        """
        
        
        
        .. seealso::
        
            | :obj:`ObjectStorage.getBoolean()`
        """

    def getByte(self) -> int:
        """
        
        
        
        .. seealso::
        
            | :obj:`ObjectStorage.getByte()`
        """

    def getBytes(self) -> jpype.JArray[jpype.JByte]:
        """
        
        
        
        .. seealso::
        
            | :obj:`ObjectStorage.getBytes()`
        """

    def getDouble(self) -> float:
        """
        
        
        
        .. seealso::
        
            | :obj:`ObjectStorage.getDouble()`
        """

    def getDoubles(self) -> jpype.JArray[jpype.JDouble]:
        """
        
        
        
        .. seealso::
        
            | :obj:`ObjectStorage.getDoubles()`
        """

    def getFloat(self) -> float:
        """
        
        
        
        .. seealso::
        
            | :obj:`ObjectStorage.getFloat()`
        """

    def getFloats(self) -> jpype.JArray[jpype.JFloat]:
        """
        
        
        
        .. seealso::
        
            | :obj:`ObjectStorage.getFloats()`
        """

    def getInt(self) -> int:
        """
        
        
        
        .. seealso::
        
            | :obj:`ObjectStorage.getInt()`
        """

    def getInts(self) -> jpype.JArray[jpype.JInt]:
        """
        
        
        
        .. seealso::
        
            | :obj:`ObjectStorage.getInts()`
        """

    def getLong(self) -> int:
        """
        
        
        
        .. seealso::
        
            | :obj:`ObjectStorage.getLong()`
        """

    def getLongs(self) -> jpype.JArray[jpype.JLong]:
        """
        
        
        
        .. seealso::
        
            | :obj:`ObjectStorage.getLongs()`
        """

    def getShort(self) -> int:
        """
        
        
        
        .. seealso::
        
            | :obj:`ObjectStorage.getShort()`
        """

    def getShorts(self) -> jpype.JArray[jpype.JShort]:
        """
        
        
        
        .. seealso::
        
            | :obj:`ObjectStorage.getShorts()`
        """

    def getString(self) -> str:
        """
        
        
        
        .. seealso::
        
            | :obj:`ObjectStorage.getString()`
        """

    def getStrings(self) -> jpype.JArray[java.lang.String]:
        """
        
        
        
        .. seealso::
        
            | :obj:`ObjectStorage.getStrings()`
        """

    def putBoolean(self, value: typing.Union[jpype.JBoolean, bool]):
        """
        
        
        
        .. seealso::
        
            | :obj:`ObjectStorage.putBoolean(boolean)`
        """

    def putByte(self, value: typing.Union[jpype.JByte, int]):
        """
        
        
        
        .. seealso::
        
            | :obj:`ObjectStorage.putByte(byte)`
        """

    def putBytes(self, value: jpype.JArray[jpype.JByte]):
        """
        
        
        
        .. seealso::
        
            | :obj:`ObjectStorage.putBytes(byte[])`
        """

    def putDouble(self, value: typing.Union[jpype.JDouble, float]):
        """
        
        
        
        .. seealso::
        
            | :obj:`ObjectStorage.putDouble(double)`
        """

    def putDoubles(self, value: jpype.JArray[jpype.JDouble]):
        """
        
        
        
        .. seealso::
        
            | :obj:`ObjectStorage.putDoubles(double[])`
        """

    def putFloat(self, value: typing.Union[jpype.JFloat, float]):
        """
        
        
        
        .. seealso::
        
            | :obj:`ObjectStorage.putFloat(float)`
        """

    def putFloats(self, value: jpype.JArray[jpype.JFloat]):
        """
        
        
        
        .. seealso::
        
            | :obj:`ObjectStorage.putFloats(float[])`
        """

    def putInt(self, value: typing.Union[jpype.JInt, int]):
        """
        
        
        
        .. seealso::
        
            | :obj:`ObjectStorage.putInt(int)`
        """

    def putInts(self, value: jpype.JArray[jpype.JInt]):
        """
        
        
        
        .. seealso::
        
            | :obj:`ObjectStorage.putInts(int[])`
        """

    def putLong(self, value: typing.Union[jpype.JLong, int]):
        """
        
        
        
        .. seealso::
        
            | :obj:`ObjectStorage.putLong(long)`
        """

    def putLongs(self, value: jpype.JArray[jpype.JLong]):
        """
        
        
        
        .. seealso::
        
            | :obj:`ObjectStorage.putLongs(long[])`
        """

    def putShort(self, value: typing.Union[jpype.JShort, int]):
        """
        
        
        
        .. seealso::
        
            | :obj:`ObjectStorage.putShort(short)`
        """

    def putShorts(self, value: jpype.JArray[jpype.JShort]):
        """
        
        
        
        .. seealso::
        
            | :obj:`ObjectStorage.putShorts(short[])`
        """

    def putString(self, value: typing.Union[java.lang.String, str]):
        """
        
        
        
        .. seealso::
        
            | :obj:`ObjectStorage.putString(String)`
        """

    def putStrings(self, value: jpype.JArray[java.lang.String]):
        """
        
        
        
        .. seealso::
        
            | :obj:`ObjectStorage.putStrings(String[])`
        """

    @property
    def floats(self) -> jpype.JArray[jpype.JFloat]:
        ...

    @property
    def string(self) -> java.lang.String:
        ...

    @property
    def double(self) -> jpype.JDouble:
        ...

    @property
    def byte(self) -> jpype.JByte:
        ...

    @property
    def float(self) -> jpype.JFloat:
        ...

    @property
    def long(self) -> jpype.JLong:
        ...

    @property
    def int(self) -> jpype.JInt:
        ...

    @property
    def longs(self) -> jpype.JArray[jpype.JLong]:
        ...

    @property
    def boolean(self) -> jpype.JBoolean:
        ...

    @property
    def strings(self) -> jpype.JArray[java.lang.String]:
        ...

    @property
    def ints(self) -> jpype.JArray[jpype.JInt]:
        ...

    @property
    def doubles(self) -> jpype.JArray[jpype.JDouble]:
        ...

    @property
    def bytes(self) -> jpype.JArray[jpype.JByte]:
        ...

    @property
    def short(self) -> jpype.JShort:
        ...

    @property
    def shorts(self) -> jpype.JArray[jpype.JShort]:
        ...


class ObjectValueMap(ValueMap[T], typing.Generic[T]):
    """
    Handles general storage and retrieval of object values indexed by long keys.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, name: typing.Union[java.lang.String, str]):
        """
        Constructor for ObjectPropertySet.
        
        :param java.lang.String or str name: the name associated with this property set.
        """

    def getObject(self, index: typing.Union[jpype.JLong, int]) -> T:
        """
        Retrieves the object stored at the given index.
        
        :param jpype.JLong or int index: the index at which to retrieve the object.
        :return: the object stored at the given index or null if no object is
        stored at the index.
        :rtype: T
        """

    def putObject(self, index: typing.Union[jpype.JLong, int], value: T):
        """
        Stores an object at the given index.  Any object currently at that index
        will be replaced by the new object.
        
        :param jpype.JLong or int index: the index at which to store the object.
        :param T value: the object to store.
        """

    @property
    def object(self) -> T:
        ...


@typing.type_check_only
class ValueStoragePage(java.io.Serializable, typing.Generic[T]):
    """
    Manages property values of type int, String, Object, and
    "void"  for a page of possible addresses. Void serves as a marker 
    for whether an address has a property. The derived class for each type holds
    the actual value of the property, and overrides the
    appropriate add() and get() methods.
    """

    class_: typing.ClassVar[java.lang.Class]



__all__ = ["LongIteratorImpl", "IntValueMap", "TypeMismatchException", "ValueMap", "ValueStoragePageIndex", "ObjectStorageAdapter", "ObjectValueMap", "ValueStoragePage"]
