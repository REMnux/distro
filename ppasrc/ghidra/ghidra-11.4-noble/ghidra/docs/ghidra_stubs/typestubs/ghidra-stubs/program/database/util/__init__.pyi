from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import db
import db.util
import ghidra.program.database
import ghidra.program.database.map
import ghidra.program.model.address
import ghidra.program.model.util
import ghidra.util
import ghidra.util.datastruct
import ghidra.util.task
import java.lang # type: ignore
import java.util # type: ignore


class AddressSetPropertyMapDB(ghidra.program.model.util.AddressSetPropertyMap):
    """
    AddressSetPropertyMap that uses a RangeMapDB to maintain a set of addresses.
    """

    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def createPropertyMap(program: ghidra.program.database.ProgramDB, mapName: typing.Union[java.lang.String, str], errHandler: db.util.ErrorHandler, addrMap: ghidra.program.database.map.AddressMap, lock: ghidra.util.Lock) -> AddressSetPropertyMapDB:
        ...

    def delete(self):
        ...

    @staticmethod
    def getPropertyMap(program: ghidra.program.database.ProgramDB, mapName: typing.Union[java.lang.String, str], errHandler: db.util.ErrorHandler, addrMap: ghidra.program.database.map.AddressMap, lock: ghidra.util.Lock) -> AddressSetPropertyMapDB:
        ...

    def moveAddressRange(self, fromAddr: ghidra.program.model.address.Address, toAddr: ghidra.program.model.address.Address, length: typing.Union[jpype.JLong, int], monitor: ghidra.util.task.TaskMonitor):
        """
        Move the address range to a new starting address.
        
        :param ghidra.program.model.address.Address fromAddr: move from address
        :param ghidra.program.model.address.Address toAddr: move to address
        :param jpype.JLong or int length: number of address to move
        :param ghidra.util.task.TaskMonitor monitor: 
        :raises CancelledException:
        """


class Query(java.lang.Object):
    """
    Query interface used to test a record for some condition.
    """

    class_: typing.ClassVar[java.lang.Class]

    def matches(self, record: db.DBRecord) -> bool:
        """
        Returns true if the given record matches the querys condition.
        
        :param db.DBRecord record: the record to test for compliance.
        """


class DBFieldAdapter(java.lang.Object):
    """
    Interface to get a field adapter where the Field is the primary
    key in the table.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getFields(self, start: typing.Union[jpype.JLong, int], end: typing.Union[jpype.JLong, int]) -> db.DBFieldIterator:
        """
        Get the iterator over the primary key.
        
        :param jpype.JLong or int start: start of iterator
        :param jpype.JLong or int end: end of iterator
        :raises IOException: if there was a problem accessing the database
        """


class DBKeyAdapter(java.lang.Object):
    """
    Adapter to get an iterator over keys in a table.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getKeys(self, start: ghidra.program.model.address.Address, end: ghidra.program.model.address.Address) -> db.DBLongIterator:
        """
        Get an iterator over the keys in the given range.
        
        :param ghidra.program.model.address.Address start: start of range
        :param ghidra.program.model.address.Address end: end of range (inclusive)
        :raises IOException: if there was a problem accessing the database
        """


class EmptyRecordIterator(db.RecordIterator):
    """
    Implementation of a RecordIterator that is always empty.
    """

    class_: typing.ClassVar[java.lang.Class]
    INSTANCE: typing.Final[db.RecordIterator]

    def __init__(self):
        ...

    def delete(self) -> bool:
        """
        
        
        
        .. seealso::
        
            | :obj:`db.RecordIterator.delete()`
        """

    def hasNext(self) -> bool:
        """
        
        
        
        .. seealso::
        
            | :obj:`db.RecordIterator.hasNext()`
        """

    def hasPrevious(self) -> bool:
        """
        
        
        
        .. seealso::
        
            | :obj:`db.RecordIterator.hasPrevious()`
        """

    def next(self) -> db.DBRecord:
        """
        
        
        
        .. seealso::
        
            | :obj:`db.RecordIterator.next()`
        """

    def previous(self) -> db.DBRecord:
        """
        
        
        
        .. seealso::
        
            | :obj:`db.RecordIterator.previous()`
        """


class FieldMatchQuery(Query):
    """
    Query implementation used to test a field in a record to match a given value.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, column: typing.Union[jpype.JInt, int], value: db.Field):
        """
        Constructs a new FieldMatchQuery that tests a records field against a particular value.
        
        :param jpype.JInt or int column: the field index in the record to test.
        :param db.Field value: the Field value to test the record's field against.
        """

    def matches(self, record: db.DBRecord) -> bool:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.database.util.Query.matches(db.DBRecord)`
        """


@typing.type_check_only
class AddressRangeMapIterator(ghidra.program.model.address.AddressRangeIterator):
    """
    An iterator over ranges that have a defined values in the AddressRangeMapDB
     
    
    NOTE: this iterator is complicated by the fact that there can exist a record that represents
    an address range that "wraps around" from the max address to the 0 address, where this record
    actually represents two address ranges. This is cause by changing the image base which shifts
    all records up or down. That shift can cause a record to have a wrapping range where the start
    address is larger than the end address. If such a record exists, it is found during construction
    and the lower address range is extracted from the record and is stored as a special "start range"
    that should be emitted before any other ranges in that space. The upper range of a wrapping
    record will be handled more naturally during the iteration process. When a wrapping record is
    encountered during the normal iteration, only the upper range is used and it will be in the
    correct address range ordering.
    """

    class_: typing.ClassVar[java.lang.Class]


class NotQuery(Query):
    """
    Negates the given query such that this query is the logical "NOT" of the given query.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, q1: Query):
        """
        Construct a new query that results in the not of the given query.
        
        :param Query q1: the query to logically negate.
        """

    def matches(self, record: db.DBRecord) -> bool:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.database.util.Query.matches(db.DBRecord)`
        """


class IndexedAddressIterator(ghidra.program.model.address.AddressIterator):
    """
    Iterates over a FieldIterator; the field is the address but not
    the key; the column for the field must be indexed.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, iter: db.DBFieldIterator, addrMap: ghidra.program.database.map.AddressMap, colIndex: typing.Union[jpype.JInt, int], errHandler: db.util.ErrorHandler):
        """
        Constructor
        
        :param db.DBFieldIterator iter: field iterator that is the address
        :param ghidra.program.database.map.AddressMap addrMap: address map to convert the longs to addresses
        :param jpype.JInt or int colIndex: indexed column in the record
        """


class StringMatchQuery(Query):
    """
    Query for matching string fields with wildcard string.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, col: typing.Union[jpype.JInt, int], searchString: typing.Union[java.lang.String, str], caseSensitive: typing.Union[jpype.JBoolean, bool]):
        """
        Construct a new StringMatchQuery
        
        :param jpype.JInt or int col: column index
        :param java.lang.String or str searchString: string to match
        :param jpype.JBoolean or bool caseSensitive: true if the match should be case sensitive
        """


@deprecated("This map class should not be used except by the OldFunctionMapDB class")
class SharedRangeMapDB(java.lang.Object):
    """
    ``SharedRangeMapDB`` provides a long value range map backed by a database table.
    This map allows values to share a given range with other values.
    
    
    .. deprecated::
    
    This map class should not be used except by the OldFunctionMapDB class
    """

    @typing.type_check_only
    class ValueIterator(java.util.Iterator[db.Field]):
        """
        Iterates over all values which occur within the given range.
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class RangeIterator(ghidra.util.datastruct.IndexRangeIterator):
        """
        Iterates over all ranges occupied by a given value.
        """

        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, dbHandle: db.DBHandle, name: typing.Union[java.lang.String, str], errHandler: db.util.ErrorHandler, create: typing.Union[jpype.JBoolean, bool]):
        """
        Construct a shared range map.
        
        :param db.DBHandle dbHandle: database handle.
        :param java.lang.String or str name: map name used in naming the underlying database table.  
        This name must be unqiue across all shared range maps.
        :param db.util.ErrorHandler errHandler: database error handler.
        :param jpype.JBoolean or bool create: if true the underlying database tables will be created.
        """

    def add(self, start: typing.Union[jpype.JLong, int], end: typing.Union[jpype.JLong, int], value: typing.Union[jpype.JLong, int]):
        """
        Add a value to this map over the specified range.
        
        :param jpype.JLong or int start: the start of the range.
        :param jpype.JLong or int end: the end of the range.
        :param jpype.JLong or int value: the value to associate with the range.
        """

    def dispose(self):
        """
        Frees resources used by this map.
        """

    def getValueIterator(self, start: typing.Union[jpype.JLong, int], end: typing.Union[jpype.JLong, int]) -> java.util.Iterator[db.Field]:
        """
        Get a LongField value iterator over the specified range.
        List is pre-calculated such that any changes made to the map
        after invoking this method will not be reflected by the iterator
        and invalid function keys may be returned.
        The implementation assumes a small set of values exist over the 
        range.
        
        :param jpype.JLong or int start: 
        :param jpype.JLong or int end: 
        :return: Iterator of unique LongField values occuring within the
        specified range.
        :rtype: java.util.Iterator[db.Field]
        """

    def getValueRangeIterator(self, value: typing.Union[jpype.JLong, int]) -> ghidra.util.datastruct.IndexRangeIterator:
        """
        Get an index range iterator for a specified value.
        
        :param jpype.JLong or int value: the value for which to iterator indexes over.
        :return: IndexRangeIterator
        :rtype: ghidra.util.datastruct.IndexRangeIterator
        """

    def remove(self, value: typing.Union[jpype.JLong, int]):
        """
        Remove a value from this map.
        
        :param jpype.JLong or int value: the value to remove.
        """

    @property
    def valueRangeIterator(self) -> ghidra.util.datastruct.IndexRangeIterator:
        ...


class AndQuery(Query):
    """
    Combines two queries such that this query is the logical "AND" of the two queries.  If the
    first query does not match, then the second query is not executed.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, q1: Query, q2: Query):
        """
        Construct a new AndQuery from two other queries.
        
        :param Query q1: the first query
        :param Query q2: the second query
        """

    def matches(self, record: db.DBRecord) -> bool:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.database.util.Query.matches(db.DBRecord)`
        """


class RecordFilter(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def matches(self, record: db.DBRecord) -> bool:
        ...


class QueryRecordIterator(db.RecordIterator):
    """
    Iterator that only returns records from another iterator that match the given query.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, iter: db.RecordIterator, query: Query):
        """
        Constructs a new QueryRecordIterator that filters the given record iterator with
        the given Query.
        
        :param db.RecordIterator iter: the record iterator to filter.
        :param Query query: the query used to filter.
        """

    @typing.overload
    def __init__(self, iter: db.RecordIterator, query: Query, forward: typing.Union[jpype.JBoolean, bool]):
        """
        Constructor
        
        :param db.RecordIterator iter: record iterator
        :param Query query: query needed to match the record
        :param jpype.JBoolean or bool forward: true means iterate in the forward direction
        """

    def delete(self) -> bool:
        """
        
        
        
        .. seealso::
        
            | :obj:`db.RecordIterator.delete()`
        """

    def hasNext(self) -> bool:
        """
        
        
        
        .. seealso::
        
            | :obj:`db.RecordIterator.hasNext()`
        """

    def hasPrevious(self) -> bool:
        """
        
        
        
        .. seealso::
        
            | :obj:`db.RecordIterator.hasPrevious()`
        """

    def next(self) -> db.DBRecord:
        """
        
        
        
        .. seealso::
        
            | :obj:`db.RecordIterator.next()`
        """

    def previous(self) -> db.DBRecord:
        """
        
        
        
        .. seealso::
        
            | :obj:`db.RecordIterator.previous()`
        """


class FieldRangeQuery(Query):
    """
    Query implementation used to test a field in a record to fall within a range of values.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, column: typing.Union[jpype.JInt, int], min: db.Field, max: db.Field):
        """
        Constructs a new FieldRangeQuery that tests a records field against a range of values.
        
        :param jpype.JInt or int column: the field index in the record to test.
        :param db.Field min: the minimum field value to test against.
        :param db.Field max: the maximum field value to test against.
        """

    def matches(self, record: db.DBRecord) -> bool:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.database.util.Query.matches(db.DBRecord)`
        """


class OrQuery(Query):
    """
    Combines two queries such that this query is the logical "OR" of the two queries.  If the
    first query matches, then the second query is not executed.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, q1: Query, q2: Query):
        """
        Construct a new OrQuery from two other queries.
        
        :param Query q1: the first query
        :param Query q2: the second query
        """

    def matches(self, record: db.DBRecord) -> bool:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.database.util.Query.matches(db.DBRecord)`
        """


class AddressRangeMapDB(db.DBListener):
    """
    ``AddressRangeMapDB`` provides a generic value range map backed by a database table.
    Values can be stored for ranges of addresses. When a value is stored for a range, it replaces
    any previous values for that range. It is kind of like painting. If you first paint a region
    red, but then later paint a region in the middle of the red region green, you end up with
    three regions - a green region surrounded by two red regions.
     
    
    This is implemented by storing records for each contiguous range with the same value.
     
    * The key is the encoded start address of the range.
    * The TO_COL column of the record stores the encoded end address of the range.
    * The VALUE_COL column of the record stores the value for the range.
    
     
    
    This implementation is complicated by several issues. 
     
    1. Addresses stored in Ghidra database records are encoded as long keys (see 
    :obj:`AddressMap`). 
    Encoded addresses do not necessarily encode to keys that have the same ordering.
    Therefore, all comparisons must be done in address space and not in the encoded space.
    Also, record iterators must use the:obj:`AddressKeyRecordIterator` which will return
    records in address order versus encoded key order.
    2. The default space's image base can be changed after records have been created. This can
    cause the address ranges represented by a record to wrap around. For example, suppose
    the image base is 0 and you paint a range from address 0 to 0x20, which say maps to
    keys 0 and 20, respectively. Now suppose the image base changes to 0xfffffffe, which
    means key 0 maps to address 0xfffffffe and key 0x20 maps to address 0x1e,(the addresses
    have been effectively shifted down by 2). So now the stored record has a start key of
    0 and an end key of 0x20 which now maps to start address of 0xfffffffe and an end
    address of 0x1e. For our purposes, it is important that we don't just flip the start
    and end address which be a very large range instead of a small range. Instead, we need
    to interpret that as 2 ranges (0xfffffffe - 0xffffffff) and (0 - 0x1e). So all methods
    in this class have be coded to handle this special case. To simplify the painting
    logic, any wrapping record will first be split into two records before painting. However
    we can only do this during a write operation (when we can make changes). Since the getter
    methods and iterators cannot modify the database, they have to deal with wrapping
    records on the fly.
    """

    class_: typing.ClassVar[java.lang.Class]
    RANGE_MAP_TABLE_PREFIX: typing.Final = "Range Map - "

    def __init__(self, dbHandle: db.DBHandle, addressMap: ghidra.program.database.map.AddressMap, lock: ghidra.util.Lock, name: typing.Union[java.lang.String, str], errHandler: db.util.ErrorHandler, valueField: db.Field, indexed: typing.Union[jpype.JBoolean, bool]):
        """
        Construct a generic range map
        
        :param db.DBHandle dbHandle: database handle
        :param ghidra.program.database.map.AddressMap addressMap: the address map
        :param ghidra.util.Lock lock: the program lock
        :param java.lang.String or str name: map name used in naming the underlying database table
        This name must be unique across all range maps
        :param db.util.ErrorHandler errHandler: database error handler
        :param db.Field valueField: specifies the type for the values stored in this map
        :param jpype.JBoolean or bool indexed: if true, values will be indexed allowing use of the 
        :meth:`AddressRangeMapDB.getAddressSet(Field) <AddressRangeMapDB.getAddressSet>` method.
        """

    def clearRange(self, startAddr: ghidra.program.model.address.Address, endAddr: ghidra.program.model.address.Address):
        """
        Remove values from the given range.
        
        :param ghidra.program.model.address.Address startAddr: the start address.
        :param ghidra.program.model.address.Address endAddr: the end address.
        """

    def dispose(self):
        """
        Deletes the database table used to store this range map.
        """

    @staticmethod
    def exists(dbHandle: db.DBHandle, name: typing.Union[java.lang.String, str]) -> bool:
        """
        Tests if an AddressRangeMap table exists with the given name
        
        :param db.DBHandle dbHandle: the database handle
        :param java.lang.String or str name: the name to test for
        :return: true if the a table exists for the given name
        :rtype: bool
        """

    def getAddressRangeContaining(self, address: ghidra.program.model.address.Address) -> ghidra.program.model.address.AddressRange:
        """
        Returns the bounding address range for the given address where all addresses in that
        range have the same value (this also works for now value. i.e finding a gap)
        
        :param ghidra.program.model.address.Address address: the address to find a range for
        :return: an address range that contains the given address and has all the same value
        :rtype: ghidra.program.model.address.AddressRange
        """

    @typing.overload
    def getAddressRanges(self) -> ghidra.program.model.address.AddressRangeIterator:
        """
        Returns an address range iterator over all ranges in the map where a value has been set
        
        :return: AddressRangeIterator that iterates over all occupied ranges in the map
        :rtype: ghidra.program.model.address.AddressRangeIterator
        """

    @typing.overload
    def getAddressRanges(self, startAddress: ghidra.program.model.address.Address) -> ghidra.program.model.address.AddressRangeIterator:
        """
        Returns an address range iterator over all ranges in the map where a value has been set
        starting with the given address
        
        :param ghidra.program.model.address.Address startAddress: The address at which to start iterating ranges
        :return: AddressRangeIterator that iterates over all occupied ranges in the map from the
        given start address
        :rtype: ghidra.program.model.address.AddressRangeIterator
        """

    @typing.overload
    def getAddressRanges(self, startAddress: ghidra.program.model.address.Address, endAddr: ghidra.program.model.address.Address) -> ghidra.program.model.address.AddressRangeIterator:
        """
        Returns an address range iterator over all ranges in the map where a value has been set
        starting with the given address and ending with the given end address
        
        :param ghidra.program.model.address.Address startAddress: the address at which to start iterating ranges
        :param ghidra.program.model.address.Address endAddr: the address at which to end the iterator
        :return: AddressRangeIterator that iterates over all occupied ranges in the map from the
        given start address
        :rtype: ghidra.program.model.address.AddressRangeIterator
        """

    @typing.overload
    def getAddressSet(self) -> ghidra.program.model.address.AddressSet:
        """
        Returns set of addresses where a values has been set
        
        :return: set of addresses where a values has been set
        :rtype: ghidra.program.model.address.AddressSet
        """

    @typing.overload
    def getAddressSet(self, value: db.Field) -> ghidra.program.model.address.AddressSet:
        """
        Returns set of addresses where the given value has been set.
        This method may only be invoked on indexed :obj:`AddressRangeMapDB`s!
        
        :param db.Field value: the value to search for
        :return: set of addresses where the given value has been set
        :rtype: ghidra.program.model.address.AddressSet
        """

    def getRecordCount(self) -> int:
        """
        Returns the number of records contained within this map.
        NOTE: This number will be greater or equal to the number of
        address ranges contained within the map.
        
        :return: record count
        :rtype: int
        """

    def getValue(self, address: ghidra.program.model.address.Address) -> db.Field:
        """
        Returns the value associated with the given address
        
        :param ghidra.program.model.address.Address address: the address of the value
        :return: value or null no value exists
        :rtype: db.Field
        """

    def invalidate(self):
        """
        Notification that something may have changed (undo/redo/image base change) and we need
        to invalidate our cache and possibly have a wrapping record again.
        """

    def isEmpty(self) -> bool:
        """
        Returns true if this map is empty
        
        :return: true if this map is empty
        :rtype: bool
        """

    def moveAddressRange(self, fromAddr: ghidra.program.model.address.Address, toAddr: ghidra.program.model.address.Address, length: typing.Union[jpype.JLong, int], monitor: ghidra.util.task.TaskMonitor):
        """
        Move all values within an address range to a new range.
        
        :param ghidra.program.model.address.Address fromAddr: the first address of the range to be moved.
        :param ghidra.program.model.address.Address toAddr: the address where to the range is to be moved.
        :param jpype.JLong or int length: the number of addresses to move.
        :param ghidra.util.task.TaskMonitor monitor: the task monitor.
        :raises CancelledException: if the user canceled the operation via the task monitor.
        """

    def paintRange(self, startAddress: ghidra.program.model.address.Address, endAddress: ghidra.program.model.address.Address, value: db.Field):
        """
        Associates the given value with every address from start to end (inclusive)
        Any previous associates are overwritten.
        
        :param ghidra.program.model.address.Address startAddress: the start address.
        :param ghidra.program.model.address.Address endAddress: the end address.
        :param db.Field value: value to be painted, or null for value removal.
        :raises IllegalArgumentException: if the start and end addresses are not in the same
        address space
        :raises IllegalArgumentException: if the end address is greater then the start address
        """

    def setName(self, newName: typing.Union[java.lang.String, str]) -> bool:
        """
        Set the name associated with this range map
        
        :param java.lang.String or str newName: the new name for this range map
        :return: true if successful, else false
        :rtype: bool
        :raises DuplicateNameException: if there is already range map with that name
        """

    @property
    def addressSet(self) -> ghidra.program.model.address.AddressSet:
        ...

    @property
    def addressRanges(self) -> ghidra.program.model.address.AddressRangeIterator:
        ...

    @property
    def addressRangeContaining(self) -> ghidra.program.model.address.AddressRange:
        ...

    @property
    def recordCount(self) -> jpype.JInt:
        ...

    @property
    def value(self) -> db.Field:
        ...

    @property
    def empty(self) -> jpype.JBoolean:
        ...


class DBRecordAdapter(java.lang.Object):
    """
    Interface to get a record iterator.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getRecordCount(self) -> int:
        """
        Get the number of function definition datatype records
        
        :return: total record count
        :rtype: int
        """

    def getRecords(self) -> db.RecordIterator:
        """
        Get a record iterator for all records.
        
        :return: record iterator
        :rtype: db.RecordIterator
        :raises IOException: if there was a problem accessing the database
        """

    @property
    def records(self) -> db.RecordIterator:
        ...

    @property
    def recordCount(self) -> jpype.JInt:
        ...


class DatabaseVersionException(java.lang.Exception):
    """
    Exception thrown if the database does not match the expected version of the program classes.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        Construct a new DatabaseException.
        """

    @typing.overload
    def __init__(self, msg: typing.Union[java.lang.String, str]):
        """
        Construct a new DatabaseException with the given message.
        
        :param java.lang.String or str msg: the message.
        """


class DatabaseTableUtils(java.lang.Object):
    """
    Collection of static functions for upgrading various database tables.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    @typing.overload
    def updateAddressKey(table: db.Table, addrMap: ghidra.program.database.map.AddressMap, fromAddr: ghidra.program.model.address.Address, toAddr: ghidra.program.model.address.Address, length: typing.Union[jpype.JLong, int], monitor: ghidra.util.task.TaskMonitor):
        """
        Handles redoing a table whose key is address based when a ranges of addresses is moved.
        
        :param db.Table table: the database table.
        :param ghidra.program.database.map.AddressMap addrMap: the address map.
        :param ghidra.program.model.address.Address fromAddr: the from address of the block being moved.
        :param ghidra.program.model.address.Address toAddr: the destination address of the block being moved.
        :param jpype.JLong or int length: the size of the block being moved.
        :param ghidra.util.task.TaskMonitor monitor: the taskmonitor
        :raises IOException: thrown if a database io error occurs.
        :raises CancelledException: thrown if the user cancels the move operation.
        """

    @staticmethod
    @typing.overload
    def updateAddressKey(table: db.Table, addrMap: ghidra.program.database.map.AddressMap, fromAddr: ghidra.program.model.address.Address, endAddr: ghidra.program.model.address.Address, toAddr: ghidra.program.model.address.Address, monitor: ghidra.util.task.TaskMonitor):
        """
        Handles redoing a table whose key is address based when a ranges of addresses is moved.
        
        :param db.Table table: the database table.
        :param ghidra.program.database.map.AddressMap addrMap: the address map.
        :param ghidra.program.model.address.Address fromAddr: the first address of the block being moved.
        :param ghidra.program.model.address.Address endAddr: the last address of the block being moved.
        :param ghidra.program.model.address.Address toAddr: the destination address of the block being moved.
        :param ghidra.util.task.TaskMonitor monitor: the task monitor
        :raises IOException: thrown if a database io error occurs.
        :raises CancelledException: thrown if the user cancels the move operation.
        """

    @staticmethod
    def updateIndexedAddressField(table: db.Table, addrCol: typing.Union[jpype.JInt, int], addrMap: ghidra.program.database.map.AddressMap, fromAddr: ghidra.program.model.address.Address, toAddr: ghidra.program.model.address.Address, length: typing.Union[jpype.JLong, int], filter: RecordFilter, monitor: ghidra.util.task.TaskMonitor):
        """
        Updates an indexed address field for when a block is moved.
        
        :param db.Table table: the database table
        :param jpype.JInt or int addrCol: the address column in the table
        :param ghidra.program.database.map.AddressMap addrMap: the address map
        :param ghidra.program.model.address.Address fromAddr: the from address of the block being moved
        :param ghidra.program.model.address.Address toAddr: the address to where the block is being moved.
        :param jpype.JLong or int length: the size of the block being moved.
        :param ghidra.util.task.TaskMonitor monitor: the task monitor
        :raises IOException: thrown if a database io error occurs.
        :raises CancelledException: thrown if the user cancels the move operation.
        """


class SynchronizedAddressSetCollection(ghidra.program.model.address.AddressSetCollection):
    """
    Implementation of AddressSetCollection used by :obj:`ProgramChangeSet`.  It contains the
    actual instances of the addressSets used by the :obj:`ProgramChangeSet` and protects access
    to them by synchronizing on the ProgramChangeSet.
     
    Because these objects use the actual addressSets within the programChangeSet for
    efficiency reasons, any changes to those
    underlying sets will be reflected in the set of addresses represented by this collection.  
    But since it is synchronized, you will always get a stable set during any given call and
    the AddressSetCollection interface is careful not to include iterator or other methods
    that can't tolerate a underlying change.  This object is really only intended for use by
    the GUI change bars and if it changes, it only results in possibly seeing the changes bars
    a bit earlier than otherwise.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, sync: java.lang.Object, *addressSetViews: ghidra.program.model.address.AddressSetView):
        ...



__all__ = ["AddressSetPropertyMapDB", "Query", "DBFieldAdapter", "DBKeyAdapter", "EmptyRecordIterator", "FieldMatchQuery", "AddressRangeMapIterator", "NotQuery", "IndexedAddressIterator", "StringMatchQuery", "SharedRangeMapDB", "AndQuery", "RecordFilter", "QueryRecordIterator", "FieldRangeQuery", "OrQuery", "AddressRangeMapDB", "DBRecordAdapter", "DatabaseVersionException", "DatabaseTableUtils", "SynchronizedAddressSetCollection"]
