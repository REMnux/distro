from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import db.buffers
import db.util
import ghidra.framework
import ghidra.util
import ghidra.util.task
import java.io # type: ignore
import java.lang # type: ignore


@typing.type_check_only
class VarRecNode(LongKeyRecordNode):
    """
    ``VarRecNode`` is an implementation of a BTree leaf node
    which utilizes long key values and stores variable-length records.
     
    
    This type of node has the following layout within a single DataBuffer 
    (field size in bytes):
    ``  | NodeType(1) | KeyCount(4) | PrevLeafId(4) | NextLeafId(4) | Key0(8) | RecOffset0(4) | IndFlag0(1) |...  | KeyN(8) | RecOffsetN(4) | IndFlagN(1) |...<FreeSpace>... | RecN |... | Rec0 |``
    IndFlag - if not zero the record has been stored within a chained DBBuffer 
    whose 4-byte integer buffer ID has been stored within this leaf at the record offset.
    """

    class_: typing.ClassVar[java.lang.Class]

    def removeLeaf(self) -> LongKeyNode:
        """
        Removes this leaf and all associated chained buffers.
        
        
        .. seealso::
        
            | :obj:`db.LongKeyRecordNode.removeLeaf()`
        """


@typing.type_check_only
class LongKeyRecordNode(LongKeyNode, RecordNode):
    """
    ``LongKeyRecordNode`` is an abstract implementation of a BTree leaf node
    which utilizes long key values and stores records.
     
    
    This type of node has the following partial layout within a single DataBuffer
    (field size in bytes):
     
    | NodeType(1) | KeyCount(4) | PrevLeafId(4) | NextLeafId(4) | ...
    """

    class_: typing.ClassVar[java.lang.Class]


class Buffer(java.lang.Object):
    """
    ``Buffer`` provides a general purpose storage buffer interface
    providing various data access methods.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def get(self, offset: typing.Union[jpype.JInt, int], bytes: jpype.JArray[jpype.JByte]):
        """
        Get the byte data located at the specified offset and store into the
        bytes array provided.
        
        :param jpype.JInt or int offset: byte offset from start of buffer.
        :param jpype.JArray[jpype.JByte] bytes: byte array to store data
        :raises java.lang.IndexOutOfBoundsException: is thrown if an invalid offset is specified.
        :raises IOException: is thrown if an error occurs while accessing the
        underlying storage.
        """

    @typing.overload
    def get(self, offset: typing.Union[jpype.JInt, int], data: jpype.JArray[jpype.JByte], dataOffset: typing.Union[jpype.JInt, int], length: typing.Union[jpype.JInt, int]):
        """
        Get the byte data located at the specified offset and store into the data
        array  at the specified data offset.
        
        :param jpype.JInt or int offset: byte offset from the start of the buffer.
        :param jpype.JArray[jpype.JByte] data: byte array to store the data.
        :param jpype.JInt or int dataOffset: offset into the data buffer
        :param jpype.JInt or int length: amount of data to read
        :raises java.lang.IndexOutOfBoundsException: if an invalid offset, dataOffset, or length is specified.
        :raises IOException: is thrown if an error occurs while accessing the
        underlying storage.
        """

    @typing.overload
    def get(self, offset: typing.Union[jpype.JInt, int], length: typing.Union[jpype.JInt, int]) -> jpype.JArray[jpype.JByte]:
        """
        Get the byte data located at the specified offset.
        
        :param jpype.JInt or int offset: byte offset from start of buffer.
        :param jpype.JInt or int length: number of bytes to be read and returned
        :return: the byte array.
        :rtype: jpype.JArray[jpype.JByte]
        :raises java.lang.IndexOutOfBoundsException: is thrown if an invalid offset is
        specified or the end of the buffer was encountered while reading the
        data.
        :raises IOException: is thrown if an error occurs while accessing the
        underlying storage.
        """

    def getByte(self, offset: typing.Union[jpype.JInt, int]) -> int:
        """
        Get the 8-bit byte value located at the specified offset.
        
        :param jpype.JInt or int offset: byte offset from start of buffer.
        :return: the byte value at the specified offset.
        :rtype: int
        :raises java.lang.IndexOutOfBoundsException: is thrown if an invalid offset is specified.
        :raises IOException: is thrown if an error occurs while accessing the
        underlying storage.
        """

    def getId(self) -> int:
        """
        Get the buffer ID for this buffer.
        
        :return: int
        :rtype: int
        """

    def getInt(self, offset: typing.Union[jpype.JInt, int]) -> int:
        """
        Get the 32-bit integer value located at the specified offset.
        
        :param jpype.JInt or int offset: byte offset from start of buffer.
        :return: the integer value at the specified offset.
        :rtype: int
        :raises java.lang.IndexOutOfBoundsException: is thrown if an invalid offset is
        specified or the end of the buffer was encountered while reading the
        value.
        :raises IOException: is thrown if an error occurs while accessing the
        underlying storage.
        """

    def getLong(self, offset: typing.Union[jpype.JInt, int]) -> int:
        """
        Get the 64-bit long value located at the specified offset.
        
        :param jpype.JInt or int offset: byte offset from start of buffer.
        :return: the long value at the specified offset.
        :rtype: int
        :raises java.lang.IndexOutOfBoundsException: is thrown if an invalid offset is
        specified or the end of the buffer was encountered while reading the
        value.
        :raises IOException: is thrown if an error occurs while accessing the
        underlying storage.
        """

    def getShort(self, offset: typing.Union[jpype.JInt, int]) -> int:
        """
        Get the 16-bit short value located at the specified offset.
        
        :param jpype.JInt or int offset: byte offset from start of buffer.
        :return: the short value at the specified offset.
        :rtype: int
        :raises java.lang.IndexOutOfBoundsException: is thrown if an invalid offset is
        specified or the end of the buffer was encountered while reading the
        value.
        :raises IOException: is thrown if an error occurs while accessing the
        underlying storage.
        """

    def length(self) -> int:
        """
        Get the length of the buffer in bytes.  The length reflects the number of
        bytes which have been allocated to the buffer.
        
        :return: length of allocated buffer.
        :rtype: int
        """

    @typing.overload
    def put(self, offset: typing.Union[jpype.JInt, int], data: jpype.JArray[jpype.JByte], dataOffset: typing.Union[jpype.JInt, int], length: typing.Union[jpype.JInt, int]) -> int:
        """
        Put a specified number of bytes from the array provided into the buffer
        at the specified offset.  The number of bytes stored is specified by the
        length specified.
        
        :param jpype.JInt or int offset: byte offset from start of buffer.
        :param jpype.JArray[jpype.JByte] data: the byte data to be stored.
        :param jpype.JInt or int dataOffset: the starting offset into the data.
        :param jpype.JInt or int length: the number of bytes to be stored.
        :return: the next available offset into the buffer, or -1 if the buffer is
        full.
        :rtype: int
        :raises java.lang.IndexOutOfBoundsException: if an invalid offset is provided
        or the end of buffer was encountered while storing the data.
        :raises IOException: is thrown if an error occurs while accessing the
        underlying storage.
        """

    @typing.overload
    def put(self, offset: typing.Union[jpype.JInt, int], bytes: jpype.JArray[jpype.JByte]) -> int:
        """
        Put the bytes provided into the buffer at the specified offset. The
        number of bytes stored is determined by the length of the bytes
        array.
        
        :param jpype.JInt or int offset: byte offset from start of buffer.
        :param jpype.JArray[jpype.JByte] bytes: the byte data to be stored.
        :return: the next available offset into the buffer, or -1 if the buffer is
        full.
        :rtype: int
        :raises java.lang.IndexOutOfBoundsException: if an invalid offset is provided
        or the end of buffer was encountered while storing the data.
        :raises IOException: is thrown if an error occurs while accessing the
        underlying storage.
        """

    def putByte(self, offset: typing.Union[jpype.JInt, int], b: typing.Union[jpype.JByte, int]) -> int:
        """
        Put the 8-bit byte value into the buffer at the specified offset.
        
        :param jpype.JInt or int offset: byte offset from start of buffer.
        :param jpype.JByte or int b: the byte value to be stored.
        :return: the next available offset into the buffer, or -1 if the buffer is
        full.
        :rtype: int
        :raises java.lang.IndexOutOfBoundsException: if an invalid offset is provided.
        :raises IOException: is thrown if an error occurs while accessing the
        underlying storage.
        """

    def putInt(self, offset: typing.Union[jpype.JInt, int], v: typing.Union[jpype.JInt, int]) -> int:
        """
        Put the 32-bit integer value into the buffer at the specified offset.
        
        :param jpype.JInt or int offset: byte offset from start of buffer.
        :param jpype.JInt or int v: the integer value to be stored.
        :return: the next available offset into the buffer, or -1 if the buffer is
        full.
        :rtype: int
        :raises java.lang.IndexOutOfBoundsException: if an invalid offset is provided
        or the end of buffer was encountered while storing the data.
        :raises IOException: is thrown if an error occurs while accessing the
        underlying storage.
        """

    def putLong(self, offset: typing.Union[jpype.JInt, int], v: typing.Union[jpype.JLong, int]) -> int:
        """
        Put the 64-bit long value into the buffer at the specified offset.
        
        :param jpype.JInt or int offset: byte offset from start of buffer.
        :param jpype.JLong or int v: the long value to be stored.
        :return: the next available offset into the buffer, or -1 if the buffer is
        full.
        :rtype: int
        :raises java.lang.IndexOutOfBoundsException: if an invalid offset is provided
        or the end of buffer was encountered while storing the data.
        :raises IOException: is thrown if an error occurs while accessing the
        underlying storage.
        """

    def putShort(self, offset: typing.Union[jpype.JInt, int], v: typing.Union[jpype.JShort, int]) -> int:
        """
        Put the 16-bit short value into the buffer at the specified offset.
        
        :param jpype.JInt or int offset: byte offset from start of buffer.
        :param jpype.JShort or int v: the short value to be stored.
        :return: the next available offset into the buffer, or -1 if the buffer is
        full.
        :rtype: int
        :raises java.lang.IndexOutOfBoundsException: if an invalid offset is provided
        or the end of buffer was encountered while storing the data.
        :raises IOException: is thrown if an error occurs while accessing the
        underlying storage.
        """

    @property
    def byte(self) -> jpype.JByte:
        ...

    @property
    def short(self) -> jpype.JShort:
        ...

    @property
    def id(self) -> jpype.JInt:
        ...

    @property
    def long(self) -> jpype.JLong:
        ...

    @property
    def int(self) -> jpype.JInt:
        ...


class ByteField(PrimitiveField):
    """
    ``ByteField`` provides a wrapper for single signed byte data 
    which is read or written to a Record.
    """

    class_: typing.ClassVar[java.lang.Class]
    MIN_VALUE: typing.Final[ByteField]
    """
    Minimum byte field value
    """

    MAX_VALUE: typing.Final[ByteField]
    """
    Maximum byte field value
    """

    ZERO_VALUE: typing.Final[ByteField]
    """
    Zero byte field value
    """

    INSTANCE: typing.Final[ByteField]
    """
    Instance intended for defining a :obj:`Table` :obj:`Schema`
    """


    @typing.overload
    def __init__(self):
        """
        Construct a byte field with an initial value of 0.
        """

    @typing.overload
    def __init__(self, b: typing.Union[jpype.JByte, int]):
        """
        Construct a byte field with an initial value of b.
        
        :param jpype.JByte or int b: initial value
        """


@typing.type_check_only
class FieldKeyRecordNode(RecordNode, FieldKeyNode):
    """
    ``FieldKeyRecordNode`` defines a common interface for :obj:`FieldKeyNode` 
    implementations which are also a :obj:`RecordNode` (i.e., leaf node).
    """

    class_: typing.ClassVar[java.lang.Class]

    def deleteRecord(self, key: Field, table: Table) -> FieldKeyNode:
        """
        Delete the record identified by the specified key.
        
        :param Field key: record key
        :param Table table: table which will be notified when record is deleted.
        :return: root node which may have changed.
        :rtype: FieldKeyNode
        :raises IOException: thrown if IO error occurs
        """

    def getNextLeaf(self) -> FieldKeyRecordNode:
        """
        Get this leaf node's right sibling
        
        :return: this leaf node's right sibling or null if right sibling does not exist.
        :rtype: FieldKeyRecordNode
        :raises IOException: if an IO error occurs
        """

    def getPreviousLeaf(self) -> FieldKeyRecordNode:
        """
        Get this leaf node's left sibling
        
        :return: this leaf node's left sibling or null if left sibling does not exist.
        :rtype: FieldKeyRecordNode
        :raises IOException: if an IO error occurs
        """

    @typing.overload
    def getRecord(self, schema: Schema, index: typing.Union[jpype.JInt, int]) -> DBRecord:
        """
        Get the record located at the specified index.
        
        :param Schema schema: record data schema
        :param jpype.JInt or int index: key index
        :return: Record
        :rtype: DBRecord
        :raises IOException: thrown if IO error occurs
        """

    @typing.overload
    def getRecord(self, key: Field, schema: Schema) -> DBRecord:
        """
        Get the record identified by the specified key.
        
        :param Field key: search key
        :param Schema schema: record data schema
        :return: Record requested or null if record not found.
        :rtype: DBRecord
        :raises IOException: thrown if IO error occurs
        """

    def getRecordAfter(self, key: Field, schema: Schema) -> DBRecord:
        """
        Get the record with the minimum key value which is greater than 
        the specified key.
        
        :param Field key: search key
        :param Schema schema: record data schema
        :return: Record requested or null if record not found.
        :rtype: DBRecord
        :raises IOException: thrown if IO error occurs
        """

    def getRecordAtOrAfter(self, key: Field, schema: Schema) -> DBRecord:
        """
        Get the record with the minimum key value which is greater than or equal 
        to the specified key.
        
        :param Field key: search key
        :param Schema schema: record data schema
        :return: Record requested or null if record not found.
        :rtype: DBRecord
        :raises IOException: thrown if IO error occurs
        """

    def getRecordAtOrBefore(self, key: Field, schema: Schema) -> DBRecord:
        """
        Get the record with the maximum key value which is less than or equal 
        to the specified key.
        
        :param Field key: search key
        :param Schema schema: record data schema
        :return: Record requested or null if record not found.
        :rtype: DBRecord
        :raises IOException: thrown if IO error occurs
        """

    def getRecordBefore(self, key: Field, schema: Schema) -> DBRecord:
        """
        Get the record with the maximum key value which is less than  
        the specified key.
        
        :param Field key: search key
        :param Schema schema: record data schema
        :return: Record requested or null if record not found.
        :rtype: DBRecord
        :raises IOException: thrown if IO error occurs
        """

    def hasNextLeaf(self) -> bool:
        """
        Determine if this record node has a right sibling.
        
        :return: true if right sibling exists
        :rtype: bool
        :raises IOException: if IO error occurs
        """

    def hasPreviousLeaf(self) -> bool:
        """
        Determine if this record node has a left sibling.
        
        :return: true if left sibling exists
        :rtype: bool
        :raises IOException: if IO error occurs
        """

    def putRecord(self, record: DBRecord, table: Table) -> FieldKeyNode:
        """
        Insert or Update a record.
        
        :param DBRecord record: data record with long key
        :param Table table: table which will be notified when record is inserted or updated.
        :return: root node which may have changed.
        :rtype: FieldKeyNode
        :raises IOException: thrown if IO error occurs
        """

    def remove(self, index: typing.Union[jpype.JInt, int]):
        """
        Remove the record identified by index.
        This will never be the last record within the node.
        
        :param jpype.JInt or int index: record index
        :raises IOException: thrown if IO error occurs
        """

    def removeLeaf(self) -> FieldKeyNode:
        """
        Remove this leaf from the tree.
        
        :return: root node which may have changed.
        :rtype: FieldKeyNode
        :raises IOException: thrown if IO error occurs
        """

    @property
    def nextLeaf(self) -> FieldKeyRecordNode:
        ...

    @property
    def previousLeaf(self) -> FieldKeyRecordNode:
        ...


class KeyToRecordIterator(RecordIterator):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, table: Table, keyIter: DBFieldIterator):
        """
        Construct a record iterator from a secondary index key iterator.
        
        :param DBFieldIterator keyIter: key iterator.
        """


class DBInitializer(ghidra.framework.ModuleInitializer):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def run(self):
        ...


@typing.type_check_only
class BinaryDataBuffer(db.buffers.DataBuffer):
    """
    Provides data buffer for encoding use.
    """

    class_: typing.ClassVar[java.lang.Class]


class DBBuffer(java.lang.Object):
    """
    ``DBBuffer`` facilitates synchronized access to a ChainedBuffer.
    """

    class_: typing.ClassVar[java.lang.Class]

    def append(self, buffer: DBBuffer):
        """
        Append the contents of the specified dbBuf onto the end of this buffer.
        The size of this buffer increases by the size of dbBuf.  When the operation 
        is complete, dbBuf object is no longer valid and must not be used.
        
        :param DBBuffer buffer: the buffer to be appended to this buffer.
        :raises UnsupportedOperationException: if read-only, uninitialized data source is used,
        or both buffers do not have the same obfuscation enablement
        :raises IOException: thrown if an IO error occurs
        """

    def delete(self):
        """
        Delete and release all underlying DataBuffers.
        
        :raises IOException: is thrown if an error occurs while accessing the
        underlying storage.
        """

    @typing.overload
    def fill(self, startOffset: typing.Union[jpype.JInt, int], endOffset: typing.Union[jpype.JInt, int], fillByte: typing.Union[jpype.JByte, int]):
        """
        Fill the buffer over the specified range with a byte value.
        
        :param jpype.JInt or int startOffset: starting offset, inclusive
        :param jpype.JInt or int endOffset: ending offset, exclusive
        :param jpype.JByte or int fillByte: byte value
        :raises java.lang.IndexOutOfBoundsException: if an invalid offsets are provided
        or the end of buffer was encountered while storing the data.
        :raises IOException: thrown if an IO error occurs
        """

    @typing.overload
    def fill(self, in_: java.io.InputStream):
        """
        Fill buffer with data provided by InputStream.  If 
        stream is exhausted, the remainder of the buffer will be filled
        with 0's.
        
        :param java.io.InputStream in: data source
        :raises IOException: thrown if IO error occurs.
        """

    @typing.overload
    def get(self, offset: typing.Union[jpype.JInt, int], data: jpype.JArray[jpype.JByte], dataOffset: typing.Union[jpype.JInt, int], length: typing.Union[jpype.JInt, int]):
        """
        Get the byte data located at the specified offset and store into the data
        array  at the specified data offset.
        
        :param jpype.JInt or int offset: byte offset from the start of the buffer.
        :param jpype.JArray[jpype.JByte] data: byte array to store the data.
        :param jpype.JInt or int dataOffset: offset into the data buffer
        :param jpype.JInt or int length: amount of data to read
        :raises java.lang.IndexOutOfBoundsException: if an invalid offset, dataOffset,
        or length is specified.
        :raises IOException: is thrown if an error occurs while accessing the
        underlying storage.
        """

    @typing.overload
    def get(self, offset: typing.Union[jpype.JInt, int], data: jpype.JArray[jpype.JByte]):
        """
        Get the byte data located at the specified offset.
        
        :param jpype.JInt or int offset: byte offset from start of buffer.
        :param jpype.JArray[jpype.JByte] data: data buffer to be filled
        :raises java.lang.IndexOutOfBoundsException: is thrown if an invalid offset is
        specified or the end of the buffer was encountered while reading the
        data.
        :raises IOException: is thrown if an error occurs while accessing the
        underlying storage.
        """

    def getByte(self, offset: typing.Union[jpype.JInt, int]) -> int:
        """
        Get the 8-bit byte value located at the specified offset.
        
        :param jpype.JInt or int offset: byte offset from start of buffer.
        :return: the byte value at the specified offset.
        :rtype: int
        :raises java.lang.IndexOutOfBoundsException: is thrown if an invalid offset is
        specified.
        :raises IOException: is thrown if an error occurs while accessing the
        underlying storage.
        """

    def getId(self) -> int:
        """
        Get the first buffer ID associated with this chained buffer.  This DBBuffer
        may be reinstatiated using the returned buffer ID provided subsequent changes 
        are not made.
        
        :return: buffer ID
        :rtype: int
        """

    def length(self) -> int:
        """
        Returns the length;
        
        :return: this buffers length
        :rtype: int
        """

    @typing.overload
    def put(self, offset: typing.Union[jpype.JInt, int], bytes: jpype.JArray[jpype.JByte], dataOffset: typing.Union[jpype.JInt, int], length: typing.Union[jpype.JInt, int]):
        """
        Put a specified number of bytes from the array provided into the buffer
        at the specified offset.  The number of bytes stored is specified by the
        length specified.
        
        :param jpype.JInt or int offset: byte offset from start of buffer.
        :param jpype.JArray[jpype.JByte] bytes: the byte data to be stored.
        :param jpype.JInt or int dataOffset: the starting offset into the data.
        :param jpype.JInt or int length: the number of bytes to be stored.
        :raises java.lang.IndexOutOfBoundsException: if an invalid offset is provided
        or the end of buffer was encountered while storing the data.
        :raises IOException: is thrown if an error occurs while accessing the
        underlying storage.
        """

    @typing.overload
    def put(self, offset: typing.Union[jpype.JInt, int], bytes: jpype.JArray[jpype.JByte]):
        """
        Put the bytes provided into the buffer at the specified offset. The
        number of bytes stored is determined by the length of the bytes
        array.
        
        :param jpype.JInt or int offset: byte offset from start of buffer.
        :param jpype.JArray[jpype.JByte] bytes: the byte data to be stored.
        :raises java.lang.IndexOutOfBoundsException: if an invalid offset is provided
        or the end of buffer was encountered while storing the data.
        :raises IOException: is thrown if an error occurs while accessing the
        underlying storage.
        """

    def putByte(self, offset: typing.Union[jpype.JInt, int], b: typing.Union[jpype.JByte, int]):
        """
        Put the 8-bit byte value into the buffer at the specified offset.
        
        :param jpype.JInt or int offset: byte offset from start of buffer.
        :param jpype.JByte or int b: the byte value to be stored.
        :raises java.lang.IndexOutOfBoundsException: if an invalid offset is provided.
        :raises IOException: is thrown if an error occurs while accessing the
        underlying storage.
        """

    def setSize(self, size: typing.Union[jpype.JInt, int], preserveData: typing.Union[jpype.JBoolean, bool]):
        """
        Set the new size for this DBBuffer object.
        
        :param jpype.JInt or int size: new size
        :param jpype.JBoolean or bool preserveData: if true, existing data is preserved at the original offsets.  If false,
        no additional effort will be expended to preserve data.
        :raises UnsupportedOperationException: thrown if this ChainedBuffer utilizes an 
        Uninitialized Data Source or is read-only
        :raises IOException: thrown if an IO error occurs.
        """

    def split(self, offset: typing.Union[jpype.JInt, int]) -> DBBuffer:
        """
        Split this DBBuffer object into two separate DBBuffers.  This DBBuffer remains
        valid but its new size is equal offset.  The newly created DBBuffer is 
        returned.
        
        :param jpype.JInt or int offset: the split point.  The byte at this offset becomes the first
        byte within the new buffer.
        :return: the new DBBuffer object.
        :rtype: DBBuffer
        :raises java.lang.IndexOutOfBoundsException: if offset is invalid.
        :raises IOException: thrown if an IO error occurs
        """

    @property
    def byte(self) -> jpype.JByte:
        ...

    @property
    def id(self) -> jpype.JInt:
        ...


class DBChangeSet(java.lang.Object):
    """
    ``DBChangeSet`` facilitates the reading and writing of application
    level change data associated with BufferFile.
    """

    class_: typing.ClassVar[java.lang.Class]

    def read(self, dbh: DBHandle):
        """
        Read into this change set from the specified database handle.
        The database handle will not be retained and should be closed
        by the invoker of this method.
        
        :param DBHandle dbh: database handle
        :raises IOException: if IO error occurs
        """

    def write(self, dbh: DBHandle, isRecoverySave: typing.Union[jpype.JBoolean, bool]):
        """
        Write this change set to the specified database handle.
        The database handle will not be retained and should be closed
        by the invoker of this method.
        
        :param DBHandle dbh: database handle
        :param jpype.JBoolean or bool isRecoverySave: true if this write is because of a recovery snapshot or false
        if due to a user save action.
        :raises IOException: if IO error occurs
        """


@typing.type_check_only
class FixedKeyNode(FieldKeyNode):
    """
    ``FixedKeyNode`` is an abstract implementation of a BTree node
    which utilizes fixed-length key values.  
     
    | NodeType(1) | KeyCount(4) | ...
    """

    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class IndexField(Field):
    """
    ``IndexField`` provides a index table primary key :obj:`Field` 
    implementation which wraps both the index field value (fixed or varaible length) 
    and its' corresponding primary key (fixed or variable length).
    """

    class_: typing.ClassVar[java.lang.Class]


class TerminatedTransactionException(java.lang.RuntimeException):
    """
    ``TerminatedTransactionException`` occurs when a database modification is
    attempted following the forced/premature termination of an open transaction.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, msg: typing.Union[java.lang.String, str]):
        ...


class IllegalFieldAccessException(java.lang.RuntimeException):
    """
    An illegal access has been performed on a field.
    """

    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class LongKeyInteriorNode(LongKeyNode, InteriorNode):
    """
    ``LongKeyInteriorNode`` stores a BTree node for use as an interior
    node when searching for Table records within the database.  This type of node
    has the following layout within a single DataBuffer (field size in bytes):
     
    | NodeType(1) | KeyCount(4) | Key0(8) | ID0(4) | ... | KeyN(8) | IDN(4) |
    """

    class_: typing.ClassVar[java.lang.Class]

    def isLeftmostKey(self, key: typing.Union[jpype.JLong, int]) -> bool:
        ...

    def isRightmostKey(self, key: typing.Union[jpype.JLong, int]) -> bool:
        ...

    @property
    def rightmostKey(self) -> jpype.JBoolean:
        ...

    @property
    def leftmostKey(self) -> jpype.JBoolean:
        ...


@typing.type_check_only
class VarKeyRecordNode(VarKeyNode, FieldKeyRecordNode):
    """
    ``VarKeyRecordNode`` is an implementation of a BTree leaf node
    which utilizes variable-length key values and stores variable-length records.
    This type of node has the following layout within a single DataBuffer 
    (field size in bytes):
     
    |   NodeType(1) | KeyType(1) | KeyCount(4) | PrevLeafId(4) | NextLeafId(4) | KeyOffset0(4) | IndFlag0(1) |...      
     
    | KeyOffsetN(4) | IndFlagN(1) |...<FreeSpace>... | KeyN | RecN |... | Key0 | Rec0 |
     
    IndFlag - if not zero the record has been stored within a chained DBBuffer 
    whose 4-byte integer buffer ID has been stored within this leaf at the record offset.
    """

    class_: typing.ClassVar[java.lang.Class]

    def deleteRecord(self, key: Field, table: Table) -> VarKeyNode:
        """
        Delete the record identified by the specified key.
        
        :param Field key: record key
        :param Table table: table which will be notified when record is deleted.
        :return: root node which may have changed.
        :rtype: VarKeyNode
        :raises IOException: thrown if IO error occurs
        """

    def getNextLeaf(self) -> VarKeyRecordNode:
        """
        Get this leaf node's right sibling
        
        :return: this leaf node's right sibling or null if right sibling does not exist.
        :rtype: VarKeyRecordNode
        :raises IOException: thrown if an IO error occurs
        """

    def getPreviousLeaf(self) -> VarKeyRecordNode:
        """
        Get this leaf node's left sibling
        
        :return: this leaf node's left sibling or null if left sibling does not exist.
        :rtype: VarKeyRecordNode
        :raises IOException: if an IO error occurs
        """

    def getRecord(self, schema: Schema, index: typing.Union[jpype.JInt, int]) -> DBRecord:
        """
        Get the record located at the specified index.
        
        :param Schema schema: record data schema
        :param jpype.JInt or int index: key index
        :return: Record
        :rtype: DBRecord
        """

    def remove(self, index: typing.Union[jpype.JInt, int]):
        """
        Remove the record identified by index.
        This will never be the last record within the node.
        
        :param jpype.JInt or int index: record index
        :raises IOException: thrown if IO error occurs
        """

    def removeLeaf(self) -> VarKeyNode:
        """
        Remove this leaf and all associated chained buffers from the tree.
        
        :return: root node which may have changed.
        :rtype: VarKeyNode
        :raises IOException: thrown if IO error occurs
        """

    @property
    def nextLeaf(self) -> VarKeyRecordNode:
        ...

    @property
    def previousLeaf(self) -> VarKeyRecordNode:
        ...


@typing.type_check_only
class IndexTable(java.lang.Object):
    """
    ``IndexTable`` maintains a secondary index within a private Table instance.
    This index facilitates the indexing of non-unique secondary keys within a
    user Table.
    """

    class_: typing.ClassVar[java.lang.Class]


class TranslatedRecordIterator(RecordIterator):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, it: RecordIterator, translator: RecordTranslator):
        ...


@typing.type_check_only
class FixedKeyVarRecNode(FixedKeyRecordNode):
    """
    ``FixedKeyVarRecNode`` is an implementation of a BTree leaf node
    which utilizes fixed-length key values and stores variable-length records.
     
    
    This type of node has the following layout within a single DataBuffer 
    (field size in bytes, where 'L' is the fixed length of the fixed-length 
    key as specified by key type in associated Schema)::
     
    | NodeType(1) | KeyCount(4) | PrevLeafId(4) | NextLeafId(4) | Key0(L) | RecOffset0(4) | IndFlag0(1) |...  
         
    | KeyN(L) | RecOffsetN(4) | IndFlagN(1) |...<FreeSpace>... | RecN |... | Rec0 |
     
    IndFlag - if not zero the record has been stored within a chained DBBuffer 
    whose 4-byte integer buffer ID has been stored within this leaf at the record offset.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getRecordDataOffset(self, index: typing.Union[jpype.JInt, int]) -> int:
        """
        Get the record offset within the buffer
        
        :param jpype.JInt or int index: key index
        :return: record offset
        :rtype: int
        """

    @property
    def recordDataOffset(self) -> jpype.JInt:
        ...


class BinaryCodedField(BinaryField):
    """
    Allows various non-database supported data types to be
    encoded within a BinaryField which may be stored within the
    database.
     
    
    Although the BinaryField stores a byte array, this type
    is supported by this class so that the use of a BinaryField
    within a table can always relate to this class and still
    support a byte array.
    """

    class_: typing.ClassVar[java.lang.Class]
    BYTE_ARRAY: typing.Final = 0
    """
    byte[] data type
    """

    FLOAT: typing.Final = 1
    """
    float data type
    """

    DOUBLE: typing.Final = 2
    """
    double data type
    """

    SHORT_ARRAY: typing.Final = 3
    """
    short data type
    """

    INT_ARRAY: typing.Final = 4
    """
    int[] data type
    """

    LONG_ARRAY: typing.Final = 5
    """
    long[] data type
    """

    FLOAT_ARRAY: typing.Final = 6
    """
    float[] data type
    """

    DOUBLE_ARRAY: typing.Final = 7
    """
    double[] data type
    """

    STRING_ARRAY: typing.Final = 8
    """
    String[] data type
    """


    @typing.overload
    def __init__(self, binField: BinaryField):
        """
        Construct a coded field from an existing binary field.
        
        :param BinaryField binField: the binary field
        """

    @typing.overload
    def __init__(self, value: typing.Union[jpype.JDouble, float]):
        """
        Construct a coded field from a double value.
        
        :param jpype.JDouble or float value: the double value
        """

    @typing.overload
    def __init__(self, value: typing.Union[jpype.JFloat, float]):
        """
        Construct a coded field from a float value.
        
        :param jpype.JFloat or float value: the float value
        """

    @typing.overload
    def __init__(self, values: jpype.JArray[jpype.JByte]):
        """
        Construct a coded field from a byte array.
        
        :param jpype.JArray[jpype.JByte] values: byte array
        """

    @typing.overload
    def __init__(self, values: jpype.JArray[jpype.JShort]):
        """
        Construct a coded field from a short array.
        
        :param jpype.JArray[jpype.JShort] values: short array
        """

    @typing.overload
    def __init__(self, values: jpype.JArray[jpype.JInt]):
        """
        Construct a coded field from a int array.
        
        :param jpype.JArray[jpype.JInt] values: int array
        """

    @typing.overload
    def __init__(self, values: jpype.JArray[jpype.JLong]):
        """
        Construct a coded field from a long array.
        
        :param jpype.JArray[jpype.JLong] values: long array
        """

    @typing.overload
    def __init__(self, values: jpype.JArray[jpype.JFloat]):
        """
        Construct a coded field from a float array.
        
        :param jpype.JArray[jpype.JFloat] values: float array
        """

    @typing.overload
    def __init__(self, values: jpype.JArray[jpype.JDouble]):
        """
        Construct a coded field from a double array.
        
        :param jpype.JArray[jpype.JDouble] values: double array
        """

    @typing.overload
    def __init__(self, strings: jpype.JArray[java.lang.String]):
        """
        Construct a coded field from a String array.
        
        :param jpype.JArray[java.lang.String] strings: String array
        """

    def getByteArray(self) -> jpype.JArray[jpype.JByte]:
        """
        Get the byte array contained with this field.
        
        :return: byte array
        :rtype: jpype.JArray[jpype.JByte]
        :raises IllegalFieldAccessException: if data type is not BYTE_ARRAY.
        """

    def getDataType(self) -> int:
        """
        Get the data type associated with this field.
        
        :return: data type
        :rtype: int
        """

    def getDoubleArray(self) -> jpype.JArray[jpype.JDouble]:
        """
        Get the double array contained with this field.
        
        :return: double array
        :rtype: jpype.JArray[jpype.JDouble]
        :raises IllegalFieldAccessException: if data type is not DOUBLE_ARRAY.
        """

    def getDoubleValue(self) -> float:
        """
        Get the double value contained with this field.
        
        :return: double value
        :rtype: float
        :raises IllegalFieldAccessException: if data type is not DOUBLE.
        """

    def getFloatArray(self) -> jpype.JArray[jpype.JFloat]:
        """
        Get the float array contained with this field.
        
        :return: float array
        :rtype: jpype.JArray[jpype.JFloat]
        :raises IllegalFieldAccessException: if data type is not FLOAT_ARRAY.
        """

    def getFloatValue(self) -> float:
        """
        Get the float value contained with this field.
        
        :return: float value
        :rtype: float
        :raises IllegalFieldAccessException: if data type is not FLOAT.
        """

    def getIntArray(self) -> jpype.JArray[jpype.JInt]:
        """
        Get the int array contained with this field.
        
        :return: int array
        :rtype: jpype.JArray[jpype.JInt]
        :raises IllegalFieldAccessException: if data type is not INT_ARRAY.
        """

    def getLongArray(self) -> jpype.JArray[jpype.JLong]:
        """
        Get the long array contained with this field.
        
        :return: long array
        :rtype: jpype.JArray[jpype.JLong]
        :raises IllegalFieldAccessException: if data type is not LONG_ARRAY.
        """

    def getShortArray(self) -> jpype.JArray[jpype.JShort]:
        """
        Get the short array contained with this field.
        
        :return: short array
        :rtype: jpype.JArray[jpype.JShort]
        :raises IllegalFieldAccessException: if data type is not SHORT_ARRAY.
        """

    def getStringArray(self) -> jpype.JArray[java.lang.String]:
        """
        Get the String array contained with this field.
        
        :return: String array
        :rtype: jpype.JArray[java.lang.String]
        :raises IllegalFieldAccessException: if data type is not STRING_ARRAY.
        """

    @property
    def floatArray(self) -> jpype.JArray[jpype.JFloat]:
        ...

    @property
    def shortArray(self) -> jpype.JArray[jpype.JShort]:
        ...

    @property
    def doubleArray(self) -> jpype.JArray[jpype.JDouble]:
        ...

    @property
    def longArray(self) -> jpype.JArray[jpype.JLong]:
        ...

    @property
    def dataType(self) -> jpype.JByte:
        ...

    @property
    def byteArray(self) -> jpype.JArray[jpype.JByte]:
        ...

    @property
    def floatValue(self) -> jpype.JFloat:
        ...

    @property
    def stringArray(self) -> jpype.JArray[java.lang.String]:
        ...

    @property
    def doubleValue(self) -> jpype.JDouble:
        ...

    @property
    def intArray(self) -> jpype.JArray[jpype.JInt]:
        ...


class BooleanField(PrimitiveField):
    """
    ``BooleanField`` provides a wrapper for boolean data which is read or
    written to a Record.
    """

    class_: typing.ClassVar[java.lang.Class]
    MIN_VALUE: typing.Final[BooleanField]
    """
    Minimum boolean field value (FALSE)
    """

    MAX_VALUE: typing.Final[BooleanField]
    """
    Maximum boolean field value (TRUE)
    """

    INSTANCE: typing.Final[BooleanField]
    """
    Instance intended for defining a :obj:`Table` :obj:`Schema`
    """


    @typing.overload
    def __init__(self):
        """
        Construct a boolean data field with an initial value of false.
        """

    @typing.overload
    def __init__(self, b: typing.Union[jpype.JBoolean, bool]):
        """
        Construct a boolean data field with an initial value of b.
        
        :param jpype.JBoolean or bool b: initial value
        """


class ObjectStorageAdapterDB(ghidra.util.ObjectStorage):
    """
    ``ObjectStorageAdapterDB`` provides an ObjectStorage 
    implementation for use by Saveable objects.  This allows Saveable objects 
    to save or restore their state using a fixed set of primitives and primitive arrays. 
    This implementation provides various data access methods for storing/retrieving data.
    In addition, support is provided for utilizing a Record object for data storage
    using a suitable schema.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        Construct an empty writable storage adapter.
        """

    @typing.overload
    def __init__(self, rec: DBRecord):
        """
        Construct a read-only storage adapter from an
        existing record.
        
        :param DBRecord rec: data record
        """

    def getSchema(self, version: typing.Union[jpype.JInt, int]) -> Schema:
        """
        Get the Schema associated with the stored data.
        
        :param jpype.JInt or int version: version to be assigned to schema instance
        :return: Schema
        :rtype: Schema
        """

    def save(self, rec: DBRecord):
        """
        Save data into a Record.
        
        :param DBRecord rec: database record.
        """

    @property
    def schema(self) -> Schema:
        ...


class InteriorNode(BTreeNode):
    """
    Marker interface for :obj:`Table` interior nodes within the BTree structure.
    """

    class_: typing.ClassVar[java.lang.Class]


class DBFileListener(java.lang.Object):
    """
    ``DBFileListener`` facilitates listener notification
    when new database versions are created.
    """

    class_: typing.ClassVar[java.lang.Class]

    def versionCreated(self, db: Database, version: typing.Union[jpype.JInt, int]):
        """
        A new database version has been created.
        
        :param Database db: 
        :param jpype.JInt or int version:
        """


class FieldKeyInteriorNode(InteriorNode, FieldKeyNode):
    """
    ``FieldKeyInteriorNode`` defines a common interface for :obj:`FieldKeyNode` 
    implementations which are also an :obj:`InteriorNode`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def keyChanged(self, oldKey: Field, newKey: Field, childNode: FieldKeyNode):
        """
        Callback method for when a child node's leftmost key changes.
        
        :param Field oldKey: previous leftmost key.
        :param Field newKey: new leftmost key.
        :param FieldKeyNode childNode: child node containing oldKey (null if not a VarKeyNode)
        :raises IOException: if IO error occurs
        """


class ChainedBuffer(Buffer):
    """
    ``DBBuffer`` provides storage for large data objects utilizing a common
    buffer management system.  Smaller data buffers are allocated and chained as needed.
    All instances of DBBuffer must be immediately discarded following an undo or redo on the 
    associated DBHandle.
     
    
    The largest supported chained buffer is about 2-GBytes.  This limit may be slightly smaller 
    based upon the underlying database buffer size.
     
    
    The buffer may consist of either a single Data Node or a series of Index Nodes 
    which reference Data Nodes.
     
    Data Node (Non-indexed):
    | 9 (1) | Obfuscation/DataLength(4) | Data ...
     
    Data Node (Indexed):
    | 9 (1) | Data ...
     
    Index Node:
    | 8 (1) | Obfuscation/DataLength(4) | NextIndexId(4) | DataBuffer1Id(4) | ... | DataBufferNId(4) |
    Number of index entries computed based upon data length and buffer size.  The index for 
    the entire data space is divided among a series of Index Nodes which
    are chained together using the NextIndexId field. Each Index Node identifies 
    Data Nodes which have been allocated by a DataBufferId.  A DataBufferId of -1 indicates an
    non-allocated data node.  The DataLength field is only used in the first index buffer.
       
    Obfuscation:
    Data obfuscation is indicated by a '1' in the most-significant bit of the Obfuscation/DataLength 
    field.
     
    Once a DBBuffer is deleted or appended to another DBBuffer, it becomes invalid and 
    may no longer be used.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, size: typing.Union[jpype.JInt, int], enableObfuscation: typing.Union[jpype.JBoolean, bool], uninitializedDataSource: Buffer, unintializedDataSourceOffset: typing.Union[jpype.JInt, int], bufferMgr: db.buffers.BufferMgr):
        """
        Construct a new chained buffer with optional obfuscation and uninitialized data source.
        This method may only be invoked while a database transaction 
        is in progress.
        
        :param jpype.JInt or int size: buffer size (0 < size <= 0x7fffffff)
        :param jpype.JBoolean or bool enableObfuscation: true to enable xor-ing of stored data to facilitate data obfuscation.
        :param Buffer uninitializedDataSource: optional data source for uninitialized data.  This should be a 
        read-only buffer which will always be used when re-instantiating the same stored ChainedBuffer.
        This should not be specified if buffer will be completely filled/initialized.
        :param jpype.JInt or int unintializedDataSourceOffset: uninitialized data source offset which corresponds to
        this buffers contents.
        :param db.buffers.BufferMgr bufferMgr: database buffer manager
        :raises IOException: thrown if an IO error occurs
        """

    @typing.overload
    def __init__(self, size: typing.Union[jpype.JInt, int], enableObfuscation: typing.Union[jpype.JBoolean, bool], bufferMgr: db.buffers.BufferMgr):
        """
        Construct a new chained buffer with optional obfuscation.
        This method may only be invoked while a database transaction 
        is in progress.
        
        :param jpype.JInt or int size: buffer size (0 < size <= 0x7fffffff)
        :param jpype.JBoolean or bool enableObfuscation: true to enable xor-ing of stored data to facilitate data obfuscation.
        :param db.buffers.BufferMgr bufferMgr: database buffer manager
        :raises IOException: thrown if an IO error occurs
        """

    @typing.overload
    def __init__(self, size: typing.Union[jpype.JInt, int], bufferMgr: db.buffers.BufferMgr):
        """
        Construct a new chained buffer.
        This method may only be invoked while a database transaction is in progress.
        
        :param jpype.JInt or int size: buffer size (0 < size <= 0x7fffffff)
        :param db.buffers.BufferMgr bufferMgr: database buffer manager
        :raises IOException: thrown if an IO error occurs
        """

    @typing.overload
    def __init__(self, bufferMgr: db.buffers.BufferMgr, bufferId: typing.Union[jpype.JInt, int], uninitializedDataSource: Buffer, unintializedDataSourceOffset: typing.Union[jpype.JInt, int]):
        """
        Construct an existing chained buffer.
        
        :param db.buffers.BufferMgr bufferMgr: database buffer manager
        :param jpype.JInt or int bufferId: database buffer ID which corresponds to a stored ChainedBuffer
        :param Buffer uninitializedDataSource: optional data source for uninitialized data.  This should be a 
        read-only buffer which will always be used when re-instantiating the same stored ChainedBuffer.
        This should not be specified if buffer will be completely filled/initialized.
        :param jpype.JInt or int unintializedDataSourceOffset: uninitialized data source offset which corresponds to
        this buffers contents.
        :raises IOException: thrown if an IO error occurs
        """

    @typing.overload
    def __init__(self, bufferMgr: db.buffers.BufferMgr, bufferId: typing.Union[jpype.JInt, int]):
        """
        Construct an existing chained buffer.
        
        :param db.buffers.BufferMgr bufferMgr: database buffer manager
        :param jpype.JInt or int bufferId: database buffer ID which corresponds to a stored ChainedBuffer
        :raises IOException: thrown if an IO error occurs
        """

    def append(self, dbBuf: ChainedBuffer):
        """
        Append the contents of the specified dbBuf onto the end of this buffer.
        The size of this buffer increases by the size of dbBuf.  When the operation 
        is complete, dbBuf object is no longer valid and must not be used.
        
        :param ChainedBuffer dbBuf: the buffer to be appended to this buffer.
        :raises IOException: thrown if an IO error occurs
        :raises UnsupportedOperationException: if read-only, uninitialized data source is used,
        or both buffers do not have the same obfuscation enablement
        """

    def delete(self):
        """
        Delete and release all underlying DataBuffers.
        
        :raises IOException: thrown if an IO error occurs
        """

    @typing.overload
    def fill(self, startOffset: typing.Union[jpype.JInt, int], endOffset: typing.Union[jpype.JInt, int], fillByte: typing.Union[jpype.JByte, int]):
        """
        Fill the buffer over the specified range with a byte value.
        
        :param jpype.JInt or int startOffset: starting offset, inclusive
        :param jpype.JInt or int endOffset: ending offset, inclusive
        :param jpype.JByte or int fillByte: byte value
        :raises java.lang.IndexOutOfBoundsException: if an invalid offsets are provided
        or the end of buffer was encountered while storing the data.
        :raises IOException: thrown if an IO error occurs
        """

    @typing.overload
    def fill(self, in_: java.io.InputStream):
        """
        Fill buffer with data provided by InputStream.  If 
        stream is exhausted, the remainder of the buffer will be filled
        with 0's.
        
        :param java.io.InputStream in: data source
        :raises IOException: thrown if IO error occurs.
        """

    def getId(self) -> int:
        """
        Get the first buffer ID associated with this chained buffer.  This DBBuffer
        may be reinstatiated using the returned buffer ID provided subsequent changes 
        are not made.
        
        :return: buffer ID
        :rtype: int
        """

    def hasObfuscatedStorage(self) -> bool:
        """
        
        
        :return: true if obfuscated data storage has been enabled
        :rtype: bool
        """

    def setReadOnly(self):
        """
        Set the read-only state of this ChainedBuffer.  After invoking this method any
        attempt to alter this buffer will result in an UnsupportedOperation exception.
        """

    def setSize(self, size: typing.Union[jpype.JInt, int], preserveData: typing.Union[jpype.JBoolean, bool]):
        """
        Set the new size for this DBBuffer object.
        
        :param jpype.JInt or int size: new size
        :param jpype.JBoolean or bool preserveData: if true, existing data is preserved at the original offsets.  If false,
        no additional effort will be expended to preserve data.
        :raises UnsupportedOperationException: thrown if this ChainedBuffer utilizes an 
        Uninitialized Data Source or is read-only
        :raises IOException: thrown if an IO error occurs.
        """

    def split(self, offset: typing.Union[jpype.JInt, int]) -> ChainedBuffer:
        """
        Split this DBBuffer object into two separate DBBuffers.  This DBBuffer remains
        valid but its new size is equal offset.  The newly created DBBuffer is 
        returned.
        
        :param jpype.JInt or int offset: the split point.  The byte at this offset becomes the first
        byte within the new buffer.
        :return: the new DBBuffer object.
        :rtype: ChainedBuffer
        :raises UnsupportedOperationException: thrown if this ChainedBuffer is read-only
        :raises java.lang.IndexOutOfBoundsException: if offset is invalid.
        :raises IOException: thrown if an IO error occurs
        """

    @property
    def id(self) -> jpype.JInt:
        ...


@typing.type_check_only
class NodeMgr(java.lang.Object):
    """
    The ``NodeMgr`` manages all database nodes associated with 
    a table.  Each table should use a separate instance of a NodeMgr.
    The NodeMgr is resposible for interacting with the BufferMgr performing 
    buffer allocations, retrievals and releases as required.   The NodeMgr
    also performs hard caching of all buffers until the releaseNodes
    method is invoked. 
     
    Legacy Issues (prior to Ghidra 9.2):
     
    * Legacy :obj:`Table` implementation incorrectly employed :obj:`VarKeyNode` 
    storage with primitive fixed-length primary keys other than:obj:`LongField` 
    (e.g.,:obj:`ByteField`).  With improved support for fixed-length keys
    legacy data poses a backward capatibility issue.  This has been
    addressed through the use of a hack whereby a:obj:`Schema` is forced to
    treat the primary key as variable length
    (see:meth:`Schema.forceUseOfVariableLengthKeyNodes() <Schema.forceUseOfVariableLengthKeyNodes>`.  The detection
    for this rare condition is provided by:obj:`TableRecord` during
    schema instantiation.
    * Legacy :obj:`Table` implementation incorrectly employed variable 
    length storage when both primary key and indexed fields were
    LongField types.  This issue has been addressed by treating the
    :obj:`Field.LEGACY_INDEX_LONG_TYPE` (0x8) as variable-length (see 
    implementation:obj:`LegacyIndexField`).
    """

    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class FixedKeyInteriorNode(FixedKeyNode, FieldKeyInteriorNode):
    """
    ``FixedKeyInteriorNode`` stores a BTree node for use as an interior
    node when searching for Table records within the database.  This type of node
    has the following layout within a single DataBuffer (field size in bytes,
    where 'L' is the fixed length of the fixed-length key as specified by 
    key type in associated Schema):
     
    | NodeType(1) | KeyCount(4) | Key0(L) | ID0(4) | ... | KeyN(L) | IDN(4) |
    """

    class_: typing.ClassVar[java.lang.Class]


class FixedField10(FixedField):
    """
    ``FixedField10`` provide an unsigned 10-byte fixed-length field value.
    The most-significant byte corresponds to index-0 (i.e., data[0]).
    """

    class_: typing.ClassVar[java.lang.Class]
    ZERO_VALUE: typing.Final[FixedField10]
    """
    Zero fixed10 field value
    """

    MIN_VALUE: typing.ClassVar[FixedField10]
    """
    Minimum long field value
    """

    MAX_VALUE: typing.ClassVar[FixedField10]
    """
    Maximum long field value
    """

    INSTANCE: typing.Final[FixedField10]
    """
    Instance intended for defining a :obj:`Table` :obj:`Schema`
    """


    @typing.overload
    def __init__(self):
        """
        Construct a 10-byte fixed-length field with an initial value of 0.
        """

    @typing.overload
    def __init__(self, data: jpype.JArray[jpype.JByte]):
        """
        Construct a 10-byte fixed-length field with an initial value of data.
        
        :param jpype.JArray[jpype.JByte] data: initial 10-byte binary value.  A null corresponds to zero value 
        and does not affect the null-state (see :meth:`setNull() <.setNull>` and :meth:`isNull() <.isNull>`).
        :raises IllegalArgumentException: thrown if data is not 10-bytes in length
        """

    @typing.overload
    def __init__(self, data: jpype.JArray[jpype.JByte], immutable: typing.Union[jpype.JBoolean, bool]):
        """
        Construct a 10-byte fixed-length binary field with an initial value of data.
        
        :param jpype.JArray[jpype.JByte] data: initial 10-byte binary value.  A null corresponds to zero value 
        and does not affect the null-state (see :meth:`setNull() <.setNull>` and :meth:`isNull() <.isNull>`).
        :param jpype.JBoolean or bool immutable: true if field value is immutable
        :raises IllegalArgumentException: thrown if data is not 10-bytes in length
        """


class RecordTranslator(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def translateRecord(self, oldRecord: DBRecord) -> DBRecord:
        """
        Translate the indicated old database record into a current database record.
        
        :param DBRecord oldRecord: the old database record.
        :return: the new data base record in the form required for the current database version.
        :rtype: DBRecord
        :raises IOException: if database IO error occurs
        """


class Table(java.lang.Object):
    """
    Table implementation class.
    NOTE: Most public methods are synchronized on the associated DBHandle instance
    to prevent concurrent modification by multiple threads.
    """

    @typing.type_check_only
    class LongKeyRecordIterator(RecordIterator):
        """
        A RecordIterator class for use with table data contained within LeafNode's.
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class FieldKeyRecordIterator(RecordIterator):
        """
        A RecordIterator class for use with table data contained within LeafNode's.
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class LongKeyIterator(DBLongIterator):
        """
        A long key iterator class.
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class LongDurationLongKeyIterator(DBLongIterator):
        """
        A long key iterator class - optimized for long iterations since
        all keys are read for each record node.
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ShortDurationLongKeyIterator(DBLongIterator):
        """
        A long key iterator class - optimized for short iterations since
        the number of keys read from each record node is minimized.
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class FieldKeyIterator(DBFieldIterator):
        """
        A Field key iterator class.  The initial iterator is optimized for
        short iterations.  If it determined that the iterator is to be used 
        for a large number of iterations, the underlying iterator is switched
        to one optimized for longer iterations.
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class LongDurationFieldKeyIterator(DBFieldIterator):
        """
        A Field key iterator class - optimized for long iterations since
        all keys are read for each record node.
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ShortDurationFieldKeyIterator(DBFieldIterator):
        """
        A Field key iterator class - optimized for short iterations since
        the number of keys read from each record node is minimized.
        """

        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def deleteAll(self):
        """
        Delete all records within this table.
        
        :raises IOException: if IO error occurs
        """

    @typing.overload
    def deleteRecord(self, key: typing.Union[jpype.JLong, int]) -> bool:
        """
        Delete a record identified by the specified key value.
        
        :param jpype.JLong or int key: unique record key.
        :return: true if record was deleted successfully.
        :rtype: bool
        :raises IOException: throw if an IO Error occurs
        """

    @typing.overload
    def deleteRecord(self, key: Field) -> bool:
        """
        Delete a record identified by the specified key value.
        
        :param Field key: unique record key.
        :return: true if record was deleted successfully.
        :rtype: bool
        :raises IOException: throw if an IO Error occurs
        """

    @typing.overload
    def deleteRecords(self, startKey: typing.Union[jpype.JLong, int], endKey: typing.Union[jpype.JLong, int]) -> bool:
        """
        Delete all records whose keys fall within the specified range, inclusive.
        
        :param jpype.JLong or int startKey: minimum key value
        :param jpype.JLong or int endKey: maximum key value
        :return: true if one or more records were deleted.
        :rtype: bool
        :raises IOException: thrown if an IO error occurs
        """

    @typing.overload
    def deleteRecords(self, startKey: Field, endKey: Field) -> bool:
        """
        Delete all records whose keys fall within the specified range, inclusive.
        
        :param Field startKey: minimum key value
        :param Field endKey: maximum key value
        :return: true if one or more records were deleted.
        :rtype: bool
        :raises IOException: thrown if an IO error occurs
        """

    @typing.overload
    def fieldKeyIterator(self) -> DBFieldIterator:
        """
        Iterate over all primary keys in ascending sorted order.
        
        :return: Field type key iterator
        :rtype: DBFieldIterator
        :raises IOException: if an I/O error occurs.
        """

    @typing.overload
    def fieldKeyIterator(self, startKey: Field) -> DBFieldIterator:
        """
        Iterate over the primary keys in ascending sorted order
        starting at the specified startKey.
        
        :param Field startKey: the first primary key.  If null the minimum key value will be assumed.
        :return: Field type key iterator
        :rtype: DBFieldIterator
        :raises IOException: if an I/O error occurs.
        """

    @typing.overload
    def fieldKeyIterator(self, minKey: Field, maxKey: Field, startKey: Field) -> DBFieldIterator:
        """
        Iterate over the records in ascending sorted order
        starting at the specified startKey.
        
        :param Field minKey: minimum key value.  Null corresponds to minimum key value.
        :param Field maxKey: maximum key value.  Null corresponds to maximum key value.
        :param Field startKey: the initial iterator position.  If null minKey will be assumed,
        if still null the minimum key value will be assumed.
        :return: Field type key iterator
        :rtype: DBFieldIterator
        :raises IOException: if an I/O error occurs.
        """

    @typing.overload
    def fieldKeyIterator(self, minKey: Field, maxKey: Field, before: typing.Union[jpype.JBoolean, bool]) -> DBFieldIterator:
        """
        Iterate over the records in ascending sorted order
        starting at the specified startKey.
        
        :param Field minKey: minimum key value.  Null corresponds to minimum key value.
        :param Field maxKey: maximum key value.  Null corresponds to maximum key value.
        :param jpype.JBoolean or bool before: if true initial position is before minKey, else position
        is after maxKey.
        :return: Field type key iterator
        :rtype: DBFieldIterator
        :raises IOException: if an I/O error occurs.
        """

    def findRecords(self, field: Field, columnIndex: typing.Union[jpype.JInt, int]) -> jpype.JArray[Field]:
        """
        Find the primary keys corresponding to those records which contain the
        specified field value in the specified record column.  The table must
        have been created with long keys and a secondary index on the specified 
        column index.
        
        :param Field field: the field value
        :param jpype.JInt or int columnIndex: the record schema column which should be searched.
        :return: list of primary keys
        :rtype: jpype.JArray[Field]
        :raises IOException: if a secondary index does not exist for the specified
        column, or the wrong field type was specified, or an I/O error occurs.
        """

    def getAllStatistics(self) -> jpype.JArray[TableStatistics]:
        """
        Get table statistics.
        
        :return: list of diagnostic statistics data for this table and related index tables.
        :rtype: jpype.JArray[TableStatistics]
        :raises IOException: database IO error
        """

    def getIndexedColumns(self) -> jpype.JArray[jpype.JInt]:
        """
        Get the list of columns which are indexed
        
        :return: list of indexed columns
        :rtype: jpype.JArray[jpype.JInt]
        """

    def getKey(self) -> int:
        """
        Get the next available key.
        This method is only valid for those tables which employ a long key.
        
        :return: next available key.
        :rtype: int
        """

    def getMatchingRecordCount(self, field: Field, columnIndex: typing.Union[jpype.JInt, int]) -> int:
        """
        Get the number of records which contain the
        specified field value in the specified record column.  The table must
        have been created with a secondary index on the specified column index.
        
        :param Field field: the field value
        :param jpype.JInt or int columnIndex: the record schema column which should be searched.
        :return: number of records which match the specified field value.
        :rtype: int
        :raises IOException: if a secondary index does not exist for the specified
        column, or the wrong field type was specified, or an I/O error occurs.
        """

    def getMaxKey(self) -> int:
        """
        Get the maximum record key which has ever been assigned within this table.
        This method is only valid for those tables which employ a long key and may
        not reflect records which have been removed (i.e., returned key may not 
        correspond to an existing record).
        
        :return: maximum record key.
        :rtype: int
        """

    def getName(self) -> str:
        """
        Get table name
        
        :return: table name
        :rtype: str
        """

    @typing.overload
    def getRecord(self, key: typing.Union[jpype.JLong, int]) -> DBRecord:
        """
        Get the record identified by the specified key value.
        
        :param jpype.JLong or int key: unique record key.
        :return: Record the record identified by key, or null if record was not
        found.
        :rtype: DBRecord
        :raises IOException: throw if an IO Error occurs
        """

    @typing.overload
    def getRecord(self, key: Field) -> DBRecord:
        """
        Get the record identified by the specified key value.
        
        :param Field key: unique record key.
        :return: Record the record identified by key, or null if record was not
        found.
        :rtype: DBRecord
        :raises IOException: throw if an IO Error occurs
        """

    @typing.overload
    def getRecordAfter(self, key: typing.Union[jpype.JLong, int]) -> DBRecord:
        """
        Get the record with the minimum key value which is greater than 
        the specified key.
        
        :param jpype.JLong or int key: unique key which may or may not exist within the table.
        :return: the first record which has a key value greater than the 
        specified key, or null if no record was found.
        :rtype: DBRecord
        :raises IOException: throw if an IO Error occurs
        """

    @typing.overload
    def getRecordAfter(self, key: Field) -> DBRecord:
        """
        Get the record with the minimum key value which is greater than 
        the specified key.
        
        :param Field key: unique key which may or may not exist within the table.
        :return: the first record which has a key value greater than the 
        specified key, or null if no record was found.
        :rtype: DBRecord
        :raises IOException: throw if an IO Error occurs
        """

    @typing.overload
    def getRecordAtOrAfter(self, key: typing.Union[jpype.JLong, int]) -> DBRecord:
        """
        Get the record with the minimum key value which is greater than or equal 
        to the specified key.
        
        :param jpype.JLong or int key: unique key which may or may not exist within the table.
        :return: the first record which has a key value greater than or equal to the 
        specified key, or null if no record was found.
        :rtype: DBRecord
        :raises IOException: throw if an IO Error occurs
        """

    @typing.overload
    def getRecordAtOrAfter(self, key: Field) -> DBRecord:
        """
        Get the record with the minimum key value which is greater than or equal 
        to the specified key.
        
        :param Field key: unique key which may or may not exist within the table.
        :return: the first record which has a key value greater than or equal to the 
        specified key, or null if no record was found.
        :rtype: DBRecord
        :raises IOException: throw if an IO Error occurs
        """

    @typing.overload
    def getRecordAtOrBefore(self, key: typing.Union[jpype.JLong, int]) -> DBRecord:
        """
        Get the record with the maximum key value which is less than or equal 
        to the specified key.
        
        :param jpype.JLong or int key: unique key which may or may not exist within the table.
        :return: the first record which has a key value less than or equal to the 
        specified key, or null if no record was found.
        :rtype: DBRecord
        :raises IOException: throw if an IO Error occurs
        """

    @typing.overload
    def getRecordAtOrBefore(self, key: Field) -> DBRecord:
        """
        Get the record with the maximum key value which is less than or equal 
        to the specified key.
        
        :param Field key: unique key which may or may not exist within the table.
        :return: the first record which has a key value less than or equal to the 
        specified key, or null if no record was found.
        :rtype: DBRecord
        :raises IOException: throw if an IO Error occurs
        """

    @typing.overload
    def getRecordBefore(self, key: typing.Union[jpype.JLong, int]) -> DBRecord:
        """
        Get the record with the maximum key value which is less than  
        the specified key.
        
        :param jpype.JLong or int key: unique key which may or may not exist within the table.
        :return: the first record which has a key value less than the 
        specified key, or null if no record was found.
        :rtype: DBRecord
        :raises IOException: throw if an IO Error occurs
        """

    @typing.overload
    def getRecordBefore(self, key: Field) -> DBRecord:
        """
        Get the record with the maximum key value which is less than  
        the specified key.
        
        :param Field key: unique key which may or may not exist within the table.
        :return: the first record which has a key value less than the 
        specified key, or null if no record was found.
        :rtype: DBRecord
        :raises IOException: throw if an IO Error occurs
        """

    def getRecordCount(self) -> int:
        """
        Get record count
        
        :return: record count
        :rtype: int
        """

    def getSchema(self) -> Schema:
        """
        Get this tables schema.
        
        :return: table schema
        :rtype: Schema
        """

    def getStatistics(self) -> TableStatistics:
        """
        Compile table statitics.
        
        :return: table statistics data
        :rtype: TableStatistics
        :raises IOException: thrown if an IO error occurs
        """

    @typing.overload
    def hasRecord(self, key: typing.Union[jpype.JLong, int]) -> bool:
        """
        Determine if this table contains a record with the specified key.
        
        :param jpype.JLong or int key: record key.
        :return: true if record exists with key, else false.
        :rtype: bool
        :raises IOException: thrown if IO error occurs
        """

    @typing.overload
    def hasRecord(self, key: Field) -> bool:
        """
        Determine if this table contains a record with the specified key.
        
        :param Field key: record key.
        :return: true if record exists with key, else false.
        :rtype: bool
        :raises IOException: throw if an IO Error occurs
        """

    @typing.overload
    def hasRecord(self, field: Field, columnIndex: typing.Union[jpype.JInt, int]) -> bool:
        """
        Determine if a record exists with the specified value within the specified
        column.  The table must have been created with a secondary index on the 
        specified column index.
        
        :param Field field: the field value
        :param jpype.JInt or int columnIndex: the record schema column which should be searched.
        :return: true if one or more records exis with the specified value.
        :rtype: bool
        :raises IOException: thrown if IO error occurs
        """

    @typing.overload
    def indexFieldIterator(self, columnIndex: typing.Union[jpype.JInt, int]) -> DBFieldIterator:
        """
        Iterate over all the unique index field values.  Index values are
        returned in an ascending sorted order with the initial iterator position
        set to the minimum index value.
        
        :param jpype.JInt or int columnIndex: identifies an indexed column.
        :return: index field iterator.
        :rtype: DBFieldIterator
        :raises IOException: thrown if IO error occurs
        """

    @typing.overload
    def indexFieldIterator(self, minField: Field, maxField: Field, before: typing.Union[jpype.JBoolean, bool], columnIndex: typing.Union[jpype.JInt, int]) -> DBFieldIterator:
        """
        Iterate over all the unique index field values within the specified range identified
        by minField and maxField.  Index values are returned in an ascending sorted order.
        
        :param Field minField: minimum index column value, if null absolute minimum is used
        :param Field maxField: maximum index column value, if null absolute maximum is used
        :param jpype.JBoolean or bool before: if true initial position is before minField, else position
        is after maxField
        :param jpype.JInt or int columnIndex: identifies an indexed column.
        :return: index field iterator.
        :rtype: DBFieldIterator
        :raises IOException: thrown if IO error occurs
        """

    @typing.overload
    def indexFieldIterator(self, minField: Field, maxField: Field, startField: Field, before: typing.Union[jpype.JBoolean, bool], columnIndex: typing.Union[jpype.JInt, int]) -> DBFieldIterator:
        """
        Iterate over all the unique index field values within the specified range identified
        by minField and maxField.  Index values are returned in an ascending sorted order with the 
        initial iterator position corresponding to the startField.
        
        :param Field minField: minimum index column value, if null absolute minimum is used
        :param Field maxField: maximum index column value, if null absolute maximum is used
        :param Field startField: index column value corresponding to initial position of iterator
        :param jpype.JBoolean or bool before: if true initial position is before startField value, else position
        is after startField value
        :param jpype.JInt or int columnIndex: identifies an indexed column.
        :return: index field iterator.
        :rtype: DBFieldIterator
        :raises IOException: if a secondary index does not exist for the specified
        column or an I/O error occurs.
        """

    @typing.overload
    def indexIterator(self, columnIndex: typing.Union[jpype.JInt, int]) -> RecordIterator:
        """
        Iterate over the records using a secondary index.  Sorting occurs on the
        specified schema column.  This table must have been constructed with a secondary
        index on the specified column.
        
        :param jpype.JInt or int columnIndex: schema column to sort on.
        :return: RecordIterator record iterator.
        :rtype: RecordIterator
        :raises IOException: if a secondary index does not exist for the specified
        column or an I/O error occurs.
        """

    @typing.overload
    def indexIterator(self, columnIndex: typing.Union[jpype.JInt, int], startValue: Field, endValue: Field, atStart: typing.Union[jpype.JBoolean, bool]) -> RecordIterator:
        """
        Iterate over a range of records using a secondary index.  Sorting occurs on the
        specified schema column. The iterator is initially positioned before the startValue.
        This table must have been constructed with a secondary index on the specified column.
        
        :param jpype.JInt or int columnIndex: schema column to sort on.
        :param Field startValue: the starting and minimum value of the secondary index field.
        :param Field endValue: the ending and maximum value of the secondary index field.
        :param jpype.JBoolean or bool atStart: if true, position the iterator before the start value. 
        Otherwise, position the iterator after the end value.
        :return: record iterator.
        :rtype: RecordIterator
        :raises IOException: if a secondary index does not exist for the specified
        column, or the wrong field type was specified, or an I/O error occurs.
        """

    @typing.overload
    def indexIteratorAfter(self, columnIndex: typing.Union[jpype.JInt, int], startValue: Field) -> RecordIterator:
        """
        Iterate over the records using a secondary index.  Sorting occurs on the
        specified schema column.  The iterator's initial position immediately follows 
        the specified startValue. If this value does not exist, the initial position corresponds
        to where it would exist.
        This table must have been constructed with a secondary index on the specified column.
        
        :param jpype.JInt or int columnIndex: schema column to sort on.
        :param Field startValue: the starting value of the secondary index field.
        :return: RecordIterator record iterator.
        :rtype: RecordIterator
        :raises IOException: if a secondary index does not exist for the specified
        column, or the wrong field type was specified, or an I/O error occurs.
        """

    @typing.overload
    def indexIteratorAfter(self, columnIndex: typing.Union[jpype.JInt, int], startValue: Field, primaryKey: Field) -> RecordIterator:
        """
        Iterate over the records using a secondary index.  Sorting occurs on the
        specified schema column.  The iterator's initial position immediately follows 
        the specified startValue and primaryKey. If no such entry exists, the initial position 
        corresponds to where it would exist.
         
        
        This table must have been constructed with a secondary index on the specified column.
        
        :param jpype.JInt or int columnIndex: schema column to sort on.
        :param Field startValue: the starting value of the secondary index field.
        :param Field primaryKey: the primary key associated with the startField.
        :return: RecordIterator record iterator.
        :rtype: RecordIterator
        :raises IOException: if a secondary index does not exist for the specified
        column, or the wrong field type was specified, or an I/O error occurs.
        """

    @typing.overload
    def indexIteratorBefore(self, columnIndex: typing.Union[jpype.JInt, int], startValue: Field) -> RecordIterator:
        """
        Iterate over the records using a secondary index.  Sorting occurs on the
        specified schema column.  The iterator's initial position immediately precedes 
        the specified startValue. If this value does not exist, the initial position corresponds
        to where it would exist.
        This table must have been constructed with a secondary index on the specified column.
        
        :param jpype.JInt or int columnIndex: schema column to sort on.
        :param Field startValue: the starting value of the secondary index field.
        :return: RecordIterator record iterator.
        :rtype: RecordIterator
        :raises IOException: if a secondary index does not exist for the specified
        column, or the wrong field type was specified, or an I/O error occurs.
        """

    @typing.overload
    def indexIteratorBefore(self, columnIndex: typing.Union[jpype.JInt, int], startValue: Field, primaryKey: Field) -> RecordIterator:
        """
        Iterate over the records using a secondary index.  Sorting occurs on the
        specified schema column.  The iterator's initial position immediately precedes 
        the specified startValue and primaryKey. If no such entry exists, the initial position 
        corresponds to where it would exist.
         
        
        This table must have been constructed with a secondary index on the specified column.
        
        :param jpype.JInt or int columnIndex: schema column to sort on.
        :param Field startValue: the starting value of the secondary index field.
        :param Field primaryKey: the primary key associated with the startField.
        :return: RecordIterator record iterator.
        :rtype: RecordIterator
        :raises IOException: if a secondary index does not exist for the specified
        column, or the wrong field type was specified, or an I/O error occurs.
        """

    @typing.overload
    def indexKeyIterator(self, columnIndex: typing.Union[jpype.JInt, int]) -> DBFieldIterator:
        """
        Iterate over all primary keys sorted based upon the associated index key.
        
        :param jpype.JInt or int columnIndex: schema column to sort on.
        :return: primary key iterator
        :rtype: DBFieldIterator
        :raises IOException: thrown if IO error occurs
        """

    @typing.overload
    def indexKeyIterator(self, columnIndex: typing.Union[jpype.JInt, int], minField: Field, maxField: Field, atMin: typing.Union[jpype.JBoolean, bool]) -> DBFieldIterator:
        """
        Iterate over all primary keys sorted based upon the associated index key.
        The iterator is limited to range of index keys of minField through maxField, inclusive.
        If atMin is true, the iterator is initially positioned before the first index 
        buffer whose index key is greater than or equal to the specified minField value. 
        If atMin is false, the iterator is initially positioned after the first index 
        buffer whose index key is less than or equal to the specified maxField value.
        
        :param jpype.JInt or int columnIndex: schema column to sort on
        :param Field minField: minimum index column value
        :param Field maxField: maximum index column value
        :param jpype.JBoolean or bool atMin: if true, position iterator before minField value, 
        Otherwise, position iterator after maxField value.
        :return: primary key iterator
        :rtype: DBFieldIterator
        :raises IOException: thrown if IO error occurs
        """

    @typing.overload
    def indexKeyIterator(self, columnIndex: typing.Union[jpype.JInt, int], minField: Field, maxField: Field, startField: Field, before: typing.Union[jpype.JBoolean, bool]) -> DBFieldIterator:
        """
        Iterate over all primary keys sorted based upon the associated index key.
        The iterator is limited to range of index keys of minField through maxField, inclusive.
        The iterator is initially positioned before or after the specified startField index value.
        
        :param jpype.JInt or int columnIndex: schema column to sort on
        :param Field minField: minimum index column value
        :param Field maxField: maximum index column value
        :param Field startField: starting indexed value position
        :param jpype.JBoolean or bool before: if true positioned before startField value, else positioned after maxField
        :return: primary key iterator
        :rtype: DBFieldIterator
        :raises IOException: thrown if IO error occurs
        """

    @typing.overload
    def indexKeyIteratorAfter(self, columnIndex: typing.Union[jpype.JInt, int], startField: Field) -> DBFieldIterator:
        """
        Iterate over all primary keys sorted based upon the associated index key.
        The iterator is initially positioned after the index buffer whose index key 
        is equal to the specified startField value or immediately before the first 
        index buffer whose index key is greater than the specified startField value.
        
        :param jpype.JInt or int columnIndex: schema column to sort on
        :param Field startField: index column value which determines initial position of iterator
        :return: primary key iterator
        :rtype: DBFieldIterator
        :raises IOException: thrown if IO error occurs
        """

    @typing.overload
    def indexKeyIteratorAfter(self, columnIndex: typing.Union[jpype.JInt, int], startField: Field, primaryKey: Field) -> DBFieldIterator:
        """
        Iterate over all primary keys sorted based upon the associated index key.
        The iterator is initially positioned after the primaryKey within the index buffer 
        whose index key is equal to the specified startField value or immediately before the first 
        index buffer whose index key is greater than the specified startField value.
        
        :param jpype.JInt or int columnIndex: schema column to sort on
        :param Field startField: index column value which determines initial position of iterator
        :param Field primaryKey: initial position within index buffer if index key matches startField value.
        :return: primary key iterator
        :rtype: DBFieldIterator
        :raises IOException: thrown if IO error occurs
        """

    @typing.overload
    def indexKeyIteratorBefore(self, columnIndex: typing.Union[jpype.JInt, int], startField: Field) -> DBFieldIterator:
        """
        Iterate over all primary keys sorted based upon the associated index key.
        The iterator is initially positioned before the first index buffer whose index key 
        is greater than or equal to the specified startField value.
        
        :param jpype.JInt or int columnIndex: schema column to sort on
        :param Field startField: index column value which determines initial position of iterator
        :return: primary key iterator
        :rtype: DBFieldIterator
        :raises IOException: thrown if IO error occurs
        """

    @typing.overload
    def indexKeyIteratorBefore(self, columnIndex: typing.Union[jpype.JInt, int], startField: Field, primaryKey: Field) -> DBFieldIterator:
        """
        Iterate over all primary keys sorted based upon the associated index key.
        The iterator is initially positioned before the primaryKey within the index buffer 
        whose index key is equal to the specified startField value or immediately before the first 
        index buffer whose index key is greater than the specified startField value.
        
        :param jpype.JInt or int columnIndex: schema column to sort on
        :param Field startField: index column value which determines initial position of iterator
        :param Field primaryKey: initial position within index buffer if index key matches startField value.
        :return: primary key iterator
        :rtype: DBFieldIterator
        :raises IOException: thrown if IO error occurs
        """

    def isConsistent(self, monitor: ghidra.util.task.TaskMonitor) -> bool:
        """
        Check the consistency of this table and its associated index tables.
        
        :param ghidra.util.task.TaskMonitor monitor: task monitor
        :return: true if consistency check passed, else false
        :rtype: bool
        :raises IOException: thrown if IO error occurs
        :raises CancelledException: is task was cancelled
        """

    def isInvalid(self) -> bool:
        """
        
        
        :return: true if table is valid and has not been invalidated
        :rtype: bool
        """

    @typing.overload
    def iterator(self) -> RecordIterator:
        """
        Iterate over the records in ascending sorted order.  Sorting occurs on the primary key value.
        
        :return: record iterator
        :rtype: RecordIterator
        :raises IOException: if an I/O error occurs.
        """

    @typing.overload
    def iterator(self, startKey: typing.Union[jpype.JLong, int]) -> RecordIterator:
        """
        Iterate over the records in ascending sorted order.  Sorting occurs on the primary key value
        starting at the specified startKey.
        
        :param jpype.JLong or int startKey: the first primary key.
        :return: record iterator
        :rtype: RecordIterator
        :raises IOException: if an I/O error occurs.
        """

    @typing.overload
    def iterator(self, minKey: typing.Union[jpype.JLong, int], maxKey: typing.Union[jpype.JLong, int], startKey: typing.Union[jpype.JLong, int]) -> RecordIterator:
        """
        Iterate over the records in ascending sorted order.  Sorting occurs on the primary key value
        starting at the specified startKey.
        
        :param jpype.JLong or int minKey: the minimum primary key.
        :param jpype.JLong or int maxKey: the maximum primary key.
        :param jpype.JLong or int startKey: the initial iterator position.
        :return: record iterator
        :rtype: RecordIterator
        :raises IOException: if an I/O error occurs.
        :raises IllegalArgumentException: if long keys are not in use or startKey 
        is less than minKey or greater than maxKey.
        """

    @typing.overload
    def iterator(self, startKey: Field) -> RecordIterator:
        """
        Iterate over the records in ascending sorted order.  Sorting occurs on the primary key value
        starting at the specified startKey.
        
        :param Field startKey: the first primary key.
        :return: record iterator
        :rtype: RecordIterator
        :raises IOException: if an I/O error occurs.
        """

    @typing.overload
    def iterator(self, minKey: Field, maxKey: Field, startKey: Field) -> RecordIterator:
        """
        Iterate over the records in ascending sorted order.  Sorting occurs on the primary key value
        starting at the specified startKey.
        
        :param Field minKey: the minimum primary key, may be null.
        :param Field maxKey: the maximum primary key, may be null.
        :param Field startKey: the initial iterator position, if null minKey is also start.
        :return: record iterator
        :rtype: RecordIterator
        :raises IOException: if an I/O error occurs.
        """

    @typing.overload
    def longKeyIterator(self) -> DBLongIterator:
        """
        Iterate over all long primary keys in ascending sorted order.
        
        :return: long key iterator
        :rtype: DBLongIterator
        :raises IOException: if an I/O error occurs.
        """

    @typing.overload
    def longKeyIterator(self, startKey: typing.Union[jpype.JLong, int]) -> DBLongIterator:
        """
        Iterate over the long primary keys in ascending sorted order
        starting at the specified startKey.
        
        :param jpype.JLong or int startKey: the first primary key.
        :return: long key iterator
        :rtype: DBLongIterator
        :raises IOException: if an I/O error occurs.
        """

    @typing.overload
    def longKeyIterator(self, minKey: typing.Union[jpype.JLong, int], maxKey: typing.Union[jpype.JLong, int], startKey: typing.Union[jpype.JLong, int]) -> DBLongIterator:
        """
        Iterate over the long primary keys in ascending sorted order
        starting at the specified startKey.
        
        :param jpype.JLong or int minKey: the minimum primary key.
        :param jpype.JLong or int maxKey: the maximum primary key.
        :param jpype.JLong or int startKey: the initial iterator position.
        :return: long key iterator
        :rtype: DBLongIterator
        :raises IOException: if an I/O error occurs.
        """

    def putRecord(self, record: DBRecord):
        """
        Put the specified record into the stored BTree.
        
        :param DBRecord record: the record to be stored.
        :raises IOException: throw if an IO Error occurs
        """

    def rebuild(self, monitor: ghidra.util.task.TaskMonitor):
        """
        Rebuild table and associated indexes to ensure consistent state.
        
        :param ghidra.util.task.TaskMonitor monitor: task monitor
        :raises IOException: if unable to rebuild
        :raises CancelledException: if task was cancelled
        """

    def setName(self, name: typing.Union[java.lang.String, str]) -> bool:
        """
        Change the name of this table
        
        :param java.lang.String or str name: new table name
        :return: true if rename successful
        :rtype: bool
        :raises DuplicateNameException: if new table name already exists
        """

    def useFixedKeys(self) -> bool:
        """
        Determine if this table uses FixedField keys.
        
        :return: true if this table utilizes FixedField keys.
        :rtype: bool
        """

    def useLongKeys(self) -> bool:
        """
        Determine if this table uses long keys.
        
        :return: true if this table utilizes long keys.
        :rtype: bool
        """

    @property
    def schema(self) -> Schema:
        ...

    @property
    def recordAtOrAfter(self) -> DBRecord:
        ...

    @property
    def allStatistics(self) -> jpype.JArray[TableStatistics]:
        ...

    @property
    def recordCount(self) -> jpype.JInt:
        ...

    @property
    def consistent(self) -> jpype.JBoolean:
        ...

    @property
    def recordBefore(self) -> DBRecord:
        ...

    @property
    def recordAtOrBefore(self) -> DBRecord:
        ...

    @property
    def recordAfter(self) -> DBRecord:
        ...

    @property
    def maxKey(self) -> jpype.JLong:
        ...

    @property
    def indexedColumns(self) -> jpype.JArray[jpype.JInt]:
        ...

    @property
    def record(self) -> DBRecord:
        ...

    @property
    def invalid(self) -> jpype.JBoolean:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def key(self) -> jpype.JLong:
        ...

    @property
    def statistics(self) -> TableStatistics:
        ...


class DatabaseUtils(java.lang.Object):
    """
    ``DatabaseUtils`` provides a collection of database related utilities.
    """

    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def moveRecords(table: Table, oldStart: typing.Union[jpype.JLong, int], newStart: typing.Union[jpype.JLong, int], size: typing.Union[jpype.JLong, int]):
        """
        Reassign the long key assigned to a contiguous group of records within a table.
        A shift in the key value is computed as the difference of oldStart and newStart.
        Existing records whose keys lie within the new range will be removed prior to
        moving the target set of records.
        
        :param Table table: table within which records should be moved.
        :param jpype.JLong or int oldStart: old key value for start of range
        :param jpype.JLong or int newStart: new key value for start of range
        :param jpype.JLong or int size: determines the range of keys to be moved (oldStart to oldStart+size-1, inclusive)
        :raises IOException: if there is an error moving the records
        """


@typing.type_check_only
class LongKeyNode(BTreeNode):
    """
    ``LongKeyNode`` is an abstract implementation of a BTree node
    which utilizes long key values.
    """

    class_: typing.ClassVar[java.lang.Class]


class Field(java.lang.Comparable[Field]):
    """
    
    ``Field`` is an abstract data wrapper for use with Records.
    Note that when comparing two Field instances both must be of the same 
    class.
    
     
     
    Fields may take on a null state.  In the case of :obj:`FixedField`
    and :obj:`PrimitiveField` this state is distinct from value and only
    applies when used for a sparse column within a :obj:`SparseRecord`.
    In this sparse column situation the :meth:`SparseRecord.setField(int, Field) <SparseRecord.setField>` 
    method may be passed a null Field argument.  Sparse columns with a 
    null value/state will not be indexed within a :obj:`Table`.
     
     
    Stored Schema Field Type Encoding:
    
     
     
    8-bit Legacy Field Type Encoding (I....FFF)
    
    Supported encodings: 0x00..0x06 and 0x80..0x86,
    where:
     
        FFF  - indexed field type (0..6)
        I    - index field indicator (only long primary keys were supported)
     
       
     
    8-bit Field Type Encoding (PPPPFFFF)
    
    (Reserved for future field extensions: 0x88 and 0xf0..0xff)
     
        0xff - see :obj:`Schema.FIELD_EXTENSION_INDICATOR`
     
    where:
     
        FFFF - normal/indexed field type
        PPPP - indexed table primary key type (1000b: LegacyIndexField)
    """

    class UnsupportedFieldException(java.io.IOException):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]
    EMPTY_ARRAY: typing.Final[jpype.JArray[Field]]

    @staticmethod
    def canIndex(field: Field) -> bool:
        """
        Determine if a specified field instance may be indexed
        
        :param Field field: field to be checked
        :return: true if field can be indexed
        :rtype: bool
        """

    def compareTo(self, otherField: Field) -> int:
        """
        Compares this Field with another Field for order.  Returns a
        negative integer, zero, or a positive integer as this object is less
        than, equal to, or greater than the specified Field.  
         
        
        NOTE: Field objects do not fully comply with the Comparable interface.
        Only the same Field implementations may be compared.  In addition, the 
        null state is not considered when comparing :obj:`PrimitiveField`s which have a 
        zero (0) value.
        
        :param Field otherField: another Field which is the same type as this Field
        :return: field comparison result (see :meth:`Comparable.compareTo(Object) <Comparable.compareTo>`).
        :rtype: int
        :raises ClassCastException: if an attempt to compare dissimilar Fields (e.g., 
        an IntField may not be compared with a ShortField).
        """

    def copyField(self) -> Field:
        """
        Create new instance of this field with the same value.
        
        :return: new field instance with same value
        :rtype: Field
        """

    def equals(self, obj: java.lang.Object) -> bool:
        """
        Determine if the specified Object is another Field which has the same 
        type and value as this Field.  When comparing a :obj:`PrimitiveField`,
        with a null state, a value of zero (0) is used.
        
        :param java.lang.Object obj: another object
        :return: true if this field equals obj
        :rtype: bool
        """

    def getBinaryData(self) -> jpype.JArray[jpype.JByte]:
        """
        Get data as a byte array.
        
        :return: byte[]
        :rtype: jpype.JArray[jpype.JByte]
        """

    def getBooleanValue(self) -> bool:
        """
        Get field as a boolean value.
        
        :return: boolean value
        :rtype: bool
        :raises IllegalFieldAccessException: thrown if method is not supported by specific
        Field instance.
        """

    def getByteValue(self) -> int:
        """
        Get field as a byte value.
        
        :return: byte value
        :rtype: int
        :raises IllegalFieldAccessException: thrown if method is not supported by specific
        Field instance.
        """

    def getIntValue(self) -> int:
        """
        Get field as an integer value.
        
        :return: integer value
        :rtype: int
        :raises IllegalFieldAccessException: thrown if method is not supported by specific
        Field instance.
        """

    def getLongValue(self) -> int:
        """
        Get field as a long value.
        All fixed-length field objects must implement this method
        
        :return: long value
        :rtype: int
        :raises IllegalFieldAccessException: thrown if method is not supported by specific
        Field instance.
        """

    def getShortValue(self) -> int:
        """
        Get field as a short value.
        
        :return: short value
        :rtype: int
        :raises IllegalFieldAccessException: thrown if method is not supported by specific
        Field instance.
        """

    def getString(self) -> str:
        """
        Get field as a String value.
        
        :return: String value
        :rtype: str
        :raises IllegalFieldAccessException: thrown if method is not supported by specific
        Field instance.
        """

    def getValueAsString(self) -> str:
        """
        Get field value as a formatted string
        
        :return: field value string
        :rtype: str
        """

    def isNull(self) -> bool:
        """
        Determine if the field has been set to a null-state or value.
        
        :return: true if field has been set to a null state or value, else false
        :rtype: bool
        """

    def isSameType(self, field: Field) -> bool:
        """
        Determine if specified field is same type as this field
        
        :param Field field: a Field instance
        :return: true if field is same type as this field
        :rtype: bool
        """

    def isVariableLength(self) -> bool:
        """
        
        
        :return: true if a Field instance is variable length, else false.
        :rtype: bool
        """

    def newField(self) -> Field:
        """
        Create new instance of this field type.
        
        :return: new field instance with undefined initial value
        :rtype: Field
        """

    def setBinaryData(self, bytes: jpype.JArray[jpype.JByte]):
        """
        Set data from binary byte array.
        All variable-length fields must implement this method.
        
        :param jpype.JArray[jpype.JByte] bytes: field data
        :raises IllegalFieldAccessException: if error occurs while reading bytes
        into field which will generally be caused by the incorrect number of 
        bytes provided to a fixed-length field.
        """

    def setBooleanValue(self, value: typing.Union[jpype.JBoolean, bool]):
        """
        Set field's boolean value.
        
        :param jpype.JBoolean or bool value: boolean value
        :raises IllegalFieldAccessException: thrown if method is not supported by specific
        Field instance.
        """

    def setByteValue(self, value: typing.Union[jpype.JByte, int]):
        """
        Set field's byte value.
        
        :param jpype.JByte or int value: byte value
        :raises IllegalFieldAccessException: thrown if method is not supported by specific
        Field instance.
        """

    def setIntValue(self, value: typing.Union[jpype.JInt, int]):
        """
        Set field's integer value.
        
        :param jpype.JInt or int value: integer value
        :raises IllegalFieldAccessException: thrown if method is not supported by specific
        Field instance.
        """

    def setLongValue(self, value: typing.Union[jpype.JLong, int]):
        """
        Set field's long value.
        All fixed-length field objects must implement this method
        
        :param jpype.JLong or int value: long value
        :raises IllegalFieldAccessException: thrown if method is not supported by specific
        Field instance.
        """

    def setShortValue(self, value: typing.Union[jpype.JShort, int]):
        """
        Set field's short value.
        
        :param jpype.JShort or int value: short value
        :raises IllegalFieldAccessException: thrown if method is not supported by specific
        Field instance.
        """

    def setString(self, str: typing.Union[java.lang.String, str]):
        """
        Set field's String value.
        
        :param java.lang.String or str str: String value
        :raises IllegalFieldAccessException: thrown if method is not supported by specific
        Field instance.
        """

    @property
    def null(self) -> jpype.JBoolean:
        ...

    @property
    def string(self) -> java.lang.String:
        ...

    @string.setter
    def string(self, value: java.lang.String):
        ...

    @property
    def variableLength(self) -> jpype.JBoolean:
        ...

    @property
    def binaryData(self) -> jpype.JArray[jpype.JByte]:
        ...

    @binaryData.setter
    def binaryData(self, value: jpype.JArray[jpype.JByte]):
        ...

    @property
    def intValue(self) -> jpype.JInt:
        ...

    @intValue.setter
    def intValue(self, value: jpype.JInt):
        ...

    @property
    def valueAsString(self) -> java.lang.String:
        ...

    @property
    def shortValue(self) -> jpype.JShort:
        ...

    @shortValue.setter
    def shortValue(self, value: jpype.JShort):
        ...

    @property
    def booleanValue(self) -> jpype.JBoolean:
        ...

    @booleanValue.setter
    def booleanValue(self, value: jpype.JBoolean):
        ...

    @property
    def sameType(self) -> jpype.JBoolean:
        ...

    @property
    def longValue(self) -> jpype.JLong:
        ...

    @longValue.setter
    def longValue(self, value: jpype.JLong):
        ...

    @property
    def byteValue(self) -> jpype.JByte:
        ...

    @byteValue.setter
    def byteValue(self, value: jpype.JByte):
        ...


class ShortField(PrimitiveField):
    """
    ``ShortField`` provides a wrapper for 2-byte signed short data 
    which is read or written to a Record.
    """

    class_: typing.ClassVar[java.lang.Class]
    MIN_VALUE: typing.Final[ShortField]
    """
    Minimum short field value
    """

    MAX_VALUE: typing.Final[ShortField]
    """
    Maximum short field value
    """

    ZERO_VALUE: typing.Final[ShortField]
    """
    Zero short field value
    """

    INSTANCE: typing.Final[ShortField]
    """
    Instance intended for defining a :obj:`Table` :obj:`Schema`
    """


    @typing.overload
    def __init__(self):
        """
        Construct a short field with an initial value of 0.
        """

    @typing.overload
    def __init__(self, s: typing.Union[jpype.JShort, int]):
        """
        Construct a short field with an initial value of s.
        
        :param jpype.JShort or int s: initial value
        """


class BinaryField(Field):
    """
    ``BinaryField`` provides a wrapper for variable length binary data which is read or
    written to a Record.
    """

    class_: typing.ClassVar[java.lang.Class]
    INSTANCE: typing.Final[BinaryField]
    """
    Instance intended for defining a :obj:`Table` :obj:`Schema`
    """


    @typing.overload
    def __init__(self):
        """
        Construct a binary data field with an initial value of null.
        """

    @typing.overload
    def __init__(self, data: jpype.JArray[jpype.JByte]):
        """
        Construct a binary data field with an initial value of data.
        
        :param jpype.JArray[jpype.JByte] data: initial value
        """

    @staticmethod
    def getValueAsString(data: jpype.JArray[jpype.JByte]) -> str:
        """
        Get format value string for byte array
        
        :param jpype.JArray[jpype.JByte] data: byte array
        :return: formatted value string
        :rtype: str
        """


@typing.type_check_only
class LegacyIndexField(IndexField):
    """
    ``LegacyIndexField`` supports legacy index tables where the indexed
    field was a :obj:`LongField` and improperly employed a variable-length
    index storage scheme when the primary key was a LongField.
    """

    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class FixedField(BinaryField):
    """
    ``FixedField`` provides an abstract implementation of an unsigned fixed-length
    field whose value is specified with a byte-array.  This field behaves similar to a 
    :obj:`PrimitiveField` in that a null "state" (see :meth:`isNull() <.isNull>`) is supported for 
    sparse record column use with a zero (0) value.  Unlike a variable-length 
    :obj:`BinaryField` a null "value" (i.e., data byte array) is not permitted.
     
    
    Implementations may use the internal data byte-array as a lazy storage cache for
    the actual fixed-length value (i.e., invoking :meth:`getBinaryData() <.getBinaryData>` may update
    the internal data byte-array if needed).
    """

    class_: typing.ClassVar[java.lang.Class]


class NoTransactionException(java.lang.RuntimeException):
    """
    ``NoTransactionException`` occurs when a database modification is
    attempted when no transaction exists.
    """

    class_: typing.ClassVar[java.lang.Class]


class ConvertedRecordIterator(RecordIterator):
    """
    ``ConvertedRecordIterator`` provides a RecordIterator wrapper
    for performing record conversion frequently required when using older
    data.
    """

    class_: typing.ClassVar[java.lang.Class]

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

    def next(self) -> DBRecord:
        """
        
        
        
        .. seealso::
        
            | :obj:`db.RecordIterator.next()`
        """

    def previous(self) -> DBRecord:
        """
        
        
        
        .. seealso::
        
            | :obj:`db.RecordIterator.previous()`
        """


class StringField(Field):
    """
    ``StringField`` provides a wrapper for variable length String data which is read or
    written to a Record. Strings are always encoded as UTF-8.
    """

    class_: typing.ClassVar[java.lang.Class]
    NULL_VALUE: typing.Final[StringField]
    """
    Null string field value
    """

    INSTANCE: typing.Final[StringField]
    """
    Instance intended for defining a :obj:`Table` :obj:`Schema`
    """


    @typing.overload
    def __init__(self):
        """
        Construct a String field with an initial value of null.
        """

    @typing.overload
    def __init__(self, str: typing.Union[java.lang.String, str]):
        """
        Construct a String field with an initial value of s.
        
        :param java.lang.String or str str: initial string value or null
        """


@typing.type_check_only
class JavaBinarySearcher(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def binarySearch(self, buf: jpype.JArray[jpype.JByte], key: typing.Union[jpype.JLong, int], nKeys: typing.Union[jpype.JInt, int]) -> int:
        ...


@typing.type_check_only
class FixedKeyRecordNode(FixedKeyNode, FieldKeyRecordNode):
    """
    ``FixedKeyRecordNode`` is an abstract implementation of a BTree leaf node
    which utilizes fixed-length binary key values and stores records.
     
    
    This type of node has the following partial layout within a single DataBuffer 
    (field size in bytes):
     
    | NodeType(1) | KeyCount(4) | PrevLeafId(4) | NextLeafId(4) ...
    """

    class_: typing.ClassVar[java.lang.Class]

    def getKeyOffset(self, index: typing.Union[jpype.JInt, int]) -> int:
        """
        Get the key offset within the node's data buffer
        
        :param jpype.JInt or int index: key/record index
        :return: positive record offset within buffer
        :rtype: int
        """

    def removeLeaf(self) -> FixedKeyNode:
        """
        Remove this leaf from the tree.
        
        :return: root node which may have changed.
        :rtype: FixedKeyNode
        :raises IOException: thrown if IO error occurs
        """

    @property
    def keyOffset(self) -> jpype.JInt:
        ...


class RecordIterator(java.lang.Object):
    """
    ``RecordIterator`` provides the ability to iterate over
    data records within a table.
    """

    class_: typing.ClassVar[java.lang.Class]

    def delete(self) -> bool:
        """
        Delete the last Record read via the next or previous methods.
        
        :return: true if record was successfully deleted.
        :rtype: bool
        :raises IOException: thrown if an IO error occurs.
        """

    def hasNext(self) -> bool:
        """
        Return true if a Record is available in the forward direction.
        
        :raises IOException: thrown if an IO error occurs
        """

    def hasPrevious(self) -> bool:
        """
        Return true if a Record is available in the reverse direction
        
        :raises IOException: thrown if an IO error occurs
        """

    def next(self) -> DBRecord:
        """
        Return the next Record or null if one is not available.
        
        :raises IOException: thrown if an IO error occurs
        """

    def previous(self) -> DBRecord:
        """
        Return the previous Record or null if one is not available.
        
        :raises IOException: thrown if an IO error occurs
        """


@typing.type_check_only
class TableRecord(java.lang.Comparable[TableRecord]):
    """
    ``TableRecord`` manages information about a table.  Each TableRecord 
    corresponds to a stored record within the master table.
    """

    class_: typing.ClassVar[java.lang.Class]

    def compareTo(self, otherRecord: TableRecord) -> int:
        """
        Compares the key associated with this table record with the 
        key of another table record (obj).
        
        
        .. seealso::
        
            | :obj:`java.lang.Comparable.compareTo(java.lang.Object)`
        """


class Transaction(java.lang.AutoCloseable):
    """
    Provides syntax for opening a database transaction using a try-with-resources block
    
     
    
    For example, using :meth:`DBHandle.startTransaction() <DBHandle.startTransaction>` directly:
     
     
    int txid = dbHandle.startTransaction();
    try {
        // ... Do something
    }
    finally {
        program.endTransaction(txid, true);
    }
     
     
     
    
    Can be expressed using a :obj:`Transaction` instead:
     
     
    try (Transaction tx = dbHandle.openTransaction(dbErrorHandler)) {
        // ... Do something
    }
    """

    class_: typing.ClassVar[java.lang.Class]

    def abort(self):
        """
        Mark transaction for rollback/non-commit and end transaction if active.
        """

    def abortOnClose(self):
        """
        Mark transaction for rollback/non-commit upon closing.
         
         
        
        A subsequent invocation of :meth:`commitOnClose() <.commitOnClose>` will alter this state prior to closing.
        """

    def close(self):
        """
        End this transaction if active using the current commit state.
        
        
        .. seealso::
        
            | :obj:`.commitOnClose()`
        
            | :obj:`.abortOnClose()`
        """

    def commit(self):
        """
        Mark transaction for commit and end transaction if active.
        """

    def commitOnClose(self):
        """
        Mark transaction for commit upon closing.
         
         
        
        This state is assumed by default. A subsequent invocation of :meth:`abortOnClose() <.abortOnClose>` will
        alter this state prior to closing.
        """

    def isSubTransaction(self) -> bool:
        """
        Determine if this is a sub-transaction to a larger transaction.
         
         
        
        If true is returned the larger transaction will not complete until all sub-transactions have
        ended. The larger transaction will rollback upon completion if any of the sub-transactions do
        not commit.
        
        :return: true if this is a sub-transaction, else false.
        :rtype: bool
        """

    @property
    def subTransaction(self) -> jpype.JBoolean:
        ...


class LongField(PrimitiveField):
    """
    ``LongField`` provides a wrapper for 8-byte signed long data 
    which is read or written to a Record.
    """

    class_: typing.ClassVar[java.lang.Class]
    MIN_VALUE: typing.Final[LongField]
    """
    Minimum long field value
    """

    MAX_VALUE: typing.Final[LongField]
    """
    Maximum long field value
    """

    ZERO_VALUE: typing.Final[LongField]
    """
    Zero long field value
    """

    INSTANCE: typing.Final[LongField]
    """
    Instance intended for defining a :obj:`Table` :obj:`Schema`
    """


    @typing.overload
    def __init__(self):
        """
        Construct a long field with an initial value of 0.
        """

    @typing.overload
    def __init__(self, l: typing.Union[jpype.JLong, int]):
        """
        Construct a long field with an initial value of l.
        
        :param jpype.JLong or int l: initial value
        """


class Schema(java.lang.Object):
    """
    Class for definining the columns in a Ghidra Database table.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, version: typing.Union[jpype.JInt, int], keyField: Field, keyName: typing.Union[java.lang.String, str], fields: jpype.JArray[Field], fieldNames: jpype.JArray[java.lang.String], sparseColumns: jpype.JArray[jpype.JInt]):
        """
        Construct a new Schema.
        
        :param jpype.JInt or int version: schema version
        :param Field keyField: field associated with primary key (representative instance)
        :param java.lang.String or str keyName: primary key name
        :param jpype.JArray[Field] fields: array of column fields (representative instances)
        :param jpype.JArray[java.lang.String] fieldNames: array of column field names
        :param jpype.JArray[jpype.JInt] sparseColumns: column indexes corresponding to those
        columns which utilize sparse storage (null if no sparse columns).  
        Valid sparse column indexes are in the range 0..127.
        :raises IllegalArgumentException: invalid parameters
        """

    @typing.overload
    def __init__(self, version: typing.Union[jpype.JInt, int], keyField: Field, keyName: typing.Union[java.lang.String, str], fields: jpype.JArray[Field], fieldNames: jpype.JArray[java.lang.String]):
        """
        Construct a new Schema.
        
        :param jpype.JInt or int version: schema version
        :param Field keyField: field associated with primary key (representative instance)
        :param java.lang.String or str keyName: primary key name
        :param jpype.JArray[Field] fields: array of column fields (representative instances)
        :param jpype.JArray[java.lang.String] fieldNames: array of column field names
        :raises IllegalArgumentException: invalid parameters
        """

    @typing.overload
    def __init__(self, version: typing.Union[jpype.JInt, int], keyName: typing.Union[java.lang.String, str], fields: jpype.JArray[Field], fieldNames: jpype.JArray[java.lang.String]):
        """
        Construct a new Schema which uses a long key.
        
        :param jpype.JInt or int version: schema version
        :param java.lang.String or str keyName: primary key name
        :param jpype.JArray[Field] fields: array of column fields (representative instances)
        :param jpype.JArray[java.lang.String] fieldNames: array of column field names
        :raises IllegalArgumentException: invalid parameters
        """

    @typing.overload
    def __init__(self, version: typing.Union[jpype.JInt, int], keyName: typing.Union[java.lang.String, str], fields: jpype.JArray[Field], fieldNames: jpype.JArray[java.lang.String], sparseColumns: jpype.JArray[jpype.JInt]):
        """
        Construct a new Schema which uses a long key.
        
        :param jpype.JInt or int version: schema version
        :param java.lang.String or str keyName: primary key name
        :param jpype.JArray[Field] fields: array of column fields (representative instances)
        :param jpype.JArray[java.lang.String] fieldNames: array of column field names
        :param jpype.JArray[jpype.JInt] sparseColumns: column indexes corresponding to those
        columns which utilize sparse storage (null if no sparse columns).
        Valid sparse column indexes are in the range 0..127.
        :raises IllegalArgumentException: invalid parameters
        """

    @typing.overload
    def __init__(self, version: typing.Union[jpype.JInt, int], keyClass: java.lang.Class[typing.Any], keyName: typing.Union[java.lang.String, str], fieldClasses: jpype.JArray[java.lang.Class[typing.Any]], fieldNames: jpype.JArray[java.lang.String]):
        """
        Construct a new Schema.
        
        :param jpype.JInt or int version: schema version
        :param java.lang.Class[typing.Any] keyClass: field class associated with primary key
        :param java.lang.String or str keyName: primary key name
        :param jpype.JArray[java.lang.Class[typing.Any]] fieldClasses: array of column field classes
        :param jpype.JArray[java.lang.String] fieldNames: array of column field names
        :raises IllegalArgumentException: invalid parameters
        """

    @typing.overload
    def __init__(self, version: typing.Union[jpype.JInt, int], keyClass: java.lang.Class[typing.Any], keyName: typing.Union[java.lang.String, str], fieldClasses: jpype.JArray[java.lang.Class[typing.Any]], fieldNames: jpype.JArray[java.lang.String], sparseColumns: jpype.JArray[jpype.JInt]):
        """
        Construct a new Schema.
        
        :param jpype.JInt or int version: schema version
        :param java.lang.Class[typing.Any] keyClass: field class associated with primary key
        :param java.lang.String or str keyName: primary key name
        :param jpype.JArray[java.lang.Class[typing.Any]] fieldClasses: array of column field classes
        :param jpype.JArray[java.lang.String] fieldNames: array of column field names
        :param jpype.JArray[jpype.JInt] sparseColumns: column indexes corresponding to those
        columns which utilize sparse storage (null if no sparse columns).
        Valid sparse column indexes are in the range 0..127.
        :raises IllegalArgumentException: invalid parameters
        """

    @typing.overload
    def __init__(self, version: typing.Union[jpype.JInt, int], keyName: typing.Union[java.lang.String, str], fieldClasses: jpype.JArray[java.lang.Class[typing.Any]], fieldNames: jpype.JArray[java.lang.String]):
        """
        Construct a new Schema which uses a long key.
        
        :param jpype.JInt or int version: schema version
        :param java.lang.String or str keyName: primary key name
        :param jpype.JArray[java.lang.Class[typing.Any]] fieldClasses: array of column field classes
        :param jpype.JArray[java.lang.String] fieldNames: array of column field names
        :raises IllegalArgumentException: invalid parameters
        """

    @typing.overload
    def __init__(self, version: typing.Union[jpype.JInt, int], keyName: typing.Union[java.lang.String, str], fieldClasses: jpype.JArray[java.lang.Class[typing.Any]], fieldNames: jpype.JArray[java.lang.String], sparseColumns: jpype.JArray[jpype.JInt]):
        """
        Construct a new Schema which uses a long key.
        
        :param jpype.JInt or int version: schema version
        :param java.lang.String or str keyName: primary key name
        :param jpype.JArray[java.lang.Class[typing.Any]] fieldClasses: array of column field classes
        :param jpype.JArray[java.lang.String] fieldNames: array of column field names
        :param jpype.JArray[jpype.JInt] sparseColumns: column indexes corresponding to those
        columns which utilize sparse storage (null if no sparse columns).
        Valid sparse column indexes are in the range 0..127.
        :raises IllegalArgumentException: invalid parameters
        """

    @typing.overload
    def createRecord(self, key: typing.Union[jpype.JLong, int]) -> DBRecord:
        """
        Create an empty record for the specified key.
        
        :param jpype.JLong or int key: long key
        :return: new record
        :rtype: DBRecord
        """

    @typing.overload
    def createRecord(self, key: Field) -> DBRecord:
        """
        Create an empty record for the specified key.
        
        :param Field key: record key field
        :return: new record
        :rtype: DBRecord
        """

    def equals(self, obj: java.lang.Object) -> bool:
        """
        Compare two schemas for equality.
        Field names are ignored in this comparison.  Instance variables such as :obj:`.fixedLength`,
        :obj:`Schema.isVariableLength` and :obj:`.forceUseVariableLengthKeyNodes` are also ignored.
        
        
        .. seealso::
        
            | :obj:`java.lang.Object.equals(java.lang.Object)`
        """

    def getFieldCount(self) -> int:
        """
        Get the number of data Fields
        
        :return: data Field count
        :rtype: int
        """

    def getFieldNames(self) -> jpype.JArray[java.lang.String]:
        """
        Get the list of data Field names for this schema.
        The returned list is ordered consistent with the schema definition.
        
        :return: data Field names
        :rtype: jpype.JArray[java.lang.String]
        """

    def getFields(self) -> jpype.JArray[Field]:
        """
        Get the list of data Field classes for this schema.
        The returned list is ordered consistent with the schema definition.
        
        :return: data Field classes
        :rtype: jpype.JArray[Field]
        """

    def getFixedLength(self) -> int:
        """
        Get length of fixed-length schema record.
        
        :return: record length or 0 for variable length.
        :rtype: int
        """

    def getKeyFieldType(self) -> Field:
        """
        Get the Field type for the key.
        
        :return: key Field type
        :rtype: Field
        """

    def getKeyName(self) -> str:
        """
        Get the key name
        
        :return: key name
        :rtype: str
        """

    def getVersion(self) -> int:
        """
        Get the schema version.
        
        :return: schema version
        :rtype: int
        """

    def hasSparseColumns(self) -> bool:
        """
        Determine if schema employs sparse column storage
        
        :return: true if schema employs sparse column storage
        :rtype: bool
        """

    def isSparseColumn(self, columnIndex: typing.Union[jpype.JInt, int]) -> bool:
        """
        Determine if the specified column index has been designated as a sparse
        column within the associated record storage
        
        :param jpype.JInt or int columnIndex: column index
        :return: true if designated column uses sparse storage
        :rtype: bool
        """

    def isVariableLength(self) -> bool:
        """
        Returns true if records for this Schema can be of variable lengths.
        
        :return: true if records with this Schema are variable length.
        :rtype: bool
        """

    @property
    def fieldCount(self) -> jpype.JInt:
        ...

    @property
    def fixedLength(self) -> jpype.JInt:
        ...

    @property
    def variableLength(self) -> jpype.JBoolean:
        ...

    @property
    def fieldNames(self) -> jpype.JArray[java.lang.String]:
        ...

    @property
    def keyName(self) -> java.lang.String:
        ...

    @property
    def keyFieldType(self) -> Field:
        ...

    @property
    def fields(self) -> jpype.JArray[Field]:
        ...

    @property
    def version(self) -> jpype.JInt:
        ...

    @property
    def sparseColumn(self) -> jpype.JBoolean:
        ...


class Database(java.lang.Object):
    """
    ``Database`` facilitates the creation of a DBHandle for accessing
    a database.
     
    
    Public constructors are only provided for use with "Non-Versioned" databases.
    This class should be extended when additional management features are needed, 
    such as for a "Versioned" database.
     
    
    This class assumes exclusive control of the associated files contained within the 
    associated database directory and relies on the proper establishment of a 
    syncObject to midigate potential concurrent modification issues.
    """

    @typing.type_check_only
    class DBBufferFileManager(db.buffers.BufferFileManager):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def getCurrentVersion(self) -> int:
        """
        Returns the version number associated with the latest buffer file version.
        """

    def lastModified(self) -> int:
        """
        Returns the time at which this database was last saved.
        """

    def length(self) -> int:
        """
        Returns the length of this domain file.  This size is the minimum disk space
        used for storing this file, but does not account for additional storage space
        used to tracks changes, etc.
        
        :return: file length
        :rtype: int
        :raises IOException: thrown if IO or access error occurs
        """

    def open(self, monitor: ghidra.util.task.TaskMonitor) -> DBHandle:
        """
        Open the stored database for non-update use.
        The returned handle does not support the Save operation.
        
        :param ghidra.util.task.TaskMonitor monitor: task monitor (may be null)
        :return: database handle
        :rtype: DBHandle
        :raises FileInUseException: thrown if unable to obtain the required database lock(s).
        :raises IOException: thrown if IO error occurs.
        :raises CancelledException: if cancelled by monitor
        """

    def openForUpdate(self, monitor: ghidra.util.task.TaskMonitor) -> DBHandle:
        """
        Open the stored database for update use.
        
        :param ghidra.util.task.TaskMonitor monitor: task monitor (may be null)
        :return: buffer file
        :rtype: DBHandle
        :raises FileInUseException: thrown if unable to obtain the required database lock(s).
        :raises IOException: thrown if IO error occurs.
        :raises CancelledException: if cancelled by monitor
        """

    def refresh(self):
        """
        Scan files and update state.
        """

    def setSynchronizationObject(self, syncObject: java.lang.Object):
        """
        Set the object to be used for synchronization.
        
        :param java.lang.Object syncObject:
        """

    @property
    def currentVersion(self) -> jpype.JInt:
        ...


class DBFieldIterator(java.lang.Object):
    """
    ``DBFieldIterator`` provides the ability to iterate over
    Field values within a table.
    """

    class_: typing.ClassVar[java.lang.Class]

    def delete(self) -> bool:
        """
        Delete the last record(s) associated with the last Field value
        read via the next or previous methods.
        
        :return: true if record(s) was successfully deleted.
        :rtype: bool
        :raises IOException: thrown if an IO error occurs.
        """

    def hasNext(self) -> bool:
        """
        Return true if a Field is available in the forward direction.
        
        :raises IOException: thrown if an IO error occurs
        """

    def hasPrevious(self) -> bool:
        """
        Return true if a Field is available in the reverse direction
        
        :raises IOException: thrown if an IO error occurs
        """

    def next(self) -> Field:
        """
        Return the next Field value or null if one is not available.
        
        :raises IOException: thrown if an IO error occurs
        """

    def previous(self) -> Field:
        """
        Return the previous Field value or null if one is not available.
        
        :raises IOException: thrown if an IO error occurs
        """


class TableStatistics(java.lang.Object):
    """
    Table statistics data
    """

    class_: typing.ClassVar[java.lang.Class]
    name: java.lang.String
    """
    Name of table (same name used by both primary table and related index tables)
    """

    indexColumn: jpype.JInt
    """
    For index tables, this indicates the indexed column within the primary table.
    For primary tables, this value is -1 and does not apply.
    """

    bufferCount: jpype.JInt
    """
    Total number of table nodes
    """

    size: jpype.JInt
    """
    Total size of table
    """

    interiorNodeCnt: jpype.JInt
    """
    Total number of interior nodes
    """

    recordNodeCnt: jpype.JInt
    """
    Total number of leaf/record nodes.
    """

    chainedBufferCnt: jpype.JInt
    """
    Total number of buffers used within chanined DBBuffers for
    record storage.
    """


    def __init__(self):
        ...


@typing.type_check_only
class JavaBinarySearcher2(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def binarySearch(self, buf: jpype.JArray[jpype.JByte], key: typing.Union[jpype.JLong, int], nKeys: typing.Union[jpype.JInt, int]) -> int:
        ...


class DBListener(java.lang.Object):
    """
    Database Listener.
    """

    class_: typing.ClassVar[java.lang.Class]

    def dbClosed(self, dbh: DBHandle):
        """
        Database has been closed
        
        :param DBHandle dbh: associated database handle
        """

    def dbRestored(self, dbh: DBHandle):
        """
        Provides notification that an undo or redo was performed.
        During the restore process :meth:`tableAdded(DBHandle, Table) <.tableAdded>` and
        :meth:`tableDeleted(DBHandle, Table) <.tableDeleted>` notifications will be supressed.
        Any listener concerned with tables added or removed should reacquire their table(s).
        
        :param DBHandle dbh: associated database handle
        """

    def tableAdded(self, dbh: DBHandle, table: Table):
        """
        Provides notification that a table was added.
        The state of the database may still be in transition and should not be accessed
        by this callback method.
        
        :param DBHandle dbh: associated database handle
        :param Table table:
        """

    def tableDeleted(self, dbh: DBHandle, table: Table):
        """
        Provides notification that a table was deleted.
        The state of the database may still be in transition and should not be accessed
        by this callback method.
        
        :param DBHandle dbh: associated database handle
        :param Table table:
        """


class IntField(PrimitiveField):
    """
    ``IntField`` provides a wrapper for 4-byte signed integer data 
    which is read or written to a Record.
    """

    class_: typing.ClassVar[java.lang.Class]
    MIN_VALUE: typing.Final[IntField]
    """
    Minimum integer field value
    """

    MAX_VALUE: typing.Final[IntField]
    """
    Maximum integer field value
    """

    ZERO_VALUE: typing.Final[IntField]
    """
    Zero int field value
    """

    INSTANCE: typing.Final[IntField]
    """
    Instance intended for defining a :obj:`Table` :obj:`Schema`
    """


    @typing.overload
    def __init__(self):
        """
        Construct an integer field with an initial value of 0.
        """

    @typing.overload
    def __init__(self, i: typing.Union[jpype.JInt, int]):
        """
        Construct an integer field with an initial value of i.
        
        :param jpype.JInt or int i: initial value
        """


@typing.type_check_only
class VarKeyInteriorNode(VarKeyNode, FieldKeyInteriorNode):
    """
    ``LongKeyInteriorNode`` stores a BTree node for use as an interior
    node when searching for Table records within the database.  This type of node
    has the following layout within a single DataBuffer (field size in bytes):
     
    | NodeType(1) | KeyType(1) | KeyCount(4) | KeyOffset0(4) | ID0(4) | ... | KeyOffsetN(4) | IDN(4) | 
        ...<FreeSpace>... | KeyN | ... | Key0 |
    """

    class_: typing.ClassVar[java.lang.Class]

    def getKeyOffset(self, index: typing.Union[jpype.JInt, int]) -> int:
        """
        Get the key offset within the buffer
        
        :param jpype.JInt or int index: key index
        :return: record key offset
        :rtype: int
        """

    def isLeftmostKey(self, key: Field) -> bool:
        ...

    def isRightmostKey(self, key: Field) -> bool:
        ...

    def keyChanged(self, oldKey: Field, newKey: Field, node: FieldKeyNode):
        """
        Callback method for when a child node's leftmost key changes.
        
        :param Field oldKey: previous leftmost key.
        :param Field newKey: new leftmost key.
        :param FieldKeyNode node: child node containing oldKey
        :raises IOException: if IO error occurs
        """

    @property
    def rightmostKey(self) -> jpype.JBoolean:
        ...

    @property
    def leftmostKey(self) -> jpype.JBoolean:
        ...

    @property
    def keyOffset(self) -> jpype.JInt:
        ...


@typing.type_check_only
class FieldKeyNode(BTreeNode):
    """
    ``FieldKeyNode`` defines a common interface for :obj:`BTreeNode` 
    implementations which utilize a :obj:`Field` key.
    """

    class_: typing.ClassVar[java.lang.Class]

    def compareKeyField(self, k: Field, keyIndex: typing.Union[jpype.JInt, int]) -> int:
        """
        Performs a fast in-place key comparison of the specified key
        value with a key stored within this node at the specified keyIndex.
        
        :param Field k: key value to be compared
        :param jpype.JInt or int keyIndex: key index to another key within this node's buffer
        :return: comparison value, zero if equal, -1 if k has a value less than
        the store key, or +1 if k has a value greater than the stored key located
        at keyIndex.
        :rtype: int
        """

    def getLeafNode(self, key: Field) -> FieldKeyRecordNode:
        """
        Get the leaf node which contains the specified key.
        
        :param Field key: key value
        :return: leaf node
        :rtype: FieldKeyRecordNode
        :raises IOException: thrown if an IO error occurs
        """

    def getLeftmostLeafNode(self) -> FieldKeyRecordNode:
        """
        Get the left-most leaf node within the tree.
        
        :return: left-most leaf node.
        :rtype: FieldKeyRecordNode
        :raises IOException: thrown if IO error occurs
        """

    def getRightmostLeafNode(self) -> FieldKeyRecordNode:
        """
        Get the right-most leaf node within the tree.
        
        :return: right-most leaf node.
        :rtype: FieldKeyRecordNode
        :raises IOException: thrown if IO error occurs
        """

    @property
    def rightmostLeafNode(self) -> FieldKeyRecordNode:
        ...

    @property
    def leftmostLeafNode(self) -> FieldKeyRecordNode:
        ...

    @property
    def leafNode(self) -> FieldKeyRecordNode:
        ...


class DBHandle(java.lang.Object):
    """
    ``DBHandle`` provides access to an open database.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        Construct a temporary database handle.
        The saveAs method must be used to save the database.
        
        :raises IOException: if a IO error occurs
        """

    @typing.overload
    def __init__(self, requestedBufferSize: typing.Union[jpype.JInt, int]):
        """
        Construct a temporary database handle.
        The saveAs method must be used to save the database.
        
        :param jpype.JInt or int requestedBufferSize: requested buffer size.  Actual buffer size may vary.
        :raises IOException: if a IO error occurs
        """

    @typing.overload
    def __init__(self, requestedBufferSize: typing.Union[jpype.JInt, int], approxCacheSize: typing.Union[jpype.JLong, int]):
        """
        Construct a temporary database handle.
        The saveAs method must be used to save the database.
        
        :param jpype.JInt or int requestedBufferSize: requested buffer size.  Actual buffer size may vary.
        :param jpype.JLong or int approxCacheSize: approximate size of cache in Bytes.
        :raises IOException: if a IO error occurs
        """

    @typing.overload
    def __init__(self, bufferFile: db.buffers.BufferFile):
        """
        Open the database contained within the specified
        bufferFile.  The update mode is determined by the buffer file.
        
        :param db.buffers.BufferFile bufferFile: database buffer file
        :raises IOException: if IO error occurs
        """

    @typing.overload
    def __init__(self, bufferFile: db.buffers.BufferFile, recover: typing.Union[jpype.JBoolean, bool], monitor: ghidra.util.task.TaskMonitor):
        """
        Open the database contained within the specified
        bufferFile.  The update mode is determined by the buffer file.
        
        :param db.buffers.BufferFile bufferFile: database buffer file
        :param jpype.JBoolean or bool recover: if true an attempt will be made to recover unsaved data if the file is open for update
        :param ghidra.util.task.TaskMonitor monitor: recovery monitor
        :raises IOException: if IO error occurs
        :raises CancelledException: if buffer file recovery is cancelled
        """

    @typing.overload
    def __init__(self, file: jpype.protocol.SupportsPath):
        """
        Open a specific buffer file containing a database
        for non-update use.  This method is provided primarily
        for testing.
        
        :param jpype.protocol.SupportsPath file: buffer file
        :raises IOException: if IO error occurs
        """

    def addListener(self, listener: DBListener):
        """
        Add Database listener
        
        :param DBListener listener: database listener
        """

    def canRedo(self) -> bool:
        """
        Determine if there are any changes which can be redone
        
        :return: true if a redo can be performed.
        :rtype: bool
        """

    def canUndo(self) -> bool:
        """
        Determine if there are any changes which can be undone.
        
        :return: true if an undo can be performed.
        :rtype: bool
        """

    def canUpdate(self) -> bool:
        """
        Determine if this database can be updated.
        
        :return: true if this database handle is intended for update
        :rtype: bool
        """

    def checkIsClosed(self):
        """
        Check if the database is closed.
        
        :raises ClosedException: if database is closed and further operations are unsupported
        """

    def checkTransaction(self):
        """
        Verify that a valid transaction has been started.
        
        :raises NoTransactionException: if transaction has not been started
        :raises TerminatedTransactionException: transaction was prematurely terminated
        """

    @typing.overload
    def close(self):
        """
        Close the database and dispose of the underlying buffer manager.
        Any existing recovery data will be discarded.
        """

    @typing.overload
    def close(self, keepRecoveryData: typing.Union[jpype.JBoolean, bool]):
        """
        Close the database and dispose of the underlying buffer manager.
        
        :param jpype.JBoolean or bool keepRecoveryData: true if existing recovery data should be retained or false to remove
        any recovery data
        """

    def closeScratchPad(self):
        """
        Close the scratch-pad database handle if it open.
        """

    @typing.overload
    def createBuffer(self, length: typing.Union[jpype.JInt, int]) -> DBBuffer:
        """
        Create a new buffer with the specified length.
        This method may only be invoked while a database transaction 
        is in progress. A database transaction must also be in progress
        when invoking the various put, delete and setSize methods on the returned buffer.
        
        :param jpype.JInt or int length: the size of the buffer to create
        :return: Buffer the newly created buffer
        :rtype: DBBuffer
        :raises IOException: if an I/O error occurs while creating the buffer.
        """

    @typing.overload
    def createBuffer(self, shadowBuffer: DBBuffer) -> DBBuffer:
        """
        Create a new buffer that layers on top of another buffer.  This buffer
        will return values from the shadowBuffer unless they have been changed in this buffer.
        This method may only be invoked while a database transaction 
        is in progress. A database transaction must also be in progress
        when invoking the various put, delete and setSize methods on the returned buffer.
        
        :param DBBuffer shadowBuffer: the source of the byte values to use unless they have been changed.
        :return: Buffer the newly created buffer
        :rtype: DBBuffer
        :raises IOException: if an I/O error occurs while creating the buffer.
        """

    @typing.overload
    def createTable(self, name: typing.Union[java.lang.String, str], schema: Schema) -> Table:
        """
        Creates a new table with the given name and schema.
        
        :param java.lang.String or str name: table name
        :param Schema schema: table schema
        :return: new table instance
        :rtype: Table
        :raises IOException: if IO error occurs during table creation
        """

    @typing.overload
    def createTable(self, name: typing.Union[java.lang.String, str], schema: Schema, indexedColumns: jpype.JArray[jpype.JInt]) -> Table:
        """
        Creates a new table with the given name and schema.
        Create secondary indexes as specified by the array of column indexes.
        
        :param java.lang.String or str name: table name
        :param Schema schema: table schema
        :param jpype.JArray[jpype.JInt] indexedColumns: array of column indices which should have an index associated with them
        :return: new table instance
        :rtype: Table
        :raises IOException: if IO error occurs during table creation
        """

    def deleteTable(self, name: typing.Union[java.lang.String, str]):
        """
        Delete the specified table from the database.
        
        :param java.lang.String or str name: table name
        :raises IOException: if there is an I/O error or the table does not exist
        """

    def enablePreCache(self):
        """
        Enable and start source file pre-cache if appropriate.
        WARNING! EXPERIMENTAL !!!
        """

    def endTransaction(self, id: typing.Union[jpype.JLong, int], commit: typing.Union[jpype.JBoolean, bool]) -> bool:
        """
        End current transaction.  If commit is false a rollback may occur followed by
        :meth:`DBListener.dbRestored(DBHandle) <DBListener.dbRestored>` notification to listeners.
        
        :param jpype.JLong or int id: transaction ID
        :param jpype.JBoolean or bool commit: if true a new checkpoint will be established for active transaction, if
        false all changes since the previous checkpoint will be discarded.
        :return: true if new checkpoint established, false if nothing to commit
        or commit parameter specified as false and active transaction is terminated with rollback.
        :rtype: bool
        :raises IOException: if IO error occurs
        """

    def getAvailableRedoCount(self) -> int:
        """
        
        
        :return: the number of redo-able transactions
        :rtype: int
        """

    def getAvailableUndoCount(self) -> int:
        """
        
        
        :return: number of undo-able transactions
        :rtype: int
        """

    @typing.overload
    def getBuffer(self, id: typing.Union[jpype.JInt, int]) -> DBBuffer:
        """
        Get an existing buffer.  This method should be used with care to avoid 
        providing an improper id.  A database transaction must be in progress
        when invoking the various put, delete and setSize methods on the returned buffer.
        
        :param jpype.JInt or int id: the buffer id.
        :return: Buffer the buffer associated with the given id.
        :rtype: DBBuffer
        :raises IOException: if an I/O error occurs while getting the buffer.
        """

    @typing.overload
    def getBuffer(self, id: typing.Union[jpype.JInt, int], shadowBuffer: DBBuffer) -> DBBuffer:
        """
        Get an existing buffer that uses a shadowBuffer for byte values if they haven't been
        explicitly changed in this buffer.  This method should be used with care to avoid 
        providing an improper id.  A database transaction must be in progress
        when invoking the various put, delete and setSize methods on the returned buffer.
        
        :param jpype.JInt or int id: the buffer id.
        :param DBBuffer shadowBuffer: the buffer to use for byte values if they haven't been changed in 
        this buffer.
        :return: Buffer the buffer associated with the given id.
        :rtype: DBBuffer
        :raises IOException: if an I/O error occurs while getting the buffer.
        """

    def getBufferSize(self) -> int:
        """
        Returns size of buffers utilized within the underlying
        buffer file.  This may be larger than the requested 
        buffer size.  This value may be used to instatiate a 
        new BufferFile which is compatible with this database
        when using the saveAs method.
        
        :return: buffer size utilized by this database
        :rtype: int
        """

    def getCacheHits(self) -> int:
        """
        
        
        :return: number of buffer cache hits
        :rtype: int
        """

    def getCacheMisses(self) -> int:
        """
        
        
        :return: number of buffer cache misses
        :rtype: int
        """

    def getDatabaseId(self) -> int:
        """
        
        
        :return: unique database ID or 0 if this is an older read-only database.
        :rtype: int
        """

    def getLowBufferCount(self) -> int:
        """
        
        
        :return: low water mark (minimum buffer pool size)
        :rtype: int
        """

    def getModCount(self) -> int:
        """
        Provides a means of detecting changes to the underlying database buffers 
        during a transaction.
        
        :return: current modification count
        :rtype: int
        """

    def getRecoveryChangeSetFile(self) -> db.buffers.LocalBufferFile:
        """
        Returns the recovery changeSet data file for reading or null if one is not available.
        The caller must dispose of the returned file before peforming generating any new
        recovery snapshots.
        
        :return: recovery changeSet data file for reading or null if one is not available.
        :rtype: db.buffers.LocalBufferFile
        :raises IOException: if IO error occurs
        """

    def getScratchPad(self) -> DBHandle:
        """
        Returns a shared temporary database handle.
        This temporary handle will remain open unitl either this 
        handle is closed or closeScratchPad is invoked.
        
        :return: shared temporary database handle.
        :rtype: DBHandle
        :raises IOException: if IO error occurs
        """

    def getTable(self, name: typing.Union[java.lang.String, str]) -> Table:
        """
        Returns the Table that was created with the given name or null if
        no such table exists.
        
        :param java.lang.String or str name: of requested table
        :return: table instance or null if not found
        :rtype: Table
        """

    def getTableCount(self) -> int:
        """
        Return the number of tables defined within the master table.
        
        :return: int number of tables.
        :rtype: int
        """

    def getTables(self) -> jpype.JArray[Table]:
        """
        Get all tables defined within the database.
        
        :return: Table[] tables
        :rtype: jpype.JArray[Table]
        """

    def hasUncommittedChanges(self) -> bool:
        """
        Returns true if there are uncommitted changes to the database.
        
        :return: true if there are uncommitted changes to the database.
        :rtype: bool
        """

    def isChanged(self) -> bool:
        """
        Determine if the underlying database has changed.
        NOTE: The returned value reflects a cached state assuming all underlaying database 
        transactions, saving, etc. are facilitated by this handle object.
        
        :return: true if unsaved changes have been made.
        :rtype: bool
        """

    def isClosed(self) -> bool:
        """
        
        
        :return: true if this database handle has been closed.
        :rtype: bool
        """

    def isConsistent(self, monitor: ghidra.util.task.TaskMonitor) -> bool:
        """
        Check the consistency of this database.
        
        :param ghidra.util.task.TaskMonitor monitor: task monitor
        :return: true if consistency check passed, else false
        :rtype: bool
        :raises CancelledException: if consistency check is cancelled
        """

    def isTransactionActive(self) -> bool:
        """
        
        
        :return: true if transaction is currently active
        :rtype: bool
        """

    def openTransaction(self, errorHandler: db.util.ErrorHandler) -> Transaction:
        """
        Open new transaction.  This should generally be done with a try-with-resources block:
         
        try (Transaction tx = dbHandle.openTransaction(dbErrorHandler)) {
            // ... Do something
        }
         
        
        :param db.util.ErrorHandler errorHandler: handler resposible for handling an IOException which may result during
        transaction processing.  In general, a :obj:`RuntimeException` should be thrown by the 
        handler to ensure continued processing is properly signaled/interupted.
        :return: transaction object
        :rtype: Transaction
        :raises java.lang.IllegalStateException: if transaction is already active or this :obj:`DBHandle` has 
        already been closed.
        """

    def rebuild(self, monitor: ghidra.util.task.TaskMonitor) -> bool:
        """
        Rebuild database tables to resolve certain consistency problems.  Use of this
        method does not recover lost data which may have occurred during original 
        database corruption.
        
        :param ghidra.util.task.TaskMonitor monitor: task monitor
        :return: true if rebuild succeeded, else false
        :rtype: bool
        :raises CancelledException: if rebuild is cancelled
        """

    def redo(self) -> bool:
        """
        Redo previously undone transaction checkpoint.
        Moves forward by one checkpoint only.
        All upper-levels must clear table-based cached data prior to 
        invoking this method.
        
        :return: boolean if redo is successful, else false if undo not allowed
        :rtype: bool
        :raises IOException: if IO error occurs
        """

    @staticmethod
    def resetDatabaseId(file: jpype.protocol.SupportsPath):
        """
        Reset the database ID contained within the specified database file.
        This method is intended to be used when unpacking a packed database
        to ensure that a duplicate database ID does not exist within the project.
        WARNING! Use with extreme caution since this modifies
        the original file and could destroy data if used
        improperly.
        
        :param jpype.protocol.SupportsPath file: database buffer file to be updated
        :raises IOException: if IO error occurs
        """

    def save(self, comment: typing.Union[java.lang.String, str], changeSet: DBChangeSet, monitor: ghidra.util.task.TaskMonitor):
        """
        Save this database to a new version.
        
        :param java.lang.String or str comment: if version history is maintained, this comment will be 
        associated with the new version.
        :param DBChangeSet changeSet: an optional database-backed change set which reflects changes 
        made since the last version.
        :param ghidra.util.task.TaskMonitor monitor: progress monitor
        :raises CancelledException: if task monitor cancelled operation.
        :raises IOException: thrown if an IO error occurs.
        """

    @typing.overload
    def saveAs(self, outFile: db.buffers.BufferFile, associateWithNewFile: typing.Union[jpype.JBoolean, bool], monitor: ghidra.util.task.TaskMonitor):
        """
        Save the database to the specified buffer file.
        
        :param db.buffers.BufferFile outFile: buffer file open for writing
        :param jpype.JBoolean or bool associateWithNewFile: if true the outFile will be associated with this DBHandle as the 
        current source file, if false no change will be made to this DBHandle's state and the outFile
        will be written and set as read-only.  The caller is responsbile for disposing the outFile if 
        this parameter is false.
        :param ghidra.util.task.TaskMonitor monitor: progress monitor
        :raises IOException: if IO error occurs
        :raises CancelledException: if monitor cancels operation
        """

    @typing.overload
    def saveAs(self, file: jpype.protocol.SupportsPath, associateWithNewFile: typing.Union[jpype.JBoolean, bool], monitor: ghidra.util.task.TaskMonitor):
        """
        Save the database to the specified buffer file.
        
        :param jpype.protocol.SupportsPath file: buffer file to be created
        :param jpype.JBoolean or bool associateWithNewFile: if true the outFile will be associated with this DBHandle as the 
        current source file, if false no change will be made to this DBHandle's state and the outFile
        will be written and set as read-only.  The caller is responsbile for disposing the outFile if 
        this parameter is false.
        :param ghidra.util.task.TaskMonitor monitor: progress monitor
        :raises DuplicateFileException: if file already exists.
        :raises IOException: if IO error occurs
        :raises CancelledException: if monitor cancels operation
        """

    def setDBVersionedSourceFile(self, versionedSourceBufferFile: db.buffers.BufferFile):
        """
        Set the DB source buffer file with a newer local buffer file version.
        Intended for use following a merge or commit operation only where a local checkout has been
        retained.
        
        :param db.buffers.BufferFile versionedSourceBufferFile: updated local DB source buffer file opened for versioning 
        update (NOTE: file itself is read-only).  File must be an instance of 
        :obj:`LocalManagedBufferFile`.
        :raises IOException: if an IO error occurs
        """

    def setMaxUndos(self, maxUndos: typing.Union[jpype.JInt, int]):
        """
        Set the maximum number of undo transaction checkpoints maintained by the
        underlying buffer manager.
        
        :param jpype.JInt or int maxUndos: maximum number of undo checkpoints.  An illegal 
        value restores the default value.
        """

    def setTableName(self, oldName: typing.Union[java.lang.String, str], newName: typing.Union[java.lang.String, str]) -> bool:
        """
        Changes the name of an existing table.
        
        :param java.lang.String or str oldName: the old name of the table
        :param java.lang.String or str newName: the new name of the table
        :raises DuplicateNameException: if a table with the new name already exists
        :return: true if the name was changed successfully
        :rtype: bool
        """

    def startTransaction(self) -> int:
        """
        Start a new transaction
        
        :return: transaction ID
        :rtype: int
        """

    def takeRecoverySnapshot(self, changeSet: DBChangeSet, monitor: ghidra.util.task.TaskMonitor) -> bool:
        """
        Request a recovery snapshot be taken of any unsaved changes;
        
        :param DBChangeSet changeSet: an optional database-backed change set which reflects changes 
        made since the last version.
        :param ghidra.util.task.TaskMonitor monitor: task monitor
        :return: true if snapshot successful or not needed, false if an active transaction prevented snapshot
        :rtype: bool
        :raises CancelledException: if cancelled by monitor
        :raises IOException: if IO error occurs
        """

    def terminateTransaction(self, id: typing.Union[jpype.JLong, int], commit: typing.Union[jpype.JBoolean, bool]):
        """
        Terminate current transaction.  If commit is false a rollback may occur followed by
        :meth:`DBListener.dbRestored(DBHandle) <DBListener.dbRestored>` notification to listeners.  This method is very 
        similar to :meth:`endTransaction(long, boolean) <.endTransaction>` with the added behavior of setting the 
        internal :obj:`DBHandle` state such that any subsequent invocations of 
        :meth:`checkTransaction() <.checkTransaction>` will throw a :obj:`TerminatedTransactionException` until a new 
        transaction is started.
        
        :param jpype.JLong or int id: transaction ID
        :param jpype.JBoolean or bool commit: if true a new checkpoint will be established for active transaction, if
        false all changes since the previous checkpoint will be discarded.
        :raises IOException: if IO error occurs
        """

    def undo(self) -> bool:
        """
        Undo changes made during the previous transaction checkpoint.
        All upper-levels must clear table-based cached data prior to 
        invoking this method.
        
        :return: true if an undo was successful, else false if not allowed
        :rtype: bool
        :raises IOException: if IO error occurs
        """

    @property
    def lowBufferCount(self) -> jpype.JInt:
        ...

    @property
    def cacheMisses(self) -> jpype.JLong:
        ...

    @property
    def tableCount(self) -> jpype.JInt:
        ...

    @property
    def consistent(self) -> jpype.JBoolean:
        ...

    @property
    def availableRedoCount(self) -> jpype.JInt:
        ...

    @property
    def modCount(self) -> jpype.JLong:
        ...

    @property
    def tables(self) -> jpype.JArray[Table]:
        ...

    @property
    def transactionActive(self) -> jpype.JBoolean:
        ...

    @property
    def scratchPad(self) -> DBHandle:
        ...

    @property
    def recoveryChangeSetFile(self) -> db.buffers.LocalBufferFile:
        ...

    @property
    def closed(self) -> jpype.JBoolean:
        ...

    @property
    def cacheHits(self) -> jpype.JLong:
        ...

    @property
    def availableUndoCount(self) -> jpype.JInt:
        ...

    @property
    def buffer(self) -> DBBuffer:
        ...

    @property
    def databaseId(self) -> jpype.JLong:
        ...

    @property
    def table(self) -> Table:
        ...

    @property
    def changed(self) -> jpype.JBoolean:
        ...

    @property
    def bufferSize(self) -> jpype.JInt:
        ...


@typing.type_check_only
class DBRollbackException(java.lang.Exception):
    """
    ``DBRollbackException`` thrown when a database transaction rollback was performed
    during transaction termination.
    """

    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class VarKeyNode(FieldKeyNode):
    """
    ``VarKeyNode`` is an abstract implementation of a BTree node
    which utilizes variable-length Field key values.
     
    | NodeType(1) | KeyType(1) | KeyCount(4) | ...
    """

    class_: typing.ClassVar[java.lang.Class]

    def getKeyField(self, index: typing.Union[jpype.JInt, int]) -> Field:
        """
        Get the key value at a specific index.
        
        :param jpype.JInt or int index: key index
        :return: key value
        :rtype: Field
        :raises IOException: thrown if an IO error occurs
        """

    def getKeyOffset(self, index: typing.Union[jpype.JInt, int]) -> int:
        """
        Get the key offset within the buffer
        
        :param jpype.JInt or int index: key index
        :return: record key offset
        :rtype: int
        """

    def getLeafNode(self, key: Field) -> VarKeyRecordNode:
        """
        Get the leaf node which contains the specified key.
        
        :param Field key: key value
        :return: leaf node
        :rtype: VarKeyRecordNode
        :raises IOException: thrown if an IO error occurs
        """

    def getLeftmostLeafNode(self) -> VarKeyRecordNode:
        """
        Get the left-most leaf node within the tree.
        
        :return: left-most leaf node.
        :rtype: VarKeyRecordNode
        :raises IOException: thrown if IO error occurs
        """

    def getRightmostLeafNode(self) -> VarKeyRecordNode:
        """
        Get the right-most leaf node within the tree.
        
        :return: right-most leaf node.
        :rtype: VarKeyRecordNode
        :raises IOException: thrown if IO error occurs
        """

    @property
    def rightmostLeafNode(self) -> VarKeyRecordNode:
        ...

    @property
    def keyField(self) -> Field:
        ...

    @property
    def leftmostLeafNode(self) -> VarKeyRecordNode:
        ...

    @property
    def leafNode(self) -> VarKeyRecordNode:
        ...

    @property
    def keyOffset(self) -> jpype.JInt:
        ...


class RecordNode(BTreeNode):
    """
    :obj:`Table` record leaf nodes within the BTree structure.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getKeyOffset(self, index: typing.Union[jpype.JInt, int]) -> int:
        """
        Get the key offset within the node's data buffer
        
        :param jpype.JInt or int index: key/record index
        :return: positive record offset within buffer
        :rtype: int
        :raises IOException: if IO error occurs
        """

    def getRecordOffset(self, index: typing.Union[jpype.JInt, int]) -> int:
        """
        Get the record offset within the node's data buffer
        
        :param jpype.JInt or int index: key/record index
        :return: positive record offset within buffer, or a negative bufferID for
        indirect record storage in a dedicated buffer
        :rtype: int
        :raises IOException: if IO error occurs
        """

    @property
    def keyOffset(self) -> jpype.JInt:
        ...

    @property
    def recordOffset(self) -> jpype.JInt:
        ...


class SparseRecord(DBRecord):
    ...
    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class MasterTable(java.lang.Object):
    """
    MasterTable manages data pertaining to all other tables within the database - 
    this includes index tables.
    The first buffer associated with this table is managed by the DBParms 
    object associated with the database.
    """

    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class FixedRecNode(LongKeyRecordNode):
    """
    ``FixedRecNode`` is an implementation of a BTree leaf node
    which utilizes long key values and stores fixed-length records.
     
    
    This type of node has the following layout within a single DataBuffer 
    (field size in bytes):
     
    | NodeType(1) | KeyCount(4) | PrevLeafId(4) | NextLeafId(4) | Key0(8) | Rec0 | ...
     
    | KeyN(8) | RecN |
    """

    class_: typing.ClassVar[java.lang.Class]

    def getRecordOffset(self, index: typing.Union[jpype.JInt, int]) -> int:
        """
        Get the record offset within the buffer
        
        :param jpype.JInt or int index: key index
        :return: record offset
        :rtype: int
        """

    @property
    def recordOffset(self) -> jpype.JInt:
        ...


class FieldIndexTable(IndexTable):
    """
    ``FieldIndexTable`` provides a simplified index table whose key is
    a fixed or variable length :obj:`IndexField` which consists of a concatenation of
    the index field value and associated primary table key.
    """

    @typing.type_check_only
    class IndexFieldIterator(DBFieldIterator):
        """
        Iterates over index field values within a specified range.
        NOTE: Index fields which have been truncated may be returned out of order.
        """

        class_: typing.ClassVar[java.lang.Class]

        def delete(self) -> bool:
            """
            Delete all primary records which have the current
            index value (lastKey).
            
            
            .. seealso::
            
                | :obj:`db.DBFieldIterator.delete()`
            """


    @typing.type_check_only
    class PrimaryKeyIterator(DBFieldIterator):
        """
        Iterates over primary keys which correspond to index field values within a specified range.
        NOTE: Primary keys corresponding to index fields which have been truncated may be returned out of order.
        """

        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class PrimitiveField(Field):
    """
    ``PrimitiveField`` provides a base implementation for
    all primitive value :obj:`Field`s.  
     
    
    When a :obj:`PrimitiveField` associated with a :obj:`SparseRecord` 
    has a null state it will have a zero (0) value.
    """

    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class BTreeNode(java.lang.Object):
    """
    ``BTreeNode`` defines a common interface for all types
    of BTree nodes.
    """

    class_: typing.ClassVar[java.lang.Class]

    def delete(self):
        """
        Delete this node and all child nodes.
        
        :raises IOException: thrown if IO error occurs
        """

    def getBuffer(self) -> db.buffers.DataBuffer:
        """
        
        
        :return: the data buffer associated with this node.
        :rtype: db.buffers.DataBuffer
        """

    def getBufferId(self) -> int:
        """
        
        
        :return: the data buffer ID associated with this node.
        :rtype: int
        """

    def getBufferReferences(self) -> jpype.JArray[jpype.JInt]:
        """
        Return all buffer IDs for those buffers which are children
        of this buffer.
        
        :return: array of buffer IDs
        :rtype: jpype.JArray[jpype.JInt]
        """

    def getKeyCount(self) -> int:
        """
        
        
        :return: the number of keys contained within this node.
        :rtype: int
        """

    def getKeyField(self, index: typing.Union[jpype.JInt, int]) -> Field:
        """
        Get the key value at a specific index.
        
        :param jpype.JInt or int index: key index
        :return: key value
        :rtype: Field
        :raises IOException: thrown if an IO error occurs
        """

    def getKeyIndex(self, key: Field) -> int:
        """
        Perform a binary search to locate the specified key and derive an index
        into the Buffer ID storage.  This method is intended to find the insertion 
        index or exact match for a child key.  A negative value will be returned
        when an exact match is not found and may be transformed into an 
        insertion index (insetIndex = -returnedIndex-1).
        
        :param Field key: key to search for
        :return: int buffer ID index.
        :rtype: int
        :raises IOException: thrown if an IO error occurs
        """

    def getParent(self) -> InteriorNode:
        """
        
        
        :return: the parent node or null if this is the root
        :rtype: InteriorNode
        """

    def isConsistent(self, tableName: typing.Union[java.lang.String, str], monitor: ghidra.util.task.TaskMonitor) -> bool:
        """
        Check the consistency of this node and all of its children.
        
        :return: true if consistency check passed, else false
        :rtype: bool
        :param java.lang.String or str tableName: name of table containing this node
        :param ghidra.util.task.TaskMonitor monitor: task monitor
        :raises IOException: if IO error occurred
        :raises CancelledException: if task cancelled
        """

    def setKeyCount(self, cnt: typing.Union[jpype.JInt, int]):
        """
        Set the number of keys contained within this node.
        
        :param jpype.JInt or int cnt: key count
        """

    @property
    def parent(self) -> InteriorNode:
        ...

    @property
    def keyCount(self) -> jpype.JInt:
        ...

    @keyCount.setter
    def keyCount(self, value: jpype.JInt):
        ...

    @property
    def keyField(self) -> Field:
        ...

    @property
    def bufferReferences(self) -> jpype.JArray[jpype.JInt]:
        ...

    @property
    def keyIndex(self) -> jpype.JInt:
        ...

    @property
    def buffer(self) -> db.buffers.DataBuffer:
        ...

    @property
    def bufferId(self) -> jpype.JInt:
        ...


class DBRecord(java.lang.Comparable[DBRecord]):
    """
    ``Record`` provides a portable container for data
    associated with a fixed schema.  
    A record instance contains both a primary key and zero or more data fields.
    """

    class_: typing.ClassVar[java.lang.Class]

    def compareFieldTo(self, columnIndex: typing.Union[jpype.JInt, int], value: Field) -> int:
        """
        Compare two field values.
        
        :param jpype.JInt or int columnIndex: the field index within this record
        :param Field value: another field value to compared
        :return: 0 if equals, a negative number if this record's field is less
        than the specified value, or a positive number if this record's field is
        greater than the specified value.
        :rtype: int
        :raises IndexOutOfBoundsException: if invalid columnIndex is specified
        """

    def compareTo(self, otherRec: DBRecord) -> int:
        """
        Compares the key associated with this record with the 
        key of another record (obj).
        
        
        .. seealso::
        
            | :obj:`java.lang.Comparable.compareTo(java.lang.Object)`
        """

    def copy(self) -> DBRecord:
        """
        Obtain a copy of this record object.
        
        :return: Record
        :rtype: DBRecord
        """

    def equals(self, obj: java.lang.Object) -> bool:
        """
        Compare the content of two Records for equality.
        
        
        .. seealso::
        
            | :obj:`java.lang.Object.equals(java.lang.Object)`
        """

    def fieldEquals(self, columnIndex: typing.Union[jpype.JInt, int], field: Field) -> bool:
        """
        Determine if the specified field equals the field associated with the
        specified columnIndex.
        
        :param jpype.JInt or int columnIndex: field index
        :param Field field: field value to compare with
        :return: true if the fields are equal, else false.
        :rtype: bool
        :raises IndexOutOfBoundsException: if invalid columnIndex is specified
        """

    def getBinaryData(self, colIndex: typing.Union[jpype.JInt, int]) -> jpype.JArray[jpype.JByte]:
        """
        Get the binary data array for the specified field.
        
        :param jpype.JInt or int colIndex: field index
        :return: field data
        :rtype: jpype.JArray[jpype.JByte]
        :raises IndexOutOfBoundsException: if invalid columnIndex is specified
        :raises IllegalFieldAccessException: if field does support binary data access
        """

    def getBooleanValue(self, colIndex: typing.Union[jpype.JInt, int]) -> bool:
        """
        Get the boolean value for the specified field.
        
        :param jpype.JInt or int colIndex: field index
        :return: field value
        :rtype: bool
        :raises IndexOutOfBoundsException: if invalid columnIndex is specified
        :raises IllegalFieldAccessException: if field does support boolean data access
        """

    def getByteValue(self, colIndex: typing.Union[jpype.JInt, int]) -> int:
        """
        Get the byte value for the specified field.
        
        :param jpype.JInt or int colIndex: field index
        :return: field value
        :rtype: int
        :raises IndexOutOfBoundsException: if invalid columnIndex is specified
        :raises IllegalFieldAccessException: if field does support byte data access
        """

    def getColumnCount(self) -> int:
        """
        Get the number of columns contained within this record.
        
        :return: number of field columns.
        :rtype: int
        """

    def getFieldValue(self, columnIndex: typing.Union[jpype.JInt, int]) -> Field:
        """
        Get a copy of the specified field value.
        
        :param jpype.JInt or int columnIndex: field index
        :return: Field field value
        :rtype: Field
        :raises IndexOutOfBoundsException: if invalid columnIndex is specified
        """

    def getIntValue(self, colIndex: typing.Union[jpype.JInt, int]) -> int:
        """
        Get the integer value for the specified field.
        
        :param jpype.JInt or int colIndex: field index
        :return: field value
        :rtype: int
        :raises IndexOutOfBoundsException: if invalid columnIndex is specified
        :raises IllegalFieldAccessException: if field does support integer data access
        """

    def getKey(self) -> int:
        """
        Get the record primary key.
        
        :return: primary key as long value.
        :rtype: int
        """

    def getKeyField(self) -> Field:
        """
        Get the record primary key as a Field object.
        
        :return: primary key as a field object.
        :rtype: Field
        """

    def getLongValue(self, colIndex: typing.Union[jpype.JInt, int]) -> int:
        """
        Get the long value for the specified field.
        
        :param jpype.JInt or int colIndex: field index
        :return: field value
        :rtype: int
        :raises IndexOutOfBoundsException: if invalid columnIndex is specified
        :raises IllegalFieldAccessException: if field does support long data access
        """

    def getShortValue(self, colIndex: typing.Union[jpype.JInt, int]) -> int:
        """
        Get the short value for the specified field.
        
        :param jpype.JInt or int colIndex: field index
        :return: field value
        :rtype: int
        :raises IndexOutOfBoundsException: if invalid columnIndex is specified
        :raises IllegalFieldAccessException: if field does support short data access
        """

    def getString(self, colIndex: typing.Union[jpype.JInt, int]) -> str:
        """
        Get the string value for the specified field.
        
        :param jpype.JInt or int colIndex: field index
        :return: field data
        :rtype: str
        :raises IndexOutOfBoundsException: if invalid columnIndex is specified
        :raises IllegalFieldAccessException: if field does support string data access
        """

    @typing.overload
    def hasSameSchema(self, otherRec: DBRecord) -> bool:
        """
        Determine if this record's schema is the same as another record's
        schema.  This check factors column count and column field types only.
        
        :param DBRecord otherRec: another record
        :return: true if records schemas are the same
        :rtype: bool
        """

    @typing.overload
    def hasSameSchema(self, otherSchema: Schema) -> bool:
        """
        Determine if this record's schema is compatible with the specified schema.  
        This check factors column count and column field types only.
        Index and sparse column checks are not performed.
        
        :param Schema otherSchema: other schema
        :return: true if records schemas are the same
        :rtype: bool
        """

    def isDirty(self) -> bool:
        """
        Determine if data fields have been modified since the last write
        occurred.
        
        :return: true if the field data has not been saved, else false.
        :rtype: bool
        """

    def length(self) -> int:
        """
        Get the stored record length.
        This method is used to determine the space required to store the data 
        fields within this record when written to a standard Buffer.
        
        :return: int stored record length
        :rtype: int
        """

    def read(self, buf: Buffer, offset: typing.Union[jpype.JInt, int]):
        """
        Read the record field data from the specified buffer and offset
        
        :param Buffer buf: data buffer
        :param jpype.JInt or int offset: buffer offset
        :raises java.lang.IndexOutOfBoundsException: if invalid offset is specified
        :raises IOException: thrown if IO error occurs
        """

    def setBinaryData(self, colIndex: typing.Union[jpype.JInt, int], bytes: jpype.JArray[jpype.JByte]):
        """
        Set the binary data array for the specified field.
        
        :param jpype.JInt or int colIndex: field index
        :param jpype.JArray[jpype.JByte] bytes: field value
        :raises IndexOutOfBoundsException: if invalid columnIndex is specified
        :raises IllegalFieldAccessException: if field does support binary data access
        or incorrect number of bytes provided
        """

    def setBooleanValue(self, colIndex: typing.Union[jpype.JInt, int], value: typing.Union[jpype.JBoolean, bool]):
        """
        Set the boolean value for the specified field.
        
        :param jpype.JInt or int colIndex: field index
        :param jpype.JBoolean or bool value: field value
        :raises IndexOutOfBoundsException: if invalid columnIndex is specified
        :raises IllegalFieldAccessException: if field does support boolean data access
        """

    def setByteValue(self, colIndex: typing.Union[jpype.JInt, int], value: typing.Union[jpype.JByte, int]):
        """
        Set the byte value for the specified field.
        
        :param jpype.JInt or int colIndex: field index
        :param jpype.JByte or int value: field value
        :raises IndexOutOfBoundsException: if invalid columnIndex is specified
        :raises IllegalFieldAccessException: if field does support byte data access
        """

    def setField(self, colIndex: typing.Union[jpype.JInt, int], value: Field):
        """
        Set the field value for the specified field.
        
        :param jpype.JInt or int colIndex: field index
        :param Field value: field value (null permitted for sparse column only)
        :raises IndexOutOfBoundsException: if invalid columnIndex is specified
        :raises IllegalArgumentException: if value type does not match column field type.
        """

    def setIntValue(self, colIndex: typing.Union[jpype.JInt, int], value: typing.Union[jpype.JInt, int]):
        """
        Set the integer value for the specified field.
        
        :param jpype.JInt or int colIndex: field index
        :param jpype.JInt or int value: field value
        :raises IndexOutOfBoundsException: if invalid columnIndex is specified
        :raises IllegalFieldAccessException: if field does support integer data access
        """

    @typing.overload
    def setKey(self, key: typing.Union[jpype.JLong, int]):
        """
        Set the primary key associated with this record.
        
        :param jpype.JLong or int key: primary key
        """

    @typing.overload
    def setKey(self, key: Field):
        """
        Set the primary key associated with this record.
        
        :param Field key: primary key
        """

    def setLongValue(self, colIndex: typing.Union[jpype.JInt, int], value: typing.Union[jpype.JLong, int]):
        """
        Set the long value for the specified field.
        
        :param jpype.JInt or int colIndex: field index
        :param jpype.JLong or int value: field value
        :raises IndexOutOfBoundsException: if invalid columnIndex is specified
        :raises IllegalFieldAccessException: if field does support long data access
        """

    def setNull(self, colIndex: typing.Union[jpype.JInt, int]):
        """
        Set the field to a null state.  For a non-sparse fixed-length column field this will
        set the value to zero and the null state will not be persisted when stored.
        
        :param jpype.JInt or int colIndex: field index
        :raises IndexOutOfBoundsException: if invalid columnIndex is specified
        """

    def setShortValue(self, colIndex: typing.Union[jpype.JInt, int], value: typing.Union[jpype.JShort, int]):
        """
        Set the short value for the specified field.
        
        :param jpype.JInt or int colIndex: field index
        :param jpype.JShort or int value: field value
        :raises IndexOutOfBoundsException: if invalid columnIndex is specified
        :raises IllegalFieldAccessException: if field does support short data access
        """

    def setString(self, colIndex: typing.Union[jpype.JInt, int], str: typing.Union[java.lang.String, str]):
        """
        Set the string value for the specified field.
        
        :param jpype.JInt or int colIndex: field index
        :param java.lang.String or str str: field value
        :raises IndexOutOfBoundsException: if invalid columnIndex is specified
        :raises IllegalFieldAccessException: if field does support string data access
        """

    def write(self, buf: Buffer, offset: typing.Union[jpype.JInt, int]):
        """
        Write the record fields to the specified buffer and offset.
        
        :param Buffer buf: data buffer
        :param jpype.JInt or int offset: buffer offset
        :raises java.lang.IndexOutOfBoundsException: if invalid offset is specified
        :raises IOException: thrown if IO error occurs
        """

    @property
    def dirty(self) -> jpype.JBoolean:
        ...

    @property
    def keyField(self) -> Field:
        ...

    @property
    def string(self) -> java.lang.String:
        ...

    @property
    def binaryData(self) -> jpype.JArray[jpype.JByte]:
        ...

    @property
    def intValue(self) -> jpype.JInt:
        ...

    @property
    def shortValue(self) -> jpype.JShort:
        ...

    @property
    def booleanValue(self) -> jpype.JBoolean:
        ...

    @property
    def columnCount(self) -> jpype.JInt:
        ...

    @property
    def fieldValue(self) -> Field:
        ...

    @property
    def longValue(self) -> jpype.JLong:
        ...

    @property
    def key(self) -> jpype.JLong:
        ...

    @key.setter
    def key(self, value: jpype.JLong):
        ...

    @property
    def byteValue(self) -> jpype.JByte:
        ...


@typing.type_check_only
class FixedKeyFixedRecNode(FixedKeyRecordNode):
    """
    ``FixedKeyFixedRecNode`` is an implementation of a BTree leaf node
    which utilizes fixed-length key values and stores fixed-length records.
     
    
    This type of node has the following layout within a single DataBuffer 
    (field size in bytes, where 'L' is the fixed length of the fixed-length 
    key as specified by key type in associated Schema):
     
    | NodeType(1) | KeyCount(4) | PrevLeafId(4) | NextLeafId(4) | Key0(L) | Rec0 | ...
     
    | KeyN(L) | RecN |
    """

    class_: typing.ClassVar[java.lang.Class]

    def getRecordOffset(self, index: typing.Union[jpype.JInt, int]) -> int:
        """
        Get the record offset within the buffer
        
        :param jpype.JInt or int index: key index
        :return: record offset
        :rtype: int
        """

    @property
    def recordOffset(self) -> jpype.JInt:
        ...


class TestSpeed(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def main(args: jpype.JArray[java.lang.String]):
        ...


class DBLongIterator(java.lang.Object):
    """
    ``DBLongIterator`` provides the ability to iterate over
    long values within a table.
    """

    class_: typing.ClassVar[java.lang.Class]

    def delete(self) -> bool:
        """
        Delete the last record(s) associated with the last value
        read via the next or previous methods.
        
        :return: true if record(s) was successfully deleted.
        :rtype: bool
        :raises IOException: thrown if an IO error occurs.
        """

    def hasNext(self) -> bool:
        """
        Return true if a value is available in the forward direction.
        
        :raises IOException: thrown if an IO error occurs
        """

    def hasPrevious(self) -> bool:
        """
        Return true if a value is available in the reverse direction
        
        :raises IOException: thrown if an IO error occurs
        """

    def next(self) -> int:
        """
        Return the next long value.
        
        :raises IOException: thrown if an IO error occurs
        :raises java.util.NoSuchElementException: if the next value is not available.
        """

    def previous(self) -> int:
        """
        Return the previous long value.
        
        :raises IOException: thrown if an IO error occurs
        :raises java.util.NoSuchElementException: if the previous value is not available.
        """


@typing.type_check_only
class DBParms(java.lang.Object):
    """
    ``DBParms`` manages 4-byte integer parameters associated with a database 
    and stored as the first buffer (ID 0) in the buffer file.  The maximum number of 
    parameters is determined by the .
    """

    class_: typing.ClassVar[java.lang.Class]



__all__ = ["VarRecNode", "LongKeyRecordNode", "Buffer", "ByteField", "FieldKeyRecordNode", "KeyToRecordIterator", "DBInitializer", "BinaryDataBuffer", "DBBuffer", "DBChangeSet", "FixedKeyNode", "IndexField", "TerminatedTransactionException", "IllegalFieldAccessException", "LongKeyInteriorNode", "VarKeyRecordNode", "IndexTable", "TranslatedRecordIterator", "FixedKeyVarRecNode", "BinaryCodedField", "BooleanField", "ObjectStorageAdapterDB", "InteriorNode", "DBFileListener", "FieldKeyInteriorNode", "ChainedBuffer", "NodeMgr", "FixedKeyInteriorNode", "FixedField10", "RecordTranslator", "Table", "DatabaseUtils", "LongKeyNode", "Field", "ShortField", "BinaryField", "LegacyIndexField", "FixedField", "NoTransactionException", "ConvertedRecordIterator", "StringField", "JavaBinarySearcher", "FixedKeyRecordNode", "RecordIterator", "TableRecord", "Transaction", "LongField", "Schema", "Database", "DBFieldIterator", "TableStatistics", "JavaBinarySearcher2", "DBListener", "IntField", "VarKeyInteriorNode", "FieldKeyNode", "DBHandle", "DBRollbackException", "VarKeyNode", "RecordNode", "SparseRecord", "MasterTable", "FixedRecNode", "FieldIndexTable", "PrimitiveField", "BTreeNode", "DBRecord", "FixedKeyFixedRecNode", "TestSpeed", "DBLongIterator", "DBParms"]
