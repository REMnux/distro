from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import db
import db.util
import generic.algorithms
import ghidra.framework.data
import ghidra.program.database
import ghidra.program.database.map
import ghidra.program.model.address
import ghidra.program.model.data
import ghidra.program.model.lang
import ghidra.program.model.listing
import ghidra.program.model.mem
import ghidra.program.model.symbol
import ghidra.program.model.util
import ghidra.util
import ghidra.util.task
import java.lang # type: ignore
import java.util # type: ignore


@typing.type_check_only
class ProtoDBAdapterV1(ProtoDBAdapter):
    """
    Implements version 1 of the ProtoDBAdapter interface.
    """

    class_: typing.ClassVar[java.lang.Class]

    def createRecord(self, protoID: typing.Union[jpype.JInt, int], addr: typing.Union[jpype.JLong, int], b: jpype.JArray[jpype.JByte], inDelaySlot: typing.Union[jpype.JBoolean, bool]):
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.database.code.ProtoDBAdapter.createRecord(int, byte[])`
        """

    def deleteAll(self):
        """
        s
        
        
        .. seealso::
        
            | :obj:`ghidra.program.database.code.ProtoDBAdapter.deleteAll()`
        """

    def getKey(self) -> int:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.database.code.ProtoDBAdapter.getKey()`
        """

    def getNumRecords(self) -> int:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.database.code.ProtoDBAdapter.getNumRecords()`
        """

    def getRecord(self, protoId: typing.Union[jpype.JInt, int]) -> db.DBRecord:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.database.code.ProtoDBAdapter.getRecord(int)`
        """

    def getRecords(self) -> db.RecordIterator:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.database.code.ProtoDBAdapter.getRecords()`
        """

    def getVersion(self) -> int:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.database.code.ProtoDBAdapter.getVersion()`
        """

    @property
    def records(self) -> db.RecordIterator:
        ...

    @property
    def record(self) -> db.DBRecord:
        ...

    @property
    def numRecords(self) -> jpype.JInt:
        ...

    @property
    def version(self) -> jpype.JInt:
        ...

    @property
    def key(self) -> jpype.JLong:
        ...


@typing.type_check_only
class CommentsDBAdapter(java.lang.Object):
    """
    Adapter to access the comments table for code units. The primary key
    for the table is the address. The record contains all of the comment
    types: Pre, Post, EOL, Plate, and Repeatable.
    """

    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class CommentsDBAdapterV1(CommentsDBAdapter):
    """
    Version 1 adapter for the comments table.
    """

    class_: typing.ClassVar[java.lang.Class]


class DataFilteredCodeUnitIterator(ghidra.program.model.listing.DataIterator):
    """
    Converts a code unit iterator into a data iterator.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, it: ghidra.program.model.listing.CodeUnitIterator):
        """
        Constructs a new DataFilteredCodeUnitIterator.
        
        :param ghidra.program.model.listing.CodeUnitIterator it: the codeunit iterator to filter on.
        """

    def hasNext(self) -> bool:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.model.listing.DataIterator.hasNext()`
        """

    def next(self) -> ghidra.program.model.listing.Data:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.model.listing.DataIterator.next()`
        """

    def remove(self):
        """
        
        
        
        .. seealso::
        
            | :obj:`java.util.Iterator.remove()`
        """


class CodeManager(db.util.ErrorHandler, ghidra.program.database.ManagerDB):
    """
    Class to manage database tables for data and instructions.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, handle: db.DBHandle, addrMap: ghidra.program.database.map.AddressMap, openMode: ghidra.framework.data.OpenMode, lock: ghidra.util.Lock, monitor: ghidra.util.task.TaskMonitor):
        """
        Constructs a new CodeManager for a program.
        
        :param db.DBHandle handle: handle to database
        :param ghidra.program.database.map.AddressMap addrMap: addressMap to convert between addresses and long values.
        :param ghidra.framework.data.OpenMode openMode: either READ_ONLY, UPDATE, or UPGRADE
        :param ghidra.util.Lock lock: the program synchronization lock
        :param ghidra.util.task.TaskMonitor monitor: the task monitor use while upgrading.
        :raises VersionException: if the database is incompatible with the current schema
        :raises IOException: if a database io error occurs
        :raises CancelledException: if the user cancels the upgrade operation
        """

    def activateContextLocking(self):
        ...

    def addInstructions(self, instructionSet: ghidra.program.model.lang.InstructionSet, overwrite: typing.Union[jpype.JBoolean, bool]) -> ghidra.program.model.address.AddressSetView:
        """
        Creates a complete set of instructions.  A preliminary pass will be made checking for code 
        unit conflicts which will be marked within the instructionSet causing dependent blocks to 
        get pruned.
        
        :param ghidra.program.model.lang.InstructionSet instructionSet: the set of instructions to be added. All code unit conflicts will be
        marked within the instructionSet and associated blocks.
        :param jpype.JBoolean or bool overwrite: if true, overwrites existing code units.
        :return: the set of addresses over which instructions were actually added to the program. 
        This may differ from the InstructionSet address set if conflict errors occurred. Such 
        conflict errors will be recorded within the InstructionSet and its InstructionBlocks.
        :rtype: ghidra.program.model.address.AddressSetView
        """

    def checkContextWrite(self, start: ghidra.program.model.address.Address, end: ghidra.program.model.address.Address):
        """
        Check if any instruction intersects the specified address range.
        The specified start and end addresses must form a valid range within
        a single :obj:`AddressSpace`.
        
        :param ghidra.program.model.address.Address start: start of range
        :param ghidra.program.model.address.Address end: end of range
        :raises ContextChangeException: if there is a context register change conflict
        """

    def clearAll(self, clearContext: typing.Union[jpype.JBoolean, bool], monitor: ghidra.util.task.TaskMonitor):
        """
        Clear all code units in the program.
        
        :param jpype.JBoolean or bool clearContext: true to clear the context
        :param ghidra.util.task.TaskMonitor monitor: the task monitor
        """

    def clearCodeUnits(self, start: ghidra.program.model.address.Address, end: ghidra.program.model.address.Address, clearContext: typing.Union[jpype.JBoolean, bool], monitor: ghidra.util.task.TaskMonitor):
        """
        Remove code units, symbols, equates, and references to code units in the given range 
        (inclusive).  Comments and comment history will be retained.
        The specified start and end addresses must form a valid range within
        a single :obj:`AddressSpace`.
        
        :param ghidra.program.model.address.Address start: the start address of the range to clear
        :param ghidra.program.model.address.Address end: the end address of the range to clear
        :param jpype.JBoolean or bool clearContext: if true all context-register values will be cleared over range
        :param ghidra.util.task.TaskMonitor monitor: the task monitor
        :raises CancelledException: if cancelled
        """

    def clearComments(self, start: ghidra.program.model.address.Address, end: ghidra.program.model.address.Address):
        """
        Clears all comments in the given range (inclusive).
        The specified start and end addresses must form a valid range within
        a single :obj:`AddressSpace`.
        
        :param ghidra.program.model.address.Address start: the start address of the range to clear
        :param ghidra.program.model.address.Address end: the end address of the range to clear
        """

    def clearData(self, dataTypeIDs: java.util.Set[java.lang.Long], monitor: ghidra.util.task.TaskMonitor):
        """
        Removes any data objects that have dataTypes matching the given dataType ids.
        
        :param java.util.Set[java.lang.Long] dataTypeIDs: the set of :obj:`DataType` IDs that have been deleted.
        :param ghidra.util.task.TaskMonitor monitor: the task monitor.
        :raises CancelledException: if cancelled
        """

    def clearProperties(self, start: ghidra.program.model.address.Address, end: ghidra.program.model.address.Address, monitor: ghidra.util.task.TaskMonitor):
        """
        Clears the properties in the given range (inclusive).
        The specified start and end addresses must form a valid range within
        a single :obj:`AddressSpace`.
        
        :param ghidra.program.model.address.Address start: the start address of the range to clear
        :param ghidra.program.model.address.Address end: the end address of the range to clear
        :param ghidra.util.task.TaskMonitor monitor: the task monitor
        :raises CancelledException: if cancelled
        """

    @typing.overload
    def createCodeUnit(self, address: ghidra.program.model.address.Address, prototype: ghidra.program.model.lang.InstructionPrototype, memBuf: ghidra.program.model.mem.MemBuffer, context: ghidra.program.model.lang.ProcessorContextView, length: typing.Union[jpype.JInt, int]) -> ghidra.program.model.listing.Instruction:
        """
        Creates an instruction at the specified address.
        
        :param ghidra.program.model.address.Address address: start address of instruction
        :param ghidra.program.model.lang.InstructionPrototype prototype: instruction definition object
        :param ghidra.program.model.mem.MemBuffer memBuf: the MemBuffer to use to get the bytes from memory
        :param ghidra.program.model.lang.ProcessorContextView context: object that has the state of all the registers.
        :param jpype.JInt or int length: instruction byte-length (must be in the range 0..prototype.getLength()).
        If smaller than the prototype length it must have a value no greater than 7, otherwise
        an error will be thrown.  A value of 0 or greater-than-or-equal the prototype length
        will be ignored and not impose and override length.  The length value must be a multiple 
        of the :meth:`instruction alignment <Language.getInstructionAlignment>` .
        :return: the newly created instruction.
        :rtype: ghidra.program.model.listing.Instruction
        :raises CodeUnitInsertionException: thrown if the new Instruction would overlap and 
        existing :obj:`CodeUnit` or the specified ``length`` is unsupported.
        :raises IllegalArgumentException: if a negative ``length`` is specified.
        """

    @typing.overload
    def createCodeUnit(self, addr: ghidra.program.model.address.Address, dataType: ghidra.program.model.data.DataType, length: typing.Union[jpype.JInt, int]) -> ghidra.program.model.listing.Data:
        """
        Creates a data at the specified address.
        
        :param ghidra.program.model.address.Address addr: Starting address of code unit
        :param ghidra.program.model.data.DataType dataType: data prototype for the code unit
        :param jpype.JInt or int length: the data length
        :return: the data
        :rtype: ghidra.program.model.listing.Data
        :raises CodeUnitInsertionException: if the code unit overlaps with an existing code unit
        """

    def deleteAddressRange(self, start: ghidra.program.model.address.Address, end: ghidra.program.model.address.Address, monitor: ghidra.util.task.TaskMonitor):
        """
        Removes the block of defined bytes from the listing. All necessary checks will be made by 
        listing before this method is called, so just do the work.
        
        :param ghidra.program.model.address.Address start: the first address in the range.
        :param ghidra.program.model.address.Address end: the last address in the range.
        :param ghidra.util.task.TaskMonitor monitor: the TaskMonitor that tracks progress and is used to tell if the user cancels 
        the operation.
        :raises CancelledException: if the user cancels the operation.
        """

    def fallThroughChanged(self, fromAddr: ghidra.program.model.address.Address, newFallThroughRef: ghidra.program.model.symbol.Reference):
        """
        Callback from ReferenceManager when a new fall-through reference is set.
        
        :param ghidra.program.model.address.Address fromAddr: fall-through from location
        :param ghidra.program.model.symbol.Reference newFallThroughRef: new fallthrough reference or null if removed
        """

    def getAllComments(self, address: ghidra.program.model.address.Address) -> ghidra.program.model.listing.CodeUnitComments:
        """
        Returns all the comments at the given address.
        
        :param ghidra.program.model.address.Address address: the address to get all comments for
        :return: all the comments at the given address
        :rtype: ghidra.program.model.listing.CodeUnitComments
        """

    def getCodeUnitAfter(self, addr: ghidra.program.model.address.Address) -> ghidra.program.model.listing.CodeUnit:
        """
        Returns the next code unit whose min address is greater than the specified address.
        
        :param ghidra.program.model.address.Address addr: the address to look after
        :return: CodeUnit the code unit after the specified address, or null if a code unit does not 
        exist
        :rtype: ghidra.program.model.listing.CodeUnit
        """

    def getCodeUnitAt(self, address: ghidra.program.model.address.Address) -> ghidra.program.model.listing.CodeUnit:
        """
        Returns the code unit whose min address equals the specified address.
        
        :param ghidra.program.model.address.Address address: the min address of the code unit to return
        :return: CodeUnit the code unit at the specified address, or null if a code unit does not 
        exist
        :rtype: ghidra.program.model.listing.CodeUnit
        """

    def getCodeUnitBefore(self, address: ghidra.program.model.address.Address) -> ghidra.program.model.listing.CodeUnit:
        """
        Returns the next code unit whose min address is closest to and less than the specified 
        address.
        
        :param ghidra.program.model.address.Address address: the address to look before
        :return: CodeUnit the code unit before the specified address, or null if a code unit does not 
        exist
        :rtype: ghidra.program.model.listing.CodeUnit
        """

    def getCodeUnitContaining(self, address: ghidra.program.model.address.Address) -> ghidra.program.model.listing.CodeUnit:
        """
        Returns the code unit whose min address is less than or equal to the specified address and 
        whose max address is greater than or equal to the specified address.
        codeunit.minAddress() <= addr <= codeunit.maxAddress()
        
        :param ghidra.program.model.address.Address address: the address for which to find the code containing it.
        :return: CodeUnit the code unit containing the specified address, or null if a code unit does 
        not exist.
        :rtype: ghidra.program.model.listing.CodeUnit
        """

    @typing.overload
    def getCodeUnitIterator(self, property: typing.Union[java.lang.String, str], address: ghidra.program.model.address.Address, forward: typing.Union[jpype.JBoolean, bool]) -> ghidra.program.model.listing.CodeUnitIterator:
        """
        Get an iterator that contains the code units which have the specified property type defined. 
        Only code units at an address greater than or equal to the specified start address will be 
        returned by the iterator. If the start address is null then check the entire program.
         
        
        Standard property types are defined in the CodeUnit class.  The property types are:
                  
        * COMMENT_PROPERTY
        * INSTRUCTION_PROPERTY
        * DEFINED_DATA_PROPERTY
        
        Property types can also be user defined.
        
        :param java.lang.String or str property: the name of the user defined property type or special standard name from 
        above.
        :param ghidra.program.model.address.Address address: the address to start the iterator, or null to iterator the entire program
        :param jpype.JBoolean or bool forward: true means get iterator in the forward direction
        :return: a CodeUnitIterator that returns all code units from the indicated start address that 
        have the specified property type defined.
        :rtype: ghidra.program.model.listing.CodeUnitIterator
        """

    @typing.overload
    def getCodeUnitIterator(self, property: typing.Union[java.lang.String, str], addrSetView: ghidra.program.model.address.AddressSetView, forward: typing.Union[jpype.JBoolean, bool]) -> ghidra.program.model.listing.CodeUnitIterator:
        """
        Get an iterator that contains the code units which have the specified property type defined. 
        Only code units starting within the address set specified will be returned by the iterator.
        If the address set is null then check the entire program.
         
        
        Standard property types are defined in the CodeUnit class.  The property types are:
                  
        * REFERENCE_PROPERTY
        * INSTRUCTION_PROPERTY
        * DEFINED_DATA_PROPERTY
        
        Property types can also be user defined.
        
        :param java.lang.String or str property: the name of the property type, or this can be user defined.
        :param ghidra.program.model.address.AddressSetView addrSetView: the address set to iterate, or null to iterate over the entire program
        :param jpype.JBoolean or bool forward: true means the iterator is in the forward direction
        :return: a CodeUnitIterator that returns all code units from the indicated address set that 
        have the specified property type defined.
        :rtype: ghidra.program.model.listing.CodeUnitIterator
        """

    @typing.overload
    def getCodeUnits(self, start: ghidra.program.model.address.Address, forward: typing.Union[jpype.JBoolean, bool]) -> ghidra.program.model.listing.CodeUnitIterator:
        """
        Returns an iterator over all codeUnits in the program from the given start address to either 
        the end address or the start address, depending if the iterator is forward or not.
        
        :param ghidra.program.model.address.Address start: the starting address for the iterator.
        :param jpype.JBoolean or bool forward: if true the iterator returns all codeUnits from the given start address to 
        the end of the program, otherwise it returns all codeUnits from the given start address to 
        the start of the program.
        :return: code unit iterator
        :rtype: ghidra.program.model.listing.CodeUnitIterator
        """

    @typing.overload
    def getCodeUnits(self, set: ghidra.program.model.address.AddressSetView, forward: typing.Union[jpype.JBoolean, bool]) -> ghidra.program.model.listing.CodeUnitIterator:
        """
        Returns an iterator over all codeUnits in the given addressSet. The iterator will go from 
        the lowest address to the largest or from the largest to the lowest depending on the forward 
        parameter.
        
        :param ghidra.program.model.address.AddressSetView set: the memory address set over which code units should be iterated (required)
        :param jpype.JBoolean or bool forward: determines if the iterator goes from lowest address to highest or the other
        way around.
        :return: code unit iterator
        :rtype: ghidra.program.model.listing.CodeUnitIterator
        """

    def getComment(self, commentType: ghidra.program.model.listing.CommentType, address: ghidra.program.model.address.Address) -> str:
        """
        Get the comment for the given type at the specified address.
        
        :param ghidra.program.model.listing.CommentType commentType: :obj:`comment type <CommentType>`
        :param ghidra.program.model.address.Address address: the address of the comment.
        :return: the comment string of the appropriate type or null if no comment of that type exists 
        for this code unit
        :rtype: str
        :raises IllegalArgumentException: if type is not one of the types of comments supported
        """

    def getCommentAddressCount(self) -> int:
        """
        Returns the number of addresses that have associated comments.
        
        :return: the number of addresses that have associated comments
        :rtype: int
        """

    @typing.overload
    def getCommentAddressIterator(self, commentType: ghidra.program.model.listing.CommentType, set: ghidra.program.model.address.AddressSetView, forward: typing.Union[jpype.JBoolean, bool]) -> ghidra.program.model.address.AddressIterator:
        """
        Get a forward iterator over addresses that have comments of the given type.
        
        :param ghidra.program.model.listing.CommentType commentType: comment type defined in CodeUnit
        :param ghidra.program.model.address.AddressSetView set: address set (null for all defined memory)
        :param jpype.JBoolean or bool forward: true to iterate in the direction of increasing addresses.
        :return: address iterator
        :rtype: ghidra.program.model.address.AddressIterator
        """

    @typing.overload
    def getCommentAddressIterator(self, addrSet: ghidra.program.model.address.AddressSetView, forward: typing.Union[jpype.JBoolean, bool]) -> ghidra.program.model.address.AddressIterator:
        """
        Get an iterator over addresses that have comments of any type.
        
        :param ghidra.program.model.address.AddressSetView addrSet: address set containing the comment addresses to iterate over.
        :param jpype.JBoolean or bool forward: true to iterate in the direction of increasing addresses.
        :return: the iterator
        :rtype: ghidra.program.model.address.AddressIterator
        """

    def getCommentCodeUnitIterator(self, commentType: ghidra.program.model.listing.CommentType, set: ghidra.program.model.address.AddressSetView) -> ghidra.program.model.listing.CodeUnitIterator:
        """
        Get a forward iterator over code units that have comments of the given type.
        
        :param ghidra.program.model.listing.CommentType commentType: comment type defined in CodeUnit
        :param ghidra.program.model.address.AddressSetView set: address set (null for all defined memory)
        :return: code unit iterator
        :rtype: ghidra.program.model.listing.CodeUnitIterator
        """

    def getCommentHistory(self, addr: ghidra.program.model.address.Address, commentType: ghidra.program.model.listing.CommentType) -> jpype.JArray[ghidra.program.model.listing.CommentHistory]:
        """
        Get the comment history for the comment type at the given address
        
        :param ghidra.program.model.address.Address addr: address for the comment history
        :param ghidra.program.model.listing.CommentType commentType: comment type
        :return: zero length array if no history exists
        :rtype: jpype.JArray[ghidra.program.model.listing.CommentHistory]
        """

    @typing.overload
    def getCompositeData(self, start: ghidra.program.model.address.Address, forward: typing.Union[jpype.JBoolean, bool]) -> ghidra.program.model.listing.DataIterator:
        """
        Returns a composite data iterator beginning at the specified start address.
        
        :param ghidra.program.model.address.Address start: the address to begin iterator
        :param jpype.JBoolean or bool forward: true means get iterator in forward direction
        :return: the composite data iterator
        :rtype: ghidra.program.model.listing.DataIterator
        """

    @typing.overload
    def getCompositeData(self, addrSet: ghidra.program.model.address.AddressSetView, forward: typing.Union[jpype.JBoolean, bool]) -> ghidra.program.model.listing.DataIterator:
        """
        Returns a composite data iterator limited to the addresses in the specified address set.
        
        :param ghidra.program.model.address.AddressSetView addrSet: the address set to limit the iterator
        :param jpype.JBoolean or bool forward: determines if the iterator will go from the lowest address to the highest or 
        the other way around.
        :return: DataIterator the composite data iterator
        :rtype: ghidra.program.model.listing.DataIterator
        """

    @typing.overload
    def getData(self, start: ghidra.program.model.address.Address, forward: typing.Union[jpype.JBoolean, bool]) -> ghidra.program.model.listing.DataIterator:
        """
        Returns an iterator over all data in the program from the given start address to either the 
        end address or the start address, depending if the iterator is forward or not.
        
        :param ghidra.program.model.address.Address start: the starting address for the iterator.
        :param jpype.JBoolean or bool forward: if true the iterator returns all data from the given start address to the end 
        of the program, otherwise it returns all data from the given start address to the start of 
        the program.
        :return: the iterator
        :rtype: ghidra.program.model.listing.DataIterator
        """

    @typing.overload
    def getData(self, set: ghidra.program.model.address.AddressSetView, forward: typing.Union[jpype.JBoolean, bool]) -> ghidra.program.model.listing.DataIterator:
        """
        Returns an iterator over all data in the given addressSet. The iterator will go from the 
        lowest address to the largest or from the largest to the lowest depending on the forward 
        parameter.
        
        :param ghidra.program.model.address.AddressSetView set: restrict the returned instructions to these addresses
        :param jpype.JBoolean or bool forward: determines if the iterator goes from lowest address to highest or the other 
        way around.
        :return: the iterator
        :rtype: ghidra.program.model.listing.DataIterator
        """

    def getDataAfter(self, addr: ghidra.program.model.address.Address) -> ghidra.program.model.listing.Data:
        """
        Returns the next data whose min address is greater than the specified address.
        
        :param ghidra.program.model.address.Address addr: the address to look after
        :return: the data after the specified address, or null if a data does not exist
        :rtype: ghidra.program.model.listing.Data
        """

    def getDataAt(self, address: ghidra.program.model.address.Address) -> ghidra.program.model.listing.Data:
        """
        Returns the data whose min address equals the specified address.
        
        :param ghidra.program.model.address.Address address: the min address of the data to return
        :return: the data at the specified address, or null if data does not exist
        :rtype: ghidra.program.model.listing.Data
        """

    def getDataBefore(self, addr: ghidra.program.model.address.Address) -> ghidra.program.model.listing.Data:
        """
        Returns the next data whose min address is closest to and less than the specified address.
        
        :param ghidra.program.model.address.Address addr: the address to look before
        :return: the data before the specified address, or null if a data does not exist
        :rtype: ghidra.program.model.listing.Data
        """

    def getDataContaining(self, addr: ghidra.program.model.address.Address) -> ghidra.program.model.listing.Data:
        """
        Returns the data whose min address is less than or equal to the specified address and whose 
        max address is greater than or equal to the specified address.
        data.minAddress() <= addr <= data.maxAddress()
        
        :param ghidra.program.model.address.Address addr: the address to be contained
        :return: the data containing the specified address, or null if a data does not exist that 
        starts at that address.
        :rtype: ghidra.program.model.listing.Data
        """

    @typing.overload
    def getDefinedData(self, address: ghidra.program.model.address.Address, forward: typing.Union[jpype.JBoolean, bool]) -> ghidra.program.model.listing.DataIterator:
        """
        Returns an iterator over all defined data in the program from the given start address to 
        either the end address or the start address, depending if the iterator is forward or not.
        
        :param ghidra.program.model.address.Address address: the starting address for the iterator.
        :param jpype.JBoolean or bool forward: if true the iterator returns all defined data from the given start address to 
        the end of the program, otherwise it returns all defined data from the given start address 
        to the start of the program.
        :return: the iterator
        :rtype: ghidra.program.model.listing.DataIterator
        """

    @typing.overload
    def getDefinedData(self, set: ghidra.program.model.address.AddressSetView, forward: typing.Union[jpype.JBoolean, bool]) -> ghidra.program.model.listing.DataIterator:
        """
        Returns an iterator over all defined data in the given addressSet. The iterator will go from 
        the lowest address to the largest or from the largest to the lowest depending on the forward 
        parameter.
        
        :param ghidra.program.model.address.AddressSetView set: restrict the returned instructions to these addresses
        :param jpype.JBoolean or bool forward: determines if the iterator goes from lowest address to highest or the other 
        way around.
        :return: the iterator
        :rtype: ghidra.program.model.listing.DataIterator
        """

    def getDefinedDataAfter(self, addr: ghidra.program.model.address.Address) -> ghidra.program.model.listing.Data:
        """
        Returns the next defined data whose min address is greater than the specified address.
        
        :param ghidra.program.model.address.Address addr: the address to look after
        :return: the defined data after the specified address, null if a defined data does not exist
        :rtype: ghidra.program.model.listing.Data
        """

    def getDefinedDataAt(self, address: ghidra.program.model.address.Address) -> ghidra.program.model.listing.Data:
        """
        Returns the defined data whose min address equals the specified address.
        
        :param ghidra.program.model.address.Address address: the min address of the data defined to return
        :return: the defined data at the specified address, or null if a defined data does 
        not exist
        :rtype: ghidra.program.model.listing.Data
        """

    def getDefinedDataBefore(self, addr: ghidra.program.model.address.Address) -> ghidra.program.model.listing.Data:
        """
        Returns the next defined data whose min address is closest to and less than the specified 
        address.
        
        :param ghidra.program.model.address.Address addr: the address to look before
        :return: the defined data before the specified address, null if a defined data does not exist
        :rtype: ghidra.program.model.listing.Data
        """

    def getDefinedDataContaining(self, addr: ghidra.program.model.address.Address) -> ghidra.program.model.listing.Data:
        """
        Returns the defined data whose min address is less than or equal to the specified address 
        and whose max address is greater than or equal to the specified address.
        data.minAddress() <= addr <= data.maxAddress()
        
        :param ghidra.program.model.address.Address addr: the address to be contained
        :return: the defined data containing the address, null if a defined data does not exist
        :rtype: ghidra.program.model.listing.Data
        """

    def getFirstUndefinedData(self, set: ghidra.program.model.address.AddressSetView, monitor: ghidra.util.task.TaskMonitor) -> ghidra.program.model.listing.Data:
        """
        Returns the next undefined data whose min address falls within the address set searching in 
        the forward direction ``(e.g., 0 -> 0xfff).``
        
        :param ghidra.program.model.address.AddressSetView set: the address set to look within (required).
        :param ghidra.util.task.TaskMonitor monitor: the current monitor.
        :return: the first undefined data within the address set, or null if there is none.
        :rtype: ghidra.program.model.listing.Data
        """

    def getFirstUndefinedDataAfter(self, addr: ghidra.program.model.address.Address, monitor: ghidra.util.task.TaskMonitor) -> ghidra.program.model.listing.Data:
        """
        Returns the next undefined data whose min address is greater than the specified address.
        
        :param ghidra.program.model.address.Address addr: the address to look after
        :param ghidra.util.task.TaskMonitor monitor: the task monitor
        :return: Data the undefined data after the address, null if a undefined data does not exist
        :rtype: ghidra.program.model.listing.Data
        """

    def getFirstUndefinedDataBefore(self, addr: ghidra.program.model.address.Address, monitor: ghidra.util.task.TaskMonitor) -> ghidra.program.model.listing.Data:
        """
        Returns the next undefined data whose min address is closest to and less than the specified 
        address.
        
        :param ghidra.program.model.address.Address addr: the address to look before
        :param ghidra.util.task.TaskMonitor monitor: the task monitor
        :return: the undefined data before the address, null if a undefined data does not exist
        :rtype: ghidra.program.model.listing.Data
        """

    def getInstructionAfter(self, addr: ghidra.program.model.address.Address) -> ghidra.program.model.listing.Instruction:
        """
        Returns the next instruction whose min address is greater than the specified address.
        
        :param ghidra.program.model.address.Address addr: the address to look after
        :return: the instruction after the specified address, or null if a instruction 
        does not exist
        :rtype: ghidra.program.model.listing.Instruction
        """

    def getInstructionAt(self, address: ghidra.program.model.address.Address) -> ghidra.program.model.listing.Instruction:
        """
        Returns the instruction whose min address equals the specified address or null if the 
        address is not the beginning address of some code unit.
        
        :param ghidra.program.model.address.Address address: the min address of the instruction to return
        :return: the instruction at the specified address, or null if a instruction does not 
        exist starting at the given address.
        :rtype: ghidra.program.model.listing.Instruction
        """

    def getInstructionBefore(self, addr: ghidra.program.model.address.Address) -> ghidra.program.model.listing.Instruction:
        """
        Returns the next instruction whose min address is closest to and less than the specified 
        address.
        
        :param ghidra.program.model.address.Address addr: the address to look before
        :return: the instruction before the specified address, or null if a instruction 
        does not exist
        :rtype: ghidra.program.model.listing.Instruction
        """

    def getInstructionContaining(self, address: ghidra.program.model.address.Address, usePrototypeLength: typing.Union[jpype.JBoolean, bool]) -> ghidra.program.model.listing.Instruction:
        """
        Returns an instruction whose min address is less than or equal to the specified address and 
        whose max address is greater than or equal to the specified address.
        If ``usePrototypeLength==true``
        instruction.getMinAddress() <= addr <=   instruction.getMinAddress().add(instruction.getPrototype().getLength() - 1)
        If ``usePrototypeLength==false``
            instruction.getMinAddress() <= addr <= instruction.getMaxAddress()
        The use of the prototype length is required when guarding against memory modifications.  If
        a length-override is present only one of the entangled instructions will be returned and is
        intended to simply indicate the presence of a conflict.
        
        :param ghidra.program.model.address.Address address: the address to be contained
        :param jpype.JBoolean or bool usePrototypeLength: if actual prototype length should be considered when identifying a 
        conflict (required when checking for memory modification conflicts), otherwise code unit
        length is used.  These lengths can vary when a
        :meth:`length-override <Instruction.setLengthOverride>` is in affect for an instruction.
        :return: the instruction containing the specified address, or null if a 
        instruction does not exist
        :rtype: ghidra.program.model.listing.Instruction
        """

    @typing.overload
    def getInstructions(self, address: ghidra.program.model.address.Address, forward: typing.Union[jpype.JBoolean, bool]) -> ghidra.program.model.listing.InstructionIterator:
        """
        Returns an iterator over all instructions in the program from the given start address to 
        either the end address or the start address, depending if the iterator is forward or not.
        
        :param ghidra.program.model.address.Address address: the starting address for the iterator.
        :param jpype.JBoolean or bool forward: if true the iterator returns all instructions from the given start address to 
        the end of the program, otherwise it returns all instructions from the given start address 
        to the start of the program.
        :return: the iterator
        :rtype: ghidra.program.model.listing.InstructionIterator
        """

    @typing.overload
    def getInstructions(self, set: ghidra.program.model.address.AddressSetView, forward: typing.Union[jpype.JBoolean, bool]) -> ghidra.program.model.listing.InstructionIterator:
        """
        Returns an iterator over all instructions in the given addressSet. The iterator will go from 
        the lowest address to the largest or from the largest to the lowest depending on the forward 
        parameter.
        
        :param ghidra.program.model.address.AddressSetView set: restrict the returned instructions to these addresses
        :param jpype.JBoolean or bool forward: determines if the iterator goes from lowest address to highest or the other 
        way around.
        :return: the iterator
        :rtype: ghidra.program.model.listing.InstructionIterator
        """

    def getNumDefinedData(self) -> int:
        """
        Returns the number of defined data in the program.
        
        :return: the number of defined data in the program.
        :rtype: int
        """

    def getNumInstructions(self) -> int:
        """
        Returns the number of instructions in the program.
        
        :return: the number of instructions in the program.
        :rtype: int
        """

    def getPropertyMap(self, propertyName: typing.Union[java.lang.String, str]) -> ghidra.program.model.util.PropertyMap[typing.Any]:
        """
        Returns the property map object that is associated with the specified property name.
        
        :param java.lang.String or str propertyName: the name of the property
        :return: the property map object associated to the property name
        :rtype: ghidra.program.model.util.PropertyMap[typing.Any]
        """

    def getReferenceMgr(self) -> ghidra.program.model.symbol.ReferenceManager:
        """
        Returns the reference manager being used by this code manager.
        
        :return: ReferenceManager the reference manager being used by this code manager
        :rtype: ghidra.program.model.symbol.ReferenceManager
        """

    def getUndefinedAt(self, address: ghidra.program.model.address.Address) -> ghidra.program.model.listing.Data:
        """
        Returns the undefined data whose min address equals the specified address.
        
        :param ghidra.program.model.address.Address address: the min address of the undefined data to return
        :return: Data the undefined data at the address, null if undefined data does not exist
        :rtype: ghidra.program.model.listing.Data
        """

    def getUndefinedRanges(self, set: ghidra.program.model.address.AddressSetView, initializedMemoryOnly: typing.Union[jpype.JBoolean, bool], monitor: ghidra.util.task.TaskMonitor) -> ghidra.program.model.address.AddressSetView:
        ...

    def getUserDefinedProperties(self) -> java.util.Iterator[java.lang.String]:
        """
        Returns an iterator over all user-defined properties.
        
        :return: Iterator an iterator over all user-defined properties
        :rtype: java.util.Iterator[java.lang.String]
        """

    def invalidateCodeUnitCache(self):
        """
        Invalidates the cache for the code units.
        """

    def isUndefined(self, start: ghidra.program.model.address.Address, end: ghidra.program.model.address.Address) -> bool:
        """
        Checks if all the addresses from start to end have undefined data.
        
        :param ghidra.program.model.address.Address start: the first address in the range to check.
        :param ghidra.program.model.address.Address end: the last address in the range to check.
        :return: true if all the addresses in the range have undefined data.
        :rtype: bool
        """

    def memoryChanged(self, addr: ghidra.program.model.address.Address, end: ghidra.program.model.address.Address):
        """
        Notification that memory has changed, so clear the cache for the affected code units.
        
        :param ghidra.program.model.address.Address addr: start of change
        :param ghidra.program.model.address.Address end: end address of change
        """

    def moveAddressRange(self, fromAddr: ghidra.program.model.address.Address, toAddr: ghidra.program.model.address.Address, length: typing.Union[jpype.JLong, int], monitor: ghidra.util.task.TaskMonitor):
        """
        Move a block of code from one address to a new address.
         
        
        Updates all property managers, symbols, and references.
        
        :param ghidra.program.model.address.Address fromAddr: the first address in the range to be moved.
        :param ghidra.program.model.address.Address toAddr: the address to move to.
        :param jpype.JLong or int length: the number of addresses to move.
        :param ghidra.util.task.TaskMonitor monitor: the TaskMonitor that tracks progress and is used to tell if the user cancels 
        the operation.
        :raises CancelledException: if the user cancels the operation.
        """

    def reDisassembleAllInstructions(self, monitor: ghidra.util.task.TaskMonitor):
        """
        Complete language transformation of all instructions.  All existing prototypes will be 
        discarded and all instructions re-disassembled following flow and adjusting context as 
        needed. Instructions which fail to re-disassemble will be marked - since only one byte will 
        be skipped, such bad instruction disassembly may cause subsequent errors due to possible 
        instruction shift.
         
        
        This method is only intended for use by the ProgramDB setLanguage method which must ensure 
        that the context has been properly initialized.
        
        :param ghidra.util.task.TaskMonitor monitor: task monitor
        :raises IOException: if IO error occurs
        :raises CancelledException: if the operation is canceled.
        """

    def removeUserDefinedProperty(self, propertyName: typing.Union[java.lang.String, str]):
        """
        Removes the user-defined property with the specified property name.
        
        :param java.lang.String or str propertyName: the name of the user-defined property to remove
        """

    def replaceDataTypes(self, dataTypeReplacementMap: collections.abc.Mapping):
        ...

    def setComment(self, address: ghidra.program.model.address.Address, commentType: ghidra.program.model.listing.CommentType, comment: typing.Union[java.lang.String, str]):
        """
        Set the comment for the given comment type at the specified address.
        
        :param ghidra.program.model.address.Address address: the address of the comment.
        :param ghidra.program.model.listing.CommentType commentType: either EOL_COMMENT, PRE_COMMENT, POST_COMMENT, PLATE_COMMENT, or 
        REPEATABLE_COMMENT
        :param java.lang.String or str comment: comment to set at the address
        :raises IllegalArgumentException: if type is not one of the types of comments supported
        """

    def setProgram(self, program: ghidra.program.database.ProgramDB):
        """
        Set the program after all the managers have been created.
        
        :param ghidra.program.database.ProgramDB program: The program object that this manager belongs to.
        """

    def updateDataReferences(self, data: ghidra.program.model.listing.Data):
        """
        Update the data references on this data item. Get rid of any references first, then add in 
        any new ones.
        
        :param ghidra.program.model.listing.Data data: the data object to be updated
        """

    @property
    def instructionAfter(self) -> ghidra.program.model.listing.Instruction:
        ...

    @property
    def definedDataContaining(self) -> ghidra.program.model.listing.Data:
        ...

    @property
    def definedDataAt(self) -> ghidra.program.model.listing.Data:
        ...

    @property
    def allComments(self) -> ghidra.program.model.listing.CodeUnitComments:
        ...

    @property
    def userDefinedProperties(self) -> java.util.Iterator[java.lang.String]:
        ...

    @property
    def referenceMgr(self) -> ghidra.program.model.symbol.ReferenceManager:
        ...

    @property
    def instructionBefore(self) -> ghidra.program.model.listing.Instruction:
        ...

    @property
    def definedDataBefore(self) -> ghidra.program.model.listing.Data:
        ...

    @property
    def definedDataAfter(self) -> ghidra.program.model.listing.Data:
        ...

    @property
    def dataBefore(self) -> ghidra.program.model.listing.Data:
        ...

    @property
    def codeUnitAfter(self) -> ghidra.program.model.listing.CodeUnit:
        ...

    @property
    def propertyMap(self) -> ghidra.program.model.util.PropertyMap[typing.Any]:
        ...

    @property
    def dataAt(self) -> ghidra.program.model.listing.Data:
        ...

    @property
    def codeUnitAt(self) -> ghidra.program.model.listing.CodeUnit:
        ...

    @property
    def undefinedAt(self) -> ghidra.program.model.listing.Data:
        ...

    @property
    def instructionAt(self) -> ghidra.program.model.listing.Instruction:
        ...

    @property
    def dataContaining(self) -> ghidra.program.model.listing.Data:
        ...

    @property
    def numInstructions(self) -> jpype.JInt:
        ...

    @property
    def commentAddressCount(self) -> jpype.JLong:
        ...

    @property
    def dataAfter(self) -> ghidra.program.model.listing.Data:
        ...

    @property
    def codeUnitContaining(self) -> ghidra.program.model.listing.CodeUnit:
        ...

    @property
    def codeUnitBefore(self) -> ghidra.program.model.listing.CodeUnit:
        ...

    @property
    def numDefinedData(self) -> jpype.JInt:
        ...


@typing.type_check_only
class DataDBAdapterV0(DataDBAdapter):
    """
    Version 0 implementation for the Data table.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, handle: db.DBHandle, addrMap: ghidra.program.database.map.AddressMap, create: typing.Union[jpype.JBoolean, bool]):
        """
        Constructor
        """


@typing.type_check_only
class CommentHistoryAdapterNoTable(CommentHistoryAdapter):
    """
    Adapter needed for a read-only version of Program that is not going
    to be upgraded, and there is no comment history table in the Program.
    """

    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class InstDBAdapter(java.lang.Object):
    """
    Adapter that accesses the instruction table.
    """

    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class ProtoDBAdapterV0(ProtoDBAdapter):
    """
    Version 0 of the ProtoDBAdapter
    """

    @typing.type_check_only
    class RecordUpdateIterator(db.RecordIterator):

        class_: typing.ClassVar[java.lang.Class]

        def delete(self) -> bool:
            ...

        def hasNext(self) -> bool:
            ...

        def hasPrevious(self) -> bool:
            ...

        def next(self) -> db.DBRecord:
            ...

        def previous(self) -> db.DBRecord:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def createRecord(self, protoID: typing.Union[jpype.JInt, int], addr: typing.Union[jpype.JLong, int], b: jpype.JArray[jpype.JByte], inDelaySlot: typing.Union[jpype.JBoolean, bool]):
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.database.code.ProtoDBAdapter.createRecord(int, byte[])`
        """

    def deleteAll(self):
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.database.code.ProtoDBAdapter.deleteAll()`
        """

    def getKey(self) -> int:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.database.code.ProtoDBAdapter.getKey()`
        """

    def getNumRecords(self) -> int:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.database.code.ProtoDBAdapter.getNumRecords()`
        """

    def getRecord(self, protoId: typing.Union[jpype.JInt, int]) -> db.DBRecord:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.database.code.ProtoDBAdapter.getRecord(int)`
        """

    def getRecords(self) -> db.RecordIterator:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.database.code.ProtoDBAdapter.getRecords()`
        """

    def getVersion(self) -> int:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.database.code.ProtoDBAdapter.getVersion()`
        """

    @property
    def records(self) -> db.RecordIterator:
        ...

    @property
    def record(self) -> db.DBRecord:
        ...

    @property
    def numRecords(self) -> jpype.JInt:
        ...

    @property
    def version(self) -> jpype.JInt:
        ...

    @property
    def key(self) -> jpype.JLong:
        ...


@typing.type_check_only
class DataDB(CodeUnitDB, ghidra.program.model.listing.Data):
    """
    Database implementation for the Data interface.
    
    NOTE!! DataComponents only have a unique key within its parent Struct/Array.  This places a constraint on
    the use of the key field and getKey() method on the underlying classes CodeUnitDB and DataDB.
    The CodeUnit key should only be used for managing an object cache.  The addr field should be used within
    this class instead of the key field which represents an "index in parent" for data components which are
    cached separately.
    """

    class_: typing.ClassVar[java.lang.Class]


class StringDiff(java.lang.Object):
    """
    Container object that holds a start and end position within a string. A list of StringDiffs 
    is used to keep track of changes made to a string.
    """

    class_: typing.ClassVar[java.lang.Class]
    text: java.lang.String
    """
    String being inserted.  This can be an insert or a complete replace (the positions will both
    be -1 in a replace; pos1 will be non-negative during an insert).
    """


    @staticmethod
    def allTextReplaced(newText: typing.Union[java.lang.String, str]) -> StringDiff:
        """
        Construct a new StringDiff with pos1 and pos2 are initialized to -1
        
        :param java.lang.String or str newText: string
        :return: the new diff
        :rtype: StringDiff
        """

    @staticmethod
    def restore(text: typing.Union[java.lang.String, str], start: typing.Union[jpype.JInt, int], end: typing.Union[jpype.JInt, int]) -> StringDiff:
        ...

    @staticmethod
    def textDeleted(start: typing.Union[jpype.JInt, int], end: typing.Union[jpype.JInt, int]) -> StringDiff:
        """
        Construct a new StringDiff that indicates text was deleted from pos1 to pos2
        
        :param jpype.JInt or int start: position 1 for the diff
        :param jpype.JInt or int end: position 2 for the diff
        :return: the new diff
        :rtype: StringDiff
        """

    @staticmethod
    def textInserted(newText: typing.Union[java.lang.String, str], start: typing.Union[jpype.JInt, int]) -> StringDiff:
        """
        Construct a new StringDiff that indicates that insertData was inserted at the given position
        
        :param java.lang.String or str newText: inserted string
        :param jpype.JInt or int start: position where the text was inserted
        :return: the new diff
        :rtype: StringDiff
        """


@typing.type_check_only
class DataDBAdapter(java.lang.Object):
    """
    Adapter to access the Data table.
    """

    class_: typing.ClassVar[java.lang.Class]


class DataKeyIterator(ghidra.program.model.listing.DataIterator):
    """
    Converts a DBLongIterator into a DataIterator
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, codeMgr: CodeManager, addrMap: ghidra.program.database.map.AddressMap, it: db.DBLongIterator):
        """
        Constructs a new DataKeyIterator
        
        :param CodeManager codeMgr: the code manager
        :param ghidra.program.database.map.AddressMap addrMap: the address map to convert keys to addresses.
        :param db.DBLongIterator it: DBLongIterator
        """

    def hasNext(self) -> bool:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.model.listing.CodeUnitIterator.hasNext()`
        """

    def next(self) -> ghidra.program.model.listing.Data:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.model.listing.CodeUnitIterator.next()`
        """

    def remove(self):
        """
        
        
        
        .. seealso::
        
            | :obj:`java.util.Iterator.remove()`
        """


class DataRecordIterator(ghidra.program.model.listing.DataIterator):
    """
    Converts a record iterator into a DataIterator.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, codeMgr: CodeManager, it: db.RecordIterator, forward: typing.Union[jpype.JBoolean, bool]):
        """
        Constructs a new DataRecordIterator
        
        :param CodeManager codeMgr: the code manager
        :param db.RecordIterator it: the record iterator
        :param jpype.JBoolean or bool forward: the direction of the iterator.
        """

    def hasNext(self) -> bool:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.model.listing.CodeUnitIterator.hasNext()`
        """

    def next(self) -> ghidra.program.model.listing.Data:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.model.listing.CodeUnitIterator.next()`
        """

    def remove(self):
        """
        
        
        
        .. seealso::
        
            | :obj:`java.util.Iterator.remove()`
        """


@typing.type_check_only
class CommentsDBAdapterV0(CommentsDBAdapter):
    """
    Version 0 adapter for the comments table.
    """

    @typing.type_check_only
    class RecordIteratorAdapter(db.RecordIterator):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, handle: db.DBHandle, addrMap: ghidra.program.database.map.AddressMap):
        """
        Constructor
        """


@typing.type_check_only
class CodeUnitRecordIterator(ghidra.program.model.listing.CodeUnitIterator):
    """
    Combines an Instruction iterator and Data iterator into a code unit iterator
    """

    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class InstDBAdapterV0(InstDBAdapter):
    """
    Version 0 adapter for the instruction table.
    """

    @typing.type_check_only
    class RecordIteratorAdapter(db.RecordIterator):

        class_: typing.ClassVar[java.lang.Class]

        def delete(self) -> bool:
            """
            
            
            
            .. seealso::
            
                | :obj:`ghidra.framework.store.db.RecordIterator.delete()`
            """

        def hasNext(self) -> bool:
            """
            
            
            
            .. seealso::
            
                | :obj:`ghidra.framework.store.db.RecordIterator.hasNext()`
            """

        def hasPrevious(self) -> bool:
            """
            
            
            
            .. seealso::
            
                | :obj:`ghidra.framework.store.db.RecordIterator.hasPrevious()`
            """

        def next(self) -> db.DBRecord:
            """
            
            
            
            .. seealso::
            
                | :obj:`ghidra.framework.store.db.RecordIterator.next()`
            """

        def previous(self) -> db.DBRecord:
            """
            
            
            
            .. seealso::
            
                | :obj:`ghidra.framework.store.db.RecordIterator.previous()`
            """


    class_: typing.ClassVar[java.lang.Class]


class EmptyCodeUnitIterator(ghidra.program.model.listing.CodeUnitIterator):
    """
    CodeUnitIterator that represents an empty set of codeunits.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        """
        Constructs a new EmptyCodeUnitIterator
        """


@typing.type_check_only
class DataComponent(DataDB):
    """
    ``DataComponent`` provides Data and CodeUnit access to Struct and Array components.
    
    NOTE!! DataComponents only have a unique key within its parent Struct/Array.  This places a constraint on
    the use of the key field and getKey() method on the underlying classes CodeUnitDB and DataDB.
    The CodeUnit key should only be used for managing an object cache.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, codeMgr: CodeManager, componentCache: ghidra.program.database.DBObjectCache[DataDB], address: ghidra.program.model.address.Address, addr: typing.Union[jpype.JLong, int], parent: DataDB, component: ghidra.program.model.data.DataTypeComponent):
        """
        Constructs a new :obj:`DataComponent` for a :obj:`DataTypeComponent`.
        NOTE: a zero-length component will be forced to have a length of 1-byte.
        This can result in what would appear to be overlapping components with the same overset.
        
        :param CodeManager codeMgr: the code manager.
        :param ghidra.program.database.DBObjectCache[DataDB] componentCache: data component cache
        :param ghidra.program.model.address.Address address: the address of the data component
        :param jpype.JLong or int addr: the convert address long value
        :param DataDB parent: the DataDB object that contains this component.
        :param ghidra.program.model.data.DataTypeComponent component: the DataTypeComponent for this DataComponent.
        """


@typing.type_check_only
class CommentHistoryAdapterV0(CommentHistoryAdapter):
    """
    Adapter for Version 0 of the Comment History table
    """

    class_: typing.ClassVar[java.lang.Class]


class CodeUnitKeyIterator(ghidra.program.model.listing.CodeUnitIterator):
    """
    Converts an AddressKeyIterator into a CodeUnitIterator
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, codeMgr: CodeManager, it: ghidra.program.database.map.AddressKeyIterator, forward: typing.Union[jpype.JBoolean, bool]):
        """
        Construct a new CodeUnitKeyIterator
        
        :param CodeManager codeMgr: the code manager
        :param ghidra.program.database.map.AddressKeyIterator it: the addressKeyIterator
        :param jpype.JBoolean or bool forward: the direction to iterate.
        """


@typing.type_check_only
class PrototypeManager(java.lang.Object):
    """
    Class maintain a list of prototypes and corresponding IDs.
    NOTE: The prototype ID will be negative if the prototype is in a
    delay slot.
    """

    @typing.type_check_only
    class ProtoProcessorContext(ghidra.program.model.lang.ProcessorContext):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]


class InstructionDB(CodeUnitDB, ghidra.program.model.listing.Instruction, ghidra.program.model.lang.InstructionContext):
    """
    Database implementation for an Instruction.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, codeMgr: CodeManager, cache: ghidra.program.database.DBObjectCache[CodeUnitDB], address: ghidra.program.model.address.Address, addr: typing.Union[jpype.JLong, int], proto: ghidra.program.model.lang.InstructionPrototype, flags: typing.Union[jpype.JByte, int]):
        """
        Construct a new InstructionDB.
        
        :param CodeManager codeMgr: code manager
        :param ghidra.program.database.DBObjectCache[CodeUnitDB] cache: code unit cache
        :param ghidra.program.model.address.Address address: min address of this instruction
        :param jpype.JLong or int addr: database key
        :param ghidra.program.model.lang.InstructionPrototype proto: instruction prototype
        :param jpype.JByte or int flags: flow override flags
        """

    @staticmethod
    def checkLengthOverride(length: typing.Union[jpype.JInt, int], prototype: ghidra.program.model.lang.InstructionPrototype) -> int:
        """
        Check and revise a specified ``length`` to arrive at a suitable length-override value.
        
        :param jpype.JInt or int length: instruction byte-length (must be in the range 0..``prototype-length``).
        If smaller than the prototype length it must have a value no greater than 7, otherwise
        an error will be thrown.  A value of 0 or greater-than-or-equal the prototype length
        will be ignored and not impose and override length.  The length value must be a multiple 
        of the :meth:`instruction alignment <Language.getInstructionAlignment>` .
        :param ghidra.program.model.lang.InstructionPrototype prototype: instruction prototype
        :return: length-override value (0 = disable length-override)
        :rtype: int
        :raises CodeUnitInsertionException: thrown if the new Instruction would overlap and 
        existing :obj:`CodeUnit` or the specified ``length`` is unsupported.
        :raises java.lang.IllegalArgumentException: if a negative ``length`` is specified.
        """

    def equals(self, obj: java.lang.Object) -> bool:
        """
        Return true if obj is equal to this.
        """

    def getOriginalPrototypeContext(self, baseContextReg: ghidra.program.model.lang.Register) -> ghidra.program.model.lang.RegisterValue:
        """
        Get the original context used to establish the shared prototype
        
        :param ghidra.program.model.lang.Register baseContextReg: is a context register
        :return: prototype context value
        :rtype: ghidra.program.model.lang.RegisterValue
        """

    @property
    def originalPrototypeContext(self) -> ghidra.program.model.lang.RegisterValue:
        ...


@typing.type_check_only
class CodeUnitDB(ghidra.program.database.DatabaseObject, ghidra.program.model.listing.CodeUnit, ghidra.program.model.lang.ProcessorContext):
    """
    Database implementation of CodeUnit.
    
    NOTE!! DataComponents only have a unique key within its parent Struct/Array.  This places a constraint on
    the use of the key field and getKey() method on the underlying classes CodeUnitDB and DataDB.
    The CodeUnit key should only be used for managing an object cache.  The addr field should be used within
    this class instead of the key field.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, codeMgr: CodeManager, cache: ghidra.program.database.DBObjectCache[CodeUnitDB], cacheKey: typing.Union[jpype.JLong, int], address: ghidra.program.model.address.Address, addr: typing.Union[jpype.JLong, int], length: typing.Union[jpype.JInt, int]):
        """
        Construct a new CodeUnitDB
        
        :param CodeManager codeMgr: code manager that created this codeUnit.
        :param ghidra.program.database.DBObjectCache[CodeUnitDB] cache: CodeUnitDB cache
        :param jpype.JLong or int cacheKey: the cache key (dataComponent does not use the address)
        :param ghidra.program.model.address.Address address: min address of this code unit
        :param jpype.JLong or int addr: index for min address
        :param jpype.JInt or int length: the length of the codeunit.
        """

    def toString(self) -> str:
        """
        Returns a string that represents this code unit with default markup.
        Only the mnemonic and operands are included.
        """


class InstructionRecordIterator(ghidra.program.model.listing.InstructionIterator):
    """
    Converts a record iterator into an instruction iterator.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, codeMgr: CodeManager, it: db.RecordIterator, forward: typing.Union[jpype.JBoolean, bool]):
        """
        Constructs a new InstructionRecordIterator
        
        :param CodeManager codeMgr: the code manager
        :param db.RecordIterator it: the record iterator.
        :param jpype.JBoolean or bool forward: the direction of the iterator.
        """


@typing.type_check_only
class ProtoDBAdapter(java.lang.Object):
    """
    Database adapter interface for instruction prototypes.
    """

    class_: typing.ClassVar[java.lang.Class]

    def createRecord(self, protoID: typing.Union[jpype.JInt, int], addr: typing.Union[jpype.JLong, int], b: jpype.JArray[jpype.JByte], inDelaySlot: typing.Union[jpype.JBoolean, bool]):
        """
        Creates a new prototype record in the database.
        
        :param jpype.JInt or int protoID: the id for the new prototype.
        :param jpype.JLong or int addr: the address of the bytes for the prototype.
        :param jpype.JArray[jpype.JByte] b: the bytes use to form the prototype.
        :param jpype.JBoolean or bool inDelaySlot: true if the prototype is in a delay slot.
        :raises IOException: if a database io error occurs.
        """

    def deleteAll(self):
        """
        Deletes all prototype records from the database.
        """

    def getKey(self) -> int:
        """
        Returns the next key to use.
        
        :raises IOException: if a database io error occurs.
        """

    def getNumRecords(self) -> int:
        """
        Returns the total number of prototypes in the database.
        
        :raises IOException: if a database io error occurs.
        """

    def getRecord(self, protoId: typing.Union[jpype.JInt, int]) -> db.DBRecord:
        """
        Returns the record associated with a specific prototype ID
        
        :param jpype.JInt or int protoId: 
        :return: 
        :rtype: db.DBRecord
        """

    def getRecords(self) -> db.RecordIterator:
        """
        Returns a record iterator over all records.
        
        :raises IOException: if a database io error occurs.
        """

    def getVersion(self) -> int:
        """
        Returns the database version for this adapter.
        """

    @property
    def records(self) -> db.RecordIterator:
        ...

    @property
    def record(self) -> db.DBRecord:
        ...

    @property
    def numRecords(self) -> jpype.JInt:
        ...

    @property
    def version(self) -> jpype.JInt:
        ...

    @property
    def key(self) -> jpype.JLong:
        ...


@typing.type_check_only
class InstDBAdapterV1(InstDBAdapter):
    """
    Version 0 adapter for the instruction table.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, handle: db.DBHandle, addrMap: ghidra.program.database.map.AddressMap, create: typing.Union[jpype.JBoolean, bool]):
        """
        Constructor
        
        :param db.DBHandle handle: database handle
        """


@typing.type_check_only
class StringDiffUtils(java.lang.Object):

    @typing.type_check_only
    class Line(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, line: typing.Union[java.lang.String, str], start: typing.Union[jpype.JInt, int]):
            ...


    @typing.type_check_only
    class LineLcs(generic.algorithms.ReducingListBasedLcs[StringDiffUtils.Line]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]


class CommentTypeFilterAddressIterator(ghidra.program.model.address.AddressIterator):
    """
    Filters the given address iterator to only return addresses that have a comment of the given type
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, program: ghidra.program.model.listing.Program, it: ghidra.program.model.address.AddressIterator, commentType: ghidra.program.model.listing.CommentType):
        """
        Constructs a new CommentTypeFilterAddressIterator
        
        :param ghidra.program.model.address.AddressIterator it: an address iterator whose items are tested for the comment type.
        :param ghidra.program.model.listing.CommentType commentType: the type of comment to search for.
        """


class CommentTypeFilterIterator(ghidra.program.model.listing.CodeUnitIterator):
    """
    Filters the given codeUnit iterator to only return codeUnits that have a comment of the given type
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, it: ghidra.program.model.listing.CodeUnitIterator, commentType: ghidra.program.model.listing.CommentType):
        """
        Constructs a new CommentTypeFilterIterator
        
        :param ghidra.program.model.listing.CodeUnitIterator it: a codeunit iterator whose items are tested for the comment type.
        :param ghidra.program.model.listing.CommentType commentType: the type of comment to search for.
        """


@typing.type_check_only
class CommentHistoryAdapter(java.lang.Object):
    """
    Adapter for accessing records in the CommentHistory table.
    """

    class_: typing.ClassVar[java.lang.Class]



__all__ = ["ProtoDBAdapterV1", "CommentsDBAdapter", "CommentsDBAdapterV1", "DataFilteredCodeUnitIterator", "CodeManager", "DataDBAdapterV0", "CommentHistoryAdapterNoTable", "InstDBAdapter", "ProtoDBAdapterV0", "DataDB", "StringDiff", "DataDBAdapter", "DataKeyIterator", "DataRecordIterator", "CommentsDBAdapterV0", "CodeUnitRecordIterator", "InstDBAdapterV0", "EmptyCodeUnitIterator", "DataComponent", "CommentHistoryAdapterV0", "CodeUnitKeyIterator", "PrototypeManager", "InstructionDB", "CodeUnitDB", "InstructionRecordIterator", "ProtoDBAdapter", "InstDBAdapterV1", "StringDiffUtils", "CommentTypeFilterAddressIterator", "CommentTypeFilterIterator", "CommentHistoryAdapter"]
