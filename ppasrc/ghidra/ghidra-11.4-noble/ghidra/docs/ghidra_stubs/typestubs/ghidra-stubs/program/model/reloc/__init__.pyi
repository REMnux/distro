from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.program.model.address
import ghidra.program.model.listing
import ghidra.program.model.mem
import ghidra.util.classfinder
import ghidra.util.task
import java.lang # type: ignore
import java.util # type: ignore


class RelocationUtil(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def getRelocationHandlers() -> java.util.List[RelocationHandler]:
        ...


class RelocationResult(java.lang.Record):
    """
    :obj:`RelocationResult` provides the status and byte-length of a processed relocation during
    the :obj:`Program` load process.  Intended to be used internally by a relocation handler.  
    A positive byte-length is only required for a status of :obj:`Status.APPLIED` or 
    :obj:`Status.APPLIED_OTHER`.  Use if :obj:`Status.UNKNOWN` should be avoided and is intended
    for relocation data upgrades when actual status can not be determined.
     
    
    Singleton instances are provided for relocations which did not directly results in original
    loaded memory modification.
    """

    class_: typing.ClassVar[java.lang.Class]
    FAILURE: typing.Final[RelocationResult]
    """
    See :obj:`Status.FAILURE`
    """

    UNSUPPORTED: typing.Final[RelocationResult]
    """
    See :obj:`Status.UNSUPPORTED`
    """

    SKIPPED: typing.Final[RelocationResult]
    """
    See :obj:`Status.SKIPPED`
    """

    PARTIAL: typing.Final[RelocationResult]
    """
    See :obj:`Status.PARTIAL`
    """


    def __init__(self, status: Relocation.Status, byteLength: typing.Union[jpype.JInt, int]):
        ...

    def byteLength(self) -> int:
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def status(self) -> Relocation.Status:
        ...

    def toString(self) -> str:
        ...


class RelocationTable(java.lang.Object):
    """
    An interface for storing the relocations defined in a program.
    Table must preserve the order in which relocations are added such that
    the iterators return them in the same order.
    """

    class_: typing.ClassVar[java.lang.Class]
    RELOCATABLE_PROP_NAME: typing.Final = "Relocatable"
    """
    Name of the relocatable property in the program information property list.
    """


    @typing.overload
    def add(self, addr: ghidra.program.model.address.Address, status: Relocation.Status, type: typing.Union[jpype.JInt, int], values: jpype.JArray[jpype.JLong], bytes: jpype.JArray[jpype.JByte], symbolName: typing.Union[java.lang.String, str]) -> Relocation:
        """
        Adds a new relocation entry when the original bytes being replaced are to be specified.
        
        :param ghidra.program.model.address.Address addr: the memory address where the relocation is required
        :param Relocation.Status status: relocation status (use :obj:`Status.UNKNOWN` if not known).
        :param jpype.JInt or int type: the type of relocation to perform
        :param jpype.JArray[jpype.JLong] values: relocation-specific values which may be useful in diagnosing relocation; 
        may be null.
        :param jpype.JArray[jpype.JByte] bytes: original memory bytes affected by relocation.  A null value may be
        passed but this case is deprecated (see :meth:`add(Address, Status, int, long[], int, String) <.add>`.
        If null is specified and :meth:`Status.hasBytes() <Status.hasBytes>` is true a default number of original
        bytes will be assumed and obtained from the underlying memory :obj:`FileBytes` if possible.
        :param java.lang.String or str symbolName: the name of the symbol being relocated; may be null
        :return: the newly added relocation object
        :rtype: Relocation
        """

    @typing.overload
    def add(self, addr: ghidra.program.model.address.Address, status: Relocation.Status, type: typing.Union[jpype.JInt, int], values: jpype.JArray[jpype.JLong], byteLength: typing.Union[jpype.JInt, int], symbolName: typing.Union[java.lang.String, str]) -> Relocation:
        """
        Adds a new relocation entry when the original bytes being replaced should be determined
        from the underlying :obj:`FileBytes`.
        
        :param ghidra.program.model.address.Address addr: the memory address where the relocation is required
        :param Relocation.Status status: relocation status (use :obj:`Status.UNKNOWN` if not known).
        :param jpype.JInt or int type: the type of relocation to perform
        :param jpype.JArray[jpype.JLong] values: relocation-specific values which may be useful in diagnosing relocation; 
        may be null.
        :param jpype.JInt or int byteLength: the number of bytes affected by this relocation.  This value is only
        used with a status of :obj:`Status.UNKNOWN`, :obj:`Status.APPLIED` or 
        :obj:`Status.APPLIED_OTHER`.  Valid range is 1..8 bytes.
        :param java.lang.String or str symbolName: the name of the symbol being relocated; may be null
        :return: the newly added relocation object
        :rtype: Relocation
        """

    def getRelocationAddressAfter(self, addr: ghidra.program.model.address.Address) -> ghidra.program.model.address.Address:
        """
        Returns the next relocation address which follows the specified address.
        
        :param ghidra.program.model.address.Address addr: starting point
        :return: next relocation address after addr or null if none
        :rtype: ghidra.program.model.address.Address
        """

    @typing.overload
    def getRelocations(self, addr: ghidra.program.model.address.Address) -> java.util.List[Relocation]:
        """
        Returns the ordered list of relocations which have been defined for the specified address.
        In most cases there will be one or none, but in some cases multiple relocations may be
        applied to a single address.
        
        :param ghidra.program.model.address.Address addr: the address where the relocation(s) are defined
        :return: the ordered list of relocations which have been defined for the specified address.
        :rtype: java.util.List[Relocation]
        """

    @typing.overload
    def getRelocations(self) -> java.util.Iterator[Relocation]:
        """
        Returns an iterator over all defined relocations (in ascending address order) located 
        within the program.
        
        :return: ordered relocation iterator
        :rtype: java.util.Iterator[Relocation]
        """

    @typing.overload
    def getRelocations(self, set: ghidra.program.model.address.AddressSetView) -> java.util.Iterator[Relocation]:
        """
        Returns an iterator over all defined relocations (in ascending address order) located 
        within the program over the specified address set.
        
        :param ghidra.program.model.address.AddressSetView set: address set
        :return: ordered relocation iterator
        :rtype: java.util.Iterator[Relocation]
        """

    def getSize(self) -> int:
        """
        Returns the number of relocation in this table.
        
        :return: the number of relocation in this table
        :rtype: int
        """

    def hasRelocation(self, addr: ghidra.program.model.address.Address) -> bool:
        """
        Determine if the specified address has a relocation defined.
        
        :param ghidra.program.model.address.Address addr: memory address within program
        :return: true if relocation defined, otherwise false
        :rtype: bool
        """

    def isRelocatable(self) -> bool:
        """
        Returns true if this relocation table contains relocations for a relocatable binary.
        Some binaries may contain relocations, but not actually be relocatable. For example, ELF executables.
        
        :return: true if this relocation table contains relocations for a relocatable binary
        :rtype: bool
        """

    @property
    def relocationAddressAfter(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def size(self) -> jpype.JInt:
        ...

    @property
    def relocatable(self) -> jpype.JBoolean:
        ...

    @property
    def relocations(self) -> java.util.List[Relocation]:
        ...


class RelocationHandler(ghidra.util.classfinder.ExtensionPoint):
    """
    NOTE:  ALL RelocationHandler CLASSES MUST END IN "RelocationHandler".  If not,
    the ClassSearcher will not find them.
    """

    class_: typing.ClassVar[java.lang.Class]

    def canRelocate(self, program: ghidra.program.model.listing.Program) -> bool:
        """
        Returns true if this relocation handler can relocate the
        given program. For example, an ELF program requires
        an ELF-specific relocation handler.
        
        :param ghidra.program.model.listing.Program program: the program to relocation
        :return: true if this relocation handler can relocate the given program
        :rtype: bool
        """

    def performRelocation(self, program: ghidra.program.model.listing.Program, relocation: Relocation, monitor: ghidra.util.task.TaskMonitor):
        ...

    @typing.overload
    def relocate(self, program: ghidra.program.model.listing.Program, newImageBase: ghidra.program.model.address.Address, monitor: ghidra.util.task.TaskMonitor):
        """
        
        
        :param ghidra.program.model.listing.Program program: 
        :param ghidra.program.model.address.Address newImageBase: 
        :param ghidra.util.task.TaskMonitor monitor: 
        :raises MemoryAccessException:
        """

    @typing.overload
    def relocate(self, program: ghidra.program.model.listing.Program, block: ghidra.program.model.mem.MemoryBlock, newStartAddress: ghidra.program.model.address.Address, monitor: ghidra.util.task.TaskMonitor):
        """
        Relocates the memory block to the new start address.
        All relocations in the memory block will be fixed-up.
        
        :param ghidra.program.model.listing.Program program: 
        :param ghidra.program.model.mem.MemoryBlock block: 
        :param ghidra.program.model.address.Address newStartAddress: 
        :param ghidra.util.task.TaskMonitor monitor: 
        :raises MemoryAccessException:
        """


class Relocation(java.lang.Object):
    """
    A class to store the information needed for a single
    program relocation.
    """

    class Status(java.lang.Enum[Relocation.Status]):
        """
        Relocation status.
        """

        class_: typing.ClassVar[java.lang.Class]
        UNKNOWN: typing.Final[Relocation.Status]
        """
        Relocation status is unknown and is assumed to have modified memory bytes.
        This status is intended for relocation data upgrades when actual status can not
        be determined.
        """

        SKIPPED: typing.Final[Relocation.Status]
        """
        Relocation has been intentionally skipped and should not be treated as a failure.
        """

        UNSUPPORTED: typing.Final[Relocation.Status]
        """
        Relocation type is not supported at the time relocations were applied.
        """

        FAILURE: typing.Final[Relocation.Status]
        """
        A supported relocation fail to apply properly.  This may be the result of an unexpected
        or unsupported condition which prevented its application.
        """

        PARTIAL: typing.Final[Relocation.Status]
        """
        Relocation was processed successfully although relies on a subsequent relocation to 
        affect memory.
        """

        APPLIED: typing.Final[Relocation.Status]
        """
        Relocation was applied successfully and resulted in the modification of memory bytes.
        """

        APPLIED_OTHER: typing.Final[Relocation.Status]
        """
        Loaded memory has been altered during the load process and may, or may not, be directly
        associated with a standard relocation type.
        """


        @staticmethod
        def getStatus(value: typing.Union[jpype.JInt, int]) -> Relocation.Status:
            """
            Get the Status which corresponds to the specified value.
            
            :param jpype.JInt or int value: status value
            :return: status enum
            :rtype: Relocation.Status
            """

        def getValue(self) -> int:
            """
            Get storage value associated
            
            :return: storage value associated with status
            :rtype: int
            """

        def hasBytes(self) -> bool:
            """
            
            
            :return: true if relocation reflects original bytes that may have been modified, 
            else false.
            :rtype: bool
            """

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> Relocation.Status:
            ...

        @staticmethod
        def values() -> jpype.JArray[Relocation.Status]:
            ...

        @property
        def value(self) -> jpype.JInt:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, addr: ghidra.program.model.address.Address, status: Relocation.Status, type: typing.Union[jpype.JInt, int], values: jpype.JArray[jpype.JLong], bytes: jpype.JArray[jpype.JByte], symbolName: typing.Union[java.lang.String, str]):
        """
        Constructs a new relocation.
        
        :param ghidra.program.model.address.Address addr: the address where the relocation is required
        :param Relocation.Status status: relocation status
        :param jpype.JInt or int type: the type of relocation to perform
        :param jpype.JArray[jpype.JLong] values: the values needed when performing the relocation.  Definition of values is
        specific to loader used and relocation type.
        :param jpype.JArray[jpype.JByte] bytes: original instruction bytes affected by relocation
        :param java.lang.String or str symbolName: the name of the symbol being relocated
        """

    def getAddress(self) -> ghidra.program.model.address.Address:
        """
        Returns the address where the relocation is required.
        
        :return: the address where the relocation is required
        :rtype: ghidra.program.model.address.Address
        """

    def getBytes(self) -> jpype.JArray[jpype.JByte]:
        """
        Returns the original instruction bytes affected by applied relocation.
        
        :return: original instruction bytes affected by relocation if it was successfully applied
        (i.e., :obj:`Status.APPLIED`, :obj:`Status.APPLIED_OTHER`), otherwise null may be returned.
        :rtype: jpype.JArray[jpype.JByte]
        """

    def getLength(self) -> int:
        """
        Returns the number of original instruction bytes affected by applied relocation.
        
        :return: number of original instruction bytes affected by relocation if it was successfully applied
        (i.e., :obj:`Status.APPLIED`, :obj:`Status.APPLIED_OTHER`), otherwise null may be returned.
        :rtype: int
        """

    def getStatus(self) -> Relocation.Status:
        """
        Return the relocation's application status within the program.
        
        :return: relocation's application status within the program.
        :rtype: Relocation.Status
        """

    def getSymbolName(self) -> str:
        """
        The name of the symbol being relocated or ``null`` if there is no symbol name.
        
        :return: the name of the symbol being relocated or ``null`` if there is no symbol name.
        :rtype: str
        """

    def getType(self) -> int:
        """
        Returns the type of the relocation to perform.
        
        :return: the type of the relocation to perform
        :rtype: int
        """

    def getValues(self) -> jpype.JArray[jpype.JLong]:
        """
        Returns the value needed when performing the relocation.
        
        :return: the value needed when performing the relocation
        :rtype: jpype.JArray[jpype.JLong]
        """

    @property
    def address(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def bytes(self) -> jpype.JArray[jpype.JByte]:
        ...

    @property
    def values(self) -> jpype.JArray[jpype.JLong]:
        ...

    @property
    def length(self) -> jpype.JInt:
        ...

    @property
    def symbolName(self) -> java.lang.String:
        ...

    @property
    def type(self) -> jpype.JInt:
        ...

    @property
    def status(self) -> Relocation.Status:
        ...



__all__ = ["RelocationUtil", "RelocationResult", "RelocationTable", "RelocationHandler", "Relocation"]
