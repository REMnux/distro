from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.plugin.exceptionhandlers.gcc
import ghidra.program.model.address
import ghidra.program.model.listing
import ghidra.util.task
import java.lang # type: ignore
import java.util # type: ignore


class LSDACallSiteTable(ghidra.app.plugin.exceptionhandlers.gcc.GccAnalysisClass):
    """
    Defines the specific program regions that may throw an exception within the 
    context of the LSDA.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, monitor: ghidra.util.task.TaskMonitor, program: ghidra.program.model.listing.Program, region: ghidra.app.plugin.exceptionhandlers.gcc.RegionDescriptor):
        """
        Constructor for a call site table.
         
        Note: The ``create(Address)`` method must be called after constructing an 
        LSDACallSiteTable to associate it with an address before any of its "get..." methods are called.
        
        :param ghidra.util.task.TaskMonitor monitor: task monitor to see if the user has cancelled analysis.
        :param ghidra.program.model.listing.Program program: the program containing the call site table.
        :param ghidra.app.plugin.exceptionhandlers.gcc.RegionDescriptor region: the region of the program associated with the call site table.
        """

    def create(self, addr: ghidra.program.model.address.Address):
        """
        Create a LSDA Call Site Table from the bytes at ``addr``.
         
        Note: This method must get called before any of the "get..." methods.
        
        :param ghidra.program.model.address.Address addr: the start (minimum address) of this call site table.
        :raises MemoryAccessException: if memory couldn't be accessed for the call site table
        """

    def getCallSiteRecords(self) -> java.util.List[LSDACallSiteRecord]:
        """
        Gets all of the call site records in this table.
        
        :return: the call site records in this table or empty if no address has been established for 
        this table.
        :rtype: java.util.List[LSDACallSiteRecord]
        """

    @property
    def callSiteRecords(self) -> java.util.List[LSDACallSiteRecord]:
        ...


class LSDAActionTable(java.lang.Object):
    """
    Defines the follow-on behavior of how to handle an exception in the context
    of the exceptions' C++ type.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, monitor: ghidra.util.task.TaskMonitor, program: ghidra.program.model.listing.Program, region: ghidra.app.plugin.exceptionhandlers.gcc.RegionDescriptor):
        """
        Constructor for an action table.
         
        Note: The ``create(Address)`` method must be called after constructing an 
        LSDAActionTable to associate it with an address before any of its "get..." methods are called.
        
        :param ghidra.util.task.TaskMonitor monitor: task monitor to see if the user has cancelled analysis.
        :param ghidra.program.model.listing.Program program: the program containing the action table.
        :param ghidra.app.plugin.exceptionhandlers.gcc.RegionDescriptor region: the region or section of the program containing the action table.
        """

    def create(self, address: ghidra.program.model.address.Address, maxAddress: ghidra.program.model.address.Address):
        """
        Create an LSDA Action Table from the bytes at ``address``.
         
        Note: This method must get called before any of the "get..." methods.
        
        :param ghidra.program.model.address.Address address: the start (minimum address) of this action table.
        :param ghidra.program.model.address.Address maxAddress: the end (maximum address) of this action table.
        :raises MemoryAccessException:
        """

    def getActionRecord(self, actionIndex: typing.Union[jpype.JInt, int]) -> LSDAActionRecord:
        """
        Gets the action record from the table by its index.
        
        :param jpype.JInt or int actionIndex: indicates which action record (0 based) to get from the table.
        :return: the action record or null if the index is invalid or an address hasn't been 
        established for this table yet.
        :rtype: LSDAActionRecord
        """

    def getActionRecordAtOffset(self, actionOffset: typing.Union[jpype.JInt, int]) -> LSDAActionRecord:
        """
        Gets the action record from the table for the indicated offset.
        
        :param jpype.JInt or int actionOffset: the byte offset into the table for the desired record
        :return: the action record for the specified offset or null
        :rtype: LSDAActionRecord
        """

    def getActionRecords(self) -> java.util.List[LSDAActionRecord]:
        """
        Gets all of the action records in this action table.
        
        :return: the action records in this table or empty if no address has been established for 
        this table.
        :rtype: java.util.List[LSDAActionRecord]
        """

    @property
    def actionRecord(self) -> LSDAActionRecord:
        ...

    @property
    def actionRecords(self) -> java.util.List[LSDAActionRecord]:
        ...

    @property
    def actionRecordAtOffset(self) -> LSDAActionRecord:
        ...


class LSDATypeTable(ghidra.app.plugin.exceptionhandlers.gcc.GccAnalysisClass):
    """
    Stores addresses of __type_info structures for thrown values. Used by the Unwind routines
    to determine if a given catch block appropriately handles a given exception-of-type.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, monitor: ghidra.util.task.TaskMonitor, program: ghidra.program.model.listing.Program, region: ghidra.app.plugin.exceptionhandlers.gcc.RegionDescriptor):
        """
        Constructor for a table of references to types that are associated with catch actions.
         
        Note: The ``create(Address, Address)`` method must be called after constructing 
        an LSDATypeTable to associate it with an address before any of its "get..." methods 
        are called.
        
        :param ghidra.util.task.TaskMonitor monitor: task monitor to see if the user has cancelled analysis.
        :param ghidra.program.model.listing.Program program: the program containing the type table.
        :param ghidra.app.plugin.exceptionhandlers.gcc.RegionDescriptor region: the region of the program associated with this type table.
        """

    def create(self, bottom: ghidra.program.model.address.Address, top: ghidra.program.model.address.Address):
        """
        Create a LSDA Type Table from the bytes between ``bottom`` and ``top``. 
        This table is built from bottom-to-top.
         
        Note: This method must get called before any of the "get..." methods.
        
        :param ghidra.program.model.address.Address bottom: the bottom address of the type table
        :param ghidra.program.model.address.Address top: the top address of the type table
        """

    def getNextAddress(self) -> ghidra.program.model.address.Address:
        """
        Gets the address after this type table.
        
        :return: the next address after this type table or null if this type table hasn't been 
        created at any address yet.
        :rtype: ghidra.program.model.address.Address
        """

    def getTypeInfoAddress(self, index: typing.Union[jpype.JInt, int]) -> ghidra.program.model.address.Address:
        """
        Gets the address of the type information from the reference record at the specified index in 
        the table.
        
        :param jpype.JInt or int index: the index (1-based) of the type info table record.
        :return: the address of the type info.
        :rtype: ghidra.program.model.address.Address
        """

    @property
    def typeInfoAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def nextAddress(self) -> ghidra.program.model.address.Address:
        ...


class LSDACallSiteRecord(ghidra.app.plugin.exceptionhandlers.gcc.GccAnalysisClass):
    """
    Defines the bounds of a try-catch region.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, monitor: ghidra.util.task.TaskMonitor, program: ghidra.program.model.listing.Program, region: ghidra.app.plugin.exceptionhandlers.gcc.RegionDescriptor):
        """
        Constructor for a call site record.
         
        Note: The ``create(Address)`` method must be called after constructing an 
        LSDACallSiteRecord to associate it with an address before any of its "get..." methods are 
        called.
        
        :param ghidra.util.task.TaskMonitor monitor: task monitor to see if the user has cancelled analysis.
        :param ghidra.program.model.listing.Program program: the program containing the call site record.
        :param ghidra.app.plugin.exceptionhandlers.gcc.RegionDescriptor region: the region of the program associated with the call site record.
        """

    def create(self, addr: ghidra.program.model.address.Address, decoder: ghidra.app.plugin.exceptionhandlers.gcc.DwarfEHDecoder):
        """
        Creates data for a call site record at the indicated address and creates a comment to 
        identify it as a call site record.
         
        Note: This method must get called before any of the "get..." methods.
        
        :param ghidra.program.model.address.Address addr: the start (minimum address) of this call site record.
        :param ghidra.app.plugin.exceptionhandlers.gcc.DwarfEHDecoder decoder: decodes dwarf encoded information within the LSDA
        :raises MemoryAccessException: if memory couldn't be accessed for the call site record
        """

    def getActionOffset(self) -> int:
        """
        Get the offset into the action table for the first action record to be caught.
        
        :return: the offset into the action table
        :rtype: int
        """

    def getCallSite(self) -> ghidra.program.model.address.AddressRange:
        """
        Get the call site addresses which make up the ``try``.
        
        :return: the address range of the call site
        :rtype: ghidra.program.model.address.AddressRange
        """

    def getLandingPad(self) -> ghidra.program.model.address.Address:
        """
        Get the landing pad address which indicates the ``catch`` for this call site.
        
        :return: the landing pad address of the catch.
        :rtype: ghidra.program.model.address.Address
        """

    def getLandingPadOffset(self) -> int:
        """
        Gets the offset of the landing pad address from the landing pad start.
        
        :return: the landing pad offset
        :rtype: int
        """

    @property
    def callSite(self) -> ghidra.program.model.address.AddressRange:
        ...

    @property
    def landingPadOffset(self) -> jpype.JLong:
        ...

    @property
    def landingPad(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def actionOffset(self) -> jpype.JInt:
        ...


class LSDAActionRecord(ghidra.app.plugin.exceptionhandlers.gcc.GccAnalysisClass):
    """
    A record that associates the type info with a catch action.
    """

    class_: typing.ClassVar[java.lang.Class]
    NO_ACTION: typing.Final = 0

    def __init__(self, monitor: ghidra.util.task.TaskMonitor, program: ghidra.program.model.listing.Program, region: ghidra.app.plugin.exceptionhandlers.gcc.RegionDescriptor, lsdaActionTable: LSDAActionTable):
        """
        Constructor for an action record.
         
        Note: The ``create(Address)`` method must be called after constructing an 
        LSDAActionRecord to associate it with an address before any of its "get..." methods are called.
        
        :param ghidra.util.task.TaskMonitor monitor: task monitor to see if the user has cancelled analysis.
        :param ghidra.program.model.listing.Program program: the program containing the action record.
        :param ghidra.app.plugin.exceptionhandlers.gcc.RegionDescriptor region: the region of the program associated with the action record.
        :param LSDAActionTable lsdaActionTable: the action table containing the action record.
        """

    def create(self, address: ghidra.program.model.address.Address):
        """
        Creates data for an action record at the indicated address and creates a comment to identify
        it as an action record.
         
        Note: This method must get called before any of the "get..." methods.
        
        :param ghidra.program.model.address.Address address: the start (minimum address) of this action record.
        :raises MemoryAccessException:
        """

    def getActionTypeFilter(self) -> int:
        """
        Gets the filter value indicating which type is associated with this action record.
        
        :return: the value for this action's type.
        :rtype: int
        """

    def getAddress(self) -> ghidra.program.model.address.Address:
        """
        Gets the base address (minimum address) indicating the start of this action record.
        
        :return: the address of this action record or null if this action record hasn't been 
        created at any address yet.
        :rtype: ghidra.program.model.address.Address
        """

    def getNextAction(self) -> LSDAActionRecord:
        """
        Gets the record for the next action that the catch should fall to if the type isn't 
        the one for this action.
        
        :return: the next action's record or null if there isn't another specific type of 
        exception for this try.
        :rtype: LSDAActionRecord
        """

    def getNextActionAddress(self) -> ghidra.program.model.address.Address:
        """
        Gets the base address of the next action record to consider in the action table.
        
        :return: the address of the next action record or null.
        :rtype: ghidra.program.model.address.Address
        """

    def getNextAddress(self) -> ghidra.program.model.address.Address:
        """
        Gets the next address indicating the address after this action record.
        
        :return: the next address after this action record or null if this action record hasn't been 
        created at any address yet.
        :rtype: ghidra.program.model.address.Address
        """

    def getSize(self) -> int:
        """
        Gets the size of the action record or 0 if this action record hasn't been created at any 
        address yet.
        
        :return: the size of the action record or 0;
        :rtype: int
        """

    @property
    def nextActionAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def address(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def size(self) -> jpype.JInt:
        ...

    @property
    def actionTypeFilter(self) -> jpype.JInt:
        ...

    @property
    def nextAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def nextAction(self) -> LSDAActionRecord:
        ...


class LSDAHeader(ghidra.app.plugin.exceptionhandlers.gcc.GccAnalysisClass):
    """
    Defines the bounds of exception unwinding support, within a function, 
    and unwind procedures.
    * lpStartAddr is the program address where support begins. This value is 
    encoded according to lpStartEncoding.
    * ttypeAddr is the location-relative program address, encoded per 
    ttypeEncoding, of the associated C++ types table (types of thrown values).
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, monitor: ghidra.util.task.TaskMonitor, program: ghidra.program.model.listing.Program, region: ghidra.app.plugin.exceptionhandlers.gcc.RegionDescriptor):
        """
        Constructor for the LSDA header which indicates encoding for the LSDA tables.
         
        Note: The ``create(Address)`` method must be called after constructing an 
        LSDAHeader to associate it with an address before any of its "get..." methods are called.
        
        :param ghidra.util.task.TaskMonitor monitor: task monitor to see if the user has cancelled analysis.
        :param ghidra.program.model.listing.Program program: the program containing this header.
        :param ghidra.app.plugin.exceptionhandlers.gcc.RegionDescriptor region: the region of the program associated with this header.
        """

    def create(self, addr: ghidra.program.model.address.Address):
        """
        Create a LSDA Header from the bytes at ``addr``.
         
        Note: This method must get called before any of the "get..." methods.
        
        :param ghidra.program.model.address.Address addr: the start (minimum address) of this LSDA header.
        :raises MemoryAccessException: if memory for the header couldn't be read.
        """

    def getBody(self) -> ghidra.program.model.address.AddressRange:
        """
        Gets the address range containing the LSDA header.
        
        :return: the address range of the header
        :rtype: ghidra.program.model.address.AddressRange
        """

    def getCallSiteTableEncoding(self) -> int:
        """
        Gets the dwarf encoding used for the call site table.
        
        :return: the encoding value
        :rtype: int
        """

    def getCallSiteTableHeaderSize(self) -> int:
        """
        Get the size of the header in the call site table.
        
        :return: the header size
        :rtype: int
        """

    def getCallSiteTableLength(self) -> int:
        """
        Gets the length of the call site table.
        
        :return: the table length
        :rtype: int
        """

    def getHeaderSize(self) -> int:
        """
        Gets the size of this LSDA header.
        
        :return: the header size
        :rtype: int
        """

    def getLPStartAddress(self) -> ghidra.program.model.address.Address:
        """
        Gets the landing pad start address.
        
        :return: the LP start address
        :rtype: ghidra.program.model.address.Address
        """

    def getLPStartEncoding(self) -> int:
        """
        Gets the indicator of the encoding used for the landing pad start.
        
        :return: the LP start encoding
        :rtype: int
        """

    def getNextAddress(self) -> ghidra.program.model.address.Address:
        """
        Gets the next address indicating the address after this LSDA header.
        
        :return: the next address after this LSDA header or null if this LSDA header hasn't been 
        created at any address yet.
        :rtype: ghidra.program.model.address.Address
        """

    def getTTypeBaseAddress(self) -> ghidra.program.model.address.Address:
        """
        Gets the base address of the type table. The base address is the last byte (maximum address) 
        of the type table. The type table is ordered in reverse.
        
        :return: the type table's base address or ``Address.NO_ADDRESS``
        :rtype: ghidra.program.model.address.Address
        """

    def getTTypeEncoding(self) -> int:
        """
        Gets the encoding used for the type table.
        
        :return: the value indicating the type table's encoding
        :rtype: int
        """

    def getTTypeOffset(self) -> int:
        """
        The offset from the type offset field to get to the base address of the type table.
        
        :return: the type table offset
        :rtype: int
        """

    def hasTypeTable(self) -> bool:
        """
        Determines if this LSDA has a type table.
        
        :return: true if there is a type table
        :rtype: bool
        """

    @property
    def lPStartEncoding(self) -> jpype.JInt:
        ...

    @property
    def headerSize(self) -> jpype.JLong:
        ...

    @property
    def lPStartAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def callSiteTableEncoding(self) -> jpype.JInt:
        ...

    @property
    def tTypeOffset(self) -> jpype.JInt:
        ...

    @property
    def tTypeBaseAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def callSiteTableLength(self) -> jpype.JInt:
        ...

    @property
    def nextAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def callSiteTableHeaderSize(self) -> jpype.JInt:
        ...

    @property
    def body(self) -> ghidra.program.model.address.AddressRange:
        ...

    @property
    def tTypeEncoding(self) -> jpype.JInt:
        ...


class LSDATable(java.lang.Object):
    """
    The Language Specific Data Area (LSDA) serves as a reference to the runtime for how to 
    respond to an exception. Each function that handles an exception (that is, has a 'catch' 
    block) has an LSDA, and each exception-prone fragment has a record within the LSDA.
    The runtime will walk up the call stack as part of the Unwind routines, asking the LSDA 
    if a function knows how to handle the thrown exception;the default handler typically 
    terminates the program. 
     
    
    Unwind uses the personality function and the LSDA -- the return value tells Unwind whether 
    the function can handle the exception or not.
     
    
    The LSDA is comprised of:
       
    * A header that describes the bounds of exception handling support and encoding
    modes for values found later in the LSDA table
    * A call site table that describes each location a 'throws' occurs and where
    a corresponding catch block resides, and the actions to take.
    * An action table, that describes what the runtime needs to do during unwind
    
     
      
    The structures modeled here are described in detail in the C++ ABI.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, monitor: ghidra.util.task.TaskMonitor, program: ghidra.program.model.listing.Program):
        """
        Constructor for an LSDA exception table.
         
        Note: The ``create(Address, DwarfEHDecoder, RegionDescriptor)`` method must be 
        called after constructing an LSDATable to associate it with an address before any of 
        its "get..." methods are called.
        
        :param ghidra.util.task.TaskMonitor monitor: task monitor to see if the user has cancelled analysis
        :param ghidra.program.model.listing.Program program: the program containing the table
        """

    def create(self, tableAddr: ghidra.program.model.address.Address, region: ghidra.app.plugin.exceptionhandlers.gcc.RegionDescriptor):
        """
        Create a LSDA Table from the bytes at ``addr``. Parses the header, call site table,
        action table, and type table.
         
        Note: This method must get called before any of the "get..." methods.
        
        :param ghidra.program.model.address.Address tableAddr: the start (minimum address) of this LSDA table.
        :param ghidra.app.plugin.exceptionhandlers.gcc.RegionDescriptor region: the region of the program associated with this table
        :raises MemoryAccessException: if memory couldn't be accessed for the LSDA table
        """

    def getActionTable(self) -> LSDAActionTable:
        """
        
        
        :return: the action table for this LSDA
        :rtype: LSDAActionTable
        """

    def getCallSiteTable(self) -> LSDACallSiteTable:
        """
        
        
        :return: the call site table for this LSDA
        :rtype: LSDACallSiteTable
        """

    def getTypeTable(self) -> LSDATypeTable:
        """
        
        
        :return: the type table for this LSDA
        :rtype: LSDATypeTable
        """

    @property
    def typeTable(self) -> LSDATypeTable:
        ...

    @property
    def actionTable(self) -> LSDAActionTable:
        ...

    @property
    def callSiteTable(self) -> LSDACallSiteTable:
        ...



__all__ = ["LSDACallSiteTable", "LSDAActionTable", "LSDATypeTable", "LSDACallSiteRecord", "LSDAActionRecord", "LSDAHeader", "LSDATable"]
