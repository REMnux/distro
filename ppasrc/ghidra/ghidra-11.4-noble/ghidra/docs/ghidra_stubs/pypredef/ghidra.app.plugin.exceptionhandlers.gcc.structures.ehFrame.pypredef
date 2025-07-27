from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.plugin.exceptionhandlers.gcc
import ghidra.app.plugin.exceptionhandlers.gcc.sections
import ghidra.program.model.address
import ghidra.program.model.listing
import ghidra.util.task
import java.lang # type: ignore


class ExceptionHandlerFrameException(java.lang.Exception):
    """
    Generic Exception class for classes contained in the ehFrame package
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        Constructs a new ExceptionHandlerFrameException with the specified detail message and
        cause.
        """

    @typing.overload
    def __init__(self, message: typing.Union[java.lang.String, str], cause: java.lang.Throwable):
        """
        Constructs a new ExceptionHandlerFrameException with the specified detail message and
        cause.
        
        :param java.lang.String or str message: the detail message.
        :param java.lang.Throwable cause: the cause of this exception being thrown.
        """

    @typing.overload
    def __init__(self, message: typing.Union[java.lang.String, str]):
        """
        Constructs a new ExceptionHandlerFrameException with the specified detail message.
        
        :param java.lang.String or str message: the detail message.
        """

    @typing.overload
    def __init__(self, cause: java.lang.Throwable):
        """
        Constructs a new ExceptionHandlerFrameException with the specified cause.
        
        :param java.lang.Throwable cause: the cause of this exception being thrown.
        """


class FdeTable(java.lang.Object):
    """
    Class that builds the Frame Description Entry (FDE) Table for a Common Information Entry (CIE).
     
    
    Call Frame Instructions (taken from gcc-3.2.3-20030829/gcc/dwarf2.h
     
        DW_CFA_advance_loc = 0x40,
        DW_CFA_offset = 0x80,
        DW_CFA_restore = 0xc0,
        DW_CFA_nop = 0x00,
        DW_CFA_set_loc = 0x01,
        DW_CFA_advance_loc1 = 0x02,
        DW_CFA_advance_loc2 = 0x03,
        DW_CFA_advance_loc4 = 0x04,
        DW_CFA_offset_extended = 0x05,
        DW_CFA_restore_extended = 0x06,
        DW_CFA_undefined = 0x07,
        DW_CFA_same_value = 0x08,
        DW_CFA_register = 0x09,
        DW_CFA_remember_state = 0x0a,
        DW_CFA_restore_state = 0x0b,
        DW_CFA_def_cfa = 0x0c,
        DW_CFA_def_cfa_register = 0x0d,
        DW_CFA_def_cfa_offset = 0x0e,
    
        //DWARF 3. //
        DW_CFA_def_cfa_expression = 0x0f,
        DW_CFA_expression = 0x10,
        DW_CFA_offset_extended_sf = 0x11,
        DW_CFA_def_cfa_sf = 0x12,
        DW_CFA_def_cfa_offset_sf = 0x13,
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, monitor: ghidra.util.task.TaskMonitor, curProg: ghidra.program.model.listing.Program):
        """
        Constructor for an FDE table.
        
        :param ghidra.util.task.TaskMonitor monitor: a status monitor for indicating progress or allowing a task to be cancelled.
        :param ghidra.program.model.listing.Program curProg: the program containing the FDE table.
        """

    def create(self, addr: ghidra.program.model.address.Address, decoder: ghidra.app.plugin.exceptionhandlers.gcc.DwarfEHDecoder, fdeTableCnt: typing.Union[jpype.JLong, int]):
        """
        Creates an FDE Table at the specified Address.
        
        :param ghidra.program.model.address.Address addr: Address at which the FDE Table should be created.
        :param ghidra.app.plugin.exceptionhandlers.gcc.DwarfEHDecoder decoder: the decoder for DWARF encoded exception handling information
        :param jpype.JLong or int fdeTableCnt: the number of exception handler FDEs.
        :raises MemoryAccessException: if the needed memory can't be read.
        :raises ExceptionHandlerFrameException: if the FDE table can't be decoded.
        """


class FrameDescriptionEntry(ghidra.app.plugin.exceptionhandlers.gcc.GccAnalysisClass):
    """
    A Frame Description Entry (FDE) describes the 
    stack call frame, in particular, how to restore
    registers.
     
    
    Taken from binutils-2.14.90.0.4/bfd/elf-bfd.h
     
    struct eh_cie_fde { 
            unsigned int offset; 
            unsigned int size; 
            asection *sec;
            unsigned int new_offset; 
            unsigned char fde_encoding; 
            unsigned char *lsda_encoding; 
            unsigned char lsda_offset; 
            unsigned char cie : 1; 
            unsigned char removed : 1; 
            unsigned char make_relative : 1; 
            unsigned char make_lsda_relative : 1; 
            unsigned char per_encoding_relative : 1; 
    };
     
     
    ACTUAL: struct eh_cie_fde { 
            dword fde.length 
            dword fde.ciePointer (Offset to this FDEs CIE) 
            dword fde.pcBegin 
            dword fde.pcRange 
            dword fde.augmentationLength 
            dword fde.augmentationData 
            dword Call Frame Instructions dword 
            !!! NO IDEA !!! 
    }
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, monitor: ghidra.util.task.TaskMonitor, program: ghidra.program.model.listing.Program, cieSource: ghidra.app.plugin.exceptionhandlers.gcc.sections.CieSource):
        """
        Constructor for a frame descriptor entry.
         
        Note: The ``create(Address)`` method must be called after constructing a 
        ``FrameDescriptionEntry`` to associate it with an address before any of its 
        "get..." methods are called.
        
        :param ghidra.util.task.TaskMonitor monitor: a status monitor for tracking progress and allowing cancelling when creating
        an FDE.
        :param ghidra.program.model.listing.Program program: the program where this will create an FDE.
        :param ghidra.app.plugin.exceptionhandlers.gcc.sections.CieSource cieSource: the call frame information entry for this FDE.
        """

    def create(self, fdeBaseAddress: ghidra.program.model.address.Address) -> ghidra.app.plugin.exceptionhandlers.gcc.RegionDescriptor:
        """
        Creates a Frame Description Entry (FDE) at the address
        specified.
         
        Note: This method must get called before any of the "get..." methods.
        
        :param ghidra.program.model.address.Address fdeBaseAddress: Address where the FDE should be created.
        :return: a region descriptor which holds information about this FDE. Otherwise, null.
        :rtype: ghidra.app.plugin.exceptionhandlers.gcc.RegionDescriptor
        :raises MemoryAccessException: if memory for the FDE or its associated data can't be accessed
        :raises ExceptionHandlerFrameException: if there is an error creating the FDE information.
        """

    def getAugmentationData(self) -> jpype.JArray[jpype.JByte]:
        """
        Gets the bytes which specify the FDE field that refers to the augmentation data.
        
        :return: the FDE record's augmentation data.
        :rtype: jpype.JArray[jpype.JByte]
        """

    def getAugmentationDataAddress(self) -> ghidra.program.model.address.Address:
        """
        Get the address of the augmentation data in this FDE record.
        
        :return: the augmentation data field's address
        :rtype: ghidra.program.model.address.Address
        """

    def getAugmentationExData(self) -> jpype.JArray[jpype.JByte]:
        """
        Gets the call frame augmentation data that indicates how registers are saved and restored.
        
        :return: the augmentation data
        :rtype: jpype.JArray[jpype.JByte]
        """

    def getAugmentationExDataAddress(self) -> ghidra.program.model.address.Address:
        """
        Gets the start address for the call frame augmentation data.
        
        :return: the address of the call frame augmentation data
        :rtype: ghidra.program.model.address.Address
        """

    def getNextAddress(self) -> ghidra.program.model.address.Address:
        """
        Gets the next address in memory after this FDE record.
        
        :return: the next address after this FDE or null if at the end of the section
        :rtype: ghidra.program.model.address.Address
        """

    def getProtectionRange(self) -> ghidra.program.model.address.AddressRange:
        """
        Get the address range that contains the program instructions.
        
        :return: the address range
        :rtype: ghidra.program.model.address.AddressRange
        """

    def isEndOfFrame(self) -> bool:
        """
        Determines if this FDE encountered a zero length record, which indicates the end of 
        the frame.
        
        :return: true if we are at end of frame due to encountering a zero length record.
        :rtype: bool
        """

    def setAugmentationDataExLength(self, len: typing.Union[jpype.JInt, int]) -> int:
        """
        Sets the value this region descriptor maintains to indicate the length of the 
        augmentation data.
        
        :param jpype.JInt or int len: number of bytes that compose the augmentation data
        :return: the length of the augmentation data or -1 if it has already been set.
        :rtype: int
        """

    @property
    def augmentationExDataAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def augmentationDataAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def endOfFrame(self) -> jpype.JBoolean:
        ...

    @property
    def nextAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def augmentationExData(self) -> jpype.JArray[jpype.JByte]:
        ...

    @property
    def protectionRange(self) -> ghidra.program.model.address.AddressRange:
        ...

    @property
    def augmentationData(self) -> jpype.JArray[jpype.JByte]:
        ...


class ExceptionHandlerFrameHeader(java.lang.Object):
    """
    This class represents an Exception Handler Frame Header.
     
    struct eh_frame_hdr {
        unsigned char eh_frame_header_version
        unsigned char eh_frame_pointer_encoding
        unsigned char eh_frame_description_entry_count
        unsigned_char eh_handler_table_encoding
    }
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, monitor: ghidra.util.task.TaskMonitor, curProg: ghidra.program.model.listing.Program):
        """
        Constructor for an ExceptionHandlerFrameHeader.
        
        :param ghidra.util.task.TaskMonitor monitor: a status monitor for indicating progress or allowing a task to be cancelled.
        :param ghidra.program.model.listing.Program curProg: the program containing this eh frame header.
        """

    def addToDataTypeManager(self):
        """
        Adds the structure data type for the eh frame header to the program's data type manager.
        """

    def create(self, addr: ghidra.program.model.address.Address):
        """
        Method that creates an Exception Handler Frame Header Structure
        at the address specified by 'addr'. If addr is 'null', this method returns without creating
        the structure.
        
        :param ghidra.program.model.address.Address addr: - Address at which the Exception Handler Frame Header Structure should be created.
        :raises AddressOutOfBoundsException: if the memory needed for this frame header isn't in the program.
        :raises MemoryAccessException: if the memory needed for this frame header isn't in the program.
        """

    def getEh_FrameDescEntryCntEncoding(self) -> int:
        """
        Gets the eh frame description entry count.
        
        :return: the description entry count.
        :rtype: int
        """

    def getEh_FramePtrEncoding(self) -> int:
        """
        Gets the eh frame pointer encoding.
        
        :return: the pointer encoding.
        :rtype: int
        """

    def getEh_FrameTableEncoding(self) -> int:
        """
        Gets the eh handler table encoding.
        
        :return: the table encoding.
        :rtype: int
        """

    def getEh_FrameVersion(self) -> int:
        """
        Gets the version for this program's eh frame.
        
        :return: the version indicator.
        :rtype: int
        """

    def getLength(self) -> int:
        """
        Gets the length of the EH Frame Header.
        
        :return: the length of this frame header.
        :rtype: int
        """

    @property
    def eh_FrameVersion(self) -> jpype.JInt:
        ...

    @property
    def length(self) -> jpype.JInt:
        ...

    @property
    def eh_FramePtrEncoding(self) -> jpype.JInt:
        ...

    @property
    def eh_FrameTableEncoding(self) -> jpype.JInt:
        ...

    @property
    def eh_FrameDescEntryCntEncoding(self) -> jpype.JInt:
        ...


class DwarfCallFrameOpcodeParser(java.lang.Object):
    """
    An opcode parser for operands of a call frame instruction. 
    The operands are encoded as DWARF expressions.
     
    
    The data encodings can be found in the DWARF Debugging Information Format specification
    under Call Frame Information in the Data Representation section.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, program: ghidra.program.model.listing.Program, address: ghidra.program.model.address.Address, length: typing.Union[jpype.JInt, int]):
        """
        Constructs an opcode parser.
        
        :param ghidra.program.model.listing.Program program: the program with the bytes to parse
        :param ghidra.program.model.address.Address address: the address of the bytes to parse
        :param jpype.JInt or int length: the number of bytes to parse
        """


class Cie(ghidra.app.plugin.exceptionhandlers.gcc.GccAnalysisClass):
    """
    A Common Information Entry (CIE) holds information that is shared among many
    Frame Description Entries (FDEs). There is at least one CIE in every
    non-empty .debug_frame section.
     
    
    The structures modeled here are described in detail in the C++ ABI.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, monitor: ghidra.util.task.TaskMonitor, program: ghidra.program.model.listing.Program):
        """
        Creates a common information entry object that is not in the debug frame section.
         
        Note: The ``create(Address)`` method must be called after constructing a 
        ``Cie`` to associate it with an address before any of its "process..." methods are called.
        
        :param ghidra.util.task.TaskMonitor monitor: task monitor to see if the user has cancelled analysis.
        :param ghidra.program.model.listing.Program program: the program containing the CIE.
        """

    @typing.overload
    def __init__(self, monitor: ghidra.util.task.TaskMonitor, program: ghidra.program.model.listing.Program, isInDebugFrame: typing.Union[jpype.JBoolean, bool]):
        """
        Creates a common information entry object.
         
        Note: The ``create(Address)`` method must be called after constructing a 
        ``Cie`` to associate it with an address before any of its "process..." methods are called.
        
        :param ghidra.util.task.TaskMonitor monitor: task monitor to see if the user has cancelled analysis.
        :param ghidra.program.model.listing.Program program: the program containing the CIE.
        :param jpype.JBoolean or bool isInDebugFrame: true if this CIE is in the debug frame section
        """

    def create(self, cieAddress: ghidra.program.model.address.Address):
        """
        Creates a Common Information Entry (CIE) at ``cieAddress``. 
         
        Note: This method must get called before any of the "get..." methods.
        
        :param ghidra.program.model.address.Address cieAddress: the address where the CIE should be created.
        :raises MemoryAccessException: if memory for the CIE couldn't be read.
        :raises ExceptionHandlerFrameException: if some of the CIE information couldn't be created.
        """

    def getAddress(self) -> ghidra.program.model.address.Address:
        """
        Gets the address where this CIE is located in the program.
        
        :return: the address of this CIE.
        :rtype: ghidra.program.model.address.Address
        """

    def getAugmentationString(self) -> str:
        """
        Gets the augmentation string which indicates optional fields and how to interpret them.
        
        :return: the augmentation string.
        :rtype: str
        """

    def getCieId(self) -> int:
        """
        Gets the ID for this CIE record.
        
        :return: the CIE identifier
        :rtype: int
        """

    def getCodeAlignment(self) -> int:
        """
        Gets the value of the code alignment factor for this CIE record.
        
        :return: the code alignment factor
        :rtype: int
        """

    def getDataAlignment(self) -> int:
        """
        Gets the value of the data alignment factor for this CIE record.
        
        :return: the data alignment factor
        :rtype: int
        """

    def getFDEDecoder(self) -> ghidra.app.plugin.exceptionhandlers.gcc.DwarfEHDecoder:
        """
        Gets the decoder for the FDE that is associated with this CIE.
        
        :return: the decoder for the FDE
        :rtype: ghidra.app.plugin.exceptionhandlers.gcc.DwarfEHDecoder
        """

    def getFDEEncoding(self) -> int:
        """
        Gets the indicator for the FDE address pointer encoding.
        
        :return: the FDE address pointer encoding.
        :rtype: int
        """

    def getLSDADecoder(self) -> ghidra.app.plugin.exceptionhandlers.gcc.DwarfEHDecoder:
        """
        Gets the decoder for the LSDA that is associated with this CIE.
        
        :return: the decoder for the LSDA
        :rtype: ghidra.app.plugin.exceptionhandlers.gcc.DwarfEHDecoder
        """

    def getLSDAEncoding(self) -> int:
        """
        Gets the indicator for the LSDA pointer encoding.
        
        :return: the LSDA pointer encoding.
        :rtype: int
        """

    def getNextAddress(self) -> ghidra.program.model.address.Address:
        """
        Method that returns the address immediately following the Common Information Entry
        
        :return: Address immediately following the CIE
        :rtype: ghidra.program.model.address.Address
        """

    def getReturnAddressRegisterColumn(self) -> int:
        """
        Gets the return address register column for this CIE record.
        
        :return: the return address register column
        :rtype: int
        """

    def getSegmentSize(self) -> int:
        """
        Gets the segment size for this CIE record.
        
        :return: the segment size
        :rtype: int
        """

    def isEndOfFrame(self) -> bool:
        """
        Determines if this CIE encountered a zero length record, which indicates the end of 
        the frame.
        
        :return: true if we are at end of frame due to encountering a zero length record.
        :rtype: bool
        """

    def isInDebugFrame(self) -> bool:
        """
        Determines if this CIE is in the debug frame section.
        
        :return: true if in the debug frame section.
        :rtype: bool
        """

    @property
    def address(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def lSDAEncoding(self) -> jpype.JInt:
        ...

    @property
    def codeAlignment(self) -> jpype.JInt:
        ...

    @property
    def segmentSize(self) -> jpype.JInt:
        ...

    @property
    def augmentationString(self) -> java.lang.String:
        ...

    @property
    def nextAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def lSDADecoder(self) -> ghidra.app.plugin.exceptionhandlers.gcc.DwarfEHDecoder:
        ...

    @property
    def returnAddressRegisterColumn(self) -> jpype.JInt:
        ...

    @property
    def fDEDecoder(self) -> ghidra.app.plugin.exceptionhandlers.gcc.DwarfEHDecoder:
        ...

    @property
    def fDEEncoding(self) -> jpype.JInt:
        ...

    @property
    def endOfFrame(self) -> jpype.JBoolean:
        ...

    @property
    def inDebugFrame(self) -> jpype.JBoolean:
        ...

    @property
    def dataAlignment(self) -> jpype.JInt:
        ...

    @property
    def cieId(self) -> jpype.JInt:
        ...



__all__ = ["ExceptionHandlerFrameException", "FdeTable", "FrameDescriptionEntry", "ExceptionHandlerFrameHeader", "DwarfCallFrameOpcodeParser", "Cie"]
