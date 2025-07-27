from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.plugin.exceptionhandlers.gcc.structures.ehFrame
import ghidra.app.plugin.exceptionhandlers.gcc.structures.gccexcepttable
import ghidra.app.services
import ghidra.app.util.bin
import ghidra.program.model.address
import ghidra.program.model.data
import ghidra.program.model.listing
import ghidra.program.model.mem
import ghidra.util.task
import java.lang # type: ignore


class GccExceptionAnalyzer(ghidra.app.services.AbstractAnalyzer):
    """
    An analyzer for locating and marking up the GCC exception handling information.
    """

    @typing.type_check_only
    class TypeInfo(java.lang.Object):
        """
        A TypeInfo associates the address of a type information record with the filter value that
        is used to handle a catch action for that type.
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, typeInfoAddress: ghidra.program.model.address.Address, actionFilter: typing.Union[jpype.JInt, int]):
            ...

        def getActionFilter(self) -> int:
            ...

        def getTypeInfoAddress(self) -> ghidra.program.model.address.Address:
            ...

        @property
        def typeInfoAddress(self) -> ghidra.program.model.address.Address:
            ...

        @property
        def actionFilter(self) -> jpype.JInt:
            ...


    class_: typing.ClassVar[java.lang.Class]
    NAME: typing.Final = "GCC Exception Handlers"
    DESCRIPTION: typing.Final = "Locates and annotates exception-handling infrastructure installed by the GCC compiler"

    def __init__(self):
        """
        Creates an analyzer for marking up the GCC exception handling information.
        """


@typing.type_check_only
class AbstractDwarfEHDecoder(DwarfEHDecoder):
    """
    Extended by each of the various Dwarf exception handling decoders. Provides basic types and 
    methods for maintaining and retrieving information specific to that decoder.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, mode: DwarfEHDataApplicationMode, isIndirect: typing.Union[jpype.JBoolean, bool]):
        ...

    def decode(self, context: DwarfDecodeContext) -> int:
        """
        Get the DWARF-encoded integer value as stored by the context
        
        :param DwarfDecodeContext context: Stores program location and decode parameters
        :return: the integer value
        :rtype: int
        :raises MemoryAccessException: if the data can't be read
        """

    def decodeAddress(self, context: DwarfDecodeContext) -> ghidra.program.model.address.Address:
        """
        Get the DWARF-encoded address value as stored by the context
        
        :param DwarfDecodeContext context: Stores program location and decode parameters
        :return: the address
        :rtype: ghidra.program.model.address.Address
        :raises MemoryAccessException: if the data can't be read
        """

    def doDecode(self, context: DwarfDecodeContext) -> int:
        """
        Decode an integer value according to parameters stored in the ``context`` object.
         
        
        Implementations should duplicate the result of the call to doDecode in 
        :meth:`DwarfDecodeContext.setDecodedValue(Object, int) <DwarfDecodeContext.setDecodedValue>`, as well as the underlying length of
        the data item that was decoded.
        
        :param DwarfDecodeContext context: Stores program location and decode parameters
        :return: the integer value
        :rtype: int
        :raises MemoryAccessException: if the data can't be read
        """


class DwarfDecodeContext(java.lang.Object):
    """
    Organizational class to record vital data used by a DwarfEHDecoder.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, readAddr: ghidra.program.model.address.Address):
        """
        Constructs a Dwarf decode context.
        
        :param ghidra.program.model.listing.Program program: the program containing the encoded data
        :param ghidra.program.model.address.Address readAddr: the address of the encoded data
        """

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, readAddr: ghidra.program.model.address.Address, ehBlock: ghidra.program.model.mem.MemoryBlock):
        """
        Constructs a Dwarf decode context.
        
        :param ghidra.program.model.listing.Program program: the program containing the encoded data
        :param ghidra.program.model.address.Address readAddr: the address of the encoded data
        :param ghidra.program.model.mem.MemoryBlock ehBlock: the exception handling memory block
        """

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, readAddr: ghidra.program.model.address.Address, entryPoint: ghidra.program.model.address.Address):
        """
        Constructs a Dwarf decode context.
        
        :param ghidra.program.model.listing.Program program: the program containing the encoded data
        :param ghidra.program.model.address.Address readAddr: the address of the encoded data
        :param ghidra.program.model.address.Address entryPoint: the associated function's entry point
        """

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, readAddr: ghidra.program.model.address.Address, function: ghidra.program.model.listing.Function):
        """
        Constructs a Dwarf decode context.
        
        :param ghidra.program.model.listing.Program program: the program containing the encoded data
        :param ghidra.program.model.address.Address readAddr: the address of the encoded data
        :param ghidra.program.model.listing.Function function: the associated function
        """

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, readAddr: ghidra.program.model.address.Address, ehBlock: ghidra.program.model.mem.MemoryBlock, entryPoint: ghidra.program.model.address.Address):
        """
        Constructs a Dwarf decode context.
        
        :param ghidra.program.model.listing.Program program: the program containing the encoded data
        :param ghidra.program.model.address.Address readAddr: the address of the encoded data
        :param ghidra.program.model.mem.MemoryBlock ehBlock: the exception handling memory block
        :param ghidra.program.model.address.Address entryPoint: the associated function's entry point
        """

    @typing.overload
    def __init__(self, buffer: ghidra.program.model.mem.MemBuffer, length: typing.Union[jpype.JInt, int]):
        """
        Constructs a Dwarf decode context.
        
        :param ghidra.program.model.mem.MemBuffer buffer: the memory buffer which provides the program and address of the encoded data
        :param jpype.JInt or int length: the length of the encoded data
        """

    @typing.overload
    def __init__(self, buf: ghidra.program.model.mem.MemBuffer, length: typing.Union[jpype.JInt, int], ehBlock: ghidra.program.model.mem.MemoryBlock, entryPoint: ghidra.program.model.address.Address):
        """
        Constructs a Dwarf decode context.
        
        :param ghidra.program.model.mem.MemBuffer buf: the memory buffer which provides the program and address of the encoded data
        :param jpype.JInt or int length: the length of the encoded data
        :param ghidra.program.model.mem.MemoryBlock ehBlock: the exception handling memory block
        :param ghidra.program.model.address.Address entryPoint: the function entry point
        """

    def getAddress(self) -> ghidra.program.model.address.Address:
        """
        Gets the min address of the encoded data.
        
        :return: the address
        :rtype: ghidra.program.model.address.Address
        """

    def getDecodedValue(self) -> java.lang.Object:
        """
        Gets the decoded value that is at the address.
        
        :return: the decoded value
        :rtype: java.lang.Object
        """

    def getEhBlock(self) -> ghidra.program.model.mem.MemoryBlock:
        """
        Gets the exception handling memory block with this dwarf encoded data.
        
        :return: the memory block
        :rtype: ghidra.program.model.mem.MemoryBlock
        """

    def getEncodedLength(self) -> int:
        """
        Gets the length of the encoded data that is at the address.
        
        :return: the encoded data's length
        :rtype: int
        """

    def getFunctionEntryPoint(self) -> ghidra.program.model.address.Address:
        """
        Gets the associated function's entry point.
        
        :return: the entry point address
        :rtype: ghidra.program.model.address.Address
        """

    def getProgram(self) -> ghidra.program.model.listing.Program:
        """
        Gets the program containing the encoded data.
        
        :return: the program
        :rtype: ghidra.program.model.listing.Program
        """

    def setDecodedValue(self, value: java.lang.Object, encodedLength: typing.Union[jpype.JInt, int]):
        """
        Set the value and value-length after decode
        
        :param java.lang.Object value: The integer-value having been decoded
        :param jpype.JInt or int encodedLength: The length of the encoded integer-value
        """

    @property
    def encodedLength(self) -> jpype.JInt:
        ...

    @property
    def decodedValue(self) -> java.lang.Object:
        ...

    @property
    def address(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def ehBlock(self) -> ghidra.program.model.mem.MemoryBlock:
        ...

    @property
    def program(self) -> ghidra.program.model.listing.Program:
        ...

    @property
    def functionEntryPoint(self) -> ghidra.program.model.address.Address:
        ...


class DwarfEHDataDecodeFormat(java.lang.Enum[DwarfEHDataDecodeFormat]):
    """
    Exception handling data decoding formats.
    See the `Linux Standard Base DWARF extensions specification <https://refspecs.linuxfoundation.org/LSB_5.0.0/LSB-Core-generic/LSB-Core-generic/dwarfext.html>`_ for details.
    """

    class_: typing.ClassVar[java.lang.Class]
    DW_EH_PE_absptr: typing.Final[DwarfEHDataDecodeFormat]
    DW_EH_PE_uleb128: typing.Final[DwarfEHDataDecodeFormat]
    DW_EH_PE_udata2: typing.Final[DwarfEHDataDecodeFormat]
    DW_EH_PE_udata4: typing.Final[DwarfEHDataDecodeFormat]
    DW_EH_PE_udata8: typing.Final[DwarfEHDataDecodeFormat]
    DW_EH_PE_signed: typing.Final[DwarfEHDataDecodeFormat]
    DW_EH_PE_sleb128: typing.Final[DwarfEHDataDecodeFormat]
    DW_EH_PE_sdata2: typing.Final[DwarfEHDataDecodeFormat]
    DW_EH_PE_sdata4: typing.Final[DwarfEHDataDecodeFormat]
    DW_EH_PE_sdata8: typing.Final[DwarfEHDataDecodeFormat]
    DW_EH_PE_omit: typing.Final[DwarfEHDataDecodeFormat]

    def getCode(self) -> int:
        """
        Get the code for this decode format.
        
        :return: the identifier code
        :rtype: int
        """

    @staticmethod
    @typing.overload
    def valueOf(name: typing.Union[java.lang.String, str]) -> DwarfEHDataDecodeFormat:
        ...

    @staticmethod
    @typing.overload
    def valueOf(code: typing.Union[jpype.JInt, int]) -> DwarfEHDataDecodeFormat:
        """
        Gets the exception handling decode format for the indicated code.
        
        :param jpype.JInt or int code: the code
        :return: the decode format
        :rtype: DwarfEHDataDecodeFormat
        """

    @staticmethod
    def values() -> jpype.JArray[DwarfEHDataDecodeFormat]:
        ...

    @property
    def code(self) -> jpype.JInt:
        ...


class DwarfEHDataApplicationMode(java.lang.Enum[DwarfEHDataApplicationMode]):
    """
    An application mode for encoded exception handling data.
    See the `Linux Standard Base DWARF extensions specification <http://refspecs.freestandards.org/LSB_3.0.0/LSB-Core-generic/LSB-Core-generic/dwarfext.html>`_ for details.
    """

    class_: typing.ClassVar[java.lang.Class]
    DW_EH_PE_absptr: typing.Final[DwarfEHDataApplicationMode]
    DW_EH_PE_pcrel: typing.Final[DwarfEHDataApplicationMode]
    DW_EH_PE_texrel: typing.Final[DwarfEHDataApplicationMode]
    DW_EH_PE_datarel: typing.Final[DwarfEHDataApplicationMode]
    DW_EH_PE_funcrel: typing.Final[DwarfEHDataApplicationMode]
    DW_EH_PE_aligned: typing.Final[DwarfEHDataApplicationMode]
    DW_EH_PE_indirect: typing.Final[DwarfEHDataApplicationMode]
    DW_EH_PE_omit: typing.Final[DwarfEHDataApplicationMode]

    @staticmethod
    @typing.overload
    def valueOf(name: typing.Union[java.lang.String, str]) -> DwarfEHDataApplicationMode:
        ...

    @staticmethod
    @typing.overload
    def valueOf(code: typing.Union[jpype.JInt, int]) -> DwarfEHDataApplicationMode:
        """
        Determines the data application mode for the indicated code.
        
        :param jpype.JInt or int code: a code that indicates a data application mode
        :return: the data application mode or null if the code isn't valid
        :rtype: DwarfEHDataApplicationMode
        """

    @staticmethod
    def values() -> jpype.JArray[DwarfEHDataApplicationMode]:
        ...


class GccAnalysisUtils(java.lang.Object):
    """
    Utility methods for use by the gcc exception handling analysis.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def readByte(program: ghidra.program.model.listing.Program, addr: ghidra.program.model.address.Address) -> int:
        """
        Reads a byte from the program's memory at the indicated address.
        
        :param ghidra.program.model.listing.Program program: the program containing the byte to read
        :param ghidra.program.model.address.Address addr: the address to start reading
        :return: the byte
        :rtype: int
        :raises MemoryAccessException: if the byte can't be read.
        """

    @staticmethod
    def readBytes(program: ghidra.program.model.listing.Program, addr: ghidra.program.model.address.Address, buffer: jpype.JArray[jpype.JByte]):
        """
        Reads buffer.length number of bytes from the program's memory starting at the indicated address.
        
        :param ghidra.program.model.listing.Program program: the program containing the bytes to read
        :param ghidra.program.model.address.Address addr: the address to start reading
        :param jpype.JArray[jpype.JByte] buffer: the array to save the bytes that were read.
        :raises MemoryAccessException: if the expected number of bytes can't be read.
        """

    @staticmethod
    def readDWord(program: ghidra.program.model.listing.Program, addr: ghidra.program.model.address.Address) -> int:
        """
        Reads a double word from the program's memory starting at the indicated address.
        
        :param ghidra.program.model.listing.Program program: the program containing the bytes to read
        :param ghidra.program.model.address.Address addr: the address to start reading
        :return: the double word
        :rtype: int
        :raises MemoryAccessException: if 4 bytes can't be read.
        """

    @staticmethod
    def readQWord(program: ghidra.program.model.listing.Program, addr: ghidra.program.model.address.Address) -> int:
        """
        Reads a quad word from the program's memory starting at the indicated address.
        
        :param ghidra.program.model.listing.Program program: the program containing the bytes to read
        :param ghidra.program.model.address.Address addr: the address to start reading
        :return: the quad word
        :rtype: int
        :raises MemoryAccessException: if 8 bytes can't be read.
        """

    @staticmethod
    def readSLEB128Info(program: ghidra.program.model.listing.Program, addr: ghidra.program.model.address.Address) -> ghidra.app.util.bin.LEB128Info:
        """
        Reads an signed little endian base 128 integer from memory.
        
        :param ghidra.program.model.listing.Program program: the program with memory to be read.
        :param ghidra.program.model.address.Address addr: the address in memory to begin reading the signed LEB128.
        :return: :obj:`LEB128Info` (value + metadata)
        :rtype: ghidra.app.util.bin.LEB128Info
        """

    @staticmethod
    def readULEB128Info(program: ghidra.program.model.listing.Program, addr: ghidra.program.model.address.Address) -> ghidra.app.util.bin.LEB128Info:
        """
        Reads an unsigned little endian base 128 integer from memory.
        
        :param ghidra.program.model.listing.Program program: the program with memory to be read.
        :param ghidra.program.model.address.Address addr: the address in memory to begin reading the unsigned LEB128.
        :return: :obj:`LEB128Info` (value + metadata)
        :rtype: ghidra.app.util.bin.LEB128Info
        """

    @staticmethod
    def readWord(program: ghidra.program.model.listing.Program, addr: ghidra.program.model.address.Address) -> int:
        """
        Reads a word from the program's memory starting at the indicated address.
        
        :param ghidra.program.model.listing.Program program: the program containing the bytes to read
        :param ghidra.program.model.address.Address addr: the address to start reading
        :return: the word
        :rtype: int
        :raises MemoryAccessException: if 2 bytes can't be read.
        """


class DwarfEHDecoder(java.lang.Object):
    """
    Decodes a sequence of program bytes to Ghidra addressing types.
    """

    class_: typing.ClassVar[java.lang.Class]

    def decode(self, context: DwarfDecodeContext) -> int:
        """
        Decodes an integer value which is indicated by the context.
        
        :param DwarfDecodeContext context: Stores program location and decode parameters
        :return: the value
        :rtype: int
        :raises MemoryAccessException: if the data can't be read
        """

    def decodeAddress(self, context: DwarfDecodeContext) -> ghidra.program.model.address.Address:
        """
        Decodes the address which is indicated by the context.
        
        :param DwarfDecodeContext context: Stores program location and decode parameters
        :return: the address
        :rtype: ghidra.program.model.address.Address
        :raises MemoryAccessException: if the data can't be read
        """

    def getDataApplicationMode(self) -> DwarfEHDataApplicationMode:
        """
        Gets the data application mode.
        
        :return: the data application mode
        :rtype: DwarfEHDataApplicationMode
        """

    def getDataFormat(self) -> DwarfEHDataDecodeFormat:
        """
        Gets the exception handling data decoding format.
        
        :return: the data decoding format
        :rtype: DwarfEHDataDecodeFormat
        """

    def getDataType(self, program: ghidra.program.model.listing.Program) -> ghidra.program.model.data.DataType:
        """
        Gets this decoder's encoded data type.
        
        :param ghidra.program.model.listing.Program program: the program containing the data to be decoded.
        :return: the data type.
        :rtype: ghidra.program.model.data.DataType
        """

    def getDecodeSize(self, program: ghidra.program.model.listing.Program) -> int:
        """
        Gets the size of the encoded data.
        
        :param ghidra.program.model.listing.Program program: the program containing the data to be decoded.
        :return: the size of the encoded data
        :rtype: int
        """

    def isSigned(self) -> bool:
        """
        Whether or not this decoder is for decoding signed or unsigned data.
        
        :return: true if the decoder is for signed data. false for unsigned
        :rtype: bool
        """

    @property
    def dataApplicationMode(self) -> DwarfEHDataApplicationMode:
        ...

    @property
    def dataFormat(self) -> DwarfEHDataDecodeFormat:
        ...

    @property
    def dataType(self) -> ghidra.program.model.data.DataType:
        ...

    @property
    def signed(self) -> jpype.JBoolean:
        ...

    @property
    def decodeSize(self) -> jpype.JInt:
        ...


class GccAnalysisClass(java.lang.Object):
    """
    An abstract class that can be extended by other classes that perform part of the gcc analysis.
    It provides some basic data types and methods for use by the extending class.
    """

    class_: typing.ClassVar[java.lang.Class]
    NEWLINE: typing.Final[java.lang.String]

    def __init__(self, monitor: ghidra.util.task.TaskMonitor, program: ghidra.program.model.listing.Program):
        """
        Creates an abstract GccAnalysisClass object. Subclasses should call this constructor
        to initialize the program and task monitor.
        
        :param ghidra.util.task.TaskMonitor monitor: task monitor to see if the user has cancelled analysis.
        :param ghidra.program.model.listing.Program program: the program being analyzed.
        """


class DwarfDecoderFactory(java.lang.Object):
    """
    Generate instances of DwarfEHDecoder suitable for various pointer-encodings.
    """

    @typing.type_check_only
    class AbstractSignedDwarEHfDecoder(AbstractDwarfEHDecoder):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, mode: DwarfEHDataApplicationMode, isIndirect: typing.Union[jpype.JBoolean, bool]):
            ...


    @typing.type_check_only
    class AbstractUnsignedDwarfEHDecoder(AbstractDwarfEHDecoder):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, mode: DwarfEHDataApplicationMode, isIndirect: typing.Union[jpype.JBoolean, bool]):
            ...


    @typing.type_check_only
    class DW_EH_PE_absptr_Decoder(DwarfDecoderFactory.AbstractUnsignedDwarfEHDecoder):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, mode: DwarfEHDataApplicationMode, isIndirect: typing.Union[jpype.JBoolean, bool]):
            ...


    @typing.type_check_only
    class DW_EH_PE_omit_Decoder(DwarfDecoderFactory.AbstractUnsignedDwarfEHDecoder):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, mode: DwarfEHDataApplicationMode, isIndirect: typing.Union[jpype.JBoolean, bool]):
            ...


    @typing.type_check_only
    class DW_EH_PE_uleb128_Decoder(DwarfDecoderFactory.AbstractUnsignedDwarfEHDecoder):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, mode: DwarfEHDataApplicationMode, isIndirect: typing.Union[jpype.JBoolean, bool]):
            ...


    @typing.type_check_only
    class DW_EH_PE_udata2_Decoder(DwarfDecoderFactory.AbstractUnsignedDwarfEHDecoder):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, mode: DwarfEHDataApplicationMode, isIndirect: typing.Union[jpype.JBoolean, bool]):
            ...


    @typing.type_check_only
    class DW_EH_PE_udata4_Decoder(DwarfDecoderFactory.AbstractUnsignedDwarfEHDecoder):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, mode: DwarfEHDataApplicationMode, isIndirect: typing.Union[jpype.JBoolean, bool]):
            ...


    @typing.type_check_only
    class DW_EH_PE_udata8_Decoder(DwarfDecoderFactory.AbstractUnsignedDwarfEHDecoder):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, mode: DwarfEHDataApplicationMode, isIndirect: typing.Union[jpype.JBoolean, bool]):
            ...


    @typing.type_check_only
    class DW_EH_PE_signed_Decoder(DwarfDecoderFactory.AbstractSignedDwarEHfDecoder):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, mode: DwarfEHDataApplicationMode, isIndirect: typing.Union[jpype.JBoolean, bool]):
            ...


    @typing.type_check_only
    class DW_EH_PE_sleb128_Decoder(DwarfDecoderFactory.AbstractSignedDwarEHfDecoder):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, mode: DwarfEHDataApplicationMode, isIndirect: typing.Union[jpype.JBoolean, bool]):
            ...


    @typing.type_check_only
    class DW_EH_PE_sdata2_Decoder(DwarfDecoderFactory.AbstractSignedDwarEHfDecoder):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, mode: DwarfEHDataApplicationMode, isIndirect: typing.Union[jpype.JBoolean, bool]):
            ...


    @typing.type_check_only
    class DW_EH_PE_sdata4_Decoder(DwarfDecoderFactory.AbstractSignedDwarEHfDecoder):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, mode: DwarfEHDataApplicationMode, isIndirect: typing.Union[jpype.JBoolean, bool]):
            ...


    @typing.type_check_only
    class DW_EH_PE_sdata8_Decoder(DwarfDecoderFactory.AbstractSignedDwarEHfDecoder):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, mode: DwarfEHDataApplicationMode, isIndirect: typing.Union[jpype.JBoolean, bool]):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def getDecoder(mode: typing.Union[jpype.JInt, int]) -> DwarfEHDecoder:
        """
        Get the appropriate decoder for the given 8-bit mode; mode is parsed into
        decode format, application mode, and indirection flag.
        
        :param jpype.JInt or int mode: a byte that indicates an encoding
        :return: the decoder for the indicated mode of encoding
        :rtype: DwarfEHDecoder
        
        .. seealso::
        
            | :obj:`.createDecoder(DwarfEHDataDecodeFormat, DwarfEHDataApplicationMode, boolean)`
        """


class RegionDescriptor(java.lang.Object):
    """
    RegionDescriptor holds information about a call frame.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, ehblock: ghidra.program.model.mem.MemoryBlock):
        """
        Constructor for a region descriptor.
        
        :param ghidra.program.model.mem.MemoryBlock ehblock: the exception handling memory block for the region to be described.
        """

    def getActionTable(self) -> ghidra.app.plugin.exceptionhandlers.gcc.structures.gccexcepttable.LSDAActionTable:
        """
        Gets the action table for this region's frame.
        
        :return: the action table or null if it hasn't been set for this region
        :rtype: ghidra.app.plugin.exceptionhandlers.gcc.structures.gccexcepttable.LSDAActionTable
        """

    def getCallSiteTable(self) -> ghidra.app.plugin.exceptionhandlers.gcc.structures.gccexcepttable.LSDACallSiteTable:
        """
        Gets the call site table for this region's frame.
        
        :return: the call site table
        :rtype: ghidra.app.plugin.exceptionhandlers.gcc.structures.gccexcepttable.LSDACallSiteTable
        """

    def getEHMemoryBlock(self) -> ghidra.program.model.mem.MemoryBlock:
        """
        Gets the exception handling memory block associated with this region.
        
        :return: the memory block
        :rtype: ghidra.program.model.mem.MemoryBlock
        """

    def getFrameDescriptorEntry(self) -> ghidra.app.plugin.exceptionhandlers.gcc.structures.ehFrame.FrameDescriptionEntry:
        """
        Gets the FDE associated with this region.
        
        :return: the FDE
        :rtype: ghidra.app.plugin.exceptionhandlers.gcc.structures.ehFrame.FrameDescriptionEntry
        """

    def getLSDAAddress(self, addr: ghidra.program.model.address.Address) -> ghidra.program.model.address.Address:
        """
        Gets the address of the start of the LSDA.
        
        :return: the LSDA address.
        :rtype: ghidra.program.model.address.Address
        """

    def getLSDATable(self) -> ghidra.app.plugin.exceptionhandlers.gcc.structures.gccexcepttable.LSDATable:
        """
        Gets the LSDA table for this frame region.
        
        :return: the LSDA table
        :rtype: ghidra.app.plugin.exceptionhandlers.gcc.structures.gccexcepttable.LSDATable
        """

    def getRange(self) -> ghidra.program.model.address.AddressRange:
        """
        Gets the address range of the IP (instructions) for this region.
        
        :return: the instruction addresses
        :rtype: ghidra.program.model.address.AddressRange
        """

    def getRangeSize(self) -> int:
        """
        Gets the size of the address range for the IP.
        
        :return: the IP address range size
        :rtype: int
        """

    def getRangeStart(self) -> ghidra.program.model.address.Address:
        """
        Gets the start (minimum address) of the IP range for this region.
        
        :return: the IP range start address
        :rtype: ghidra.program.model.address.Address
        """

    def getTypeTable(self) -> ghidra.app.plugin.exceptionhandlers.gcc.structures.gccexcepttable.LSDATypeTable:
        """
        Gets the type table for this region's frame.
        
        :return: the LSDA type table or null if it hasn't been set for this region
        :rtype: ghidra.app.plugin.exceptionhandlers.gcc.structures.gccexcepttable.LSDATypeTable
        """

    def setFrameDescriptorEntry(self, frameDescriptionEntry: ghidra.app.plugin.exceptionhandlers.gcc.structures.ehFrame.FrameDescriptionEntry):
        """
        Sets the FDE associated with the region.
        
        :param ghidra.app.plugin.exceptionhandlers.gcc.structures.ehFrame.FrameDescriptionEntry frameDescriptionEntry: the FDE
        """

    def setIPRange(self, range: ghidra.program.model.address.AddressRange):
        """
        Sets the address range of the IP (instructions) for this region.
        
        :param ghidra.program.model.address.AddressRange range: the address range to associate with this region.
        """

    def setLSDAAddress(self, addr: ghidra.program.model.address.Address):
        """
        Sets the address of the start of the LSDA.
        
        :param ghidra.program.model.address.Address addr: the LSDA address.
        """

    def setLSDATable(self, lsdaTable: ghidra.app.plugin.exceptionhandlers.gcc.structures.gccexcepttable.LSDATable):
        """
        Sets the LSDA table for this frame region.
        
        :param ghidra.app.plugin.exceptionhandlers.gcc.structures.gccexcepttable.LSDATable lsdaTable: the LSDA table
        """

    @property
    def rangeStart(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def frameDescriptorEntry(self) -> ghidra.app.plugin.exceptionhandlers.gcc.structures.ehFrame.FrameDescriptionEntry:
        ...

    @frameDescriptorEntry.setter
    def frameDescriptorEntry(self, value: ghidra.app.plugin.exceptionhandlers.gcc.structures.ehFrame.FrameDescriptionEntry):
        ...

    @property
    def typeTable(self) -> ghidra.app.plugin.exceptionhandlers.gcc.structures.gccexcepttable.LSDATypeTable:
        ...

    @property
    def lSDAAddress(self) -> ghidra.program.model.address.Address:
        ...

    @lSDAAddress.setter
    def lSDAAddress(self, value: ghidra.program.model.address.Address):
        ...

    @property
    def range(self) -> ghidra.program.model.address.AddressRange:
        ...

    @property
    def lSDATable(self) -> ghidra.app.plugin.exceptionhandlers.gcc.structures.gccexcepttable.LSDATable:
        ...

    @lSDATable.setter
    def lSDATable(self, value: ghidra.app.plugin.exceptionhandlers.gcc.structures.gccexcepttable.LSDATable):
        ...

    @property
    def actionTable(self) -> ghidra.app.plugin.exceptionhandlers.gcc.structures.gccexcepttable.LSDAActionTable:
        ...

    @property
    def rangeSize(self) -> jpype.JLong:
        ...

    @property
    def callSiteTable(self) -> ghidra.app.plugin.exceptionhandlers.gcc.structures.gccexcepttable.LSDACallSiteTable:
        ...

    @property
    def eHMemoryBlock(self) -> ghidra.program.model.mem.MemoryBlock:
        ...



__all__ = ["GccExceptionAnalyzer", "AbstractDwarfEHDecoder", "DwarfDecodeContext", "DwarfEHDataDecodeFormat", "DwarfEHDataApplicationMode", "GccAnalysisUtils", "DwarfEHDecoder", "GccAnalysisClass", "DwarfDecoderFactory", "RegionDescriptor"]
