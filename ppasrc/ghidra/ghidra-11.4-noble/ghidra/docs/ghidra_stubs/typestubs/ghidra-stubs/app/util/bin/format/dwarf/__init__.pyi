from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import generic.jar
import ghidra.app.plugin.core.analysis
import ghidra.app.util.bin
import ghidra.app.util.bin.format.dwarf.attribs
import ghidra.app.util.bin.format.dwarf.expression
import ghidra.app.util.bin.format.dwarf.funcfixup
import ghidra.app.util.bin.format.dwarf.line
import ghidra.app.util.bin.format.dwarf.sectionprovider
import ghidra.app.util.importer
import ghidra.framework.options
import ghidra.program.model.address
import ghidra.program.model.data
import ghidra.program.model.lang
import ghidra.program.model.listing
import ghidra.program.model.pcode
import ghidra.program.model.symbol
import ghidra.util.datastruct
import ghidra.util.task
import java.io # type: ignore
import java.lang # type: ignore
import java.lang.reflect # type: ignore
import java.util # type: ignore
import java.util.function # type: ignore
import org.jdom # type: ignore


R = typing.TypeVar("R")
T = typing.TypeVar("T")


class DWARFEndianity(java.lang.Object):
    """
    DWARF Endianity consts from www.dwarfstd.org/doc/DWARF4.pdf
    """

    class_: typing.ClassVar[java.lang.Class]
    DW_END_default: typing.Final = 0
    DW_END_big: typing.Final = 1
    DW_END_little: typing.Final = 2
    DW_END_lo_user: typing.Final = 64
    DW_END_hi_user: typing.Final = 255

    def __init__(self):
        ...

    @staticmethod
    def getEndianity(endian: typing.Union[jpype.JLong, int], defaultisBigEndian: typing.Union[jpype.JBoolean, bool]) -> bool:
        """
        Get the endianity given a DWARFEndianity value.
        
        :param jpype.JLong or int endian: DWARFEndianity value to check
        :param jpype.JBoolean or bool defaultisBigEndian: true if by default is big endian and false otherwise
        :return: true if big endian and false if little endian
        :rtype: bool
        :raises IllegalArgumentException: if an unknown endian value is given
        """


class DWARFDataInstanceHelper(java.lang.Object):
    """
    Logic to test if a Data instance is replaceable with a data type.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, program: ghidra.program.model.listing.Program):
        ...

    def isDataTypeCompatibleWithAddress(self, dataType: ghidra.program.model.data.DataType, address: ghidra.program.model.address.Address) -> bool:
        ...

    def setAllowTruncating(self, b: typing.Union[jpype.JBoolean, bool]) -> DWARFDataInstanceHelper:
        ...


class DWARFLocation(java.lang.Object):
    """
    Represents the location of an item that is only valid for a certain range of program-counter
    locations.
     
    
    An instance that does not have a DWARFRange is considered valid for any pc.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, start: typing.Union[jpype.JLong, int], end: typing.Union[jpype.JLong, int], expr: jpype.JArray[jpype.JByte]):
        """
        Create a Location given an address range and location expression.
        
        :param jpype.JLong or int start: start address range
        :param jpype.JLong or int end: end of address range
        :param jpype.JArray[jpype.JByte] expr: bytes of a DWARFExpression
        """

    @typing.overload
    def __init__(self, addressRange: DWARFRange, expr: jpype.JArray[jpype.JByte]):
        ...

    def contains(self, addr: typing.Union[jpype.JLong, int]) -> bool:
        ...

    def evaluate(self, cu: DWARFCompilationUnit) -> ghidra.app.util.bin.format.dwarf.expression.DWARFExpressionResult:
        ...

    def getExpr(self) -> jpype.JArray[jpype.JByte]:
        ...

    def getOffset(self, pc: typing.Union[jpype.JLong, int]) -> int:
        ...

    def getRange(self) -> DWARFRange:
        ...

    def isWildcard(self) -> bool:
        ...

    @property
    def offset(self) -> jpype.JLong:
        ...

    @property
    def range(self) -> DWARFRange:
        ...

    @property
    def expr(self) -> jpype.JArray[jpype.JByte]:
        ...

    @property
    def wildcard(self) -> jpype.JBoolean:
        ...


class DWARFLengthValue(java.lang.Record):
    """
    A tuple of length (of a thing in a dwarf stream) and size of integers used in the dwarf section.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, length: typing.Union[jpype.JLong, int], intSize: typing.Union[jpype.JInt, int]):
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def intSize(self) -> int:
        ...

    def length(self) -> int:
        ...

    @staticmethod
    def read(reader: ghidra.app.util.bin.BinaryReader, defaultPointerSize: typing.Union[jpype.JInt, int]) -> DWARFLengthValue:
        """
        Read a variable-length length value from the stream.
         
        
        The length value will either occupy 4 (int32) or 12 bytes (int32 flag + int64 length) and
        as a side-effect signals the size integer values occupy.
        
        :param ghidra.app.util.bin.BinaryReader reader: :obj:`BinaryReader` stream to read from
        :param jpype.JInt or int defaultPointerSize: size in bytes of pointers in the program
        :return: new :obj:`DWARFLengthValue`, or null if the stream was just zero-padded data
        :rtype: DWARFLengthValue
        :raises IOException: if io error
        """

    def toString(self) -> str:
        ...


class DWARFAddressListHeader(DWARFIndirectTableHeader):
    """
    Header at the beginning of a address list table
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, startOffset: typing.Union[jpype.JLong, int], endOffset: typing.Union[jpype.JLong, int], firstElementOffset: typing.Union[jpype.JLong, int], addressSize: typing.Union[jpype.JInt, int], segmentSelectorSize: typing.Union[jpype.JInt, int], addrCount: typing.Union[jpype.JInt, int]):
        ...

    def getAddressSize(self) -> int:
        ...

    def getSegmentSelectorSize(self) -> int:
        ...

    @staticmethod
    def read(reader: ghidra.app.util.bin.BinaryReader, defaultIntSize: typing.Union[jpype.JInt, int]) -> DWARFAddressListHeader:
        """
        Reads a :obj:`DWARFAddressListHeader` from the stream.
        
        :param ghidra.app.util.bin.BinaryReader reader: :obj:`BinaryReader` stream
        :param jpype.JInt or int defaultIntSize: native int size for the binary
        :return: :obj:`DWARFAddressListHeader`, or null if end-of-list marker
        :rtype: DWARFAddressListHeader
        :raises IOException: if error reading
        """

    @property
    def addressSize(self) -> jpype.JInt:
        ...

    @property
    def segmentSelectorSize(self) -> jpype.JInt:
        ...


class DWARFImportOptions(java.lang.Object):
    """
    Import options exposed by the :obj:`DWARFAnalyzer`
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        """
        Create new instance
        """

    def getDefaultCC(self) -> str:
        ...

    def getMaxSourceMapEntryLength(self) -> int:
        """
        Option to control the maximum length of a source map entry.  If a longer length is calculated
        it will be replaced with 0.
        
        :return: max source map entry length
        :rtype: int
        """

    def getOptionsUpdater(self) -> ghidra.app.plugin.core.analysis.AnalysisOptionsUpdater:
        """
        See :meth:`Analyzer.getOptionsUpdater() <Analyzer.getOptionsUpdater>`
        
        :return: :obj:`AnalysisOptionsUpdater`
        :rtype: ghidra.app.plugin.core.analysis.AnalysisOptionsUpdater
        """

    def isCopyExternalDebugFileSymbols(self) -> bool:
        ...

    def isCopyRenameAnonTypes(self) -> bool:
        """
        Option to control a feature that copies anonymous types into a structure's "namespace"
        CategoryPath and giving that anonymous type a new name based on the structure's field's
        name.
        
        :return: boolean flag.
        :rtype: bool
        """

    def isCreateFuncSignatures(self) -> bool:
        """
        Option to control creating FunctionSignature datatypes for each function defintion
        found in the DWARF debug data.
        
        :return: boolean flag.
        :rtype: bool
        """

    def isElideTypedefsWithSameName(self) -> bool:
        """
        Option to control eliding typedef creation if the dest type has the same name.
        
        :return: boolean true if the DWARF importer should skip creating a typedef if its
        dest has the same name.
        :rtype: bool
        """

    def isIgnoreParamStorage(self) -> bool:
        ...

    def isImportDataTypes(self) -> bool:
        """
        Option to turn on/off the import of data types.
        
        :return: boolean true if import should import data types.
        :rtype: bool
        """

    def isImportFuncs(self) -> bool:
        """
        Option to turn on/off the import of funcs.
        
        :return: boolean true if import should import funcs.
        :rtype: bool
        """

    def isImportLocalVariables(self) -> bool:
        ...

    def isOrganizeTypesBySourceFile(self) -> bool:
        """
        Option to organize imported datatypes into sub-folders based on their source file name.
        
        :return: boolean flag
        :rtype: bool
        """

    def isOutputDIEInfo(self) -> bool:
        """
        Option to control tagging data types and functions with their DWARF DIE
        record number.
        
        :return: boolean true if the DWARF importer should tag items with their DIE record
        number.
        :rtype: bool
        """

    def isOutputInlineFuncComments(self) -> bool:
        """
        Option to control tagging inlined-functions with comments.
        
        :return: boolean flag.
        :rtype: bool
        """

    def isOutputLexicalBlockComments(self) -> bool:
        """
        Option to control tagging lexical blocks with Ghidra comments.
        
        :return: boolean flag.
        :rtype: bool
        """

    def isOutputSourceLineInfo(self) -> bool:
        """
        Option to control whether source map info from DWARF is stored in the Program.
        
        :return: ``true`` if option turned on
        :rtype: bool
        """

    def isOutputSourceLocationInfo(self) -> bool:
        """
        Option to control tagging data types and functions with their source code
        location (ie. filename : line number ) if the information is present in the DWARF record.
        
        :return: boolean true if the DWARF importer should tag items with their source code location
        info.
        :rtype: bool
        """

    def isSpecialCaseSizedBaseTypes(self) -> bool:
        """
        Option to recognize named base types that have an explicit size in the name (eg "int32_t)
        and use statically sized data types instead of compiler-dependent data types.
        
        :return: boolean true if option is turned on
        :rtype: bool
        """

    def isTryPackStructs(self) -> bool:
        """
        Option to enable packing on structures/unions created during the DWARF import.  If packing
        would change the structure's details, packing is left disabled.
        
        :return: boolean flag
        :rtype: bool
        """

    def isUseBookmarks(self) -> bool:
        ...

    def optionsChanged(self, options: ghidra.framework.options.Options):
        """
        See :meth:`Analyzer.optionsChanged(Options, ghidra.program.model.listing.Program) <Analyzer.optionsChanged>`
        
        :param ghidra.framework.options.Options options: :obj:`Options`
        """

    def registerOptions(self, options: ghidra.framework.options.Options):
        """
        See :meth:`Analyzer.registerOptions(Options, ghidra.program.model.listing.Program) <Analyzer.registerOptions>`
        
        :param ghidra.framework.options.Options options: :obj:`Options`
        """

    def setCopyExternalDebugFileSymbols(self, b: typing.Union[jpype.JBoolean, bool]):
        ...

    def setCopyRenameAnonTypes(self, b: typing.Union[jpype.JBoolean, bool]):
        """
        Option to control a feature that copies anonymous types into a structure's "namespace"
        CategoryPath and giving that anonymousfunction.getEntryPoint() type a new name based on the structure's field's
        name.
        
        :param jpype.JBoolean or bool b: boolean flag to set.
        """

    def setCreateFuncSignatures(self, createFuncSignatures: typing.Union[jpype.JBoolean, bool]):
        """
        Option to control creating FunctionSignature datatypes for each function defintion
        found in the DWARF debug data.
        
        :param jpype.JBoolean or bool createFuncSignatures: boolean flag to set.
        """

    def setDefaultCC(self, defaultCC: typing.Union[java.lang.String, str]):
        ...

    def setElideTypedefsWithSameName(self, elide_typedefs_with_same_name: typing.Union[jpype.JBoolean, bool]):
        """
        Option to control eliding typedef creation if the dest type has the same name.
        
        :param jpype.JBoolean or bool elide_typedefs_with_same_name: boolean to set
        """

    def setIgnoreParamStorage(self, ignoreParamStorage: typing.Union[jpype.JBoolean, bool]):
        ...

    def setImportDataTypes(self, importDataTypes: typing.Union[jpype.JBoolean, bool]):
        """
        Option to turn on/off the import of data types.
        
        :param jpype.JBoolean or bool importDataTypes: boolean to set
        """

    def setImportFuncs(self, output_Funcs: typing.Union[jpype.JBoolean, bool]):
        ...

    def setImportLocalVariables(self, importLocalVariables: typing.Union[jpype.JBoolean, bool]):
        ...

    def setMaxSourceMapEntryLength(self, maxLength: typing.Union[jpype.JLong, int]):
        """
        Option to control the maximum length of a source map entry.  If a longer length is calculated
        it will be replaced with 0.
        
        :param jpype.JLong or int maxLength: new max source entry length
        """

    def setOrganizeTypesBySourceFile(self, organizeTypesBySourceFile: typing.Union[jpype.JBoolean, bool]):
        """
        Option to organize imported datatypes into sub-folders based on their source file name.
        
        :param jpype.JBoolean or bool organizeTypesBySourceFile: boolean flag to set.
        """

    def setOutputDIEInfo(self, output_DWARF_die_info: typing.Union[jpype.JBoolean, bool]):
        """
        Option to control tagging data types and functions with their DWARF DIE
        record number.
        
        :param jpype.JBoolean or bool output_DWARF_die_info: boolean to set
        """

    def setOutputInlineFuncComments(self, output_InlineFunc_comments: typing.Union[jpype.JBoolean, bool]):
        ...

    def setOutputLexicalBlockComments(self, output_LexicalBlock_comments: typing.Union[jpype.JBoolean, bool]):
        """
        Option to control tagging lexical blocks with Ghidra comments.
        
        :param jpype.JBoolean or bool output_LexicalBlock_comments: boolean flag to set.
        """

    def setOutputSourceLineInfo(self, outputSourceLineInfo: typing.Union[jpype.JBoolean, bool]):
        """
        Option to control whether source map info from DWARF is stored in the Program.
        
        :param jpype.JBoolean or bool outputSourceLineInfo: true to turn option on, false to turn off
        """

    def setOutputSourceLocationInfo(self, output_DWARF_location_info: typing.Union[jpype.JBoolean, bool]):
        """
        Option to control tagging data types and functions with their source code
        location (ie. filename : line number ) if the information is present in the DWARF record.
        
        :param jpype.JBoolean or bool output_DWARF_location_info: boolean to set
        """

    def setSpecialCaseSizedBaseTypes(self, b: typing.Union[jpype.JBoolean, bool]):
        """
        Option to recognize named base types that have an explicit size in the name (eg "int32_t)
        and use statically sized data types instead of compiler-dependent data types.
        
        :param jpype.JBoolean or bool b: true to turn option on, false to turn off
        """

    def setTryPackDataTypes(self, tryPackStructs: typing.Union[jpype.JBoolean, bool]):
        """
        Option to enable packing on structures created during the DWARF import.  If packing
        would change the structure's details, packing is left disabled.
        
        :param jpype.JBoolean or bool tryPackStructs: boolean flag to set
        """

    @property
    def outputSourceLocationInfo(self) -> jpype.JBoolean:
        ...

    @outputSourceLocationInfo.setter
    def outputSourceLocationInfo(self, value: jpype.JBoolean):
        ...

    @property
    def optionsUpdater(self) -> ghidra.app.plugin.core.analysis.AnalysisOptionsUpdater:
        ...

    @property
    def specialCaseSizedBaseTypes(self) -> jpype.JBoolean:
        ...

    @specialCaseSizedBaseTypes.setter
    def specialCaseSizedBaseTypes(self, value: jpype.JBoolean):
        ...

    @property
    def importFuncs(self) -> jpype.JBoolean:
        ...

    @importFuncs.setter
    def importFuncs(self, value: jpype.JBoolean):
        ...

    @property
    def createFuncSignatures(self) -> jpype.JBoolean:
        ...

    @createFuncSignatures.setter
    def createFuncSignatures(self, value: jpype.JBoolean):
        ...

    @property
    def outputInlineFuncComments(self) -> jpype.JBoolean:
        ...

    @outputInlineFuncComments.setter
    def outputInlineFuncComments(self, value: jpype.JBoolean):
        ...

    @property
    def ignoreParamStorage(self) -> jpype.JBoolean:
        ...

    @ignoreParamStorage.setter
    def ignoreParamStorage(self, value: jpype.JBoolean):
        ...

    @property
    def tryPackStructs(self) -> jpype.JBoolean:
        ...

    @property
    def maxSourceMapEntryLength(self) -> jpype.JLong:
        ...

    @maxSourceMapEntryLength.setter
    def maxSourceMapEntryLength(self, value: jpype.JLong):
        ...

    @property
    def useBookmarks(self) -> jpype.JBoolean:
        ...

    @property
    def copyRenameAnonTypes(self) -> jpype.JBoolean:
        ...

    @copyRenameAnonTypes.setter
    def copyRenameAnonTypes(self, value: jpype.JBoolean):
        ...

    @property
    def elideTypedefsWithSameName(self) -> jpype.JBoolean:
        ...

    @elideTypedefsWithSameName.setter
    def elideTypedefsWithSameName(self, value: jpype.JBoolean):
        ...

    @property
    def defaultCC(self) -> java.lang.String:
        ...

    @defaultCC.setter
    def defaultCC(self, value: java.lang.String):
        ...

    @property
    def outputLexicalBlockComments(self) -> jpype.JBoolean:
        ...

    @outputLexicalBlockComments.setter
    def outputLexicalBlockComments(self, value: jpype.JBoolean):
        ...

    @property
    def outputDIEInfo(self) -> jpype.JBoolean:
        ...

    @outputDIEInfo.setter
    def outputDIEInfo(self, value: jpype.JBoolean):
        ...

    @property
    def copyExternalDebugFileSymbols(self) -> jpype.JBoolean:
        ...

    @copyExternalDebugFileSymbols.setter
    def copyExternalDebugFileSymbols(self, value: jpype.JBoolean):
        ...

    @property
    def outputSourceLineInfo(self) -> jpype.JBoolean:
        ...

    @outputSourceLineInfo.setter
    def outputSourceLineInfo(self, value: jpype.JBoolean):
        ...

    @property
    def importLocalVariables(self) -> jpype.JBoolean:
        ...

    @importLocalVariables.setter
    def importLocalVariables(self, value: jpype.JBoolean):
        ...

    @property
    def importDataTypes(self) -> jpype.JBoolean:
        ...

    @importDataTypes.setter
    def importDataTypes(self, value: jpype.JBoolean):
        ...

    @property
    def organizeTypesBySourceFile(self) -> jpype.JBoolean:
        ...

    @organizeTypesBySourceFile.setter
    def organizeTypesBySourceFile(self, value: jpype.JBoolean):
        ...


class ExternalDebugFileSymbolImporter(java.lang.Object):
    """
    Imports symbols from an external debug program (typically created via a reverse strip) into
    the program that contains the executable code that the symbols will be applied to.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, program: ghidra.program.model.listing.Program, externalDebugProgram: ghidra.program.model.listing.Program, monitor: ghidra.util.task.TaskMonitor):
        ...

    def importSymbols(self, log: ghidra.app.util.importer.MessageLog):
        ...


class DWARFLocationList(java.lang.Object):
    """
    A collection of :obj:`DWARFLocation` elements, each which represents a location of an item 
    that is only valid for a certain range of program-counter locations.
    """

    class_: typing.ClassVar[java.lang.Class]
    EMPTY: typing.Final[DWARFLocationList]

    def __init__(self, list: java.util.List[DWARFLocation]):
        ...

    def getFirstLocation(self) -> DWARFLocation:
        ...

    def getLocationContaining(self, pc: typing.Union[jpype.JLong, int]) -> DWARFLocation:
        """
        Get the location that corresponds to the specified PC location.
        
        :param jpype.JLong or int pc: programcounter address
        :return: the byte array corresponding to the location expression
        :rtype: DWARFLocation
        """

    def isEmpty(self) -> bool:
        ...

    @staticmethod
    def readV4(reader: ghidra.app.util.bin.BinaryReader, cu: DWARFCompilationUnit) -> DWARFLocationList:
        """
        Read a v4 :obj:`DWARFLocationList` from the debug_loc section.
        
        :param ghidra.app.util.bin.BinaryReader reader: stream positioned at the start of a .debug_loc location list
        :param DWARFCompilationUnit cu: the compUnit that refers to the location list
        :return: list of DWARF locations (address range and location expression)
        :rtype: DWARFLocationList
        :raises IOException: if an I/O error occurs
        """

    @staticmethod
    def readV5(reader: ghidra.app.util.bin.BinaryReader, cu: DWARFCompilationUnit) -> DWARFLocationList:
        """
        Reads a v5 :obj:`DWARFLocationList` from the debug_loclists stream.
        
        :param ghidra.app.util.bin.BinaryReader reader: stream positioned at the start of a .debug_loclists location list
        :param DWARFCompilationUnit cu: the compUnit that refers to the location list
        :return: list of DWARF locations (address range and location expression)
        :rtype: DWARFLocationList
        :raises IOException: if an I/O error occurs
        """

    @staticmethod
    def withWildcardRange(expr: jpype.JArray[jpype.JByte]) -> DWARFLocationList:
        """
        Creates a simple location list containing a single wildcarded range and the specified
        expression bytes.
        
        :param jpype.JArray[jpype.JByte] expr: :obj:`DWARFExpression` bytes
        :return: new :obj:`DWARFLocationList` containing a single wildcarded range
        :rtype: DWARFLocationList
        """

    @property
    def locationContaining(self) -> DWARFLocation:
        ...

    @property
    def firstLocation(self) -> DWARFLocation:
        ...

    @property
    def empty(self) -> jpype.JBoolean:
        ...


class DWARFEncoding(java.lang.Object):
    """
    DWARF attribute encoding consts from www.dwarfstd.org/doc/DWARF4.pdf
    """

    class_: typing.ClassVar[java.lang.Class]
    DW_ATE_void: typing.Final = 0
    DW_ATE_address: typing.Final = 1
    DW_ATE_boolean: typing.Final = 2
    DW_ATE_complex_float: typing.Final = 3
    DW_ATE_float: typing.Final = 4
    DW_ATE_signed: typing.Final = 5
    DW_ATE_signed_char: typing.Final = 6
    DW_ATE_unsigned: typing.Final = 7
    DW_ATE_unsigned_char: typing.Final = 8
    DW_ATE_imaginary_float: typing.Final = 9
    DW_ATE_packed_decimal: typing.Final = 10
    DW_ATE_numeric_string: typing.Final = 11
    DW_ATE_edited: typing.Final = 12
    DW_ATE_signed_fixed: typing.Final = 13
    DW_ATE_unsigned_fixed: typing.Final = 14
    DW_ATE_decimal_float: typing.Final = 15
    DW_ATE_UTF: typing.Final = 16
    DW_ATE_lo_user: typing.Final = 128
    DW_ATE_hi_user: typing.Final = 255

    def __init__(self):
        ...

    @staticmethod
    def getTypeName(encoding: typing.Union[jpype.JInt, int]) -> str:
        ...


class DWARFRegisterMappingsManager(java.lang.Object):
    """
    Factory class to instantiate and cache :obj:`DWARFRegisterMappings` objects.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def getMappingForLang(lang: ghidra.program.model.lang.Language) -> DWARFRegisterMappings:
        """
        Returns a possibly cached :obj:`DWARFRegisterMappings` object for the
        specified language,
        
        :param ghidra.program.model.lang.Language lang: :obj:`Language` to get the matching DWARF register mappings
                    for
        :return: :obj:`DWARFRegisterMappings` instance, never null
        :rtype: DWARFRegisterMappings
        :raises IOException: if mapping not found or invalid
        """

    @staticmethod
    def hasDWARFRegisterMapping(lang: ghidra.program.model.lang.Language) -> bool:
        """
        Returns true if the specified :obj:`Language` has DWARF register
        mappings.
        
        :param ghidra.program.model.lang.Language lang: The :obj:`Language` to test
        :return: true if the language has a DWARF register mapping specified
        :rtype: bool
        :raises IOException: if there was an error in the language LDEF file.
        """

    @staticmethod
    def readMappingForLang(lang: ghidra.program.model.lang.Language) -> DWARFRegisterMappings:
        """
        Finds the DWARF register mapping information file specified in the
        specified language's LDEF file and returns a new
        :obj:`DWARFRegisterMappings` object containing the data read from that
        file.
         
        
        Throws :obj:`IOException` if the lang does not have a mapping or it is
        invalid.
        
        :param ghidra.program.model.lang.Language lang: :obj:`Language` to read the matching DWARF register mappings
                    for
        :return: a new :obj:`DWARFRegisterMappings` instance, created from
                information read from the :obj:`.DWARF_REGISTER_MAPPING_NAME`
                xml file referenced in the language's LDEF, never null.
        :rtype: DWARFRegisterMappings
        :raises IOException: if there is no DWARF register mapping file associated
                    with the specified :obj:`Language` or if there was an error
                    in the register mapping data.
        """

    @staticmethod
    def readMappingFrom(rootElem: org.jdom.Element, lang: ghidra.program.model.lang.Language) -> DWARFRegisterMappings:
        """
        Creates a new :obj:`DWARFRegisterMappings` from the data present in the
        xml element.
        
        :param org.jdom.Element rootElem: JDom XML element containing the <dwarf> root
                    element of the mapping file.
        :param ghidra.program.model.lang.Language lang: The Ghidra :obj:`Language` that the DWARF register mapping
                    applies to
        :return: a new :obj:`DWARFRegisterMappings` instance, never null.
        :rtype: DWARFRegisterMappings
        :raises IOException: if missing or invalid data found in xml
        """


class DWARFChildren(java.lang.Object):
    """
    DWARF child determination consts from www.dwarfstd.org/doc/DWARF4.pdf.
     
    
    Yes, its a direct equiv to a boolean, but its in the spec.
    """

    class_: typing.ClassVar[java.lang.Class]
    DW_CHILDREN_no: typing.Final = 0
    DW_CHILDREN_yes: typing.Final = 1

    def __init__(self):
        ...


class DWARFAbbreviation(java.lang.Object):
    """
    This class represents the 'schema' for a DWARF DIE record.
     
    
    A raw DWARF DIE record specifies its abbreviation code (pointing to an instance of
    this class) and the corresponding DWARFAbbreviation instance has the information
    about how the raw DIE is laid out.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, abbreviationCode: typing.Union[jpype.JInt, int], tagId: typing.Union[jpype.JInt, int], hasChildren: typing.Union[jpype.JBoolean, bool], attributes: jpype.JArray[ghidra.app.util.bin.format.dwarf.attribs.DWARFAttribute.AttrDef]):
        ...

    def findAttribute(self, attributeId: ghidra.app.util.bin.format.dwarf.attribs.DWARFAttribute) -> ghidra.app.util.bin.format.dwarf.attribs.DWARFAttribute.AttrDef:
        """
        Get the attribute with the given attribute key.
        
        :param ghidra.app.util.bin.format.dwarf.attribs.DWARFAttribute attributeId: attribute key
        :return: attribute specification
        :rtype: ghidra.app.util.bin.format.dwarf.attribs.DWARFAttribute.AttrDef
        """

    def getAbbreviationCode(self) -> int:
        """
        Get the abbreviation code.
        
        :return: the abbreviation code
        :rtype: int
        """

    def getAttributeAt(self, index: typing.Union[jpype.JInt, int]) -> ghidra.app.util.bin.format.dwarf.attribs.DWARFAttribute.AttrDef:
        """
        Get the attribute at the given index.
        
        :param jpype.JInt or int index: index of the attribute
        :return: attribute specification
        :rtype: ghidra.app.util.bin.format.dwarf.attribs.DWARFAttribute.AttrDef
        """

    def getAttributeCount(self) -> int:
        """
        Return number of attribute values.
        
        :return: number of attribute values
        :rtype: int
        """

    def getAttributes(self) -> jpype.JArray[ghidra.app.util.bin.format.dwarf.attribs.DWARFAttribute.AttrDef]:
        """
        Return a live list of the attributes.
        
        :return: list of attributes
        :rtype: jpype.JArray[ghidra.app.util.bin.format.dwarf.attribs.DWARFAttribute.AttrDef]
        """

    def getTag(self) -> DWARFTag:
        """
        Get the tag value.
        
        :return: the tag value
        :rtype: DWARFTag
        """

    def getTagName(self) -> str:
        ...

    def hasChildren(self) -> bool:
        """
        Checks to see if this abbreviation has any DIE children.
        
        :return: true if this abbreviation has DIE children
        :rtype: bool
        """

    @staticmethod
    def read(reader: ghidra.app.util.bin.BinaryReader, prog: DWARFProgram, monitor: ghidra.util.task.TaskMonitor) -> DWARFAbbreviation:
        """
        Reads a :obj:`DWARFAbbreviation` from the stream.
        
        :param ghidra.app.util.bin.BinaryReader reader: :obj:`BinaryReader` stream
        :param DWARFProgram prog: :obj:`DWARFProgram`
        :param ghidra.util.task.TaskMonitor monitor: :obj:`TaskMonitor`
        :return: :obj:`DWARFAbbreviation`, or null if the stream was at a end-of-list marker
        :rtype: DWARFAbbreviation
        :raises IOException: if error reading
        :raises CancelledException: if canceled
        """

    @staticmethod
    def readAbbreviations(reader: ghidra.app.util.bin.BinaryReader, prog: DWARFProgram, monitor: ghidra.util.task.TaskMonitor) -> java.util.Map[java.lang.Integer, DWARFAbbreviation]:
        """
        Reads a list of :obj:`DWARFAbbreviation`, stopping when the end-of-list marker is
        encountered.
        
        :param ghidra.app.util.bin.BinaryReader reader: :obj:`BinaryReader` .debug_abbr stream
        :param DWARFProgram prog: :obj:`DWARFProgram`
        :param ghidra.util.task.TaskMonitor monitor: :obj:`TaskMonitor`
        :return: map of abbrCode -> abbr instance
        :rtype: java.util.Map[java.lang.Integer, DWARFAbbreviation]
        :raises IOException: if error reading
        :raises CancelledException: if cancelled
        """

    @property
    def attributeAt(self) -> ghidra.app.util.bin.format.dwarf.attribs.DWARFAttribute.AttrDef:
        ...

    @property
    def attributeCount(self) -> jpype.JInt:
        ...

    @property
    def attributes(self) -> jpype.JArray[ghidra.app.util.bin.format.dwarf.attribs.DWARFAttribute.AttrDef]:
        ...

    @property
    def tag(self) -> DWARFTag:
        ...

    @property
    def abbreviationCode(self) -> jpype.JInt:
        ...

    @property
    def tagName(self) -> java.lang.String:
        ...


class NameDeduper(java.lang.Object):
    """
    Helper for allocating unique string names.
     
    
    "Reserved names" are names that will be used by later calls to the de-duper.
     
    
    "Used names" are names that are already allocated and are in use.
     
    
    Reserved names only prevent re-use of a name when a name is being generated because of a
    collision with a "used name".
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        """
        Create a new name de-duper.
        """

    def addReservedNames(self, additionalReservedNames: collections.abc.Sequence):
        """
        Add names to the de-duper that will be used in a future call.  These names do not block
        calls to confirm that a name is unique, but instead prevent the name from being used
        when an auto-generated name is created.
        
        :param collections.abc.Sequence additionalReservedNames: names to reserve
        """

    def addUsedNames(self, alreadyUsedNames: collections.abc.Sequence):
        """
        Add names to the de-duper that have already been used.
        
        :param collections.abc.Sequence alreadyUsedNames: names already used
        """

    def getUniqueName(self, name: typing.Union[java.lang.String, str]) -> str:
        """
        Confirms that the specified name is unique, or returns a generated name that is unique.
        
        :param java.lang.String or str name: name to test
        :return: ``null`` if specified name is already unique (and marks the specified name as
        used), or returns a new, unique generated name
        :rtype: str
        """

    def isUniqueName(self, name: typing.Union[java.lang.String, str]) -> bool:
        """
        Returns true if the specified name hasn't been allocated yet.
        
        :param java.lang.String or str name: string name to check
        :return: boolean true if the specified name hasn't been allocated yet
        :rtype: bool
        """

    @property
    def uniqueName(self) -> java.lang.String:
        ...


class DWARFStringOffsetTableHeader(DWARFIndirectTableHeader):
    """
    Table of offsets that point into the string table.  These tables are stored sequentially in the
    :obj:`.debug_str_offsets <DWARFSectionNames.DEBUG_STROFFSETS>` section.
     
    
    Elements in the table are referred to by index via :obj:`DWARFForm.DW_FORM_strx` and friends.
     
    
    The table's :meth:`getFirstElementOffset() <.getFirstElementOffset>` is referred to by a compUnit's 
    :obj:`DWARFAttribute.DW_AT_str_offsets_base` value.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, startOffset: typing.Union[jpype.JLong, int], endOffset: typing.Union[jpype.JLong, int], firstElementOffset: typing.Union[jpype.JLong, int], intSize: typing.Union[jpype.JInt, int], count: typing.Union[jpype.JInt, int]):
        ...

    @staticmethod
    def readV5(reader: ghidra.app.util.bin.BinaryReader, defaultIntSize: typing.Union[jpype.JInt, int]) -> DWARFStringOffsetTableHeader:
        """
        Reads a string offset table header (found in the .debug_str_offsets section)
        
        :param ghidra.app.util.bin.BinaryReader reader: :obj:`BinaryReader`
        :return: new :obj:`DWARFStringOffsetTableHeader` instance
        :rtype: DWARFStringOffsetTableHeader
        :raises IOException: if error reading
        """


class DWARFIndirectTable(java.lang.Object):
    """
    Handles a grouping of :obj:`DWARFIndirectTableHeader`s that specify how to look up a
    certain type of item (per CU).
    """

    class CheckedIOFunction(java.lang.Object, typing.Generic[T, R]):

        class_: typing.ClassVar[java.lang.Class]

        def apply(self, value: T) -> R:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, baseOffsetFunc: java.util.function.Function[DWARFCompilationUnit, java.lang.Long]):
        """
        Creates a :obj:`DWARFIndirectTable`
        
        :param ghidra.app.util.bin.BinaryReader reader: :obj:`BinaryReader` containing the :obj:`DWARFIndirectTableHeader`s
        :param java.util.function.Function[DWARFCompilationUnit, java.lang.Long] baseOffsetFunc: a function that will return the baseoffset value for a
        :obj:`DWARFCompilationUnit`.
        """

    def bootstrap(self, msg: typing.Union[java.lang.String, str], headerReader: DWARFIndirectTable.CheckedIOFunction[ghidra.app.util.bin.BinaryReader, DWARFIndirectTableHeader], monitor: ghidra.util.task.TaskMonitor):
        """
        Populates this instance will all :obj:`DWARFIndirectTableHeader` instances that can be
        read from the stream.
        
        :param java.lang.String or str msg: String message to use for the taskmonitor
        :param DWARFIndirectTable.CheckedIOFunction[ghidra.app.util.bin.BinaryReader, DWARFIndirectTableHeader] headerReader: a function that reads the specific table header type from the stream
        :param ghidra.util.task.TaskMonitor monitor: :obj:`TaskMonitor`
        :raises CancelledException: if cancelled
        :raises IOException: if error reading a header
        """

    def clear(self):
        ...

    def getOffset(self, index: typing.Union[jpype.JInt, int], cu: DWARFCompilationUnit) -> int:
        """
        Returns the offset of an item, based on its index in a particular header (which is found
        by the controlling CU)
        
        :param jpype.JInt or int index: index of the item
        :param DWARFCompilationUnit cu: :obj:`DWARFCompilationUnit`
        :return: long offset of the item.  Caller responsible for reading the item themselves
        :rtype: int
        :raises IOException: if error reading table data
        """


class DWARFUnitType(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    DW_UT_compile: typing.Final = 1
    DW_UT_type: typing.Final = 2
    DW_UT_partial: typing.Final = 3
    DW_UT_skeleton: typing.Final = 4
    DW_UT_split_compile: typing.Final = 5
    DW_UT_split_type: typing.Final = 6
    DW_UT_lo_user: typing.Final = 128
    DW_UT_hi_user: typing.Final = 255

    def __init__(self):
        ...


class DebugInfoEntry(java.lang.Object):
    """
    A DWARF Debug Info Entry is a collection of :obj:`attributes <DWARFAttributeValue>`
    in a hierarchical structure (see :meth:`getParent() <.getParent>`, :meth:`getChildren() <.getChildren>`).
     
    
    This class is a lower-level class and :obj:`DIEAggregate` should be used instead in most
    cases when examining information from the DWARF system.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, cu: DWARFCompilationUnit, offset: typing.Union[jpype.JLong, int], dieIndex: typing.Union[jpype.JInt, int], abbreviation: DWARFAbbreviation, attrOffsets: jpype.JArray[jpype.JInt]):
        """
        Creates a DIE.
        
        :param DWARFCompilationUnit cu: compunit containing the DIE
        :param jpype.JLong or int offset: offset of the DIE
        :param jpype.JInt or int dieIndex: index of the DIE
        :param DWARFAbbreviation abbreviation: that defines the schema of this DIE record
        :param jpype.JArray[jpype.JInt] attrOffsets: offset (from the die offset) of each attribute value
        """

    def findAttribute(self, attributeId: ghidra.app.util.bin.format.dwarf.attribs.DWARFAttribute) -> ghidra.app.util.bin.format.dwarf.attribs.DWARFAttributeValue:
        """
        Searches the list of attributes for a specific attribute, by id.
        
        :param ghidra.app.util.bin.format.dwarf.attribs.DWARFAttribute attributeId: :obj:`DWARFAttribute`
        :return: :obj:`DWARFAttributeValue`, or null if not found
        :rtype: ghidra.app.util.bin.format.dwarf.attribs.DWARFAttributeValue
        """

    def getAbbreviation(self) -> DWARFAbbreviation:
        """
        Get the abbreviation of this DIE.
        
        :return: the abbreviation of this DIE
        :rtype: DWARFAbbreviation
        """

    def getAttributeCount(self) -> int:
        """
        Returns the number of attributes in this DIE.
        
        :return: number of attribute values in this DIE
        :rtype: int
        """

    def getAttributeValue(self, attribIndex: typing.Union[jpype.JInt, int]) -> ghidra.app.util.bin.format.dwarf.attribs.DWARFAttributeValue:
        """
        Returns the indexed attribute value.
        
        :param jpype.JInt or int attribIndex: index (0..count)
        :return: :obj:`DWARFAttributeValue`
        :rtype: ghidra.app.util.bin.format.dwarf.attribs.DWARFAttributeValue
        :raises IOException: if error reading the value
        """

    @typing.overload
    def getChildren(self) -> java.util.List[DebugInfoEntry]:
        """
        Return a list of the child DIE's.
        
        :return: list of child DIE's
        :rtype: java.util.List[DebugInfoEntry]
        """

    @typing.overload
    def getChildren(self, childTag: DWARFTag) -> java.util.List[DebugInfoEntry]:
        """
        Return a list of children that are of a specific DWARF type.
        
        :param DWARFTag childTag: DIE tag used to filter the child DIEs
        :return: list of matching child DIE records
        :rtype: java.util.List[DebugInfoEntry]
        """

    def getCompilationUnit(self) -> DWARFCompilationUnit:
        ...

    def getDepth(self) -> int:
        ...

    def getIndex(self) -> int:
        """
        Returns the index of this DIE in the entire dwarf program.
        
        :return: index of this DIE
        :rtype: int
        """

    def getOffset(self) -> int:
        """
        Get the offset of this DIE from the beginning of the debug_info section.
        
        :return: the offset of this DIE from the beginning of the debug_info section
        :rtype: int
        """

    def getParent(self) -> DebugInfoEntry:
        """
        Get the parent DIE of this DIE.
        
        :return: the parent DIE, or null if this DIE is the root of the compilation unit
        :rtype: DebugInfoEntry
        """

    def getPositionInParent(self) -> int:
        """
        Returns the ordinal position of this DIE record in its parent's list of children.
        
        :return: index of ourself in our parent, or -1 if root DIE
        :rtype: int
        """

    def getProgram(self) -> DWARFProgram:
        ...

    def getTag(self) -> DWARFTag:
        """
        Get the DWARFTag value of this DIE.
        
        :return: the DWARFTag value of this DIE
        :rtype: DWARFTag
        """

    def isTerminator(self) -> bool:
        """
        Check to see if the DIE is a terminator.
        
        :return: true if the DIE is a terminator and false otherwise
        :rtype: bool
        """

    @staticmethod
    def read(reader: ghidra.app.util.bin.BinaryReader, cu: DWARFCompilationUnit, dieIndex: typing.Union[jpype.JInt, int]) -> DebugInfoEntry:
        """
        Read a DIE record.
        
        :param ghidra.app.util.bin.BinaryReader reader: :obj:`BinaryReader` positioned at the start of a DIE record
        :param DWARFCompilationUnit cu: the compunit that contains the DIE
        :param jpype.JInt or int dieIndex: the index of the DIE
        :return: new DIE instance
        :rtype: DebugInfoEntry
        :raises IOException: if error reading data, or bad DWARF
        """

    def setAttributeValue(self, index: typing.Union[jpype.JInt, int], attrVal: ghidra.app.util.bin.format.dwarf.attribs.DWARFAttributeValue):
        ...

    @property
    def parent(self) -> DebugInfoEntry:
        ...

    @property
    def depth(self) -> jpype.JInt:
        ...

    @property
    def compilationUnit(self) -> DWARFCompilationUnit:
        ...

    @property
    def offset(self) -> jpype.JLong:
        ...

    @property
    def children(self) -> java.util.List[DebugInfoEntry]:
        ...

    @property
    def attributeValue(self) -> ghidra.app.util.bin.format.dwarf.attribs.DWARFAttributeValue:
        ...

    @property
    def index(self) -> jpype.JInt:
        ...

    @property
    def attributeCount(self) -> jpype.JInt:
        ...

    @property
    def terminator(self) -> jpype.JBoolean:
        ...

    @property
    def positionInParent(self) -> jpype.JInt:
        ...

    @property
    def tag(self) -> DWARFTag:
        ...

    @property
    def program(self) -> DWARFProgram:
        ...

    @property
    def abbreviation(self) -> DWARFAbbreviation:
        ...


class DWARFUnitHeader(java.lang.Object):
    """
    The base class for a set of headers that share a common field layout.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getDWARFVersion(self) -> int:
        ...

    def getEndOffset(self) -> int:
        """
        Returns the byte offset to the end of this unit.
        
        :return: the byte offset to the end of this unit
        :rtype: int
        """

    def getIntSize(self) -> int:
        """
        Returns either 4 (for DWARF_32) or 8 (for DWARF_64) depending on the current unit format
        
        :return: size of ints in this unit (4 or 8)
        :rtype: int
        """

    def getProgram(self) -> DWARFProgram:
        ...

    def getStartOffset(self) -> int:
        """
        Returns the byte offset to the start of this unit.
        
        :return: the byte offset to the start of this unit
        :rtype: int
        """

    def getUnitNumber(self) -> int:
        """
        Return the ordinal number of this unit
        
        :return: ordinal of this unit
        :rtype: int
        """

    @staticmethod
    def read(dprog: DWARFProgram, reader: ghidra.app.util.bin.BinaryReader, abbrReader: ghidra.app.util.bin.BinaryReader, unitNumber: typing.Union[jpype.JInt, int], monitor: ghidra.util.task.TaskMonitor) -> DWARFUnitHeader:
        """
        Reads the initial fields found in a unit header.
        
        :param DWARFProgram dprog: :obj:`DWARFProgram`
        :param ghidra.app.util.bin.BinaryReader reader: :obj:`BinaryReader` stream
        :param ghidra.app.util.bin.BinaryReader abbrReader: :obj:`BinaryReader` .debug_abbr stream
        :param jpype.JInt or int unitNumber: ordinal of this item
        :param ghidra.util.task.TaskMonitor monitor: :obj:`TaskMonitor`
        :return: a unit header (only comp units for now), or null if at end-of-list
        :rtype: DWARFUnitHeader
        :raises DWARFException: if invalid dwarf data
        :raises IOException: if error reading data
        :raises CancelledException: if cancelled
        """

    @property
    def endOffset(self) -> jpype.JLong:
        ...

    @property
    def startOffset(self) -> jpype.JLong:
        ...

    @property
    def dWARFVersion(self) -> jpype.JShort:
        ...

    @property
    def unitNumber(self) -> jpype.JInt:
        ...

    @property
    def program(self) -> DWARFProgram:
        ...

    @property
    def intSize(self) -> jpype.JInt:
        ...


class DWARFLocationListEntry(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    DW_LLE_end_of_list: typing.Final = 0
    DW_LLE_base_addressx: typing.Final = 1
    DW_LLE_startx_endx: typing.Final = 2
    DW_LLE_startx_length: typing.Final = 3
    DW_LLE_offset_pair: typing.Final = 4
    DW_LLE_default_location: typing.Final = 5
    DW_LLE_base_address: typing.Final = 6
    DW_LLE_start_end: typing.Final = 7
    DW_LLE_start_length: typing.Final = 8

    def __init__(self):
        ...

    @staticmethod
    def toString(value: typing.Union[jpype.JLong, int]) -> str:
        ...


class DWARFDataTypeManager(java.lang.Object):
    """
    Manages mappings between DWARF DIEs and Ghidra DataTypes.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, prog: DWARFProgram, dataTypeManager: ghidra.program.model.data.DataTypeManager):
        """
        Creates a new :obj:`DWARFDataTypeManager` instance.
        
        :param DWARFProgram prog: :obj:`DWARFProgram` that holds the Ghidra :obj:`Program` being imported.
        :param ghidra.program.model.data.DataTypeManager dataTypeManager: :obj:`DataTypeManager` of the Ghidra Program.
        """

    def addDataType(self, offset: typing.Union[jpype.JLong, int], dataType: ghidra.program.model.data.DataType, dsi: DWARFSourceInfo):
        ...

    def doGetDataType(self, diea: DIEAggregate) -> ghidra.program.model.data.DataType:
        """
        Creates a :obj:`DataType` from the DWARF :obj:`DIEA <DIEAggregate>`, or returns a
        pre-existing :obj:`DataType` created by the specified DIEA previously.
         
        
        Creating a new DataType happens in two stages, where the DataType is created as
        an 'impl' DataType first (possibly representing a large graph of referred-to datatypes),
        and then it is submitted to the :obj:`DataTypeManager` to be added to the database and
        converted to a 'db' object.
         
        
        Mapping from the DIEA's offset to the resultant 'db' DataType object is a two step
        process.
         
        
        A :obj:`DataTypeGraphComparator` is used to walk the 'impl' DataType object graph
        in lock-step with the resultant 'db' DataType object graph, and the mapping between
        the 'impl' object and its creator DIEA (held in :obj:`DWARFDataType`)
        is used to create a mapping to the resultant 'db' DataType's path.
        
        :param DIEAggregate diea: DWARF :obj:`DIEAggregate` with datatype information that needs to be converted
        to a Ghidra DataType.
        :return: :obj:`DataType` that is ready to use.
        :rtype: ghidra.program.model.data.DataType
        :raises IOException: if problem
        :raises DWARFExpressionException: if problem
        """

    def forAllConflicts(self, dtp: ghidra.program.model.data.DataTypePath) -> java.lang.Iterable[ghidra.program.model.data.DataType]:
        """
        Iterate all :obj:`DataType`s that match the CategoryPath / name given
        in the :obj:`DataTypePath` parameter, including "conflict" datatypes
        that have a ".CONFLICTxx" suffix.
        
        :param ghidra.program.model.data.DataTypePath dtp: 
        :return: 
        :rtype: java.lang.Iterable[ghidra.program.model.data.DataType]
        """

    @typing.overload
    def getBaseType(self, name: typing.Union[java.lang.String, str]) -> ghidra.program.model.data.DataType:
        """
        Returns a DWARF base data type based on its name, or null if it does not exist.
        
        :param java.lang.String or str name: base type name
        :return: :obj:`DataType` or null if base type does not exist
        :rtype: ghidra.program.model.data.DataType
        """

    @typing.overload
    def getBaseType(self, name: typing.Union[java.lang.String, str], dwarfSize: typing.Union[jpype.JInt, int], dwarfEncoding: typing.Union[jpype.JInt, int], isBigEndian: typing.Union[jpype.JBoolean, bool], isExplictSize: typing.Union[jpype.JBoolean, bool]) -> ghidra.program.model.data.DataType:
        """
        Returns a Ghidra :obj:`datatype <DataType>` that corresponds to the DWARF named type.
         
        
        If there is no direct matching named Ghidra type, generic types of matching
        size will be returned for integer and floating numeric dwarf encoding types, boolean,
        and character types.  Failing that, generic storage types of matching size
        (word, dword, etc) will be returned, and failing that, an array of the correct size
        will be returned.
         
        
        If the returned data type is not a direct named match, the returned data type
        will be wrapped in a Ghidra typedef using the dwarf type's name.
         
        
        Any newly created Ghidra data types will be cached and the same instance will be returned
        if the same DWARF named base type is requested again.
        
        :param java.lang.String or str name: 
        :param jpype.JInt or int dwarfSize: 
        :param jpype.JInt or int dwarfEncoding: 
        :param jpype.JBoolean or bool isBigEndian: 
        :param jpype.JBoolean or bool isExplictSize: boolean flag, if true the returned data type will not be linked to
        the dataOrganization's compiler specified data types (eg. if type is something like int32_t, 
        the returned type should never change size, even if the dataOrg changes).  If false,
        the returned type will be linked to the dataOrg's compiler specified data types if possible,
        except for data types that have a name that include a bitsize in the name, such as "int64_t".
        :return: 
        :rtype: ghidra.program.model.data.DataType
        """

    @typing.overload
    def getDataType(self, diea: DIEAggregate, defaultValue: ghidra.program.model.data.DataType) -> ghidra.program.model.data.DataType:
        """
        Returns a Ghidra :obj:`DataType` corresponding to the specified :obj:`DIEAggregate`,
        or the specified defaultValue if the DIEA param is null or does not map to an already
        defined datatype (registered with :meth:`addDataType(long, DataType, DWARFSourceInfo) <.addDataType>`).
        
        :param DIEAggregate diea: :obj:`DIEAggregate` that defines a data type
        :param ghidra.program.model.data.DataType defaultValue: Ghidra :obj:`DataType` to return if the specified DIEA is null
        or not already defined.
        :return: Ghidra :obj:`DataType`
        :rtype: ghidra.program.model.data.DataType
        """

    @typing.overload
    def getDataType(self, dieOffset: typing.Union[jpype.JLong, int], defaultValue: ghidra.program.model.data.DataType) -> ghidra.program.model.data.DataType:
        """
        Returns a Ghidra :obj:`DataType` corresponding to the specified DIE (based on its
        offset), or the specified defaultValue if the DIE does not map to a defined
        datatype (registered with :meth:`addDataType(long, DataType, DWARFSourceInfo) <.addDataType>`).
        
        :param jpype.JLong or int dieOffset: offset of a DIE record that defines a data type
        :param ghidra.program.model.data.DataType defaultValue: Ghidra :obj:`DataType` to return if the specified DIE not already defined.
        :return: Ghidra :obj:`DataType`
        :rtype: ghidra.program.model.data.DataType
        """

    def getDataTypeForVariable(self, diea: DIEAggregate) -> ghidra.program.model.data.DataType:
        ...

    def getFunctionSignature(self, diea: DIEAggregate) -> ghidra.program.model.data.FunctionDefinition:
        """
        Construct a temporary 'impl' :obj:`FunctionDefinition` DataType using the information
        found in the specified :obj:`DIEAggregate`.
        
        :param DIEAggregate diea: :obj:`DIEAggregate` of a subprogram, callsite, etc.
        :return: :obj:`FunctionDefinition` impl (not saved to the DB) or null if not a valid
        DIEA.
        :rtype: ghidra.program.model.data.FunctionDefinition
        """

    def getImportedTypes(self) -> java.util.List[ghidra.program.model.data.DataTypePath]:
        ...

    def getOffsetType(self, size: typing.Union[jpype.JInt, int]) -> ghidra.program.model.data.DataType:
        """
        Returns a Ghidra :obj:`datatype <DataType>` that corresponds to a type
        that can be used to represent an offset.
        
        :param jpype.JInt or int size: 
        :return: 
        :rtype: ghidra.program.model.data.DataType
        """

    @typing.overload
    def getPtrTo(self, dt: ghidra.program.model.data.DataType) -> ghidra.program.model.data.DataType:
        """
        Returns a pointer to the specified data type.
        
        :param ghidra.program.model.data.DataType dt: Ghidra :obj:`DataType`
        :return: a :obj:`Pointer` that points to the specified datatype.
        :rtype: ghidra.program.model.data.DataType
        """

    @typing.overload
    def getPtrTo(self, dt: ghidra.program.model.data.DataType, ptrSize: typing.Union[jpype.JInt, int]) -> ghidra.program.model.data.DataType:
        ...

    def getSourceInfo(self, dataType: ghidra.program.model.data.DataType) -> DWARFSourceInfo:
        ...

    def getSpecificDataType(self, diea: DIEAggregate, dataTypeClazz: java.lang.Class[T]) -> T:
        ...

    def getVoidType(self) -> ghidra.program.model.data.DataType:
        """
        Returns the void type.
        
        :return: void :obj:`DataType`
        :rtype: ghidra.program.model.data.DataType
        """

    def importAllDataTypes(self, monitor: ghidra.util.task.TaskMonitor):
        """
        Does the actual import work.  Updates the :obj:`summary <.importSummary>` object
        with information about the types imported and errors encountered.
        
        :param ghidra.util.task.TaskMonitor monitor: to watch for cancel
        :raises IOException: if errors are encountered reading data
        :raises DWARFException: if errors are encountered processing
        :raises CancelledException: if the :obj:`TaskMonitor` is canceled by the user.
        """

    @property
    def sourceInfo(self) -> DWARFSourceInfo:
        ...

    @property
    def ptrTo(self) -> ghidra.program.model.data.DataType:
        ...

    @property
    def offsetType(self) -> ghidra.program.model.data.DataType:
        ...

    @property
    def functionSignature(self) -> ghidra.program.model.data.FunctionDefinition:
        ...

    @property
    def dataTypeForVariable(self) -> ghidra.program.model.data.DataType:
        ...

    @property
    def voidType(self) -> ghidra.program.model.data.DataType:
        ...

    @property
    def importedTypes(self) -> java.util.List[ghidra.program.model.data.DataTypePath]:
        ...

    @property
    def baseType(self) -> ghidra.program.model.data.DataType:
        ...


class DWARFImporter(java.lang.Object):
    """
    Performs a DWARF datatype import and a DWARF function import, under the control of the
    :obj:`DWARFImportOptions`.
    """

    class_: typing.ClassVar[java.lang.Class]
    DEFAULT_COMPILATION_DIR: typing.Final = "DWARF_DEFAULT_COMP_DIR"

    def __init__(self, prog: DWARFProgram, monitor: ghidra.util.task.TaskMonitor):
        ...

    def performImport(self) -> DWARFImportSummary:
        """
        Imports DWARF information according to the :obj:`DWARFImportOptions` set.
        
        :return: 
        :rtype: DWARFImportSummary
        :raises IOException: 
        :raises DWARFException: 
        :raises CancelledException:
        """


class DWARFDataTypeImporter(java.lang.Object):
    """
    Creates Ghidra :obj:`DataType`s using information from DWARF debug entries.  The caller
    is responsible for writing the resulting temporary DataType instances into the database.
     
    
    Create a new instance of this class for each :obj:`DIEAggregate` datatype that you wish
    to convert into a DataType.
    """

    @typing.type_check_only
    class DWARFDataType(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        def hexOffsets(self) -> str:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, prog: DWARFProgram, dwarfDTM: DWARFDataTypeManager):
        """
        Create a new data type importer.
        
        :param DWARFProgram prog: :obj:`DWARFProgram` that is being imported
        :param DWARFDataTypeManager dwarfDTM: :obj:`DWARFDataTypeManager` helper
        """

    def getDDTByInstance(self, dtInstance: ghidra.program.model.data.DataType) -> DWARFDataTypeImporter.DWARFDataType:
        ...

    def getDataType(self, diea: DIEAggregate, defaultValue: DWARFDataTypeImporter.DWARFDataType) -> DWARFDataTypeImporter.DWARFDataType:
        """
        Converts the specified DWARF debug entry into a Ghidra :obj:`DataType` (wrapped
        in a simple holder object to also return associated metadata).
        
        :param DIEAggregate diea: DWARF :obj:`DIEAggregate` to convert into Ghidra DataType.
        :param DWARFDataTypeImporter.DWARFDataType defaultValue: value to return if the specified DIEA is null or there is a problem
        with the DWARF debug data.
        :return: a :obj:`DWARFDataType` wrapper around the new Ghidra :obj:`DataType`.
        :rtype: DWARFDataTypeImporter.DWARFDataType
        :raises IOException: 
        :raises DWARFExpressionException:
        """

    @property
    def dDTByInstance(self) -> DWARFDataTypeImporter.DWARFDataType:
        ...


class DWARFDataTypeConflictHandler(ghidra.program.model.data.DataTypeConflictHandler):
    """
    This :obj:`conflict handler <DataTypeConflictHandler>` attempts to match
    conflicting :obj:`composite data types <Composite>` (structure or union) when
    they have compatible data layouts. (Data types that are exactly equiv will
    not be subjected to conflict handling and will never reach here)
     
    
    A default/empty sized structure, or structures with the same size are
    candidates for matching.
     
    
    Structures that have a subset of the other's field definition are candidates
    for matching.
     
    
    When a candidate data type is matched with an existing data type, this
    conflict handler will specify that the new data type is:
     
    * discarded and replaced by the existing data type
    (:obj:`ConflictResult.USE_EXISTING`)
    * used to overwrite the existing data type
    (:obj:`ConflictResult.REPLACE_EXISTING`)
    
    or the candidate data type was **NOT** matched with an existing data type,
    and the new data type is:
     
    * kept, but renamed with a .conflictNNNN suffix to make it unique
    (:obj:`ConflictResult.RENAME_AND_ADD`)
    
    **NOTE:** structures with alignment (instead of being statically laid out)
    are not treated specially and will not match other aligned or non-aligned
    structures.
    """

    class_: typing.ClassVar[java.lang.Class]
    INSTANCE: typing.Final[DWARFDataTypeConflictHandler]


class DWARFSourceInfo(java.lang.Record):
    """
    Represents the filename and line number info values from DWARF :obj:`DIEs <DebugInfoEntry>`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, filename: typing.Union[java.lang.String, str], lineNum: typing.Union[jpype.JInt, int]):
        ...

    @staticmethod
    def create(diea: DIEAggregate) -> DWARFSourceInfo:
        """
        Creates a new :obj:`DWARFSourceInfo` instance from the supplied :obj:`DIEAggregate`
        if the info is present, otherwise returns null;
        
        :param DIEAggregate diea: :obj:`DIEAggregate` to query for source info
        :return: new :obj:`DWARFSourceInfo` with filename:linenum info, or null if no info present in DIEA.
        :rtype: DWARFSourceInfo
        """

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def filename(self) -> str:
        ...

    @staticmethod
    @typing.overload
    def getDescriptionStr(diea: DIEAggregate) -> str:
        """
        Returns the source file and line number info attached to the specified :obj:`DIEAggregate`
        formatted as :meth:`getDescriptionStr() <.getDescriptionStr>`, or null if not present.
        
        :param DIEAggregate diea: :obj:`DIEAggregate` to query
        :return: string, see :meth:`getDescriptionStr() <.getDescriptionStr>`
        :rtype: str
        """

    @typing.overload
    def getDescriptionStr(self) -> str:
        """
        Returns the source location info as a string formatted as "filename:linenum"
        
        :return: "filename:linenum"
        :rtype: str
        """

    @staticmethod
    def getSourceInfoWithFallbackToParent(diea: DIEAggregate) -> DWARFSourceInfo:
        """
        Creates a new :obj:`DWARFSourceInfo` instance from the supplied :obj:`DIEAggregate`,
        falling back to the parent containing DIE record if the first record did not have any
        source info.
        
        :param DIEAggregate diea: :obj:`DIEAggregate` to query for source info.
        :return: new :obj:`DWARFSourceInfo` with filename:linenum info, or null if no info
        present in the specified DIEA and its parent.
        :rtype: DWARFSourceInfo
        """

    def hashCode(self) -> int:
        ...

    def lineNum(self) -> int:
        ...

    @property
    def descriptionStr(self) -> java.lang.String:
        ...


class DataTypeGraphComparator(java.lang.Object):
    """
    Compares two :obj:`DataType` directed graphs, calling a
    :meth:`method <DataTypePairObserver.observe>` that can observe each
    DataType pair that occupy equivalent positions in each graph.
     
    
    The first/left DataType graph is assumed to be composed of :obj:`DataTypeImpl` instances,
    and the second/right DataType graph is assumed to be composed of DataType DB instances.
     
    
    Only DataTypes in the left graph are followed and may lead to a possible match with
    the right graph.
     
    
    This class is used to help transfer mappings that point to impl DataTypes to also point them
    at the resultant 'db' DataTypes that are created by the DataTypeManager.
    """

    class DataTypePairObserver(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        def observe(self, dt1: ghidra.program.model.data.DataType, dt2: ghidra.program.model.data.DataType) -> bool:
            """
            Callback method called with a :obj:`DataType` from the first/left/src graph and
            its matching DataType element from the second/right/dest graph.
             
            
            This callback can choose to abort traversing the tree of child types if it returns
            false.  (ie. if this was a Pointer DataType, returning false would stop
            the graph comparator from comparing the DataType pointed to by this Pointer)
            
            :param ghidra.program.model.data.DataType dt1: element from the first/left/src DataType graph
            :param ghidra.program.model.data.DataType dt2: matching element from the second/right/dest DataType graph
            :return: false if abort this subtree, true if continue
            :rtype: bool
            """


    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def compare(preDT: ghidra.program.model.data.DataType, postDT: ghidra.program.model.data.DataType, observer: DataTypeGraphComparator.DataTypePairObserver):
        """
        Compares two :obj:`datatypes <DataType>` graphs, calling the observer callback
        for each paired DataType that occupy equivalent positions in each graph.
        
        :param ghidra.program.model.data.DataType preDT: - Original (impl) DataType from before submitting to DataTypeManager.
        :param ghidra.program.model.data.DataType postDT: - Result DataType from the DataTypeManager
        :param DataTypeGraphComparator.DataTypePairObserver observer: - Callback called for each position in the preDT graph that has a matching
        position in the postDT graph.
        """


class StringTable(java.lang.Object):
    """
    Represents a DWARF string table, backed by a memory section like .debug_str.
     
    
    Strings are read from the section the first time requested, and then cached in a weak lookup
    table.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader):
        """
        Creates a StringTable
        
        :param ghidra.app.util.bin.BinaryReader reader: :obj:`BinaryReader` .debug_str or .debug_line_str
        """

    def clear(self):
        ...

    def getStringAtOffset(self, offset: typing.Union[jpype.JLong, int]) -> str:
        """
        Returns the string found at ``offset``, or throws an :obj:`IOException`
        if the offset is out of bounds.
        
        :param jpype.JLong or int offset: location of string
        :return: a string, never null
        :rtype: str
        :raises IOException: if not valid location
        """

    def isValid(self, offset: typing.Union[jpype.JLong, int]) -> bool:
        """
        Returns true if the specified offset is a valid offset for this string table.
        
        :param jpype.JLong or int offset: location of possible string
        :return: boolean true if location is valid
        :rtype: bool
        """

    @staticmethod
    def of(reader: ghidra.app.util.bin.BinaryReader) -> StringTable:
        """
        Creates a StringTable instance, if the supplied BinaryReader is non-null.
        
        :param ghidra.app.util.bin.BinaryReader reader: BinaryReader
        :return: new instance, or null if reader is null
        :rtype: StringTable
        """

    @property
    def valid(self) -> jpype.JBoolean:
        ...

    @property
    def stringAtOffset(self) -> java.lang.String:
        ...


class DWARFFunctionImporter(java.lang.Object):
    """
    Iterates through all DIEAs in a :obj:`DWARFProgram` and creates Ghidra functions
    and variables.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, prog: DWARFProgram, monitor: ghidra.util.task.TaskMonitor):
        ...

    @staticmethod
    def hasDWARFProgModule(prog: ghidra.program.model.listing.Program, progModuleName: typing.Union[java.lang.String, str]) -> bool:
        ...

    def importFunctions(self):
        ...


class DWARFCompilationUnit(DWARFUnitHeader):
    """
    A DWARF CompilationUnit is a contiguous block of :obj:`DIE <DebugInfoEntry>` records found
    in a .debug_info section of an program.  The compilation unit block starts with a
    header that has a few important values and flags, and is followed by the DIE records.
     
    
    The first DIE record must be a DW_TAG_compile_unit.
     
    
    DIE records are identified by their byte offset in the .debug_info section.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, dwarfProgram: DWARFProgram, startOffset: typing.Union[jpype.JLong, int], endOffset: typing.Union[jpype.JLong, int], intSize: typing.Union[jpype.JInt, int], dwarfVersion: typing.Union[jpype.JShort, int], pointerSize: typing.Union[jpype.JByte, int], unitNumber: typing.Union[jpype.JInt, int], firstDIEOffset: typing.Union[jpype.JLong, int], codeToAbbreviationMap: collections.abc.Mapping):
        """
        This ctor is public only for junit tests.  Do not use directly.
        
        :param DWARFProgram dwarfProgram: :obj:`DWARFProgram`
        :param jpype.JLong or int startOffset: offset in provider where it starts
        :param jpype.JLong or int endOffset: offset in provider where it ends
        :param jpype.JInt or int intSize: 4 (DWARF_32) or 8 (DWARF_64)
        :param jpype.JShort or int dwarfVersion: 2-5
        :param jpype.JByte or int pointerSize: default size of pointers
        :param jpype.JInt or int unitNumber: this compunits ordinal in the file
        :param jpype.JLong or int firstDIEOffset: start of DIEs in the provider
        :param collections.abc.Mapping codeToAbbreviationMap: map of abbreviation numbers to :obj:`DWARFAbbreviation` instances
        """

    def getAbbreviation(self, ac: typing.Union[jpype.JInt, int]) -> DWARFAbbreviation:
        ...

    def getAddrTableBase(self) -> int:
        ...

    def getCodeToAbbreviationMap(self) -> java.util.Map[java.lang.Integer, DWARFAbbreviation]:
        ...

    def getCompUnitDIEA(self) -> DIEAggregate:
        """
        Returns this comp unit's root DIE as a DIE Aggregate.
        
        :return: the aggregate containing the root element of this comp unit
        :rtype: DIEAggregate
        """

    def getCompileDirectory(self) -> str:
        """
        Get the compile directory of the compile unit
        
        :return: the compile directory of the compile unit
        :rtype: str
        """

    def getFirstDIEOffset(self) -> int:
        ...

    def getLanguage(self) -> int:
        """
        Get the source language of the compile unit.
         
        
        See :obj:`DWARFSourceLanguage` for values.
        
        :return: the source language of the compile unit, or -1 if not set
        :rtype: int
        """

    def getLine(self) -> ghidra.app.util.bin.format.dwarf.line.DWARFLine:
        ...

    def getLocListsBase(self) -> int:
        ...

    def getName(self) -> str:
        """
        Get the filename that produced the compile unit
        
        :return: the filename that produced the compile unit
        :rtype: str
        """

    def getPCRange(self) -> DWARFRange:
        """
        Returns the range covered by this CU, as defined by the lo_pc and high_pc attribute values,
        defaulting to (0,0] if missing.
        
        :return: :obj:`DWARFRange` that this CU covers, never null
        :rtype: DWARFRange
        """

    def getPointerSize(self) -> int:
        """
        Returns the size of pointers in this compUnit.
        
        :return: the size in bytes of pointers
        :rtype: int
        """

    def getProducer(self) -> str:
        """
        Get the producer of the compile unit
        
        :return: the producer of the compile unit
        :rtype: str
        """

    def getRangeListsBase(self) -> int:
        ...

    def getStrOffsetsBase(self) -> int:
        ...

    def hasDWO(self) -> bool:
        ...

    def init(self, rootDIE: DebugInfoEntry):
        """
        Initializes this compunit with the root DIE (first DIE) of the compunit.  This comp unit
        isn't usable until this has happened.
        
        :param DebugInfoEntry rootDIE: :obj:`DebugInfoEntry`
        :raises IOException: if error reading data from the DIE
        """

    @staticmethod
    def readV4(partial: DWARFUnitHeader, reader: ghidra.app.util.bin.BinaryReader, abbrReader: ghidra.app.util.bin.BinaryReader, monitor: ghidra.util.task.TaskMonitor) -> DWARFCompilationUnit:
        """
        Creates a new :obj:`DWARFCompilationUnit` by reading a compilationUnit's header data
        from the debug_info section and the debug_abbr section and its compileUnit DIE (ie.
        the first DIE right after the header).
         
        
        Returns ``NULL`` if there was an ignorable error while reading the compilation unit (and
        leaves the input stream at the next compilation unit to read), otherwise throws
        an IOException if there was an unrecoverable error.
         
        
        Also returns ``NULL`` (and leaves the stream at EOF) if the remainder of the stream 
        is filled with null bytes.
        
        :param DWARFUnitHeader partial: already read partial unit header
        :param ghidra.app.util.bin.BinaryReader reader: .debug_info BinaryReader
        :param ghidra.app.util.bin.BinaryReader abbrReader: .debug_abbr BinaryReader
        :param ghidra.util.task.TaskMonitor monitor: the current task monitor
        :return: the read compilation unit, or null if the compilation unit was bad/empty and should 
        be ignored
        :rtype: DWARFCompilationUnit
        :raises DWARFException: if an invalid or unsupported DWARF version is read.
        :raises IOException: if the length of the compilation unit is invalid.
        :raises CancelledException: if the task has been canceled.
        """

    @staticmethod
    def readV5(partial: DWARFUnitHeader, reader: ghidra.app.util.bin.BinaryReader, abbrReader: ghidra.app.util.bin.BinaryReader, monitor: ghidra.util.task.TaskMonitor) -> DWARFCompilationUnit:
        """
        Creates a new :obj:`DWARFCompilationUnit` by reading a compilationUnit's header data
        from the debug_info section and the debug_abbr section and its compileUnit DIE (ie.
        the first DIE right after the header).
         
        
        Returns ``NULL`` if there was an ignorable error while reading the compilation unit (and
        leaves the input stream at the next compilation unit to read), otherwise throws
        an IOException if there was an unrecoverable error.
         
        
        Also returns ``NULL`` (and leaves the stream at EOF) if the remainder of the stream 
        is filled with null bytes.
        
        :param DWARFUnitHeader partial: already read partial unit header
        :param ghidra.app.util.bin.BinaryReader reader: .debug_info BinaryReader
        :param ghidra.app.util.bin.BinaryReader abbrReader: .debug_abbr BinaryReader
        :param ghidra.util.task.TaskMonitor monitor: the current task monitor
        :return: the read compilation unit, or null if the compilation unit was bad/empty and should 
        be ignored
        :rtype: DWARFCompilationUnit
        :raises DWARFException: if an invalid or unsupported DWARF version is read.
        :raises IOException: if the length of the compilation unit is invalid.
        :raises CancelledException: if the task has been canceled.
        """

    @property
    def line(self) -> ghidra.app.util.bin.format.dwarf.line.DWARFLine:
        ...

    @property
    def locListsBase(self) -> jpype.JLong:
        ...

    @property
    def compUnitDIEA(self) -> DIEAggregate:
        ...

    @property
    def language(self) -> jpype.JInt:
        ...

    @property
    def firstDIEOffset(self) -> jpype.JLong:
        ...

    @property
    def compileDirectory(self) -> java.lang.String:
        ...

    @property
    def abbreviation(self) -> DWARFAbbreviation:
        ...

    @property
    def pointerSize(self) -> jpype.JByte:
        ...

    @property
    def rangeListsBase(self) -> jpype.JLong:
        ...

    @property
    def pCRange(self) -> DWARFRange:
        ...

    @property
    def codeToAbbreviationMap(self) -> java.util.Map[java.lang.Integer, DWARFAbbreviation]:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def strOffsetsBase(self) -> jpype.JLong:
        ...

    @property
    def producer(self) -> java.lang.String:
        ...

    @property
    def addrTableBase(self) -> jpype.JLong:
        ...


class DWARFLocationListHeader(DWARFIndirectTableHeader):
    """
    Header found at the start of a set of DWARFLocationList entries, which are stored sequentially
    in the :obj:`.debug_loclists <DWARFSectionNames.DEBUG_LOCLISTS>` section.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, startOffset: typing.Union[jpype.JLong, int], endOffset: typing.Union[jpype.JLong, int], firstElementOffset: typing.Union[jpype.JLong, int], offsetIntSize: typing.Union[jpype.JInt, int], offsetEntryCount: typing.Union[jpype.JInt, int], addressSize: typing.Union[jpype.JInt, int], segmentSelectorSize: typing.Union[jpype.JInt, int]):
        ...

    @staticmethod
    def read(reader: ghidra.app.util.bin.BinaryReader, defaultIntSize: typing.Union[jpype.JInt, int]) -> DWARFLocationListHeader:
        ...


class DWARFRange(java.lang.Comparable[DWARFRange]):
    """
    Holds the start (inclusive) and end (exclusive, 1 past the last included address) addresses 
    of a range.
     
    
    DWARF ranges are slightly different than Ghidra :obj:`ranges <AddressRange>` because the
    end address of a Ghidra AddressRange is inclusive, and the DWARF range is exclusive.
     
    
    DWARF ranges can represent an empty range, Ghidra AddressRanges can not.
    
    Ghidra AddressRanges can include the maximum 64bit address (0xffffffffffffffff), but DWARF ranges
    can not include that.
    """

    class_: typing.ClassVar[java.lang.Class]
    EMPTY: typing.Final[DWARFRange]

    def __init__(self, start: typing.Union[jpype.JLong, int], end: typing.Union[jpype.JLong, int]):
        """
        Constructs a new :obj:`DWARFRange` using start and end values.
        
        :param jpype.JLong or int start: long starting address, inclusive
        :param jpype.JLong or int end: long ending address, exclusive
        """

    def contains(self, addr: typing.Union[jpype.JLong, int]) -> bool:
        ...

    def getFrom(self) -> int:
        """
        Returns starting address.
        
        :return: long starting address
        :rtype: int
        """

    def getTo(self) -> int:
        """
        Returns ending address, exclusive.
        
        :return: long ending address, exclusive.
        :rtype: int
        """

    def isEmpty(self) -> bool:
        ...

    @property
    def from_(self) -> jpype.JLong:
        ...

    @property
    def to(self) -> jpype.JLong:
        ...

    @property
    def empty(self) -> jpype.JBoolean:
        ...


class DWARFRangeList(java.lang.Object):
    """
    Represents a list of :obj:`DWARFRange`s.
    """

    class_: typing.ClassVar[java.lang.Class]
    EMTPY: typing.Final[DWARFRangeList]

    @typing.overload
    def __init__(self, singleRange: DWARFRange):
        ...

    @typing.overload
    def __init__(self, ranges: java.util.List[DWARFRange]):
        ...

    def get(self, index: typing.Union[jpype.JInt, int]) -> DWARFRange:
        ...

    def getFirst(self) -> DWARFRange:
        ...

    def getFirstAddress(self) -> int:
        ...

    def getFlattenedRange(self) -> DWARFRange:
        ...

    def getLast(self) -> DWARFRange:
        ...

    def getListCount(self) -> int:
        ...

    def isEmpty(self) -> bool:
        ...

    def ranges(self) -> java.util.List[DWARFRange]:
        ...

    @staticmethod
    def readV4(reader: ghidra.app.util.bin.BinaryReader, cu: DWARFCompilationUnit) -> DWARFRangeList:
        """
        Reads a v4 :obj:`DWARFRangeList` from the .debug_ranges stream.
        
        :param ghidra.app.util.bin.BinaryReader reader: stream positioned to the start of a .debug_ranges range list
        :param DWARFCompilationUnit cu: the compUnit referring to this range
        :return: new :obj:`DWARFRangeList`, never null
        :rtype: DWARFRangeList
        :raises IOException: if error reading
        """

    @staticmethod
    def readV5(reader: ghidra.app.util.bin.BinaryReader, cu: DWARFCompilationUnit) -> DWARFRangeList:
        """
        Reads a v5 :obj:`DWARFRangeList` from the .debug_rnglists stream.
        
        :param ghidra.app.util.bin.BinaryReader reader: stream positioned to the start of a .debug_rnglists range list
        :param DWARFCompilationUnit cu: the compUnit referring to this range
        :return: new :obj:`DWARFRangeList`, never null
        :rtype: DWARFRangeList
        :raises IOException: if error reading
        """

    @property
    def flattenedRange(self) -> DWARFRange:
        ...

    @property
    def last(self) -> DWARFRange:
        ...

    @property
    def firstAddress(self) -> jpype.JLong:
        ...

    @property
    def listCount(self) -> jpype.JInt:
        ...

    @property
    def first(self) -> DWARFRange:
        ...

    @property
    def empty(self) -> jpype.JBoolean:
        ...


class DWARFSourceLanguage(java.lang.Object):
    """
    DWARF source lang consts from www.dwarfstd.org/doc/DWARF4.pdf.
     
    
    TODO: The PDF also lists the default lower bound for array dw_tag_subrange_type
    attributes based on this value.
    """

    class_: typing.ClassVar[java.lang.Class]
    DW_LANG_C89: typing.Final = 1
    DW_LANG_C: typing.Final = 2
    DW_LANG_Ada83: typing.Final = 3
    DW_LANG_C_plus_plus: typing.Final = 4
    DW_LANG_Cobol74: typing.Final = 5
    DW_LANG_Cobol85: typing.Final = 6
    DW_LANG_Fortran77: typing.Final = 7
    DW_LANG_Fortran90: typing.Final = 8
    DW_LANG_Pascal83: typing.Final = 9
    DW_LANG_Modula2: typing.Final = 10
    DW_LANG_Java: typing.Final = 11
    DW_LANG_C99: typing.Final = 12
    DW_LANG_Ada95: typing.Final = 13
    DW_LANG_Fortran95: typing.Final = 14
    DW_LANG_PL1: typing.Final = 15
    DW_LANG_ObjC: typing.Final = 16
    DW_LANG_ObjC_plus_plus: typing.Final = 17
    DW_LANG_UPC: typing.Final = 18
    DW_LANG_D: typing.Final = 19
    DW_LANG_Python: typing.Final = 20
    DW_LANG_OpenCL: typing.Final = 21
    DW_LANG_Go: typing.Final = 22
    DW_LANG_Modula3: typing.Final = 23
    DW_LANG_Haskell: typing.Final = 24
    DW_LANG_C_plus_plus_03: typing.Final = 25
    DW_LANG_C_plus_plus_11: typing.Final = 26
    DW_LANG_OCaml: typing.Final = 27
    DW_LANG_Rust: typing.Final = 28
    DW_LANG_C11: typing.Final = 29
    DW_LANG_Swift: typing.Final = 30
    DW_LANG_Julia: typing.Final = 31
    DW_LANG_Dylan: typing.Final = 32
    DW_LANG_C_plus_plus_14: typing.Final = 33
    DW_LANG_Fortran03: typing.Final = 34
    DW_LANG_Fortran08: typing.Final = 35
    DW_LANG_RenderScript: typing.Final = 36
    DW_LANG_BLISS: typing.Final = 37
    DW_LANG_lo_user: typing.Final = 32768
    DW_LANG_hi_user: typing.Final = 65535
    DW_LANG_Mips_Assembler: typing.Final = 32769
    DW_LANG_GOOGLE_RenderScript: typing.Final = 36439
    DW_LANG_SUN_Assembler: typing.Final = 36865
    DW_LANG_ALTIUM_Assembler: typing.Final = 37121
    DW_LANG_BORLAND_Delphi: typing.Final = 45056

    def __init__(self):
        ...


class DWARFAccessibility(java.lang.Enum[DWARFAccessibility]):
    """
    DWARF accessibility consts from www.dwarfstd.org/doc/DWARF4.pdf
    """

    class_: typing.ClassVar[java.lang.Class]
    DW_ACCESS_public: typing.Final[DWARFAccessibility]
    DW_ACCESS_protected: typing.Final[DWARFAccessibility]
    DW_ACCESS_private: typing.Final[DWARFAccessibility]

    @staticmethod
    def find(key: java.lang.Number) -> DWARFAccessibility:
        """
        Find the accessibility value given a Number value.
        
        :param java.lang.Number key: Number value to check
        :return: DWARFAccessibility enum if it exists
        :rtype: DWARFAccessibility
        :raises IllegalArgumentException: if the key is not found
        """

    def getValue(self) -> int:
        """
        Get the integer value of this enum.
        
        :return: the integer value of the enum
        :rtype: int
        """

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> DWARFAccessibility:
        ...

    @staticmethod
    def values() -> jpype.JArray[DWARFAccessibility]:
        ...

    @property
    def value(self) -> jpype.JInt:
        ...


class DWARFVariable(java.lang.Object):
    """
    Represents a function's parameter or local variable; or a global variable.
    """

    class_: typing.ClassVar[java.lang.Class]
    name: DWARFName
    type: ghidra.program.model.data.DataType
    lexicalOffset: jpype.JLong
    isOutputParameter: jpype.JBoolean
    isExternal: jpype.JBoolean
    isThis: jpype.JBoolean
    sourceInfo: DWARFSourceInfo

    def addRamStorage(self, offset: typing.Union[jpype.JLong, int]):
        ...

    def addRegisterStorage(self, registers: java.util.List[ghidra.program.model.lang.Register]):
        ...

    def addStackStorage(self, offset: typing.Union[jpype.JLong, int], length: typing.Union[jpype.JInt, int]):
        ...

    def asLocalVariable(self) -> ghidra.program.model.listing.Variable:
        ...

    def asParameter(self, includeStorageDetail: typing.Union[jpype.JBoolean, bool]) -> ghidra.program.model.listing.Parameter:
        ...

    def asParameterDef(self) -> ghidra.program.model.data.ParameterDefinition:
        ...

    def asReturnParameter(self, includeStorageDetail: typing.Union[jpype.JBoolean, bool]) -> ghidra.program.model.listing.Parameter:
        ...

    def clearStorage(self):
        ...

    @staticmethod
    def fromDataType(dfunc: DWARFFunction, dt: ghidra.program.model.data.DataType) -> DWARFVariable:
        """
        Creates an unnamed, storage-less :obj:`DWARFVariable` from a DataType.
        
        :param DWARFFunction dfunc: containing function
        :param ghidra.program.model.data.DataType dt: :obj:`DataType` of the variable
        :return: new :obj:`DWARFVariable`, never null
        :rtype: DWARFVariable
        """

    def getDeclInfoString(self) -> str:
        ...

    def getRamAddress(self) -> ghidra.program.model.address.Address:
        """
        If this is a static/global variable, stored at a ram address, return it's
        ram address.
        
        :return: address of where this variable is stored, null if not ram address
        :rtype: ghidra.program.model.address.Address
        """

    def getStackOffset(self) -> int:
        """
        If this is a stack variable, return its stack offset.
        
        :return: its stack offset
        :rtype: int
        """

    def getStorageSize(self) -> int:
        ...

    def getVariableStorage(self) -> ghidra.program.model.listing.VariableStorage:
        ...

    def getVarnodes(self) -> java.util.List[ghidra.program.model.pcode.Varnode]:
        ...

    def isEmptyArray(self) -> bool:
        ...

    def isLocationValidOnEntry(self) -> bool:
        ...

    def isMissingStorage(self) -> bool:
        ...

    def isRamStorage(self) -> bool:
        """
        
        
        :return: true if this variable's storage is in ram
        :rtype: bool
        """

    def isStackStorage(self) -> bool:
        """
        
        
        :return: true if this variable is stored on the stack
        :rtype: bool
        """

    def isVoidType(self) -> bool:
        ...

    def isZeroByte(self) -> bool:
        ...

    @staticmethod
    def readGlobalVariable(diea: DIEAggregate) -> DWARFVariable:
        """
        Reads a static/global variable.
        
        :param DIEAggregate diea: :obj:`DIEAggregate` DW_TAG_variable
        :return: new :obj:`DWARFVariable` that represents the global variable, or
        **null** if error reading storage info
        :rtype: DWARFVariable
        """

    @staticmethod
    def readLocalVariable(diea: DIEAggregate, dfunc: DWARFFunction, offsetFromFuncStart: typing.Union[jpype.JLong, int]) -> DWARFVariable:
        """
        Reads a local variable.
        
        :param DIEAggregate diea: :obj:`DIEAggregate` DW_TAG_variable
        :param DWARFFunction dfunc: :obj:`DWARFFunction` that this local var belongs to
        :param jpype.JLong or int offsetFromFuncStart: offset from start of containing function
        :return: new DWARFVariable that represents a local var, or **null** if 
        error reading storage info
        :rtype: DWARFVariable
        """

    @staticmethod
    def readParameter(diea: DIEAggregate, dfunc: DWARFFunction, paramOrdinal: typing.Union[jpype.JInt, int]) -> DWARFVariable:
        """
        Reads a parameter.
        
        :param DIEAggregate diea: :obj:`DIEAggregate` DW_TAG_formal_parameter
        :param DWARFFunction dfunc: :obj:`DWARFFunction` that this parameter is attached to
        :param jpype.JInt or int paramOrdinal: ordinal in containing list
        :return: new parameter, never null, possibly without storage info
        :rtype: DWARFVariable
        """

    def setRamStorage(self, offset: typing.Union[jpype.JLong, int]):
        """
        Assign storage for this variable in a ram data location.
        
        :param jpype.JLong or int offset: address offset
        """

    def setRegisterStorage(self, registers: java.util.List[ghidra.program.model.lang.Register]):
        """
        Assign storage for this variable via a list of registers.
        
        :param java.util.List[ghidra.program.model.lang.Register] registers: registers that contain the data
        """

    def setStackStorage(self, offset: typing.Union[jpype.JLong, int]):
        """
        Assign storage for this variable at a stack offset.
        
        :param jpype.JLong or int offset: stack offset
        """

    def setVarnodes(self, newStorage: java.util.List[ghidra.program.model.pcode.Varnode]):
        ...

    @property
    def ramAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def stackOffset(self) -> jpype.JLong:
        ...

    @property
    def declInfoString(self) -> java.lang.String:
        ...

    @property
    def missingStorage(self) -> jpype.JBoolean:
        ...

    @property
    def stackStorage(self) -> jpype.JBoolean:
        ...

    @property
    def ramStorage(self) -> jpype.JBoolean:
        ...

    @property
    def storageSize(self) -> jpype.JInt:
        ...

    @property
    def zeroByte(self) -> jpype.JBoolean:
        ...

    @property
    def voidType(self) -> jpype.JBoolean:
        ...

    @property
    def locationValidOnEntry(self) -> jpype.JBoolean:
        ...

    @property
    def variableStorage(self) -> ghidra.program.model.listing.VariableStorage:
        ...

    @property
    def emptyArray(self) -> jpype.JBoolean:
        ...

    @property
    def varnodes(self) -> java.util.List[ghidra.program.model.pcode.Varnode]:
        ...

    @varnodes.setter
    def varnodes(self, value: java.util.List[ghidra.program.model.pcode.Varnode]):
        ...


class DWARFRegisterMappings(java.lang.Object):
    """
    Immutable mapping information between DWARF and Ghidra.
     
    
    Use :obj:`DWARFRegisterMappingsManager` to get an instance for a Program's specific
    language.
     
    
    The data held in this class is read from DWARF register mapping information contained 
    in xml files referenced from the language *.ldefs file in an
    <external_name tool="DWARF.register.mapping.file" name="register_mapping_filename_here"/> 
     
    
    The format is:
     
    <dwarf>
    <register_mappings>
        <!-- Simple single mapping: -->
        <!-- NN == dwarf register number -->
        <!-- RegName == Ghidra register name string -->
        <!-- <register_mapping dwarf="NN" ghidra="RegName" /> -->
           
        <!-- Example: -->
        <register_mapping dwarf="0" ghidra="r0" />
         
        <!-- Single mapping specifying stack pointer: -->
        <!-- NN == dwarf register number -->
        <!-- RegName == Ghidra register name string -->
        <!-- <register_mapping dwarf="NN" ghidra="RegName" stackpointer="true"/> -->
           
        <!-- Example: -->
        <register_mapping dwarf="4" ghidra="ESP" stackpointer="true"/>
         
        <!-- Multiple mapping: -->
        <!-- NN == dwarf register number -->
        <!-- XX == number of times to repeat -->
        <!-- RegNameYY == Ghidra register name string with a mandatory integer suffix -->
        <!-- <register_mapping dwarf="NN" ghidra="RegNameYY" auto_count="XX"/> -->
           
        <!-- Example, creates mapping from 0..12 to r0..r12: -->
        <register_mapping dwarf="0" ghidra="r0" auto_count="12"/>
         
        <!-- Example, creates mapping from 17..32 to XMM0..XMM15: -->
        <register_mapping dwarf="17" ghidra="XMM0" auto_count="16"/>
         
    </register_mappings>
       
        <!-- Call Frame CFA Value: -->
    <call_frame_cfa value="NN"/>
       
        <!-- Use Formal Parameter Storage toggle: -->
    <use_formal_parameter_storage/>
    </dwarf>
    """

    class_: typing.ClassVar[java.lang.Class]
    DUMMY: typing.Final[DWARFRegisterMappings]

    def __init__(self, regmap: collections.abc.Mapping, callFrameCFA: typing.Union[jpype.JLong, int], stackPointerIndex: typing.Union[jpype.JInt, int], useFPS: typing.Union[jpype.JBoolean, bool]):
        ...

    def getCallFrameCFA(self) -> int:
        ...

    def getDWARFStackPointerRegNum(self) -> int:
        ...

    def getGhidraReg(self, dwarfRegNum: typing.Union[jpype.JInt, int]) -> ghidra.program.model.lang.Register:
        ...

    def isUseFormalParameterStorage(self) -> bool:
        ...

    @property
    def ghidraReg(self) -> ghidra.program.model.lang.Register:
        ...

    @property
    def useFormalParameterStorage(self) -> jpype.JBoolean:
        ...

    @property
    def dWARFStackPointerRegNum(self) -> jpype.JInt:
        ...

    @property
    def callFrameCFA(self) -> jpype.JLong:
        ...


class DWARFIndirectTableHeader(java.lang.Object):
    """
    Common base functionality of indirect table headers (DWARFAddressListHeader, 
    DWARFLocationListHeader, etc)
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, startOffset: typing.Union[jpype.JLong, int], endOffset: typing.Union[jpype.JLong, int], firstElementOffset: typing.Union[jpype.JLong, int]):
        ...

    def getEndOffset(self) -> int:
        ...

    def getFirstElementOffset(self) -> int:
        ...

    def getOffset(self, index: typing.Union[jpype.JInt, int], reader: ghidra.app.util.bin.BinaryReader) -> int:
        ...

    def getStartOffset(self) -> int:
        ...

    @property
    def endOffset(self) -> jpype.JLong:
        ...

    @property
    def startOffset(self) -> jpype.JLong:
        ...

    @property
    def firstElementOffset(self) -> jpype.JLong:
        ...


class DWARFRangeListHeader(DWARFIndirectTableHeader):
    """
    Header found at the start of a set of DWARFRangeList entries, which are stored sequentially
    in the :obj:`.debug_rnglists <DWARFSectionNames.DEBUG_RNGLISTS>` section.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, startOffset: typing.Union[jpype.JLong, int], endOffset: typing.Union[jpype.JLong, int], firstElementOffset: typing.Union[jpype.JLong, int], offsetIntSize: typing.Union[jpype.JInt, int], offsetEntryCount: typing.Union[jpype.JInt, int], addressSize: typing.Union[jpype.JInt, int], segmentSelectorSize: typing.Union[jpype.JInt, int]):
        ...

    @staticmethod
    def read(reader: ghidra.app.util.bin.BinaryReader, defaultIntSize: typing.Union[jpype.JInt, int]) -> DWARFRangeListHeader:
        ...


class DWARFFunction(java.lang.Object):
    """
    Represents a function that was read from DWARF information.
    """

    class CommitMode(java.lang.Enum[DWARFFunction.CommitMode]):

        class_: typing.ClassVar[java.lang.Class]
        SKIP: typing.Final[DWARFFunction.CommitMode]
        FORMAL: typing.Final[DWARFFunction.CommitMode]
        STORAGE: typing.Final[DWARFFunction.CommitMode]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> DWARFFunction.CommitMode:
            ...

        @staticmethod
        def values() -> jpype.JArray[DWARFFunction.CommitMode]:
            ...


    class_: typing.ClassVar[java.lang.Class]
    diea: DIEAggregate
    name: DWARFName
    namespace: ghidra.program.model.symbol.Namespace
    address: ghidra.program.model.address.Address
    frameBase: jpype.JLong
    function: ghidra.program.model.listing.Function
    callingConventionName: java.lang.String
    retval: DWARFVariable
    params: java.util.List[DWARFVariable]
    varArg: jpype.JBoolean
    localVars: java.util.List[DWARFVariable]
    localVarErrors: jpype.JBoolean
    signatureCommitMode: DWARFFunction.CommitMode
    noReturn: jpype.JBoolean
    sourceInfo: DWARFSourceInfo
    isExternal: jpype.JBoolean

    def asFunctionDefinition(self, includeCC: typing.Union[jpype.JBoolean, bool]) -> ghidra.program.model.data.FunctionDefinition:
        """
        Returns a :obj:`FunctionDefinition` that reflects this function's information.
        
        :param jpype.JBoolean or bool includeCC: boolean flag, if true the returned funcdef will include calling convention
        :return: :obj:`FunctionDefinition` that reflects this function's information
        :rtype: ghidra.program.model.data.FunctionDefinition
        """

    def commitLocalVariable(self, dvar: DWARFVariable):
        ...

    def getAllLocalVariableNames(self) -> java.util.List[java.lang.String]:
        ...

    def getAllParamNames(self) -> java.util.List[java.lang.String]:
        ...

    def getBody(self) -> ghidra.program.model.address.AddressSetView:
        ...

    def getCallingConventionName(self) -> str:
        ...

    def getDescriptiveName(self) -> str:
        ...

    def getEntryPc(self) -> int:
        ...

    def getExistingLocalVariableNames(self) -> java.util.List[java.lang.String]:
        ...

    @staticmethod
    def getFuncBody(diea: DIEAggregate, flattenDisjoint: typing.Union[jpype.JBoolean, bool]) -> ghidra.program.model.address.AddressRange:
        ...

    @staticmethod
    def getFuncBodyRanges(diea: DIEAggregate) -> DWARFRangeList:
        ...

    def getLocalVarByOffset(self, offset: typing.Union[jpype.JLong, int]) -> DWARFVariable:
        """
        Returns the DWARFVariable that starts at the specified stack offset.
        
        :param jpype.JLong or int offset: stack offset
        :return: local variable that starts at offset, or null if not present
        :rtype: DWARFVariable
        """

    def getNonParamSymbolNames(self) -> java.util.List[java.lang.String]:
        ...

    def getParameterDefinitions(self) -> jpype.JArray[ghidra.program.model.data.ParameterDefinition]:
        """
        Returns the parameters of this function as :obj:`ParameterDefinition`s.
        
        :return: array of :obj:`ParameterDefinition`s
        :rtype: jpype.JArray[ghidra.program.model.data.ParameterDefinition]
        """

    def getParameters(self, includeStorageDetail: typing.Union[jpype.JBoolean, bool]) -> java.util.List[ghidra.program.model.listing.Parameter]:
        """
        Returns this function's parameters as a list of :obj:`Parameter` instances.
        
        :param jpype.JBoolean or bool includeStorageDetail: boolean flag, if true storage information will be included, if
        false, VariableStorage.UNASSIGNED_STORAGE will be used
        :return: list of Parameters
        :rtype: java.util.List[ghidra.program.model.listing.Parameter]
        :raises InvalidInputException: if bad information in param storage
        """

    def getProgram(self) -> DWARFProgram:
        ...

    def getRangeList(self) -> DWARFRangeList:
        ...

    def hasConflictWithExistingLocalVariableStorage(self, dvar: DWARFVariable) -> bool:
        ...

    def hasConflictWithParamStorage(self, dvar: DWARFVariable) -> bool:
        ...

    def isInLocalVarStorageArea(self, offset: typing.Union[jpype.JLong, int]) -> bool:
        """
        Returns true if the specified stack offset is within the function's local variable
        storage area.
        
        :param jpype.JLong or int offset: stack offset to test
        :return: true if stack offset is within this function's local variable area
        :rtype: bool
        """

    @staticmethod
    def read(diea: DIEAggregate) -> DWARFFunction:
        """
        Create a function instance from the information found in the specified DIEA.
        
        :param DIEAggregate diea: DW_TAG_subprogram :obj:`DIEAggregate`
        :return: new :obj:`DWARFFunction`, or null if invalid DWARF information
        :rtype: DWARFFunction
        :raises IOException: if error accessing attribute values
        :raises DWARFExpressionException: if error accessing attribute values
        """

    def runFixups(self):
        ...

    def syncWithExistingGhidraFunction(self, createIfMissing: typing.Union[jpype.JBoolean, bool]) -> bool:
        ...

    def updateFunctionSignature(self):
        ...

    @property
    def localVarByOffset(self) -> DWARFVariable:
        ...

    @property
    def existingLocalVariableNames(self) -> java.util.List[java.lang.String]:
        ...

    @property
    def descriptiveName(self) -> java.lang.String:
        ...

    @property
    def parameterDefinitions(self) -> jpype.JArray[ghidra.program.model.data.ParameterDefinition]:
        ...

    @property
    def entryPc(self) -> jpype.JLong:
        ...

    @property
    def program(self) -> DWARFProgram:
        ...

    @property
    def body(self) -> ghidra.program.model.address.AddressSetView:
        ...

    @property
    def allLocalVariableNames(self) -> java.util.List[java.lang.String]:
        ...

    @property
    def allParamNames(self) -> java.util.List[java.lang.String]:
        ...

    @property
    def inLocalVarStorageArea(self) -> jpype.JBoolean:
        ...

    @property
    def rangeList(self) -> DWARFRangeList:
        ...

    @property
    def nonParamSymbolNames(self) -> java.util.List[java.lang.String]:
        ...

    @property
    def parameters(self) -> java.util.List[ghidra.program.model.listing.Parameter]:
        ...


class DWARFTag(java.lang.Enum[DWARFTag]):
    """
    Identifier/purpose of a DWARF DIE record.
     
    
    Users of this enum should be tolerant of unknown tag id values.  See 
    :obj:`DWARFAbbreviation`'s tagId.
    """

    class_: typing.ClassVar[java.lang.Class]
    DW_TAG_array_type: typing.Final[DWARFTag]
    DW_TAG_class_type: typing.Final[DWARFTag]
    DW_TAG_entry_point: typing.Final[DWARFTag]
    DW_TAG_enumeration_type: typing.Final[DWARFTag]
    DW_TAG_formal_parameter: typing.Final[DWARFTag]
    DW_TAG_imported_declaration: typing.Final[DWARFTag]
    DW_TAG_label: typing.Final[DWARFTag]
    DW_TAG_lexical_block: typing.Final[DWARFTag]
    DW_TAG_member: typing.Final[DWARFTag]
    DW_TAG_pointer_type: typing.Final[DWARFTag]
    DW_TAG_reference_type: typing.Final[DWARFTag]
    DW_TAG_compile_unit: typing.Final[DWARFTag]
    DW_TAG_string_type: typing.Final[DWARFTag]
    DW_TAG_structure_type: typing.Final[DWARFTag]
    DW_TAG_subroutine_type: typing.Final[DWARFTag]
    DW_TAG_typedef: typing.Final[DWARFTag]
    DW_TAG_union_type: typing.Final[DWARFTag]
    DW_TAG_unspecified_parameters: typing.Final[DWARFTag]
    DW_TAG_variant: typing.Final[DWARFTag]
    DW_TAG_common_block: typing.Final[DWARFTag]
    DW_TAG_common_inclusion: typing.Final[DWARFTag]
    DW_TAG_inheritance: typing.Final[DWARFTag]
    DW_TAG_inlined_subroutine: typing.Final[DWARFTag]
    DW_TAG_module: typing.Final[DWARFTag]
    DW_TAG_ptr_to_member_type: typing.Final[DWARFTag]
    DW_TAG_set_type: typing.Final[DWARFTag]
    DW_TAG_subrange_type: typing.Final[DWARFTag]
    DW_TAG_with_stmt: typing.Final[DWARFTag]
    DW_TAG_access_declaration: typing.Final[DWARFTag]
    DW_TAG_base_type: typing.Final[DWARFTag]
    DW_TAG_catch_block: typing.Final[DWARFTag]
    DW_TAG_const_type: typing.Final[DWARFTag]
    DW_TAG_constant: typing.Final[DWARFTag]
    DW_TAG_enumerator: typing.Final[DWARFTag]
    DW_TAG_file_type: typing.Final[DWARFTag]
    DW_TAG_friend: typing.Final[DWARFTag]
    DW_TAG_namelist: typing.Final[DWARFTag]
    DW_TAG_namelist_item: typing.Final[DWARFTag]
    DW_TAG_packed_type: typing.Final[DWARFTag]
    DW_TAG_subprogram: typing.Final[DWARFTag]
    DW_TAG_template_type_param: typing.Final[DWARFTag]
    DW_TAG_template_value_param: typing.Final[DWARFTag]
    DW_TAG_thrown_type: typing.Final[DWARFTag]
    DW_TAG_try_block: typing.Final[DWARFTag]
    DW_TAG_variant_part: typing.Final[DWARFTag]
    DW_TAG_variable: typing.Final[DWARFTag]
    DW_TAG_volatile_type: typing.Final[DWARFTag]
    DW_TAG_dwarf_procedure: typing.Final[DWARFTag]
    DW_TAG_restrict_type: typing.Final[DWARFTag]
    DW_TAG_interface_type: typing.Final[DWARFTag]
    DW_TAG_namespace: typing.Final[DWARFTag]
    DW_TAG_imported_module: typing.Final[DWARFTag]
    DW_TAG_unspecified_type: typing.Final[DWARFTag]
    DW_TAG_partial_unit: typing.Final[DWARFTag]
    DW_TAG_imported_unit: typing.Final[DWARFTag]
    DW_TAG_mutable_type: typing.Final[DWARFTag]
    DW_TAG_condition: typing.Final[DWARFTag]
    DW_TAG_shared_type: typing.Final[DWARFTag]
    DW_TAG_type_unit: typing.Final[DWARFTag]
    DW_TAG_rvalue_reference_type: typing.Final[DWARFTag]
    DW_TAG_template_alias: typing.Final[DWARFTag]
    DW_TAG_coarray_type: typing.Final[DWARFTag]
    DW_TAG_generic_subrange: typing.Final[DWARFTag]
    DW_TAG_dynamic_type: typing.Final[DWARFTag]
    DW_TAG_atomic_type: typing.Final[DWARFTag]
    DW_TAG_call_site: typing.Final[DWARFTag]
    DW_TAG_call_site_parameter: typing.Final[DWARFTag]
    DW_TAG_skeleton_unit: typing.Final[DWARFTag]
    DW_TAG_immutable_type: typing.Final[DWARFTag]
    DW_TAG_lo_user: typing.Final[DWARFTag]
    DW_TAG_MIPS_loop: typing.Final[DWARFTag]
    DW_TAG_HP_array_descriptor: typing.Final[DWARFTag]
    DW_TAG_HP_Bliss_field: typing.Final[DWARFTag]
    DW_TAG_HP_Bliss_field_set: typing.Final[DWARFTag]
    DW_TAG_format_label: typing.Final[DWARFTag]
    DW_TAG_function_template: typing.Final[DWARFTag]
    DW_TAG_class_template: typing.Final[DWARFTag]
    DW_TAG_GNU_BINCL: typing.Final[DWARFTag]
    DW_TAG_GNU_EINCL: typing.Final[DWARFTag]
    DW_TAG_GNU_template_template_param: typing.Final[DWARFTag]
    DW_TAG_GNU_template_parameter_pack: typing.Final[DWARFTag]
    DW_TAG_GNU_formal_parameter_pack: typing.Final[DWARFTag]
    DW_TAG_gnu_call_site: typing.Final[DWARFTag]
    DW_TAG_gnu_call_site_parameter: typing.Final[DWARFTag]
    DW_TAG_APPLE_ptrauth_type: typing.Final[DWARFTag]
    DW_TAG_hi_user: typing.Final[DWARFTag]
    DW_TAG_UNKNOWN: typing.Final[DWARFTag]

    def getContainerTypeName(self) -> str:
        """
        Returns a string that describes what kind of object is specified by the :obj:`DIEAggregate`.
         
        
        Used to create a name for anonymous types.
        
        :return: String describing the type of the DIEA.
        :rtype: str
        """

    def getId(self) -> int:
        ...

    def getSymbolType(self) -> ghidra.program.model.symbol.SymbolType:
        """
        Returns the :obj:`SymbolType` that corresponds to a DWARF tag
         
        
        The mapping between tag type and SymbolType is not exact.  There is no matching
        SymbolType for a DWARF static variable, so "LOCAL_VAR" is used currently.
         
        
        This mainly is used in constructing a NamespacePath, and the only critical usage
        there is Namespace vs. Class vs. everything else.
        
        :return: :obj:`SymbolType`
        :rtype: ghidra.program.model.symbol.SymbolType
        """

    def isFuncDefType(self) -> bool:
        ...

    def isNameSpaceContainer(self) -> bool:
        """
        Returns true if the children of this DIE are within a new namespace.
         
        
        Ie. Namespaces, subprogram, class, interface, struct, union, enum
        
        :return: true if the children of this DIE are within a new namespace
        :rtype: bool
        """

    def isNamedType(self) -> bool:
        ...

    def isStructureType(self) -> bool:
        """
        Returns true if this DIE defines a structure-like element (class, struct, interface, union).
        
        :return: true if this DIE defines a structure-like element (class, struct, interface, union)
        :rtype: bool
        """

    def isType(self) -> bool:
        ...

    def name(self, rawTagId: typing.Union[jpype.JInt, int]) -> str:
        """
        Returns the name of this enum, falling back to the rawTagId value if this enum is the
        DW_TAG_UNKNOWN value.
        
        :param jpype.JInt or int rawTagId: tag id that corresponds to actual tag id found in the DWARF data
        :return: string name of this enum
        :rtype: str
        """

    @staticmethod
    def of(tagId: typing.Union[jpype.JInt, int]) -> DWARFTag:
        ...

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> DWARFTag:
        ...

    @staticmethod
    def values() -> jpype.JArray[DWARFTag]:
        ...

    @property
    def namedType(self) -> jpype.JBoolean:
        ...

    @property
    def structureType(self) -> jpype.JBoolean:
        ...

    @property
    def nameSpaceContainer(self) -> jpype.JBoolean:
        ...

    @property
    def funcDefType(self) -> jpype.JBoolean:
        ...

    @property
    def id(self) -> jpype.JInt:
        ...

    @property
    def type(self) -> jpype.JBoolean:
        ...

    @property
    def symbolType(self) -> ghidra.program.model.symbol.SymbolType:
        ...

    @property
    def containerTypeName(self) -> java.lang.String:
        ...


class DWARFRangeListEntry(java.lang.Object):
    """
    DWARF Range List Entry id
    """

    class_: typing.ClassVar[java.lang.Class]
    DW_RLE_end_of_list: typing.Final = 0
    DW_RLE_base_addressx: typing.Final = 1
    DW_RLE_startx_endx: typing.Final = 2
    DW_RLE_startx_length: typing.Final = 3
    DW_RLE_offset_pair: typing.Final = 4
    DW_RLE_base_address: typing.Final = 5
    DW_RLE_start_end: typing.Final = 6
    DW_RLE_start_length: typing.Final = 7

    def __init__(self):
        ...

    @staticmethod
    def toString(value: typing.Union[jpype.JLong, int]) -> str:
        ...


class DWARFImportSummary(java.lang.Object):
    """
    Information about what actions were performed during a DWARF import.
    """

    class_: typing.ClassVar[java.lang.Class]
    badSourceFileCount: jpype.JInt

    def __init__(self):
        ...

    def logSummaryResults(self):
        """
        Writes summary information to the :obj:`Msg` log.
        """


class DWARFName(java.lang.Object):
    """
    A immutable hierarchical path based name implementation that can be viewed as either
    :obj:`namespaces <Namespace>` or :obj:`categorypaths <CategoryPath>`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def asCategoryPath(self) -> ghidra.program.model.data.CategoryPath:
        """
        Converts this object into an equiv :obj:`CategoryPath`.
        
        :return: :obj:`CategoryPath`: "/organizational_cat_path/namespace1/namespace2/obj_name"
        :rtype: ghidra.program.model.data.CategoryPath
        """

    def asDataTypePath(self) -> ghidra.program.model.data.DataTypePath:
        """
        Converts this object into an equiv :obj:`DataTypePath`.
        
        :return: :obj:`DataTypePath`: { "/organizational_cat_path/namespace1/namespace2", "obj_name" }
        :rtype: ghidra.program.model.data.DataTypePath
        """

    def asNamespace(self, program: ghidra.program.model.listing.Program) -> ghidra.program.model.symbol.Namespace:
        """
        Converts this object into an equiv Ghidra :obj:`Namespace`, omitting the organizational
        category path (which only applies to DataTypes).
        
        :param ghidra.program.model.listing.Program program: :obj:`Program` where the namespace lives.
        :return: :obj:`Namespace`: "ROOT::namespace1::namespace2::obj_name"
        :rtype: ghidra.program.model.symbol.Namespace
        """

    def createChild(self, childOriginalName: typing.Union[java.lang.String, str], childName: typing.Union[java.lang.String, str], childType: ghidra.program.model.symbol.SymbolType) -> DWARFName:
        """
        Creates a :obj:`DWARFName` instance, which has a name that is contained with
        this instance's namespace, using the specified name and symbol type.
        
        :param java.lang.String or str childOriginalName: the unmodified name
        :param java.lang.String or str childName: the ghidra-ized name of the type/symbol/namespace/etc
        :param ghidra.program.model.symbol.SymbolType childType: the type of the object being named
        :return: new DWARFNameInfo instance
        :rtype: DWARFName
        """

    @staticmethod
    def createRoot(rootCategory: ghidra.program.model.data.CategoryPath) -> DWARFName:
        """
        Create a root name entry that will serve as the parent for all children.
        
        :param ghidra.program.model.data.CategoryPath rootCategory: :obj:`CategoryPath` in the data type manager that will contain
        any sub-categories that represent namespaces
        :return: a new :obj:`DWARFName` instance
        :rtype: DWARFName
        """

    @staticmethod
    def fromDataType(dataType: ghidra.program.model.data.DataType) -> DWARFName:
        """
        Create a :obj:`DWARFName` instance using the specified :obj:`DataType`'s name.
        
        :param ghidra.program.model.data.DataType dataType: :obj:`DataType`
        :return: new :obj:`DWARFName` using the same name / CategoryPath as the data type
        :rtype: DWARFName
        """

    @staticmethod
    def fromList(parent: DWARFName, names: java.util.List[java.lang.String]) -> DWARFName:
        """
        Create a child :obj:`DWARFName` instance of the specified parent.
         
        
        Example:
        
        fromList(parent, List.of("name1", "name2")) → parent_name/name1/name2
        
        :param DWARFName parent: :obj:`DWARFName` parent
        :param java.util.List[java.lang.String] names: list of names
        :return: new :obj:`DWARFName` instance that is a child of the parent
        :rtype: DWARFName
        """

    def getName(self) -> str:
        """
        Returns the name of this entry.
        
        :return: string name of this entry, safe to use to name a Ghidra object (datatype, namespace,
        etc)
        :rtype: str
        """

    def getNamespacePath(self) -> NamespacePath:
        """
        Returns the NamespacePath of this instance.
        
        :return: :obj:`NamespacePath` of this instance
        :rtype: NamespacePath
        """

    def getOrganizationalCategoryPath(self) -> ghidra.program.model.data.CategoryPath:
        """
        Returns the organizational category path.
        
        :return: organizational category path for dwarf names
        :rtype: ghidra.program.model.data.CategoryPath
        """

    def getOriginalName(self) -> str:
        """
        Returns the original name (unmodified by Ghidra-isms) of this entry.
        
        :return: original name
        :rtype: str
        """

    def getParent(self) -> DWARFName:
        """
        Returns the parent name
        
        :return: parent
        :rtype: DWARFName
        """

    def getParentCP(self) -> ghidra.program.model.data.CategoryPath:
        """
        Returns the parent's CategoryPath.
        
        :return: parent name's CategoryPath
        :rtype: ghidra.program.model.data.CategoryPath
        """

    def getParentNamespace(self, program: ghidra.program.model.listing.Program) -> ghidra.program.model.symbol.Namespace:
        """
        Returns the Ghidra :obj:`Namespace` that represents this entry's parent.
        
        :param ghidra.program.model.listing.Program program: the Ghidra program that contains the namespace
        :return: :obj:`Namespace` representing this entry's parent
        :rtype: ghidra.program.model.symbol.Namespace
        """

    def getType(self) -> ghidra.program.model.symbol.SymbolType:
        """
        Returns the SymbolType of this name.
        
        :return: :obj:`SymbolType` of this entry
        :rtype: ghidra.program.model.symbol.SymbolType
        """

    def isAnon(self) -> bool:
        """
        Returns true if the original name of this entry was blank.
        
        :return: boolean true if there was no original name
        :rtype: bool
        """

    def isNameModified(self) -> bool:
        """
        Returns true if this instance's :meth:`name <.getName>` value is different
        than its :meth:`original <.getOriginalName>` form.
        
        :return: boolean true if the original name doesn't match the ghidra-ized name
        :rtype: bool
        """

    def isRoot(self) -> bool:
        """
        Returns true if this instance has no parent and is considered the root.
        
        :return: boolean true if root name, false if not root
        :rtype: bool
        """

    def replaceName(self, newName: typing.Union[java.lang.String, str], newOriginalName: typing.Union[java.lang.String, str]) -> DWARFName:
        """
        Creates a new DWARFNameInfo instance, using this instance as the template, replacing
        the name with a new name.
        
        :param java.lang.String or str newName: name for the new instance
        :param java.lang.String or str newOriginalName: originalName for the new instance
        :return: new instance with new name
        :rtype: DWARFName
        """

    def replaceType(self, newType: ghidra.program.model.symbol.SymbolType) -> DWARFName:
        """
        Creates a new DWARFNameInfo instance, using this instance as the template, replacing
        the SymbolType with a new value.
        
        :param ghidra.program.model.symbol.SymbolType newType: new SymbolType value
        :return: new instance with the specified SymbolType
        :rtype: DWARFName
        """

    @property
    def originalName(self) -> java.lang.String:
        ...

    @property
    def anon(self) -> jpype.JBoolean:
        ...

    @property
    def parent(self) -> DWARFName:
        ...

    @property
    def root(self) -> jpype.JBoolean:
        ...

    @property
    def nameModified(self) -> jpype.JBoolean:
        ...

    @property
    def organizationalCategoryPath(self) -> ghidra.program.model.data.CategoryPath:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def parentNamespace(self) -> ghidra.program.model.symbol.Namespace:
        ...

    @property
    def namespacePath(self) -> NamespacePath:
        ...

    @property
    def type(self) -> ghidra.program.model.symbol.SymbolType:
        ...

    @property
    def parentCP(self) -> ghidra.program.model.data.CategoryPath:
        ...


class DWARFIdentifierCase(java.lang.Enum[DWARFIdentifierCase]):
    """
    DWARF identifier case consts from www.dwarfstd.org/doc/DWARF4.pdf
    """

    class_: typing.ClassVar[java.lang.Class]
    DW_ID_case_sensitive: typing.Final[DWARFIdentifierCase]
    DW_ID_up_case: typing.Final[DWARFIdentifierCase]
    DW_ID_down_case: typing.Final[DWARFIdentifierCase]
    DW_ID_case_insensitive: typing.Final[DWARFIdentifierCase]

    @staticmethod
    def find(key: typing.Union[jpype.JLong, int]) -> DWARFIdentifierCase:
        """
        Find the identifier case value given a Number value.
        
        :param jpype.JLong or int key: Number value to check
        :return: DWARFIdentifierCase enum if it exists
        :rtype: DWARFIdentifierCase
        :raises IllegalArgumentException: if the key is not found
        """

    def getValue(self) -> int:
        """
        Get the integer value of this enum.
        
        :return: the integer value of the enum
        :rtype: int
        """

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> DWARFIdentifierCase:
        ...

    @staticmethod
    def values() -> jpype.JArray[DWARFIdentifierCase]:
        ...

    @property
    def value(self) -> jpype.JInt:
        ...


class DWARFProgram(java.io.Closeable):
    """
    DWARFProgram encapsulates a :obj:`Ghidra program <Program>` with DWARF specific reference data
    used by :obj:`DWARFDataTypeImporter` and :obj:`DWARFFunctionImporter`, along with some
    helper functions.
    """

    @typing.type_check_only
    class DIEAggregateIterator(java.util.Iterator[DIEAggregate], java.lang.Iterable[DIEAggregate]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]
    DWARF_ROOT_NAME: typing.Final = "DWARF"
    DWARF_ROOT_CATPATH: typing.Final[ghidra.program.model.data.CategoryPath]
    UNCAT_CATPATH: typing.Final[ghidra.program.model.data.CategoryPath]
    DWARF_BOOKMARK_CAT: typing.Final = "DWARF"

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, importOptions: DWARFImportOptions, monitor: ghidra.util.task.TaskMonitor):
        """
        Main constructor for DWARFProgram.
         
        
        Auto-detects the DWARFSectionProvider and chains to the next constructor.
        
        :param ghidra.program.model.listing.Program program: Ghidra :obj:`Program`.
        :param DWARFImportOptions importOptions: :obj:`DWARFImportOptions` to controls options during reading / parsing /importing.
        :param ghidra.util.task.TaskMonitor monitor: :obj:`TaskMonitor` to control canceling and progress.
        :raises CancelledException: if user cancels
        :raises IOException: if error reading data
        :raises DWARFException: if bad stuff happens.
        """

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, importOptions: DWARFImportOptions, monitor: ghidra.util.task.TaskMonitor, sectionProvider: ghidra.app.util.bin.format.dwarf.sectionprovider.DWARFSectionProvider):
        """
        Constructor for DWARFProgram.
        
        :param ghidra.program.model.listing.Program program: Ghidra :obj:`Program`.
        :param DWARFImportOptions importOptions: :obj:`DWARFImportOptions` to controls options during reading / parsing /importing.
        :param ghidra.util.task.TaskMonitor monitor: :obj:`TaskMonitor` to control canceling and progress.
        :param ghidra.app.util.bin.format.dwarf.sectionprovider.DWARFSectionProvider sectionProvider: :obj:`DWARFSectionProvider` factory that finds DWARF .debug_* sections
        wherever they live.
        :raises CancelledException: if user cancels
        :raises IOException: if error reading data
        :raises DWARFException: if bad stuff happens.
        """

    def allAggregates(self) -> java.lang.Iterable[DIEAggregate]:
        """
        Returns iterable that traverses all :obj:`DIEAggregate`s in the program.
        
        :return: sequence of :obj:`DIEAggregate`es
        :rtype: java.lang.Iterable[DIEAggregate]
        """

    def dumpDIEs(self, ps: java.io.PrintStream):
        ...

    def getAddress(self, form: ghidra.app.util.bin.format.dwarf.attribs.DWARFForm, value: typing.Union[jpype.JLong, int], cu: DWARFCompilationUnit) -> int:
        """
        Returns an address value.
        
        :param ghidra.app.util.bin.format.dwarf.attribs.DWARFForm form: the format of the numeric value
        :param jpype.JLong or int value: raw offset or indirect address index (depending on the DWARFForm)
        :param DWARFCompilationUnit cu: :obj:`DWARFCompilationUnit`
        :return: address
        :rtype: int
        :raises IOException: if error reading indirect lookup tables
        """

    def getAddressRange(self, range: DWARFRange, isCode: typing.Union[jpype.JBoolean, bool]) -> ghidra.program.model.address.AddressRange:
        ...

    @typing.overload
    def getAggregate(self, die: DebugInfoEntry) -> DIEAggregate:
        """
        Returns the :obj:`DIEAggregate` that contains the specified :obj:`DebugInfoEntry`.
        
        :param DebugInfoEntry die: :obj:`DebugInfoEntry` or null
        :return: :obj:`DIEAggregate` that contains the specified DIE, or null if DIE null or
        the aggregate was not found.
        :rtype: DIEAggregate
        """

    @typing.overload
    def getAggregate(self, dieOffset: typing.Union[jpype.JLong, int]) -> DIEAggregate:
        """
        Returns the :obj:`DIEAggregate` that contains the :obj:`DebugInfoEntry` specified
        by the offset.
        
        :param jpype.JLong or int dieOffset: offset of a DIE record
        :return: :obj:`DIEAggregate` that contains the DIE record specified, or null if bad
        offset.
        :rtype: DIEAggregate
        """

    def getChildrenOf(self, dieIndex: typing.Union[jpype.JInt, int]) -> java.util.List[DebugInfoEntry]:
        """
        Returns the children of the specified DIE
        
        :param jpype.JInt or int dieIndex: index of a DIE record
        :return: list of DIE instances that are children of the specified DIE
        :rtype: java.util.List[DebugInfoEntry]
        """

    def getCodeAddress(self, offset: typing.Union[jpype.JLong, int]) -> ghidra.program.model.address.Address:
        ...

    def getCompilationUnits(self) -> java.util.List[DWARFCompilationUnit]:
        ...

    def getDIEByOffset(self, dieOffset: typing.Union[jpype.JLong, int]) -> DebugInfoEntry:
        """
        Returns the specified DIE record.
        
        :param jpype.JLong or int dieOffset: offset of a DIE record
        :return: :obj:`DebugInfoEntry` instance, or null if invalid offset
        :rtype: DebugInfoEntry
        """

    def getDIEChildIndexes(self, dieIndex: typing.Union[jpype.JInt, int]) -> ghidra.util.datastruct.IntArrayList:
        """
        Returns list of indexes of the children of the specified DIE
        
        :param jpype.JInt or int dieIndex: index of a DIE record
        :return: list of DIE indexes that are children of the specified DIE
        :rtype: ghidra.util.datastruct.IntArrayList
        """

    def getDataAddress(self, offset: typing.Union[jpype.JLong, int]) -> ghidra.program.model.address.Address:
        ...

    def getDebugLineBR(self) -> ghidra.app.util.bin.BinaryReader:
        ...

    def getDefaultIntSize(self) -> int:
        ...

    def getDwarfDTM(self) -> DWARFDataTypeManager:
        ...

    def getEntryName(self, diea: DIEAggregate) -> str:
        ...

    def getFunctionFixups(self) -> java.util.List[ghidra.app.util.bin.format.dwarf.funcfixup.DWARFFunctionFixup]:
        ...

    def getGhidraProgram(self) -> ghidra.program.model.listing.Program:
        ...

    def getImportOptions(self) -> DWARFImportOptions:
        ...

    def getImportSummary(self) -> DWARFImportSummary:
        ...

    def getLine(self, diea: DIEAggregate, attribute: ghidra.app.util.bin.format.dwarf.attribs.DWARFAttribute) -> ghidra.app.util.bin.format.dwarf.line.DWARFLine:
        """
        Returns the DWARFLine info pointed to by the specified attribute.
        
        :param DIEAggregate diea: :obj:`DIEAggregate`
        :param ghidra.app.util.bin.format.dwarf.attribs.DWARFAttribute attribute: attribute id that points to the line info
        :return: :obj:`DWARFLine`, never null, see :meth:`DWARFLine.empty() <DWARFLine.empty>`
        :rtype: ghidra.app.util.bin.format.dwarf.line.DWARFLine
        :raises IOException: if error reading line data
        """

    def getLocationList(self, diea: DIEAggregate, attribute: ghidra.app.util.bin.format.dwarf.attribs.DWARFAttribute) -> DWARFLocationList:
        """
        Returns the :obj:`DWARFLocationList` pointed to by the specified attribute value.
        
        :param DIEAggregate diea: :obj:`DIEAggregate`
        :param ghidra.app.util.bin.format.dwarf.attribs.DWARFAttribute attribute: attribute id that points to the location list
        :return: :obj:`DWARFLocationList`, never null
        :rtype: DWARFLocationList
        :raises IOException: if specified attribute is not the correct type, or if other error reading
        data
        """

    def getName(self, diea: DIEAggregate) -> DWARFName:
        """
        Returns a :obj:`DWARFName` for a :obj:`DIEAggregate`.
        
        :param DIEAggregate diea: :obj:`DIEAggregate`
        :return: :obj:`DWARFName`, never null
        :rtype: DWARFName
        """

    def getOffsetOfIndexedElement(self, form: ghidra.app.util.bin.format.dwarf.attribs.DWARFForm, index: typing.Union[jpype.JInt, int], cu: DWARFCompilationUnit) -> int:
        """
        Returns the raw offset of an indexed item.  For DW_FORM_addrx values, the returned value
        is not fixed up with Ghidra load offset.
        
        :param ghidra.app.util.bin.format.dwarf.attribs.DWARFForm form: :obj:`DWARFForm` of the index
        :param jpype.JInt or int index: int index into a lookup table (see :obj:`.addressListTable`, 
        :obj:`.locationListTable`, :obj:`.rangeListTable`, :obj:`.stringsOffsetTable`)
        :param DWARFCompilationUnit cu: :obj:`DWARFCompilationUnit`
        :return: raw offset of indexed item
        :rtype: int
        :raises IOException: if error reading index table
        """

    def getParentDepth(self, dieIndex: typing.Union[jpype.JInt, int]) -> int:
        """
        Returns the depth of the specified DIE.
        
        :param jpype.JInt or int dieIndex: index of a DIE record
        :return: parent/child depth of specified record, where 0 is the root DIE
        :rtype: int
        """

    def getParentIndex(self, dieIndex: typing.Union[jpype.JInt, int]) -> int:
        """
        Returns the index of the parent of the specified DIE.
        
        :param jpype.JInt or int dieIndex: index of a DIE record
        :return: index of the parent of specified DIE, or -1 if no parent (eg. root DIE)
        :rtype: int
        """

    def getParentOf(self, dieIndex: typing.Union[jpype.JInt, int]) -> DebugInfoEntry:
        """
        Returns the parent DIE of the specified (by index) DIE
        
        :param jpype.JInt or int dieIndex: index of a DIE record
        :return: parent DIE, or null if no parent (eg. root DIE)
        :rtype: DebugInfoEntry
        """

    def getProgramBaseAddressFixup(self) -> int:
        """
        A fixup value that needs to be applied to static addresses of the program.
         
        
        This value is necessary if the program's built-in base address is overridden at import time.
        
        :return: long value to add to static addresses discovered in DWARF to make it agree with
        Ghidra's imported program.
        :rtype: int
        """

    def getRangeList(self, diea: DIEAggregate, attribute: ghidra.app.util.bin.format.dwarf.attribs.DWARFAttribute) -> DWARFRangeList:
        """
        Returns the :obj:`DWARFRangeList` pointed at by the specified attribute.
        
        :param DIEAggregate diea: :obj:`DIEAggregate`
        :param ghidra.app.util.bin.format.dwarf.attribs.DWARFAttribute attribute: attribute id to find in the DIEA
        :return: :obj:`DWARFRangeList`, or null if attribute is not present
        :rtype: DWARFRangeList
        :raises IOException: if error reading range list
        """

    def getReaderForCompUnit(self, cu: DWARFCompilationUnit) -> ghidra.app.util.bin.BinaryReader:
        ...

    @staticmethod
    def getReferringTypedef(diea: DIEAggregate) -> DIEAggregate:
        """
        Returns the :obj:`DIEAggregate` of a typedef that points to the specified datatype.
         
        
        Returns null if there is no typedef pointing to the specified DIEA or if there are
        multiple.
        
        :param DIEAggregate diea: :obj:`DIEAggregate` of a data type that might be the target of typedefs.
        :return: :obj:`DIEAggregate` of the singular typedef that points to the arg, otherwise
        null if none or multiple found.
        :rtype: DIEAggregate
        """

    def getRegisterMappings(self) -> DWARFRegisterMappings:
        ...

    def getRootDNI(self) -> DWARFName:
        ...

    def getStackSpace(self) -> ghidra.program.model.address.AddressSpace:
        ...

    def getString(self, form: ghidra.app.util.bin.format.dwarf.attribs.DWARFForm, offset: typing.Union[jpype.JLong, int], cu: DWARFCompilationUnit) -> str:
        """
        Returns a DWARF attribute string value, as specified by a form, offset/index, and the cu.
        
        :param ghidra.app.util.bin.format.dwarf.attribs.DWARFForm form: :obj:`DWARFForm`
        :param jpype.JLong or int offset: offset or index of the value
        :param DWARFCompilationUnit cu: :obj:`DWARFCompilationUnit`
        :return: String value, never null
        :rtype: str
        :raises IOException: if invalid form or bad offset/index
        """

    def getTotalAggregateCount(self) -> int:
        """
        Returns the total number of :obj:`DIEAggregate` objects in the entire program.
        
        :return: the total number of :obj:`DIEAggregate` objects in the entire program.
        :rtype: int
        """

    def getTypeReferers(self, targetDIEA: DIEAggregate, tag: DWARFTag) -> java.util.List[DIEAggregate]:
        """
        Returns a list of :obj:`DIEAggregate`s that refer to the targetDIEA via an
        attribute of the specified tag type.
        
        :param DIEAggregate targetDIEA: :obj:`DIEAggregate` that might be pointed to by other DIEAs.
        :param DWARFTag tag: the :obj:`DWARFTag` attribute type that is pointing DIEAs are using
        to refer to the target DIEA.
        :return: list of DIEAs that point to the target, empty list if nothing found.
        :rtype: java.util.List[DIEAggregate]
        """

    def getUncategorizedRootDNI(self) -> DWARFName:
        ...

    @staticmethod
    def hasDWARFData(program: ghidra.program.model.listing.Program, monitor: ghidra.util.task.TaskMonitor) -> bool:
        """
        Returns true if the specified :obj:`program <Program>` has DWARF information.
         
        
        This is similar to :meth:`isDWARF(Program) <.isDWARF>`, but is a stronger check that is more
        expensive as it could involve searching for external files.
        
        :param ghidra.program.model.listing.Program program: :obj:`Program` to test
        :param ghidra.util.task.TaskMonitor monitor: :obj:`TaskMonitor` that can be used to cancel
        :return: boolean true if the program has DWARF info, false if not
        :rtype: bool
        """

    def init(self, monitor: ghidra.util.task.TaskMonitor):
        """
        Reads and indexes available DWARF information.
        
        :param ghidra.util.task.TaskMonitor monitor: :obj:`TaskMonitor`
        :raises IOException: if error reading data
        :raises DWARFException: if bad or invalid DWARF information
        :raises CancelledException: if cancelled
        """

    def internAttributeSpec(self, das: ghidra.app.util.bin.format.dwarf.attribs.DWARFAttribute.AttrDef) -> ghidra.app.util.bin.format.dwarf.attribs.DWARFAttribute.AttrDef:
        ...

    def isBigEndian(self) -> bool:
        ...

    @staticmethod
    def isDWARF(program: ghidra.program.model.listing.Program) -> bool:
        """
        Returns true if the :obj:`program <Program>` probably has DWARF information, without doing
        all the work that querying all registered DWARFSectionProviders would take.
         
        
        If the program is an Elf binary, it must have (at least) ".debug_info" and ".debug_abbr",
        program sections, or their compressed "z" versions, or ExternalDebugInfo that would point
        to an external DWARF file.
         
        
        If the program is a MachO binary (Mac), it must have a ".dSYM" directory co-located 
        next to the original binary file on the native filesystem (outside of Ghidra).  See the 
        DSymSectionProvider for more info.
        
        :param ghidra.program.model.listing.Program program: :obj:`Program` to test
        :return: boolean true if program probably has DWARF info, false if not
        :rtype: bool
        """

    def isLittleEndian(self) -> bool:
        ...

    def logWarningAt(self, addr: ghidra.program.model.address.Address, addrName: typing.Union[java.lang.String, str], msg: typing.Union[java.lang.String, str]):
        ...

    def setStringTable(self, st: StringTable):
        ...

    def stackGrowsNegative(self) -> bool:
        ...

    @property
    def parentIndex(self) -> jpype.JInt:
        ...

    @property
    def parentDepth(self) -> jpype.JInt:
        ...

    @property
    def dIEChildIndexes(self) -> ghidra.util.datastruct.IntArrayList:
        ...

    @property
    def uncategorizedRootDNI(self) -> DWARFName:
        ...

    @property
    def importSummary(self) -> DWARFImportSummary:
        ...

    @property
    def debugLineBR(self) -> ghidra.app.util.bin.BinaryReader:
        ...

    @property
    def aggregate(self) -> DIEAggregate:
        ...

    @property
    def bigEndian(self) -> jpype.JBoolean:
        ...

    @property
    def programBaseAddressFixup(self) -> jpype.JLong:
        ...

    @property
    def functionFixups(self) -> java.util.List[ghidra.app.util.bin.format.dwarf.funcfixup.DWARFFunctionFixup]:
        ...

    @property
    def dIEByOffset(self) -> DebugInfoEntry:
        ...

    @property
    def rootDNI(self) -> DWARFName:
        ...

    @property
    def dataAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def littleEndian(self) -> jpype.JBoolean:
        ...

    @property
    def stackSpace(self) -> ghidra.program.model.address.AddressSpace:
        ...

    @property
    def parentOf(self) -> DebugInfoEntry:
        ...

    @property
    def ghidraProgram(self) -> ghidra.program.model.listing.Program:
        ...

    @property
    def dwarfDTM(self) -> DWARFDataTypeManager:
        ...

    @property
    def codeAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def readerForCompUnit(self) -> ghidra.app.util.bin.BinaryReader:
        ...

    @property
    def compilationUnits(self) -> java.util.List[DWARFCompilationUnit]:
        ...

    @property
    def defaultIntSize(self) -> jpype.JInt:
        ...

    @property
    def importOptions(self) -> DWARFImportOptions:
        ...

    @property
    def totalAggregateCount(self) -> jpype.JInt:
        ...

    @property
    def entryName(self) -> java.lang.String:
        ...

    @property
    def name(self) -> DWARFName:
        ...

    @property
    def registerMappings(self) -> DWARFRegisterMappings:
        ...

    @property
    def childrenOf(self) -> java.util.List[DebugInfoEntry]:
        ...


class DIEAggregate(java.lang.Object):
    """
    DIEAggregate groups related :obj:`DebugInfoEntry` records together in a single interface
    for querying attribute values.
     
    
    Information about program elements are written into the .debug_info as partial snapshots
    of the element, with later follow-up records that more fully specify the program element.
     
    
    (For instance, a declaration-only DIE that introduces the name of a structure type
    will be found at the beginning of a compilation unit, followed later by a DIE that
    specifies the contents of the structure type)
     
    
    A DIEAggregate groups these :obj:`DebugInfoEntry` records under one interface so a fully
    specified view of the program element can be presented.
    """

    @typing.type_check_only
    class FoundAttribute(java.lang.Record):
        """
        A simple class used by findAttribute() to return the found attribute, along with
        the DIE it was found in, and the DWARFForm type of the raw attribute.
        """

        class_: typing.ClassVar[java.lang.Class]

        def attr(self) -> ghidra.app.util.bin.format.dwarf.attribs.DWARFAttributeValue:
            ...

        def die(self) -> DebugInfoEntry:
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def toString(self) -> str:
            ...


    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def createFromHead(die: DebugInfoEntry) -> DIEAggregate:
        """
        Creates a :obj:`DIEAggregate` starting from a 'head' :obj:`DebugInfoEntry` instance.
         
        
        DW_AT_abstract_origin and DW_AT_specification attributes are followed to find the previous
        :obj:`DebugInfoEntry` instances.
        
        :param DebugInfoEntry die: starting DIE record
        :return: new :obj:`DIEAggregate` made up of the starting DIE and all DIEs that it points
        to via abstract_origin and spec attributes.
        :rtype: DIEAggregate
        """

    @staticmethod
    def createSingle(die: DebugInfoEntry) -> DIEAggregate:
        """
        Create a :obj:`DIEAggregate` from a single :obj:`DIE <DebugInfoEntry>`.
         
        
        Mainly useful early in the :obj:`DWARFCompilationUnit`'s bootstrapping process
        when it needs to read values from DIEs.
        
        :param DebugInfoEntry die: :obj:`DebugInfoEntry`
        :return: :obj:`DIEAggregate` containing a single DIE
        :rtype: DIEAggregate
        """

    @staticmethod
    def createSkipHead(source: DIEAggregate) -> DIEAggregate:
        """
        Creates a new :obj:`DIEAggregate` from the contents of the specified DIEA, using
        all the source's :obj:`DebugInfoEntry` fragments except for the head fragment
        which is skipped.
         
        
        Used when a DIEA is composed of a head DIE with a different TAG type than the rest of
        the DIEs.  (ie. a dw_tag_call_site -> dw_tag_sub DIEA)
        
        :param DIEAggregate source: :obj:`DIEAggregate` containing fragments
        :return: :obj:`DIEAggregate` with the fragments of the source, skipping the first
        :rtype: DIEAggregate
        """

    def findAttributeInChildren(self, attribute: ghidra.app.util.bin.format.dwarf.attribs.DWARFAttribute, childTag: DWARFTag, clazz: java.lang.Class[T]) -> T:
        """
        Return an attribute that is present in this :obj:`DIEAggregate`, or in any of its
        direct children (of a specific type)
        
        :param T: attribute value type:param ghidra.app.util.bin.format.dwarf.attribs.DWARFAttribute attribute: the attribute to find
        :param DWARFTag childTag: the type of children to search
        :param java.lang.Class[T] clazz: type of the attribute to return
        :return: attribute value, or null if not found
        :rtype: T
        """

    def getAbstractInstance(self) -> DIEAggregate:
        """
        Return a :obj:`DIEAggregate` that only contains the information present in the
        "abstract instance" (and lower) DIEs.
        
        :return: a new :obj:`DIEAggregate`, or null if this DIEA was not split into a concrete and
        abstract portion
        :rtype: DIEAggregate
        """

    @typing.overload
    def getAttribute(self, attribute: ghidra.app.util.bin.format.dwarf.attribs.DWARFAttribute, clazz: java.lang.Class[T]) -> T:
        """
        Finds a :obj:`attribute <DWARFAttributeValue>` with a matching :obj:`DWARFAttribute` id.
         
        
        Returns null if the attribute does not exist or is wrong java class type.
         
        
        Attributes are searched for in each fragment in this aggregate, starting with the
        'head' fragment, progressing toward the 'decl' fragment.
        
        :param ghidra.app.util.bin.format.dwarf.attribs.DWARFAttribute attribute: See :obj:`DWARFAttribute`
        :param java.lang.Class[T] clazz: must be derived from :obj:`DWARFAttributeValue`
        :return: DWARFAttributeValue or subclass as specified by the clazz, or null if not found
        :rtype: T
        """

    @typing.overload
    def getAttribute(self, attribute: ghidra.app.util.bin.format.dwarf.attribs.DWARFAttribute) -> ghidra.app.util.bin.format.dwarf.attribs.DWARFAttributeValue:
        """
        Finds a :obj:`attribute <DWARFAttributeValue>` with a matching :obj:`DWARFAttribute` id.
         
        
        Returns null if the attribute does not exist.
         
        
        Attributes are searched for in each fragment in this aggregate, starting with the
        'head' fragment, progressing toward the 'decl' fragment.
        
        :param ghidra.app.util.bin.format.dwarf.attribs.DWARFAttribute attribute: See :obj:`DWARFAttribute`
        :return: DWARFAttributeValue, or null if not found
        :rtype: ghidra.app.util.bin.format.dwarf.attribs.DWARFAttributeValue
        """

    def getBool(self, attribute: ghidra.app.util.bin.format.dwarf.attribs.DWARFAttribute, defaultValue: typing.Union[jpype.JBoolean, bool]) -> bool:
        """
        Returns the boolean value of the requested attribute, or -defaultValue- if
        the attribute is missing or not the correct type.
        
        :param ghidra.app.util.bin.format.dwarf.attribs.DWARFAttribute attribute: :obj:`DWARFAttribute` id
        :param jpype.JBoolean or bool defaultValue: value to return if attribute is not present
        :return: boolean value, or the defaultValue if attribute is not present
        :rtype: bool
        """

    def getChildren(self, childTag: DWARFTag) -> java.util.List[DebugInfoEntry]:
        """
        Return a list of children that are of a specific DWARF type.
        
        :param DWARFTag childTag: see :obj:`DWARFTag DW_TAG_* values <DWARFTag>`
        :return: List of children DIEs that match the specified tag
        :rtype: java.util.List[DebugInfoEntry]
        """

    def getCompilationUnit(self) -> DWARFCompilationUnit:
        ...

    def getContainingTypeRef(self) -> DIEAggregate:
        """
        Returns the DIE pointed to by a DW_AT_containing_type attribute.
        
        :return: DIEA pointed to by the DW_AT_containing_type attribute, or null if not present.
        :rtype: DIEAggregate
        """

    def getDeclOffset(self) -> int:
        ...

    def getDeclParent(self) -> DIEAggregate:
        ...

    def getDepth(self) -> int:
        """
        Returns the depth of the head fragment, where depth is defined as
        the distance between the DIE and the root DIE of the owning compilation
        unit.
         
        
        The root die would return 0, the children of the root will return 1, etc.
         
        
        This value matches the nesting value shown when dumping DWARF
        info using 'readelf'.
        
        :return: depth of this instance, from the root of its head DIE fragment, with 0 indicating
        that this instance was already the root of the compUnit
        :rtype: int
        """

    def getFragmentCount(self) -> int:
        ...

    def getFunctionParamList(self) -> java.util.List[DIEAggregate]:
        """
        Returns a function's parameter list, taking care to ensure that the params
        are well ordered (to avoid issues with concrete instance param ordering)
        
        :return: list of params for this function
        :rtype: java.util.List[DIEAggregate]
        """

    def getHeadFragment(self) -> DebugInfoEntry:
        """
        Returns the first :obj:`DIE <DebugInfoEntry>` fragment, ie. the spec or abstract_origin
        DIE.
        
        :return: first DIE of this aggregate
        :rtype: DebugInfoEntry
        """

    def getHexOffset(self) -> str:
        """
        Returns :meth:`getOffset() <.getOffset>` as a hex string.
        
        :return: string hex offset of the head DIE
        :rtype: str
        """

    def getLastFragment(self) -> DebugInfoEntry:
        """
        Returns the last :obj:`DIE <DebugInfoEntry>` fragment, ie. the decl DIE.
        
        :return: last DIE of this aggregate
        :rtype: DebugInfoEntry
        """

    def getLocation(self, attribute: ghidra.app.util.bin.format.dwarf.attribs.DWARFAttribute, pc: typing.Union[jpype.JLong, int]) -> DWARFLocation:
        """
        Parses a location attribute value, and returns the :obj:`DWARFLocation` instance that
        covers the specified pc.
        
        :param ghidra.app.util.bin.format.dwarf.attribs.DWARFAttribute attribute: typically :obj:`DWARFAttribute.DW_AT_location`
        :param jpype.JLong or int pc: program counter
        :return: a :obj:`DWARFLocationList`, never null, possibly empty
        :rtype: DWARFLocation
        :raises IOException: if error reading data
        """

    def getLocationList(self, attribute: ghidra.app.util.bin.format.dwarf.attribs.DWARFAttribute) -> DWARFLocationList:
        """
        Parses a location attribute value, which can be a single expression that is valid for any
        PC, or a list of expressions that are tied to specific ranges.
        
        :param ghidra.app.util.bin.format.dwarf.attribs.DWARFAttribute attribute: typically :obj:`DWARFAttribute.DW_AT_location`
        :return: a :obj:`DWARFLocationList`, never null, possibly empty
        :rtype: DWARFLocationList
        :raises IOException: if error reading data
        """

    def getLong(self, attribute: ghidra.app.util.bin.format.dwarf.attribs.DWARFAttribute, defaultValue: typing.Union[jpype.JLong, int]) -> int:
        """
        Returns the value of the requested attribute, or -defaultValue- if the
        attribute is missing.
        
        :param ghidra.app.util.bin.format.dwarf.attribs.DWARFAttribute attribute: :obj:`DWARFAttribute` id
        :param jpype.JLong or int defaultValue: value to return if attribute is not present
        :return: long value, or the defaultValue if attribute not present
        :rtype: int
        """

    def getName(self) -> str:
        """
        Returns the string value of the :obj:`dw_at_name <DWARFAttribute.DW_AT_name>` attribute,
        or null if it is missing.
        
        :return: name of this DIE aggregate, or null if missing
        :rtype: str
        """

    def getOffset(self) -> int:
        ...

    def getOffsets(self) -> jpype.JArray[jpype.JLong]:
        ...

    def getPCRange(self) -> DWARFRange:
        """
        Return the range specified by the low_pc...high_pc attribute values.
        
        :return: :obj:`DWARFRange` containing low_pc - high_pc, or empty range if the low_pc is 
        not present
        :rtype: DWARFRange
        """

    def getParent(self) -> DIEAggregate:
        ...

    def getProgram(self) -> DWARFProgram:
        ...

    def getRangeList(self, attribute: ghidra.app.util.bin.format.dwarf.attribs.DWARFAttribute) -> DWARFRangeList:
        """
        Parses a range list.
        
        :param ghidra.app.util.bin.format.dwarf.attribs.DWARFAttribute attribute: attribute eg :obj:`DWARFAttribute.DW_AT_ranges`
        :return: list of ranges, or null if attribute is not present
        :rtype: DWARFRangeList
        :raises IOException: if an I/O error occurs
        """

    def getRef(self, attribute: ghidra.app.util.bin.format.dwarf.attribs.DWARFAttribute) -> DIEAggregate:
        """
        Returns the :obj:`diea <DIEAggregate>` instance pointed to by the requested attribute,
        or null if the attribute does not exist.
        
        :param ghidra.app.util.bin.format.dwarf.attribs.DWARFAttribute attribute: :obj:`DWARFAttribute` id
        :return: :obj:`DIEAggregate`, or the null if attribute is not present
        :rtype: DIEAggregate
        """

    def getSourceFile(self) -> str:
        """
        Returns the name of the source file this item was declared in (DW_AT_decl_file)
        
        :return: name of file this item was declared in, or null if info not available
        :rtype: str
        """

    def getString(self, attribute: ghidra.app.util.bin.format.dwarf.attribs.DWARFAttribute, defaultValue: typing.Union[java.lang.String, str]) -> str:
        """
        Returns the string value of the requested attribute, or -defaultValue- if
        the attribute is missing or not the correct type.
        
        :param ghidra.app.util.bin.format.dwarf.attribs.DWARFAttribute attribute: :obj:`DWARFAttribute` id
        :param java.lang.String or str defaultValue: value to return if attribute is not present
        :return: String value, or the defaultValue if attribute is not present
        :rtype: str
        """

    def getTag(self) -> DWARFTag:
        ...

    def getTypeRef(self) -> DIEAggregate:
        ...

    def getUnsignedLong(self, attribute: ghidra.app.util.bin.format.dwarf.attribs.DWARFAttribute, defaultValue: typing.Union[jpype.JLong, int]) -> int:
        """
        Returns the unsigned long integer value of the requested attribute, or -defaultValue-
        if the attribute is missing.
         
        
        The 'unsigned'ness of this method refers to how the binary value is read from
        the dwarf information (ie. a value with the high bit set is not treated as signed).
         
        
        The -defaultValue- parameter can accept a negative value.
        
        :param ghidra.app.util.bin.format.dwarf.attribs.DWARFAttribute attribute: :obj:`DWARFAttribute` id
        :param jpype.JLong or int defaultValue: value to return if attribute is not present
        :return: unsigned long value, or the defaultValue if attribute is not present
        :rtype: int
        """

    def hasAttribute(self, attribute: ghidra.app.util.bin.format.dwarf.attribs.DWARFAttribute) -> bool:
        """
        Returns true if the specified attribute is present.
        
        :param ghidra.app.util.bin.format.dwarf.attribs.DWARFAttribute attribute: attribute id
        :return: boolean true if value is present
        :rtype: bool
        """

    def hasOffset(self, offset: typing.Union[jpype.JLong, int]) -> bool:
        """
        Returns true if any of the :obj:`DIEs <DebugInfoEntry>` that makeup this aggregate
        have the specified offset.
        
        :param jpype.JLong or int offset: DIE offset to search for
        :return: true if this :obj:`DIEAggregate` has a fragment DIE at that offset.
        :rtype: bool
        """

    def isDanglingDeclaration(self) -> bool:
        """
        Returns true if this DIE has a DW_AT_declaration attribute and
        does NOT have a matching inbound DW_AT_specification reference.
        
        :return: boolean true if this DIE has a DW_AT_declaration attribute and
        does NOT have a matching inbound DW_AT_specification reference
        :rtype: bool
        """

    def isPartialDeclaration(self) -> bool:
        """
        Returns true if this DIE has a DW_AT_declaration attribute.
        
        :return: true if this DIE has a DW_AT_declaration attribute
        :rtype: bool
        """

    def parseDataMemberOffset(self, attribute: ghidra.app.util.bin.format.dwarf.attribs.DWARFAttribute, defaultValue: typing.Union[jpype.JInt, int]) -> int:
        """
        Returns the unsigned integer value of the requested attribute after resolving
        any DWARF expression opcodes.
        
        :param ghidra.app.util.bin.format.dwarf.attribs.DWARFAttribute attribute: :obj:`DWARFAttribute` id
        :param jpype.JInt or int defaultValue: value to return if attribute is not present
        :return: unsigned int value, or the defaultValue if attribute is not present
        :rtype: int
        :raises IOException: if error reading value or invalid value type
        :raises DWARFExpressionException: if error evaluating a DWARF expression
        """

    def parseInt(self, attribute: ghidra.app.util.bin.format.dwarf.attribs.DWARFAttribute, defaultValue: typing.Union[jpype.JInt, int]) -> int:
        """
        Returns the signed integer value of the requested attribute after resolving
        any DWARF expression opcodes.
        
        :param ghidra.app.util.bin.format.dwarf.attribs.DWARFAttribute attribute: :obj:`DWARFAttribute` id
        :param jpype.JInt or int defaultValue: value to return if attribute is not present
        :return: int value, or the defaultValue if attribute is not present
        :rtype: int
        :raises IOException: if error reading value or invalid value type
        :raises DWARFExpressionException: if error evaluating a DWARF expression
        """

    def parseUnsignedLong(self, attribute: ghidra.app.util.bin.format.dwarf.attribs.DWARFAttribute, defaultValue: typing.Union[jpype.JLong, int]) -> int:
        """
        Returns the unsigned integer value of the requested attribute after resolving
        any DWARF expression opcodes.
        
        :param ghidra.app.util.bin.format.dwarf.attribs.DWARFAttribute attribute: :obj:`DWARFAttribute` id
        :param jpype.JLong or int defaultValue: value to return if attribute is not present
        :return: unsigned long value, or the defaultValue if attribute is not present
        :rtype: int
        :raises IOException: if error reading value or invalid value type
        :raises DWARFExpressionException: if error evaluating a DWARF expression
        """

    @property
    def parent(self) -> DIEAggregate:
        ...

    @property
    def declParent(self) -> DIEAggregate:
        ...

    @property
    def program(self) -> DWARFProgram:
        ...

    @property
    def sourceFile(self) -> java.lang.String:
        ...

    @property
    def lastFragment(self) -> DebugInfoEntry:
        ...

    @property
    def ref(self) -> DIEAggregate:
        ...

    @property
    def rangeList(self) -> DWARFRangeList:
        ...

    @property
    def pCRange(self) -> DWARFRange:
        ...

    @property
    def children(self) -> java.util.List[DebugInfoEntry]:
        ...

    @property
    def partialDeclaration(self) -> jpype.JBoolean:
        ...

    @property
    def tag(self) -> DWARFTag:
        ...

    @property
    def attribute(self) -> ghidra.app.util.bin.format.dwarf.attribs.DWARFAttributeValue:
        ...

    @property
    def declOffset(self) -> jpype.JLong:
        ...

    @property
    def fragmentCount(self) -> jpype.JInt:
        ...

    @property
    def typeRef(self) -> DIEAggregate:
        ...

    @property
    def headFragment(self) -> DebugInfoEntry:
        ...

    @property
    def offset(self) -> jpype.JLong:
        ...

    @property
    def hexOffset(self) -> java.lang.String:
        ...

    @property
    def functionParamList(self) -> java.util.List[DIEAggregate]:
        ...

    @property
    def locationList(self) -> DWARFLocationList:
        ...

    @property
    def depth(self) -> jpype.JInt:
        ...

    @property
    def compilationUnit(self) -> DWARFCompilationUnit:
        ...

    @property
    def offsets(self) -> jpype.JArray[jpype.JLong]:
        ...

    @property
    def containingTypeRef(self) -> DIEAggregate:
        ...

    @property
    def abstractInstance(self) -> DIEAggregate:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def danglingDeclaration(self) -> jpype.JBoolean:
        ...


class DWARFUtil(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def appendComment(program: ghidra.program.model.listing.Program, address: ghidra.program.model.address.Address, commentType: ghidra.program.model.listing.CommentType, prefix: typing.Union[java.lang.String, str], comment: typing.Union[java.lang.String, str], sep: typing.Union[java.lang.String, str]):
        ...

    @staticmethod
    @typing.overload
    def appendDescription(dt: ghidra.program.model.data.DataType, description: typing.Union[java.lang.String, str], sep: typing.Union[java.lang.String, str]):
        """
        Append a string to a :obj:`DataType`'s description.
        
        :param ghidra.program.model.data.DataType dt: :obj:`DataType`
        :param java.lang.String or str description: string to append, if null or empty nothing happens.
        :param java.lang.String or str sep: characters to place after previous description to separate it from the
        new portion.
        """

    @staticmethod
    @typing.overload
    def appendDescription(dtc: ghidra.program.model.data.DataTypeComponent, description: typing.Union[java.lang.String, str], sep: typing.Union[java.lang.String, str]):
        """
        Append a string to a description of a field in a structure.
        
        :param ghidra.program.model.data.DataTypeComponent dtc: the :obj:`field <DataTypeComponent>` in a struct
        :param java.lang.String or str description: string to append, if null or empty nothing happens.
        :param java.lang.String or str sep: characters to place after previous description to separate it from the
        new portion.
        """

    @staticmethod
    def convertRegisterListToVarnodeStorage(registers: java.util.List[ghidra.program.model.lang.Register], dataTypeSize: typing.Union[jpype.JInt, int]) -> java.util.List[ghidra.program.model.pcode.Varnode]:
        ...

    @staticmethod
    def findLinkageNameInChildren(die: DebugInfoEntry) -> java.util.List[java.lang.String]:
        """
        Try to find gnu mangled name nesting info in a DIE's children's linkage strings.
        
        :param DebugInfoEntry die: 
        :return: a list of string of nesting names, ending with what should be the DIE parameter's
        name.
        :rtype: java.util.List[java.lang.String]
        """

    @staticmethod
    def getAnonNameForMeFromParentContext(diea: DIEAggregate) -> str:
        """
        Creates a name for anon types based on their position in their parent's childList.
        
        :param DIEAggregate diea: the die aggregate.
        :return: the anonymous name of the die aggregate.
        :rtype: str
        """

    @staticmethod
    def getAnonNameForMeFromParentContext2(diea: DIEAggregate) -> str:
        """
        Creates a name for anon types based on the names of sibling entries that are using the anon type.
         
        
        Example: "anon_struct_for_field1_field2"
         
        
        Falls back to :meth:`getAnonNameForMeFromParentContext(DIEAggregate) <.getAnonNameForMeFromParentContext>` if no siblings found.
        
        :param DIEAggregate diea: the die aggregate.
        :return: the anonymous name of the die aggregate.
        :rtype: str
        """

    @staticmethod
    def getCodeUnitForComment(program: ghidra.program.model.listing.Program, address: ghidra.program.model.address.Address) -> ghidra.program.model.listing.CodeUnit:
        ...

    @staticmethod
    def getLanguageDefinitionDirectory(lang: ghidra.program.model.lang.Language) -> generic.jar.ResourceFile:
        """
        Returns the base directory of a language definition.
        
        :param ghidra.program.model.lang.Language lang: :obj:`Language` to get base definition directory
        :return: base directory for language definition files
        :rtype: generic.jar.ResourceFile
        :raises IOException: if not a sleigh lang
        """

    @staticmethod
    def getLanguageExternalFile(lang: ghidra.program.model.lang.Language, name: typing.Union[java.lang.String, str]) -> generic.jar.ResourceFile:
        """
        Returns a file that has been referenced in the specified :obj:`language's <Language>`
        ldefs description via a
        <external_name tool="**name**" name="**value**"/>
        entry.
        
        :param ghidra.program.model.lang.Language lang: :obj:`Language` to query
        :param java.lang.String or str name: name of the option in the ldefs file
        :return: file pointed to by the specified external_name tool entry
        :rtype: generic.jar.ResourceFile
        :raises IOException: if not a sleigh lang
        """

    @staticmethod
    def getLanguageExternalNameValue(lang: ghidra.program.model.lang.Language, name: typing.Union[java.lang.String, str]) -> str:
        """
        Returns a value specified in a :obj:`Language` definition via a
        <external_name tool="**name**" name="**value**"/>
        entry.
        
        :param ghidra.program.model.lang.Language lang: :obj:`Language` to query
        :param java.lang.String or str name: name of the value
        :return: String value
        :rtype: str
        :raises IOException:
        """

    @staticmethod
    def getStaticFinalFieldWithValue(clazz: java.lang.Class[typing.Any], value: typing.Union[jpype.JLong, int]) -> java.lang.reflect.Field:
        """
        Searches a Class for a final static variable that has a specific numeric value.
        
        :param java.lang.Class[typing.Any] clazz: Class to search.
        :param jpype.JLong or int value: numeric value to search for
        :return: Java reflection :obj:`Field` that has the specified value or null
        :rtype: java.lang.reflect.Field
        """

    @staticmethod
    def getStructLayoutFingerprint(diea: DIEAggregate) -> str:
        """
        Creates a fingerprint of the layout of an (anonymous) structure using its
        size, number of members, and the hashcode of the member field names.
        
        :param DIEAggregate diea: struct/union/class
        :return: formatted string, example "80_5_73dc6de9" (80 bytes, 5 fields, hex hash of field names)
        :rtype: str
        """

    @staticmethod
    def getTemplateBaseName(name: typing.Union[java.lang.String, str]) -> str:
        """
        Determines if a name is a C++ style templated name.  If so, returns just
        the base portion of the name.
        The name must have a start and end angle bracket: '<' and '>'.
         
        
        operator<() and operator<<() are handled so their angle brackets
        don't trigger the template start/end angle bracket incorrectly.
        
        :param java.lang.String or str name: symbol name with C++ template portions
        :return: base portion of the symbol name without template portion
        :rtype: str
        """

    @staticmethod
    def isEmptyArray(dt: ghidra.program.model.data.DataType) -> bool:
        ...

    @staticmethod
    def isPointerDataType(diea: DIEAggregate) -> bool:
        ...

    @staticmethod
    def isPointerTo(targetDIEA: DIEAggregate, testDIEA: DIEAggregate) -> bool:
        ...

    @staticmethod
    def isStackVarnode(varnode: ghidra.program.model.pcode.Varnode) -> bool:
        ...

    @staticmethod
    def isThisParam(paramDIEA: DIEAggregate) -> bool:
        ...

    @staticmethod
    def isVoid(dt: ghidra.program.model.data.DataType) -> bool:
        ...

    @staticmethod
    def isZeroByteDataType(dt: ghidra.program.model.data.DataType) -> bool:
        ...

    @staticmethod
    def packCompositeIfPossible(original: ghidra.program.model.data.Composite, dtm: ghidra.program.model.data.DataTypeManager):
        ...

    @staticmethod
    def parseMangledNestings(s: typing.Union[java.lang.String, str]) -> java.util.List[java.lang.String]:
        """
        A lightweight attempt to get nesting (ie. namespaces and such) information
        from gnu mangled name strings.
         
        
        For example, "_ZN19class1_inline_funcs3fooEv" ->
        [19 chars]'class1_inline_funcs', [3 chars]'foo'
        
        :param java.lang.String or str s: 
        :return: 
        :rtype: java.util.List[java.lang.String]
        """

    @staticmethod
    @typing.overload
    def toString(clazz: java.lang.Class[typing.Any], value: typing.Union[jpype.JInt, int]) -> str:
        """
        Converts a integer value to its corresponding symbolic name from the set of
        "public static final" member variables in a class.
         
        
        This is a bit of a hack and probably originated from pre-java Enum days.
        
        :param java.lang.Class[typing.Any] clazz: The :obj:`Class` to search for the matching static value.
        :param jpype.JInt or int value: the integer value to search for
        :return: the String name of the matching field.
        :rtype: str
        """

    @staticmethod
    @typing.overload
    def toString(clazz: java.lang.Class[typing.Any], value: typing.Union[jpype.JLong, int]) -> str:
        """
        Returns the field name of a final static variable in class ``clazz``
        which holds a specific value.
         
        
        Can be thought of as an enum numeric value to do a name lookup.
        
        :param java.lang.Class[typing.Any] clazz: 
        :param jpype.JLong or int value: 
        :return: 
        :rtype: str
        """


class DWARFInline(java.lang.Enum[DWARFInline]):
    """
    DWARF inline encodings from www.dwarfstd.org/doc/DWARF4.pdf
    """

    class_: typing.ClassVar[java.lang.Class]
    DW_INL_not_inlined: typing.Final[DWARFInline]
    DW_INL_inlined: typing.Final[DWARFInline]
    DW_INL_declared_not_inlined: typing.Final[DWARFInline]
    DW_INL_declared_inlined: typing.Final[DWARFInline]

    @staticmethod
    def find(key: java.lang.Number) -> DWARFInline:
        """
        Find the accessibility value given a Number value.
        
        :param java.lang.Number key: Number value to check
        :return: DWARFAccessibility enum if it exists
        :rtype: DWARFInline
        :raises IllegalArgumentException: if the key is not found
        """

    def getValue(self) -> int:
        """
        Get the integer value of this enum.
        
        :return: the integer value of the enum
        :rtype: int
        """

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> DWARFInline:
        ...

    @staticmethod
    def values() -> jpype.JArray[DWARFInline]:
        ...

    @property
    def value(self) -> jpype.JInt:
        ...


class NamespacePath(java.lang.Comparable[NamespacePath]):
    """
    Represents a hierarchical path of containers that hold names of objects.
     
    
    Each container of names (lets call them a namespace for short) can have a type that
    distinguishes it from other containers: classes, functions, c++ namespaces, etc.
     
    
    A NamespacePath does not correlate directly to a Ghidra :obj:`Namespace`, as a Ghidra Namespace
    is tied to a Program and has rules about what can be placed inside of it.
     
    
    NamespacePath instances can be created without referring to a Ghidra Program and without
    concern as to what will be valid or have collisions.
     
    
    Use a NamespacePath to represent and hold forward-engineering namespace nesting information (ie.
    namespace info recovered from debug info), and when a Ghidra Namespace is needed,
    convert to or lookup the live/'real' Ghidra Namespace.
    """

    class_: typing.ClassVar[java.lang.Class]
    ROOT: typing.Final[NamespacePath]

    def asFormattedString(self) -> str:
        """
        Converts this namespace path into a :obj:`Namespace` style string without the ROOT namespace
        included.
        
        :return: string path "namespace1::namespace2"
        :rtype: str
        """

    def asNamespaceString(self) -> str:
        """
        Converts this namespace path into a :obj:`Namespace` style string.
        
        :return: string path "ROOT::namespace1::namespace2"
        :rtype: str
        """

    @staticmethod
    def create(parent: NamespacePath, name: typing.Union[java.lang.String, str], type: ghidra.program.model.symbol.SymbolType) -> NamespacePath:
        """
        Creates a new :obj:`NamespacePath` instance.
        
        :param NamespacePath parent: optional - parent :obj:`NamespacePath` instance, default to :obj:`.ROOT` if null.
        :param java.lang.String or str name: string name of the new namespace.
        :param ghidra.program.model.symbol.SymbolType type: :obj:`SymbolType` of the named space - ie. a "namespace", a class,
        :return: new :obj:`NamespacePath`
        :rtype: NamespacePath
        """

    def getName(self) -> str:
        """
        Returns the name of this namespace element, ie. the last thing on the path.
        
        :return: string name.
        :rtype: str
        """

    def getNamespace(self, program: ghidra.program.model.listing.Program) -> ghidra.program.model.symbol.Namespace:
        """
        Converts this NamespacePath into a Ghidra :obj:`Namespace` in the specified :obj:`Program`,
        creating missing elements on the path as necessary.
        
        :param ghidra.program.model.listing.Program program: Ghidra :obj:`Program` where the namespace should be retrieved from or created in.
        :return: :obj:`Namespace` or fallback to the progam's Global root namespace if problem.
        :rtype: ghidra.program.model.symbol.Namespace
        """

    def getParent(self) -> NamespacePath:
        """
        Returns a reference to the parent NamespacePath.
        
        :return: parent NamespacePath
        :rtype: NamespacePath
        """

    def getParts(self) -> java.util.List[java.lang.String]:
        """
        Returns the individual parts of the path as elements in a list.
        
        :return: list of strings containing individual parts of the path
        :rtype: java.util.List[java.lang.String]
        """

    def getType(self) -> ghidra.program.model.symbol.SymbolType:
        """
        Returns the :obj:`SymbolType` of this namespace element (ie. the symbol type of the last
        thing on the path).
        
        :return: :obj:`SymbolType`
        :rtype: ghidra.program.model.symbol.SymbolType
        """

    def isRoot(self) -> bool:
        """
        Returns true if this namespace path points to the root of the namespace space.
        
        :return: boolean true if ROOT
        :rtype: bool
        """

    @property
    def parent(self) -> NamespacePath:
        ...

    @property
    def root(self) -> jpype.JBoolean:
        ...

    @property
    def parts(self) -> java.util.List[java.lang.String]:
        ...

    @property
    def namespace(self) -> ghidra.program.model.symbol.Namespace:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def type(self) -> ghidra.program.model.symbol.SymbolType:
        ...


class DWARFException(java.io.IOException):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, message: typing.Union[java.lang.String, str]):
        """
        Constructs a DWARFException with the specified message.
        
        :param java.lang.String or str message: the detail message
        """

    @typing.overload
    def __init__(self, message: typing.Union[java.lang.String, str], cause: java.lang.Throwable):
        ...



__all__ = ["DWARFEndianity", "DWARFDataInstanceHelper", "DWARFLocation", "DWARFLengthValue", "DWARFAddressListHeader", "DWARFImportOptions", "ExternalDebugFileSymbolImporter", "DWARFLocationList", "DWARFEncoding", "DWARFRegisterMappingsManager", "DWARFChildren", "DWARFAbbreviation", "NameDeduper", "DWARFStringOffsetTableHeader", "DWARFIndirectTable", "DWARFUnitType", "DebugInfoEntry", "DWARFUnitHeader", "DWARFLocationListEntry", "DWARFDataTypeManager", "DWARFImporter", "DWARFDataTypeImporter", "DWARFDataTypeConflictHandler", "DWARFSourceInfo", "DataTypeGraphComparator", "StringTable", "DWARFFunctionImporter", "DWARFCompilationUnit", "DWARFLocationListHeader", "DWARFRange", "DWARFRangeList", "DWARFSourceLanguage", "DWARFAccessibility", "DWARFVariable", "DWARFRegisterMappings", "DWARFIndirectTableHeader", "DWARFRangeListHeader", "DWARFFunction", "DWARFTag", "DWARFRangeListEntry", "DWARFImportSummary", "DWARFName", "DWARFIdentifierCase", "DWARFProgram", "DIEAggregate", "DWARFUtil", "DWARFInline", "NamespacePath", "DWARFException"]
