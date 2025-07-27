from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.util
import ghidra.app.util.bin
import ghidra.app.util.importer
import ghidra.program.disassemble
import ghidra.program.model.address
import ghidra.program.model.data
import ghidra.program.model.lang
import ghidra.program.model.listing
import ghidra.util.task
import ghidra.util.xml
import ghidra.xml
import java.io # type: ignore
import java.lang # type: ignore
import java.util # type: ignore
import org.xml.sax # type: ignore


@typing.type_check_only
class EquatesXmlMgr(java.lang.Object):
    """
    XML manager for Equates.
    """

    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class CodeXmlMgr(ghidra.program.disassemble.DisassemblerMessageListener):
    ...
    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class MarkupXmlMgr(java.lang.Object):
    """
    XML manager for all references ("markup" for operand substitution).
    """

    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class RegisterValuesXmlMgr(java.lang.Object):
    """
    XML manager for register values.
    """

    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class ExtEntryPointXmlMgr(java.lang.Object):
    """
    XML manager for External Entry Points.
    """

    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class ExternalLibXmlMgr(java.lang.Object):
    """
    XML for external library table for resolved external references.
    """

    class_: typing.ClassVar[java.lang.Class]


class ProgramInfo(java.lang.Object):
    """
    This class stores values pulled from the
    PROGRAM, INFO_SOURCE, and LANGUAGE tag inside a ghidra program XML file.
     
    Please see PROGRAM.DTD
    """

    class_: typing.ClassVar[java.lang.Class]
    family: java.lang.String
    """
    The family name of the program's processor (eg, "Intel").
    """

    processorName: java.lang.String
    """
    The program's processor (eg, Processor.PROCESSOR_X86).
    """

    languageID: ghidra.program.model.lang.LanguageID
    """
    The program's language id, e.g. "x86:LE:32:default".
    """

    compilerSpecID: ghidra.program.model.lang.CompilerSpecID
    """
    The program's compilerSpec id, e.g. "gcc".
    """

    programName: java.lang.String
    """
    The preferred name of the Program when loaded back into Ghidra.
    """

    timestamp: java.lang.String
    """
    The timestamp of when the XML file was created.
    """

    user: java.lang.String
    """
    The ID of the user that created the XML file.
    """

    version: java.lang.String
    """
    The XML version. @deprecated since version 2.1.
    """

    addressModel: java.lang.String
    """
    The size of the addressing (eg, "32 bit"). @deprecated since version 2.1.
    """

    endian: java.lang.String
    """
    The endianness (eg, big or little).
    """

    exePath: java.lang.String
    """
    The absolute path of where the original executable was imported.
    """

    exeFormat: java.lang.String
    """
    The format of the original executable (eg, PE or ELF).
    """

    imageBase: java.lang.String
    """
    The image base of the program.
    """


    def __init__(self):
        ...

    def getNormalizedExternalToolName(self) -> str:
        """
        Returns normalizedExternalToolName field.  This is the name of the tool normalized into known categories ("IDA-PRO" or "GHIDRA") if appropriate.
        
        :return: normalizedExternalToolName
        :rtype: str
        """

    def getTool(self) -> str:
        """
        Returns tool field.  This is the name of the tool exactly as written in the XML being imported.
        
        :return: tool field
        :rtype: str
        """

    def setCompilerSpecID(self, compiler: typing.Union[java.lang.String, str]):
        ...

    def setTool(self, tool: typing.Union[java.lang.String, str]):
        """
        Sets tool field.
        Also sets normalizedExternalToolName to normalized tool names "IDA-PRO" or "GHIDRA" if appropriate, or just sets it to the value of tool.
        """

    def shouldProcessStack(self) -> bool:
        """
        whether the XmlMgr should process stack frames and references.
        """

    @property
    def normalizedExternalToolName(self) -> java.lang.String:
        ...

    @property
    def tool(self) -> java.lang.String:
        ...

    @tool.setter
    def tool(self, value: java.lang.String):
        ...


@typing.type_check_only
class RangeBlock(java.lang.Object):
    ...
    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class CommentsXmlMgr(java.lang.Object):
    """
    XML manager for all types of comments.
    """

    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class PropertiesXmlMgr(java.lang.Object):
    ...
    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class MemoryMapXmlMgr(java.lang.Object):
    ...
    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class MyErrorHandler(org.xml.sax.ErrorHandler):
    ...
    class_: typing.ClassVar[java.lang.Class]


class XMLErrorHandler(org.xml.sax.ErrorHandler):
    """
    An implementation of the basic interface for SAX error handlers.
    Per the documentation, this class is required to prevent the SAX
    parser from squelching all parse exceptions.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class XmlProgramOptions(java.lang.Object):
    """
    A class to hold XML options.
    """

    class_: typing.ClassVar[java.lang.Class]
    OPT_MEMORY_BLOCKS: typing.Final = 1
    """
    Flag to indicate reading/writing memory blocks
    """

    OPT_MEMORY_CONTENTS: typing.Final = 2
    """
    Flag to indicate reading/writing memory contents
    """

    OPT_CODE: typing.Final = 4
    """
    Flag to indicate reading/writing instructions
    """

    OPT_DATA: typing.Final = 8
    """
    Flag to indicate reading/writing data
    """

    OPT_SYMBOLS: typing.Final = 16
    """
    Flag to indicate reading/writing symbols
    """

    OPT_EQUATES: typing.Final = 32
    """
    Flag to indicate reading/writing equates
    """

    OPT_COMMENTS: typing.Final = 64
    """
    Flag to indicate reading/writing comments
    """

    OPT_PROPERTIES: typing.Final = 128
    """
    Flag to indicate reading/writing properties
    """

    OPT_TREES: typing.Final = 256
    """
    Flag to indicate reading/writing trees
    """

    OPT_EMPTY_TREE_NODES: typing.Final = 512
    """
    Flag to indicate reading/writing empty program tree nodes
    """

    OPT_REFERENCES: typing.Final = 1024
    """
    Flag to indicate reading/writing references
    """

    OPT_FUNCTIONS: typing.Final = 2048
    """
    Flag to indicate reading/writing functions
    """

    OVERWRITE_SYMBOLS: typing.Final = 536870912
    """
    Used to signify that symbols should be overwritten when
    necessary. This value is not being included in
    the ``ALL`` constant.
    """

    OVERWRITE_REFS: typing.Final = 1073741824
    """
    Used to signify that references should be overwritten when
    necessary. This value is not being included in
    the ``ALL`` constant.
    """

    ADD_2_PROG: typing.Final = 2147483648
    """
    Used to signify that an existing program is being
    updated. This value is not being included in
    the ``ALL`` constant.
    """


    def __init__(self):
        ...

    def getOptions(self, isAddToProgram: typing.Union[jpype.JBoolean, bool]) -> java.util.List[ghidra.app.util.Option]:
        """
        Returns an array of importer options representing
        the flags in this class.
        
        :param jpype.JBoolean or bool isAddToProgram: if true then adding to existing program
        :return: the array of importer options
        :rtype: java.util.List[ghidra.app.util.Option]
        """

    def isBookmarks(self) -> bool:
        """
        If true, then bookmarks should be read/written.
        
        :return: true if bookmarks should be read/written
        :rtype: bool
        """

    def isComments(self) -> bool:
        """
        If true, then comments should be read/written.
        
        :return: true if comments should be read/written
        :rtype: bool
        """

    def isData(self) -> bool:
        """
        If true, then data should be read/written.
        
        :return: true if data should be read/written
        :rtype: bool
        """

    def isEntryPoints(self) -> bool:
        """
        If true, then the entry points should be read/written.
        
        :return: true if the entry points should be read/written
        :rtype: bool
        """

    def isEquates(self) -> bool:
        """
        If true, then equates should be read/written.
        
        :return: true if equates should be read/written
        :rtype: bool
        """

    def isExternalLibraries(self) -> bool:
        """
        If true, then the external libraries should be read/written.
        
        :return: true if the external libraries should be read/written
        :rtype: bool
        """

    def isFunctions(self) -> bool:
        """
        If true, then functions should be read/written.
        
        :return: true if functions should be read/written
        :rtype: bool
        """

    def isInstructions(self) -> bool:
        """
        If true, then instructions should be read/written.
        
        :return: true if instructions should be read/written
        :rtype: bool
        """

    def isMemoryBlocks(self) -> bool:
        """
        If true, then memory blocks should be read/written.
        
        :return: true if memory blocks should be read/written
        :rtype: bool
        """

    def isMemoryContents(self) -> bool:
        """
        If true, then memory contents should be read/written.
        
        :return: true if memory contents should be read/written
        :rtype: bool
        """

    def isOverwriteBookmarkConflicts(self) -> bool:
        """
        If true, then bookmark conflicts will be overwritten.
        
        :return: true if bookmark conflicts will be overwritten
        :rtype: bool
        """

    def isOverwriteDataConflicts(self) -> bool:
        """
        If true, then data conflicts will be overwritten.
        
        :return: true if data conflicts will be overwritten
        :rtype: bool
        """

    def isOverwriteMemoryConflicts(self) -> bool:
        """
        If true, then memory conflicts will be overwritten.
        
        :return: true if memory conflicts will be overwritten
        :rtype: bool
        """

    def isOverwritePropertyConflicts(self) -> bool:
        """
        If true, then property conflicts will be overwritten.
        
        :return: true if property conflicts will be overwritten
        :rtype: bool
        """

    def isOverwriteReferenceConflicts(self) -> bool:
        """
        If true, then reference conflicts will be overwritten.
        
        :return: true if reference conflicts will be overwritten
        :rtype: bool
        """

    def isOverwriteSymbolConflicts(self) -> bool:
        """
        If true, then symbol conflicts will be overwritten.
        
        :return: true if symbol conflicts will be overwritten
        :rtype: bool
        """

    def isProperties(self) -> bool:
        """
        If true, then properties should be read/written.
        
        :return: true if properties should be read/written
        :rtype: bool
        """

    def isReferences(self) -> bool:
        """
        If true, then references (memory, stack, external) should be read/written.
        
        :return: true if references should be read/written
        :rtype: bool
        """

    def isRegisters(self) -> bool:
        """
        If true, then registers should be read/written.
        
        :return: true if registers should be read/written
        :rtype: bool
        """

    def isRelocationTable(self) -> bool:
        """
        If true, then the relocation table should be read/written.
        
        :return: true if the relocation table should be read/written
        :rtype: bool
        """

    def isSymbols(self) -> bool:
        """
        If true, then symbols should be read/written.
        
        :return: true if symbols should be read/written
        :rtype: bool
        """

    def isTrees(self) -> bool:
        """
        If true, then program trees should be read/written.
        
        :return: true if program trees should be read/written
        :rtype: bool
        """

    def setAddToProgram(self, addToProgram: typing.Union[jpype.JBoolean, bool]):
        ...

    def setBookmarks(self, b: typing.Union[jpype.JBoolean, bool]):
        """
        Sets bookmarks to be read/written.
        
        :param jpype.JBoolean or bool b: true if bookmarks should read/written
        """

    def setComments(self, b: typing.Union[jpype.JBoolean, bool]):
        """
        Sets comments to be read/written.
        
        :param jpype.JBoolean or bool b: true if comments should read/written
        """

    def setData(self, b: typing.Union[jpype.JBoolean, bool]):
        """
        Sets data to be read/written.
        
        :param jpype.JBoolean or bool b: true if data should read/written
        """

    def setEntryPoints(self, b: typing.Union[jpype.JBoolean, bool]):
        """
        Sets entry points to be read/written.
        
        :param jpype.JBoolean or bool b: true if entry points should read/written
        """

    def setEquates(self, b: typing.Union[jpype.JBoolean, bool]):
        """
        Sets equates to be read/written.
        
        :param jpype.JBoolean or bool b: true if equates should read/written
        """

    def setExternalLibraries(self, b: typing.Union[jpype.JBoolean, bool]):
        """
        Sets external libraries to be read/written.
        
        :param jpype.JBoolean or bool b: true if external libraries should read/written
        """

    def setFunctions(self, b: typing.Union[jpype.JBoolean, bool]):
        """
        Sets functions to be read/written.
        
        :param jpype.JBoolean or bool b: true if functions should read/written
        """

    def setInstructions(self, b: typing.Union[jpype.JBoolean, bool]):
        """
        Sets instructions to be read/written.
        
        :param jpype.JBoolean or bool b: true if instructions should read/written
        """

    def setMemoryBlocks(self, b: typing.Union[jpype.JBoolean, bool]):
        """
        Sets memory blocks to be read/written.
        
        :param jpype.JBoolean or bool b: true if memory blocks should read/written
        """

    def setMemoryContents(self, b: typing.Union[jpype.JBoolean, bool]):
        """
        Sets memory contents to be read/written.
        
        :param jpype.JBoolean or bool b: true if memory contents should read/written
        """

    def setOptions(self, options: java.util.List[ghidra.app.util.Option]):
        """
        Sets the options. This method is not for defining the options, but
        rather for setting the values of options. If invalid options
        are passed in, then OptionException should be thrown.
        
        :param java.util.List[ghidra.app.util.Option] options: the option values for XML
        :raises OptionException: if invalid options are passed in
        """

    def setOverwriteBookmarkConflicts(self, b: typing.Union[jpype.JBoolean, bool]):
        """
        Sets bookmark conflicts to always be overwritten.
        
        :param jpype.JBoolean or bool b: true if bookmark conflicts should always be overwritten
        """

    def setOverwriteDataConflicts(self, b: typing.Union[jpype.JBoolean, bool]):
        """
        Sets data conflicts to always be overwritten.
        
        :param jpype.JBoolean or bool b: true if data conflicts should always be overwritten
        """

    def setOverwriteMemoryConflicts(self, b: typing.Union[jpype.JBoolean, bool]):
        """
        Sets memory conflicts to always be overwritten.
        
        :param jpype.JBoolean or bool b: true if memory conflicts should always be overwritten
        """

    def setOverwritePropertyConflicts(self, b: typing.Union[jpype.JBoolean, bool]):
        """
        Sets property conflicts to always be overwritten.
        
        :param jpype.JBoolean or bool b: true if property conflicts should always be overwritten
        """

    def setOverwriteReferenceConflicts(self, b: typing.Union[jpype.JBoolean, bool]):
        """
        Sets reference conflicts to always be overwritten.
        
        :param jpype.JBoolean or bool b: true if reference conflicts should always be overwritten
        """

    def setOverwriteSymbolConflicts(self, b: typing.Union[jpype.JBoolean, bool]):
        """
        Sets symbol conflicts to always be overwritten.
        
        :param jpype.JBoolean or bool b: true if symbol conflicts should always be overwritten
        """

    def setProperties(self, b: typing.Union[jpype.JBoolean, bool]):
        """
        Sets properties to be read/written.
        
        :param jpype.JBoolean or bool b: true if properties should read/written
        """

    def setReferences(self, b: typing.Union[jpype.JBoolean, bool]):
        """
        Sets references to be read/written.
        
        :param jpype.JBoolean or bool b: true if references should read/written
        """

    def setRegisters(self, b: typing.Union[jpype.JBoolean, bool]):
        """
        Sets registers to be read/written.
        
        :param jpype.JBoolean or bool b: true if registers should read/written
        """

    def setRelocationTable(self, b: typing.Union[jpype.JBoolean, bool]):
        """
        Sets relocation tables to be read/written.
        
        :param jpype.JBoolean or bool b: true if relocation table should read/written
        """

    def setSymbols(self, b: typing.Union[jpype.JBoolean, bool]):
        """
        Sets symbols to be read/written.
        
        :param jpype.JBoolean or bool b: true if symbols should read/written
        """

    def setTrees(self, b: typing.Union[jpype.JBoolean, bool]):
        """
        Sets program trees to be read/written.
        
        :param jpype.JBoolean or bool b: true if program trees should read/written
        """

    @property
    def overwritePropertyConflicts(self) -> jpype.JBoolean:
        ...

    @overwritePropertyConflicts.setter
    def overwritePropertyConflicts(self, value: jpype.JBoolean):
        ...

    @property
    def instructions(self) -> jpype.JBoolean:
        ...

    @instructions.setter
    def instructions(self, value: jpype.JBoolean):
        ...

    @property
    def entryPoints(self) -> jpype.JBoolean:
        ...

    @entryPoints.setter
    def entryPoints(self, value: jpype.JBoolean):
        ...

    @property
    def comments(self) -> jpype.JBoolean:
        ...

    @comments.setter
    def comments(self, value: jpype.JBoolean):
        ...

    @property
    def references(self) -> jpype.JBoolean:
        ...

    @references.setter
    def references(self, value: jpype.JBoolean):
        ...

    @property
    def overwriteDataConflicts(self) -> jpype.JBoolean:
        ...

    @overwriteDataConflicts.setter
    def overwriteDataConflicts(self, value: jpype.JBoolean):
        ...

    @property
    def functions(self) -> jpype.JBoolean:
        ...

    @functions.setter
    def functions(self, value: jpype.JBoolean):
        ...

    @property
    def data(self) -> jpype.JBoolean:
        ...

    @data.setter
    def data(self, value: jpype.JBoolean):
        ...

    @property
    def overwriteReferenceConflicts(self) -> jpype.JBoolean:
        ...

    @overwriteReferenceConflicts.setter
    def overwriteReferenceConflicts(self, value: jpype.JBoolean):
        ...

    @property
    def externalLibraries(self) -> jpype.JBoolean:
        ...

    @externalLibraries.setter
    def externalLibraries(self, value: jpype.JBoolean):
        ...

    @property
    def overwriteBookmarkConflicts(self) -> jpype.JBoolean:
        ...

    @overwriteBookmarkConflicts.setter
    def overwriteBookmarkConflicts(self, value: jpype.JBoolean):
        ...

    @property
    def memoryBlocks(self) -> jpype.JBoolean:
        ...

    @memoryBlocks.setter
    def memoryBlocks(self, value: jpype.JBoolean):
        ...

    @property
    def trees(self) -> jpype.JBoolean:
        ...

    @trees.setter
    def trees(self, value: jpype.JBoolean):
        ...

    @property
    def equates(self) -> jpype.JBoolean:
        ...

    @equates.setter
    def equates(self, value: jpype.JBoolean):
        ...

    @property
    def symbols(self) -> jpype.JBoolean:
        ...

    @symbols.setter
    def symbols(self, value: jpype.JBoolean):
        ...

    @property
    def overwriteSymbolConflicts(self) -> jpype.JBoolean:
        ...

    @overwriteSymbolConflicts.setter
    def overwriteSymbolConflicts(self, value: jpype.JBoolean):
        ...

    @property
    def bookmarks(self) -> jpype.JBoolean:
        ...

    @bookmarks.setter
    def bookmarks(self, value: jpype.JBoolean):
        ...

    @property
    def overwriteMemoryConflicts(self) -> jpype.JBoolean:
        ...

    @overwriteMemoryConflicts.setter
    def overwriteMemoryConflicts(self, value: jpype.JBoolean):
        ...

    @property
    def memoryContents(self) -> jpype.JBoolean:
        ...

    @memoryContents.setter
    def memoryContents(self, value: jpype.JBoolean):
        ...

    @property
    def options(self) -> java.util.List[ghidra.app.util.Option]:
        ...

    @options.setter
    def options(self, value: java.util.List[ghidra.app.util.Option]):
        ...

    @property
    def registers(self) -> jpype.JBoolean:
        ...

    @registers.setter
    def registers(self, value: jpype.JBoolean):
        ...

    @property
    def relocationTable(self) -> jpype.JBoolean:
        ...

    @relocationTable.setter
    def relocationTable(self, value: jpype.JBoolean):
        ...

    @property
    def properties(self) -> jpype.JBoolean:
        ...

    @properties.setter
    def properties(self, value: jpype.JBoolean):
        ...


@typing.type_check_only
class BytesFile(java.lang.Object):
    ...
    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class RelocationTableXmlMgr(java.lang.Object):
    ...
    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class SymbolTableXmlMgr(java.lang.Object):
    """
    XML manager for the Symbol Table.
    """

    class_: typing.ClassVar[java.lang.Class]


class DataTypesXmlMgr(java.lang.Object):
    """
    This manager is responsible for reading and writing datatypes in XML.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, dataManager: ghidra.program.model.data.DataTypeManager, log: ghidra.app.util.importer.MessageLog):
        """
        Constructs a new data types XML manager.
        
        :param ghidra.program.model.data.DataTypeManager dataManager: the data type manager to read from or write to
        :param ghidra.app.util.importer.MessageLog log: the message log for recording datatype warnings
        """

    def read(self, parser: ghidra.xml.XmlPullParser, monitor: ghidra.util.task.TaskMonitor):
        """
        Reads the datatypes encoded in XML from the specified XML parser and recreates
        them in a datatype manager.
        
        :param ghidra.xml.XmlPullParser parser: the XML parser
        :param ghidra.util.task.TaskMonitor monitor: the task monitor
        :raises SAXParseException: if an XML parse error occurs
        :raises CancelledException: if the user cancels the read operation
        """

    def write(self, writer: ghidra.util.xml.XmlWriter, monitor: ghidra.util.task.TaskMonitor):
        """
        Writes datatypes into XML using the specified XML writer.
        
        :param ghidra.util.xml.XmlWriter writer: the XML writer
        :param ghidra.util.task.TaskMonitor monitor: the task monitor
        :raises CancelledException: if the user cancels the write operation
        """

    @staticmethod
    def writeAsXMLForDebug(dataManager: ghidra.program.model.data.DataTypeManager, outputFilename: typing.Union[java.lang.String, str]):
        """
        Output data types in XML format for debugging purposes.
        NOTE: There is no support for reading the XML produced by this method.
        
        :param ghidra.program.model.data.DataTypeManager dataManager: the data type manager
        :param java.lang.String or str outputFilename: name of the output file
        :raises IOException: if there was a problem writing to the file
        """


@typing.type_check_only
class FunctionsXmlMgr(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    LIB_BOOKMARK_CATEGORY: typing.Final = "Library Identification"
    FID_BOOKMARK_CATEGORY: typing.Final = "Function ID Analyzer"


@typing.type_check_only
class DtParser(java.lang.Object):
    """
    DtParser
    """

    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class DefinedDataXmlMgr(java.lang.Object):
    ...
    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class ProgramTreeXmlMgr(java.lang.Object):
    """
    XML manager for program trees.
    """

    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class BookmarksXmlMgr(java.lang.Object):
    ...
    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class DisplaySettingsHandler(java.lang.Object):
    ...
    class_: typing.ClassVar[java.lang.Class]


class ProgramXmlMgr(java.lang.Object):
    """
    The manager responsible for reading and writing a program in XML.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, file: jpype.protocol.SupportsPath):
        """
        Constructs a new program XML manager using the specified file.
        The file should be an XML file.
        
        :param jpype.protocol.SupportsPath file: the XML file
        """

    @typing.overload
    def __init__(self, bp: ghidra.app.util.bin.ByteProvider):
        """
        Constructs a new program XML manager using the specified :obj:`ByteProvider`.
         
        
        If :obj:`ByteProvider` has a :obj:`FSRL` and it is a simple local filepath,
        convert that to a normal local java.io.File instance instead of using the
        :obj:`ByteProvider`'s File property which is probably located in the
        :obj:`FileSystemService` filecache directory, which will break the ability
        to find the *.bytes file associated with this .xml file.
         
        
        This workaround will not help xml files that are truly embedded in a GFileSystem
        (ie. in a .zip file).
        
        :param ghidra.app.util.bin.ByteProvider bp:
        """

    def getProgramInfo(self) -> ProgramInfo:
        """
        Returns the program info from the underlying file. T``his method
        does not make sense to invoke if a write is being performed
        to a new file.
        
        :return: the program info
        :rtype: ProgramInfo
        :raises SAXException: if an XML error occurs
        :raises IOException: if an I/O error occurs
        """

    @staticmethod
    def getStandardName(name: typing.Union[java.lang.String, str]) -> str:
        """
        Converts from a generic format name to standard Ghidra names;
        
        :param java.lang.String or str name: the generic format name
        :return: the equivalent Ghidra name
        :rtype: str
        """

    def read(self, program: ghidra.program.model.listing.Program, monitor: ghidra.util.task.TaskMonitor, options: XmlProgramOptions) -> ghidra.app.util.importer.MessageLog:
        """
        Reads from the underlying XML file and populates the specified program.
        
        :param ghidra.program.model.listing.Program program: the program to load the XML into
        :param ghidra.util.task.TaskMonitor monitor: the task monitor
        :param XmlProgramOptions options: the XML options, which features to load and to ignore
        :return: the message log containing any warning/error messages
        :rtype: ghidra.app.util.importer.MessageLog
        :raises SAXException: if an XML error occurs
        :raises IOException: if an I/O occurs
        :raises AddressFormatException: if an invalid address is specified in the XML
        """

    def write(self, program: ghidra.program.model.listing.Program, addrSet: ghidra.program.model.address.AddressSetView, monitor: ghidra.util.task.TaskMonitor, options: XmlProgramOptions) -> ghidra.app.util.importer.MessageLog:
        """
        Writes the specified program in XML into the underlying file.
        
        :param ghidra.program.model.listing.Program program: the program to write into XML
        :param ghidra.program.model.address.AddressSetView addrSet: an address set to limit areas of program that written, or null for entire program
        :param ghidra.util.task.TaskMonitor monitor: the task monitor
        :param XmlProgramOptions options: the XML options to limit what is and is not written out
        :return: the message log containing any warning/error messages
        :rtype: ghidra.app.util.importer.MessageLog
        :raises IOException: if an I/O occurs
        :raises CancelledException: if the user cancels the read
        """

    @property
    def programInfo(self) -> ProgramInfo:
        ...



__all__ = ["EquatesXmlMgr", "CodeXmlMgr", "MarkupXmlMgr", "RegisterValuesXmlMgr", "ExtEntryPointXmlMgr", "ExternalLibXmlMgr", "ProgramInfo", "RangeBlock", "CommentsXmlMgr", "PropertiesXmlMgr", "MemoryMapXmlMgr", "MyErrorHandler", "XMLErrorHandler", "XmlProgramOptions", "BytesFile", "RelocationTableXmlMgr", "SymbolTableXmlMgr", "DataTypesXmlMgr", "FunctionsXmlMgr", "DtParser", "DefinedDataXmlMgr", "ProgramTreeXmlMgr", "BookmarksXmlMgr", "DisplaySettingsHandler", "ProgramXmlMgr"]
