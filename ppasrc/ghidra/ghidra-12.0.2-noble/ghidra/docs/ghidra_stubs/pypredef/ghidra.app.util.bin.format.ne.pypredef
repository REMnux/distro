from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.util.bin
import ghidra.app.util.bin.format.mz
import ghidra.program.model.address
import java.lang # type: ignore


class ImportedNameTable(java.lang.Object):
    """
    A class to represent the new-executable imported name table.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getNameAt(self, offset: typing.Union[jpype.JShort, int]) -> LengthStringSet:
        """
        Returns the length/string set at the given offset.
        
        :param jpype.JShort or int offset: The offset, from the beginning of the Imported Name Table,
                        to the length/string set.
        :return: the length/string set at the given offset
        :rtype: LengthStringSet
        """

    @property
    def nameAt(self) -> LengthStringSet:
        ...


@typing.type_check_only
class RelocationImportedOrdinal(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def getIndex(self) -> int:
        ...

    def getOrdinal(self) -> int:
        ...

    @property
    def index(self) -> jpype.JShort:
        ...

    @property
    def ordinal(self) -> jpype.JShort:
        ...


class EntryPoint(java.lang.Object):
    """
    A class to represent a new-executable entry point.
    """

    class_: typing.ClassVar[java.lang.Class]
    EXPORTED: typing.Final = 1
    GLOBAL: typing.Final = 2

    def getFlagword(self) -> int:
        """
        Returns the flagword.
        
        :return: the flagword
        :rtype: int
        """

    def getInstruction(self) -> int:
        """
        Returns the instruction.
        
        :return: the instruction
        :rtype: int
        """

    def getOffset(self) -> int:
        """
        Returns the offset.
        
        :return: the offset
        :rtype: int
        """

    def getSegment(self) -> int:
        """
        Returns the segment.
        
        :return: the segment
        :rtype: int
        """

    @property
    def offset(self) -> jpype.JShort:
        ...

    @property
    def flagword(self) -> jpype.JByte:
        ...

    @property
    def instruction(self) -> jpype.JShort:
        ...

    @property
    def segment(self) -> jpype.JByte:
        ...


@typing.type_check_only
class RelocationInternalRef(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def getOffset(self) -> int:
        ...

    def getPad(self) -> int:
        ...

    def getSegment(self) -> int:
        ...

    def isMoveable(self) -> bool:
        ...

    @property
    def pad(self) -> jpype.JByte:
        ...

    @property
    def offset(self) -> jpype.JShort:
        ...

    @property
    def moveable(self) -> jpype.JBoolean:
        ...

    @property
    def segment(self) -> jpype.JByte:
        ...


class NonResidentNameTable(java.lang.Object):
    """
    A class to represent the new-executable non-resident name table.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getNames(self) -> jpype.JArray[LengthStringOrdinalSet]:
        """
        Returns the array of names defined in the non-resident name table.
        
        :return: the array of names defined in the non-resident name table
        :rtype: jpype.JArray[LengthStringOrdinalSet]
        """

    def getTitle(self) -> str:
        """
        Returns the non-resident name table title.
        
        :return: the non-resident name table title
        :rtype: str
        """

    @property
    def names(self) -> jpype.JArray[LengthStringOrdinalSet]:
        ...

    @property
    def title(self) -> java.lang.String:
        ...


class ResourceName(java.lang.Object):
    """
    A class for storing new-executable resource names.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getIndex(self) -> int:
        """
        Returns the byte index of this resource name, relative to the beginning of the file.
        
        :return: the byte index of this resource name
        :rtype: int
        """

    def getLength(self) -> int:
        """
        Returns the length of the resource name.
        
        :return: the length of the resource name
        :rtype: int
        """

    def getName(self) -> str:
        """
        Returns the name of the resource name.
        
        :return: the name of the resource name
        :rtype: str
        """

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def length(self) -> jpype.JByte:
        ...

    @property
    def index(self) -> jpype.JLong:
        ...


class WindowsHeader(java.lang.Object):
    """
    A class to represent and parse the 
    Windows new-style executable (NE) header.
    """

    class_: typing.ClassVar[java.lang.Class]
    IMAGE_NE_SIGNATURE: typing.Final = 17742
    """
    The magic number for Windows NE files.
    """


    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, baseAddr: ghidra.program.model.address.SegmentedAddress, index: typing.Union[jpype.JShort, int]):
        """
        Constructor
        
        :param ghidra.app.util.bin.BinaryReader reader: the binary reader
        :param ghidra.program.model.address.SegmentedAddress baseAddr: the image base address
        :param jpype.JShort or int index: the index where the windows headers begins
        :raises InvalidWindowsHeaderException: if the bytes defined in the binary reader at
        the specified index do not constitute a valid windows header.
        :raises IOException: for problems reading the header bytes
        """

    def getEntryTable(self) -> EntryTable:
        """
        Returns the entry table.
        
        :return: the entry table
        :rtype: EntryTable
        """

    def getImportedNameTable(self) -> ImportedNameTable:
        """
        Returns the imported name table.
        
        :return: the imported name table
        :rtype: ImportedNameTable
        """

    def getInformationBlock(self) -> InformationBlock:
        """
        Returns the information block.
        
        :return: the information block
        :rtype: InformationBlock
        """

    def getModuleReferenceTable(self) -> ModuleReferenceTable:
        """
        Returns the module reference table.
        
        :return: the module reference table
        :rtype: ModuleReferenceTable
        """

    def getNonResidentNameTable(self) -> NonResidentNameTable:
        """
        Returns the non-resident name table.
        
        :return: the non-resident name table
        :rtype: NonResidentNameTable
        """

    def getProcessorName(self) -> str:
        """
        Returns the processor name.
        
        :return: the processor name
        :rtype: str
        """

    def getResidentNameTable(self) -> ResidentNameTable:
        """
        Returns the resident name table.
        
        :return: the resident name table
        :rtype: ResidentNameTable
        """

    def getResourceTable(self) -> ResourceTable:
        """
        Returns the resource table.
        
        :return: the resource table
        :rtype: ResourceTable
        """

    def getSegmentTable(self) -> SegmentTable:
        """
        Returns the segment table.
        
        :return: the segment table
        :rtype: SegmentTable
        """

    @property
    def segmentTable(self) -> SegmentTable:
        ...

    @property
    def importedNameTable(self) -> ImportedNameTable:
        ...

    @property
    def nonResidentNameTable(self) -> NonResidentNameTable:
        ...

    @property
    def informationBlock(self) -> InformationBlock:
        ...

    @property
    def residentNameTable(self) -> ResidentNameTable:
        ...

    @property
    def processorName(self) -> java.lang.String:
        ...

    @property
    def moduleReferenceTable(self) -> ModuleReferenceTable:
        ...

    @property
    def entryTable(self) -> EntryTable:
        ...

    @property
    def resourceTable(self) -> ResourceTable:
        ...


class LengthStringOrdinalSet(LengthStringSet):
    """
    A class to hold a length/string/ordinal set.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getOrdinal(self) -> int:
        """
        Returns the ordinal value.
        
        :return: the ordinal value
        :rtype: int
        """

    @property
    def ordinal(self) -> jpype.JShort:
        ...


@typing.type_check_only
class RelocationOSFixup(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def getFixupType(self) -> int:
        ...

    def getPad(self) -> int:
        ...

    @property
    def pad(self) -> jpype.JShort:
        ...

    @property
    def fixupType(self) -> jpype.JShort:
        ...


class NewExecutable(java.lang.Object):
    """
    A class to manage loading New Executables (NE).
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, bp: ghidra.app.util.bin.ByteProvider, baseAddr: ghidra.program.model.address.SegmentedAddress):
        """
        Constructs a new instance of an new executable.
        
        :param ghidra.app.util.bin.ByteProvider bp: the byte provider
        :param ghidra.program.model.address.SegmentedAddress baseAddr: the image base of the executable
        :raises IOException: if an I/O error occurs.
        """

    def getBinaryReader(self) -> ghidra.app.util.bin.BinaryReader:
        """
        Returns the underlying binary reader.
        
        :return: the underlying binary reader
        :rtype: ghidra.app.util.bin.BinaryReader
        """

    def getDOSHeader(self) -> ghidra.app.util.bin.format.mz.DOSHeader:
        """
        Returns the DOS header from the new executable.
        
        :return: the DOS header from the new executable
        :rtype: ghidra.app.util.bin.format.mz.DOSHeader
        """

    def getWindowsHeader(self) -> WindowsHeader:
        """
        Returns the Windows header from the new executable.
        
        :return: the Windows header from the new executable
        :rtype: WindowsHeader
        """

    @property
    def dOSHeader(self) -> ghidra.app.util.bin.format.mz.DOSHeader:
        ...

    @property
    def windowsHeader(self) -> WindowsHeader:
        ...

    @property
    def binaryReader(self) -> ghidra.app.util.bin.BinaryReader:
        ...


class ResidentNameTable(java.lang.Object):
    """
    A class to represent the new-executable resident name table.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getNames(self) -> jpype.JArray[LengthStringOrdinalSet]:
        """
        Returns the array of names defined in the resident name table.
        
        :return: the array of names defined in the resident name table
        :rtype: jpype.JArray[LengthStringOrdinalSet]
        """

    @property
    def names(self) -> jpype.JArray[LengthStringOrdinalSet]:
        ...


class Segment(java.lang.Object):
    """
    A class to represent a new-executable segment.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getFlagword(self) -> int:
        """
        Returns the flag word of this segment.
        
        :return: the flag word of this segment
        :rtype: int
        """

    def getLength(self) -> int:
        """
        Returns the length of this segment.
        
        :return: the length of this segment
        :rtype: int
        """

    def getMinAllocSize(self) -> int:
        """
        Returns the minimum allocation size of this segment.
        
        :return: the minimum allocation size of this segment
        :rtype: int
        """

    def getOffset(self) -> int:
        """
        Returns the offset to the contents of this segment. 
        NOTE: This value needs to be shift aligned.
        
        :return: the offset to the contents of this segment
        :rtype: int
        """

    def getOffsetShiftAligned(self) -> int:
        """
        Returns the actual (shifted) offset to the contents.
        
        :return: the actual (shifted) offset to the contents
        :rtype: int
        """

    def getRelocations(self) -> jpype.JArray[SegmentRelocation]:
        """
        Returns an array of the relocations defined for this segment.
        
        :return: an array of the relocations defined for this segment
        :rtype: jpype.JArray[SegmentRelocation]
        """

    def getSegmentID(self) -> int:
        """
        Returns segment ID.
        
        :return: segment ID
        :rtype: int
        """

    def hasRelocation(self) -> bool:
        """
        Returns true if this segment has relocations.
        
        :return: true if this segment has relocations
        :rtype: bool
        """

    def is32bit(self) -> bool:
        """
        Returns true if the segment should operate in 32 bit mode.
        
        :return: true if the segment should operate in 32 bit mode
        :rtype: bool
        """

    def isCode(self) -> bool:
        """
        Returns true if this is a code segment.
        
        :return: true if this is a code segment
        :rtype: bool
        """

    def isData(self) -> bool:
        """
        Returns true if this is a data segment.
        
        :return: true if this is a data segment
        :rtype: bool
        """

    def isDiscardable(self) -> bool:
        """
        Returns true if this segment is discardable.
        
        :return: true if this segment is discardable
        :rtype: bool
        """

    def isExecuteOnly(self) -> bool:
        """
        Returns true if this segment is execute-only.
        
        :return: true if this segment is execute-only
        :rtype: bool
        """

    def isLoaded(self) -> bool:
        """
        Returns true if this segment is loaded.
        
        :return: true if this segment is loaded
        :rtype: bool
        """

    def isLoaderAllocated(self) -> bool:
        """
        Returns true if this segment is loader allocated.
        
        :return: true if this segment is loader allocated
        :rtype: bool
        """

    def isMoveable(self) -> bool:
        """
        Returns true if this segment is moveable.
        
        :return: true if this segment is moveable
        :rtype: bool
        """

    def isPreload(self) -> bool:
        """
        Returns true if this segment is preloaded.
        
        :return: true if this segment is preloaded
        :rtype: bool
        """

    def isPure(self) -> bool:
        """
        Returns true if this segment is pure.
        
        :return: true if this segment is pure
        :rtype: bool
        """

    def isReadOnly(self) -> bool:
        """
        Returns true if this segment is read-only.
        
        :return: true if this segment is read-only
        :rtype: bool
        """

    @property
    def discardable(self) -> jpype.JBoolean:
        ...

    @property
    def code(self) -> jpype.JBoolean:
        ...

    @property
    def data(self) -> jpype.JBoolean:
        ...

    @property
    def offset(self) -> jpype.JShort:
        ...

    @property
    def moveable(self) -> jpype.JBoolean:
        ...

    @property
    def minAllocSize(self) -> jpype.JShort:
        ...

    @property
    def length(self) -> jpype.JShort:
        ...

    @property
    def readOnly(self) -> jpype.JBoolean:
        ...

    @property
    def loaderAllocated(self) -> jpype.JBoolean:
        ...

    @property
    def pure(self) -> jpype.JBoolean:
        ...

    @property
    def preload(self) -> jpype.JBoolean:
        ...

    @property
    def loaded(self) -> jpype.JBoolean:
        ...

    @property
    def flagword(self) -> jpype.JShort:
        ...

    @property
    def offsetShiftAligned(self) -> jpype.JInt:
        ...

    @property
    def segmentID(self) -> jpype.JInt:
        ...

    @property
    def executeOnly(self) -> jpype.JBoolean:
        ...

    @property
    def relocations(self) -> jpype.JArray[SegmentRelocation]:
        ...


class Resource(java.lang.Object):
    """
    An implementation of the new-executable TNAMEINFO structure.
    """

    class_: typing.ClassVar[java.lang.Class]
    FLAG_MOVEABLE: typing.Final = 16
    """
    The resources is not fixed.
    """

    FLAG_PURE: typing.Final = 32
    """
    The resource can be shared.
    """

    FLAG_PRELOAD: typing.Final = 64
    """
    The resource is preloaded.
    """


    def getBytes(self) -> jpype.JArray[jpype.JByte]:
        """
        Returns the actual bytes for this resource.
        
        :return: the actual bytes for this resource
        :rtype: jpype.JArray[jpype.JByte]
        """

    def getFileLength(self) -> int:
        """
        Returns the file length of this resource.
        
        :return: the file length of this resource
        :rtype: int
        """

    def getFileLengthShifted(self) -> int:
        """
        Returns the shifted file length of this resource.
        ``this.getFileLength() << ResourceTable.getAlignmentShiftCount()``
        
        :return: the shifted file length of this resource
        :rtype: int
        """

    def getFileOffset(self) -> int:
        """
        Returns the file offset of this resource.
        
        :return: the file offset of this resource
        :rtype: int
        """

    def getFileOffsetShifted(self) -> int:
        """
        Returns the shifted file offset of this resource.
        ``this.getFileOffset() << ResourceTable.getAlignmentShiftCount()``
        
        :return: the shifted file offset of this resource
        :rtype: int
        """

    def getFlagword(self) -> int:
        """
        Returns the flag word of this resource.
        
        :return: the flag word of this resource
        :rtype: int
        """

    def getHandle(self) -> int:
        """
        Returns the handle of this resource.
        
        :return: the handle of this resource
        :rtype: int
        """

    def getResourceID(self) -> int:
        """
        Returns the resource ID of this resource.
        
        :return: the resource ID of this resource
        :rtype: int
        """

    def getUsage(self) -> int:
        """
        Returns the usage of this resource.
        
        :return: the usage of this resource
        :rtype: int
        """

    def isMoveable(self) -> bool:
        """
        Returns true if this resource is moveable.
        
        :return: true if this resource is moveable
        :rtype: bool
        """

    def isPreload(self) -> bool:
        """
        Returns true if this resource is preloaded.
        
        :return: true if this resource is preloaded
        :rtype: bool
        """

    def isPure(self) -> bool:
        """
        Returns true if this resource is pure.
        
        :return: true if this resource is pure
        :rtype: bool
        """

    @property
    def resourceID(self) -> jpype.JShort:
        ...

    @property
    def flagword(self) -> jpype.JShort:
        ...

    @property
    def fileOffsetShifted(self) -> jpype.JInt:
        ...

    @property
    def bytes(self) -> jpype.JArray[jpype.JByte]:
        ...

    @property
    def moveable(self) -> jpype.JBoolean:
        ...

    @property
    def usage(self) -> jpype.JShort:
        ...

    @property
    def handle(self) -> jpype.JShort:
        ...

    @property
    def fileOffset(self) -> jpype.JShort:
        ...

    @property
    def pure(self) -> jpype.JBoolean:
        ...

    @property
    def preload(self) -> jpype.JBoolean:
        ...

    @property
    def fileLengthShifted(self) -> jpype.JInt:
        ...

    @property
    def fileLength(self) -> jpype.JShort:
        ...


class ResourceType(java.lang.Object):
    """
    An implementation of the TTYPEINFO structure.
    """

    class_: typing.ClassVar[java.lang.Class]
    RT_CURSOR: typing.Final = 1
    """
    Constant indicating cursor resource type.
    """

    RT_BITMAP: typing.Final = 2
    """
    Constant indicating bitmap resource type.
    """

    RT_ICON: typing.Final = 3
    """
    Constant indicating icon resource type.
    """

    RT_MENU: typing.Final = 4
    """
    Constant indicating menu resource type.
    """

    RT_DIALOG: typing.Final = 5
    """
    Constant indicating dialog resource type.
    """

    RT_STRING: typing.Final = 6
    """
    Constant indicating string resource type.
    """

    RT_FONTDIR: typing.Final = 7
    """
    Constant indicating font directory resource type.
    """

    RT_FONT: typing.Final = 8
    """
    Constant indicating font resource type.
    """

    RT_ACCELERATOR: typing.Final = 9
    """
    Constant indicating an accelerator resource type.
    """

    RT_RCDATA: typing.Final = 10
    """
    Constant indicating RC data resource type.
    """

    RT_MESSAGETABLE: typing.Final = 11
    """
    Constant indicating message table resource type.
    """

    RT_GROUP_CURSOR: typing.Final = 12
    """
    Constant indicating cursor group resource type.
    """

    RT_GROUP_ICON: typing.Final = 14
    """
    Constant indicating icon group resource type.
    """

    RT_VERSION: typing.Final = 16
    """
    Constant indicating version resource type.
    """


    def getCount(self) -> int:
        """
        Returns the number of resources of this type.
        
        :return: the number of resources of this type
        :rtype: int
        """

    def getReserved(self) -> int:
        """
        Returns the reserved value (purpose is unknown).
        
        :return: the reserved value
        :rtype: int
        """

    def getResources(self) -> jpype.JArray[Resource]:
        """
        Returns the array of resources of this type.
        
        :return: the array of resources of this type
        :rtype: jpype.JArray[Resource]
        """

    def getTypeID(self) -> int:
        """
        Returns the resource type ID.
        
        :return: the resource type ID
        :rtype: int
        """

    @property
    def reserved(self) -> jpype.JInt:
        ...

    @property
    def count(self) -> jpype.JShort:
        ...

    @property
    def resources(self) -> jpype.JArray[Resource]:
        ...

    @property
    def typeID(self) -> jpype.JShort:
        ...


class EntryTableBundle(java.lang.Object):
    """
    A class to represent a new-executable entry table bundle.
    """

    class_: typing.ClassVar[java.lang.Class]
    UNUSED: typing.Final = 0
    """
    Marker denoting an unused entry table bundle.
    """

    MOVEABLE: typing.Final = -1
    """
    Segment is moveable.
    """

    CONSTANT: typing.Final = -2
    """
    Refers to a constant defined in module.
    """


    def getCount(self) -> int:
        """
        Returns the number of entries in bundle.
        
        :return: the number of entries in bundle
        :rtype: int
        """

    def getEntryPoints(self) -> jpype.JArray[EntryPoint]:
        """
        Returns the array of entry points in this bundle.
        
        :return: the array of entry points in this bundle
        :rtype: jpype.JArray[EntryPoint]
        """

    def getType(self) -> int:
        """
        Returns the type of the bundle. For example,
        MOVEABLE, CONSTANT, or segment index.
        
        :return: the type of the bundle
        :rtype: int
        """

    def isConstant(self) -> bool:
        """
        Returns true if this bundle is constant.
        
        :return: true if this bundle is constant
        :rtype: bool
        """

    def isMoveable(self) -> bool:
        """
        Returns true if this bundle is moveable.
        
        :return: true if this bundle is moveable
        :rtype: bool
        """

    @property
    def entryPoints(self) -> jpype.JArray[EntryPoint]:
        ...

    @property
    def constant(self) -> jpype.JBoolean:
        ...

    @property
    def moveable(self) -> jpype.JBoolean:
        ...

    @property
    def count(self) -> jpype.JByte:
        ...

    @property
    def type(self) -> jpype.JByte:
        ...


class ResourceStringTable(Resource):
    """
    A class for storing new-executable resource string tables.
    Strings are not stored as individual resources, rather
    strings are grouped together into a string table. This
    string table is then stored as a resource.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getStrings(self) -> jpype.JArray[LengthStringSet]:
        """
        Returns the strings defined in this resource string table.
        
        :return: the strings defined in this resource string table
        :rtype: jpype.JArray[LengthStringSet]
        """

    @property
    def strings(self) -> jpype.JArray[LengthStringSet]:
        ...


class EntryTable(java.lang.Object):
    """
    A class to represent a new-executable entry table.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getBundles(self) -> jpype.JArray[EntryTableBundle]:
        """
        Returns an array of the entry table bundles in this
        entry table.
        
        :return: an array of entry table bundles
        :rtype: jpype.JArray[EntryTableBundle]
        """

    @property
    def bundles(self) -> jpype.JArray[EntryTableBundle]:
        ...


class ModuleReferenceTable(java.lang.Object):
    """
    A class to represent the new-executable module reference table.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getNames(self) -> jpype.JArray[LengthStringSet]:
        """
        Returns the array of names.
        
        :return: the array of names
        :rtype: jpype.JArray[LengthStringSet]
        """

    def getOffsets(self) -> jpype.JArray[jpype.JShort]:
        """
        Returns the array of offsets.
        
        :return: the array of offsets
        :rtype: jpype.JArray[jpype.JShort]
        """

    @property
    def names(self) -> jpype.JArray[LengthStringSet]:
        ...

    @property
    def offsets(self) -> jpype.JArray[jpype.JShort]:
        ...


class InvalidWindowsHeaderException(java.lang.Exception):
    """
    An exception class to handle encountering
    invalid Windows Headers.
    
    
    .. seealso::
    
        | :obj:`ghidra.app.util.bin.format.ne.WindowsHeader`
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class LengthStringSet(java.lang.Object):
    """
    A class to store a length/string set,
    where the string is not null-terminated
    and the length field determines the string
    length
    """

    class_: typing.ClassVar[java.lang.Class]

    def getIndex(self) -> int:
        """
        Returns the byte index of this string,
        relative to the beginning of the file.
        
        :return: the byte index of this string
        :rtype: int
        """

    def getLength(self) -> int:
        """
        Returns the length of the string.
        
        :return: the length of the string
        :rtype: int
        """

    def getString(self) -> str:
        """
        Returns the string.
        
        :return: the string
        :rtype: str
        """

    @property
    def string(self) -> java.lang.String:
        ...

    @property
    def length(self) -> jpype.JByte:
        ...

    @property
    def index(self) -> jpype.JLong:
        ...


class SegmentTable(java.lang.Object):
    """
    A class to represent the new-executable segment table.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getSegments(self) -> jpype.JArray[Segment]:
        """
        Returns an array of the segments defined in this segment table.
        
        :return: an array of the segments defined in this segment table
        :rtype: jpype.JArray[Segment]
        """

    @property
    def segments(self) -> jpype.JArray[Segment]:
        ...


class InformationBlock(java.lang.Object):
    """
    
    
    A class to represent the Information Block
    defined in the Windows new-style executable.
     
    
     
    
    ...as defined in WINNT.H
     
    
     
    typedef struct _IMAGE_OS2_HEADER {      // OS/2 .EXE header
        WORD   ne_magic;                    // Magic number
        CHAR   ne_ver;                      // Version number
        CHAR   ne_rev;                      // Revision number
        WORD   ne_enttab;                   // Offset of Entry Table
        WORD   ne_cbenttab;                 // Number of bytes in Entry Table
        LONG   ne_crc;                      // Checksum of whole file
        WORD   ne_flags;                    // Flag word
        WORD   ne_autodata;                 // Automatic data segment number
        WORD   ne_heap;                     // Initial heap allocation
        WORD   ne_stack;                    // Initial stack allocation
        LONG   ne_csip;                     // Initial CS:IP setting
        LONG   ne_sssp;                     // Initial SS:SP setting
        WORD   ne_cseg;                     // Count of file segments
        WORD   ne_cmod;                     // Entries in Module Reference Table
        WORD   ne_cbnrestab;                // Size of non-resident name table
        WORD   ne_segtab;                   // Offset of Segment Table
        WORD   ne_rsrctab;                  // Offset of Resource Table
        WORD   ne_restab;                   // Offset of resident name table
        WORD   ne_modtab;                   // Offset of Module Reference Table
        WORD   ne_imptab;                   // Offset of Imported Names Table
        LONG   ne_nrestab;                  // Offset of Non-resident Names Table
        WORD   ne_cmovent;                  // Count of movable entries
        WORD   ne_align;                    // Segment alignment shift count
        WORD   ne_cres;                     // Count of resource segments
        BYTE   ne_exetyp;                   // Target Operating system
        BYTE   ne_flagsothers;              // Other .EXE flags
        WORD   ne_pretthunks;               // offset to return thunks
        WORD   ne_psegrefbytes;             // offset to segment ref. bytes
        WORD   ne_swaparea;                 // Minimum code swap area size
        WORD   ne_expver;                   // Expected Windows version number
    } IMAGE_OS2_HEADER, *PIMAGE_OS2_HEADER;
     
    
    
    .. seealso::
    
        | `The NE EXE File Format <https://www.fileformat.info/format/exe/corion-ne.htm>`_
    
        | `Segmented (New) .EXE File Header Format <https://www.pcjs.org/pubs/pc/reference/microsoft/mspl13/msdos/encyclopedia/appendix-k/>`_
    """

    class_: typing.ClassVar[java.lang.Class]
    FLAGS_PROG_NO_AUTO_DATA: typing.Final = 0
    """
    Program flags: no auto data segments
    """

    FLAGS_PROG_SINGLE_DATA: typing.Final = 1
    """
    Program flags: single data segment
    """

    FLAGS_PROG_MULTIPLE_DATA: typing.Final = 2
    """
    Program flags: multiple data segments
    """

    FLAGS_PROG_GLOBAL_INIT: typing.Final = 4
    FLAGS_PROG_PROTECTED_MODE: typing.Final = 8
    FLAGS_PROG_8086: typing.Final = 16
    FLAGS_PROG_80286: typing.Final = 32
    FLAGS_PROG_80386: typing.Final = 64
    FLAGS_PROG_80x87: typing.Final = -128
    FLAGS_APP_FULL_SCREEN: typing.Final = 1
    """
    Is application full screen?
    """

    FLAGS_APP_WIN_PM_COMPATIBLE: typing.Final = 2
    """
    Is application compatible with Windows Program Manager?
    """

    FLAGS_APP_WINDOWS_PM: typing.Final = 3
    """
    Does application use Windows Program Manager?
    """

    FLAGS_APP_LOAD_CODE: typing.Final = 8
    """
    Does the first segment contain code that loads the application?
    """

    FLAGS_APP_LINK_ERRS: typing.Final = 32
    FLAGS_APP_NONCONFORMING_PROG: typing.Final = 64
    FLAGS_APP_LIBRARY_MODULE: typing.Final = -128
    EXETYPE_UNKNOWN: typing.Final = 0
    """
    Unknown executable type
    """

    EXETYPE_OS2: typing.Final = 1
    """
    OS/2 executable
    """

    EXETYPE_WINDOWS: typing.Final = 2
    """
    Windows executable
    """

    EXETYPE_EUROPEAN_DOS_4: typing.Final = 4
    """
    European DOS 4.x executable
    """

    EXETYPE_RESERVED4: typing.Final = 8
    """
    Reserved executable Type
    """

    EXETYPE_WINDOWS_386: typing.Final = 4
    """
    Windows 386 executable
    """

    EXETYPE_BOSS: typing.Final = 5
    """
    Borland Operating System Services executable
    """

    EXETYPE_PHARLAP_286_OS2: typing.Final = -127
    """
    Pharlap 286 OS/2 executable
    """

    EXETYPE_PHARLAP_286_WIN: typing.Final = -126
    """
    Pharlap 386 Windows executable
    """

    OTHER_FLAGS_SUPPORTS_LONG_NAMES: typing.Final = 0
    """
    Supports long names
    """

    OTHER_FLAGS_PROTECTED_MODE: typing.Final = 1
    """
    Protected mode
    """

    OTHER_FLAGS_PROPORTIONAL_FONT: typing.Final = 2
    """
    Proportional font
    """

    OTHER_FLAGS_GANGLOAD_AREA: typing.Final = 4
    """
    Gangload area
    """


    def getApplicationFlags(self) -> int:
        """
        Returns the application flags.
        
        :return: the application flags
        :rtype: int
        """

    def getApplicationFlagsAsString(self) -> str:
        """
        Returns a string representation of the application flags.
        
        :return: a string representation of the application flags
        :rtype: str
        """

    def getAutomaticDataSegment(self) -> int:
        """
        Returns the automatic data segment.
        
        :return: the automatic data segment
        :rtype: int
        """

    def getChecksum(self) -> int:
        """
        Returns the checksum.
        
        :return: the checksum
        :rtype: int
        """

    def getEntryPointOffset(self) -> int:
        """
        Returns the offset portion of the entry point.
        
        :return: the offset portion of the entry point
        :rtype: int
        """

    def getEntryPointSegment(self) -> int:
        """
        Returns the segment portion of the entry point.
        
        :return: the segment portion of the entry point
        :rtype: int
        """

    def getExpectedWindowsVersion(self) -> int:
        """
        Returns the expected windows version.
        
        :return: the expected windows version
        :rtype: int
        """

    def getInitialHeapSize(self) -> int:
        """
        Returns the initial heap size.
        
        :return: the initial heap size
        :rtype: int
        """

    def getInitialStackSize(self) -> int:
        """
        Returns the initial stack size.
        
        :return: the initial stack size
        :rtype: int
        """

    def getMagicNumber(self) -> int:
        """
        Returns the magic number.
        
        :return: the magic number
        :rtype: int
        """

    def getMinCodeSwapSize(self) -> int:
        """
        Returns the minimum code swap size.
        
        :return: the minimum code swap size
        :rtype: int
        """

    def getOtherFlags(self) -> int:
        """
        Returns the other flags.
        
        :return: the other flags
        :rtype: int
        """

    def getOtherFlagsAsString(self) -> str:
        """
        Returns a string representation of the other flags.
        
        :return: a string representation of the other flags
        :rtype: str
        """

    def getProgramFlags(self) -> int:
        """
        Returns the program flags.
        
        :return: the program flags
        :rtype: int
        """

    def getProgramFlagsAsString(self) -> str:
        """
        Returns a string representation of the program flags.
        
        :return: a string representation of the program flags
        :rtype: str
        """

    def getRevision(self) -> int:
        """
        Returns the revision number.
        
        :return: the revision number
        :rtype: int
        """

    def getStackPointerOffset(self) -> int:
        """
        Returns the offset portion of the stack pointer.
        
        :return: the offset portion of the stack pointer
        :rtype: int
        """

    def getStackPointerSegment(self) -> int:
        """
        Returns the segment portion of the stack pointer.
        
        :return: the segment portion of the stack pointer
        :rtype: int
        """

    def getTargetOpSys(self) -> int:
        """
        Returns the target operating system.
        
        :return: the target operating system
        :rtype: int
        """

    def getTargetOpSysAsString(self) -> str:
        """
        Returns a string representation of the target operating system.
        
        :return: a string representation of the target operating system
        :rtype: str
        """

    def getVersion(self) -> int:
        """
        Returns the version number.
        
        :return: the version number
        :rtype: int
        """

    @property
    def otherFlagsAsString(self) -> java.lang.String:
        ...

    @property
    def programFlags(self) -> jpype.JByte:
        ...

    @property
    def entryPointOffset(self) -> jpype.JShort:
        ...

    @property
    def targetOpSys(self) -> jpype.JByte:
        ...

    @property
    def initialStackSize(self) -> jpype.JShort:
        ...

    @property
    def otherFlags(self) -> jpype.JByte:
        ...

    @property
    def magicNumber(self) -> jpype.JShort:
        ...

    @property
    def expectedWindowsVersion(self) -> jpype.JShort:
        ...

    @property
    def targetOpSysAsString(self) -> java.lang.String:
        ...

    @property
    def stackPointerOffset(self) -> jpype.JShort:
        ...

    @property
    def version(self) -> jpype.JShort:
        ...

    @property
    def revision(self) -> jpype.JShort:
        ...

    @property
    def applicationFlags(self) -> jpype.JByte:
        ...

    @property
    def stackPointerSegment(self) -> jpype.JShort:
        ...

    @property
    def minCodeSwapSize(self) -> jpype.JShort:
        ...

    @property
    def initialHeapSize(self) -> jpype.JShort:
        ...

    @property
    def checksum(self) -> jpype.JInt:
        ...

    @property
    def automaticDataSegment(self) -> jpype.JShort:
        ...

    @property
    def entryPointSegment(self) -> jpype.JShort:
        ...

    @property
    def applicationFlagsAsString(self) -> java.lang.String:
        ...

    @property
    def programFlagsAsString(self) -> java.lang.String:
        ...


@typing.type_check_only
class RelocationImportedName(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def getIndex(self) -> int:
        ...

    def getOffset(self) -> int:
        ...

    @property
    def offset(self) -> jpype.JShort:
        ...

    @property
    def index(self) -> jpype.JShort:
        ...


class ResourceTable(java.lang.Object):
    """
    A class for storing the new-executable resource table.
    A resource table contains all of the supported types
    of resources.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getAlignmentShiftCount(self) -> int:
        """
        Returns the alignment shift count. 
        Some resources offsets and lengths are stored bit shifted.
        
        :return: the alignment shift count
        :rtype: int
        """

    def getIndex(self) -> int:
        """
        Returns the byte index where the resource table begins,
        relative to the beginning of the file.
        
        :return: the byte index where the resource table begins
        :rtype: int
        """

    def getResourceNames(self) -> jpype.JArray[ResourceName]:
        """
        Returns the array of resources names.
        
        :return: the array of resources names
        :rtype: jpype.JArray[ResourceName]
        """

    def getResourceTypes(self) -> jpype.JArray[ResourceType]:
        """
        Returns the array of resource types.
        
        :return: the array of resource types
        :rtype: jpype.JArray[ResourceType]
        """

    @property
    def resourceTypes(self) -> jpype.JArray[ResourceType]:
        ...

    @property
    def resourceNames(self) -> jpype.JArray[ResourceName]:
        ...

    @property
    def index(self) -> jpype.JShort:
        ...

    @property
    def alignmentShiftCount(self) -> jpype.JShort:
        ...


class SegmentRelocation(java.lang.Object):
    """
    A class to represent a new-executable segment relocation.
    """

    class_: typing.ClassVar[java.lang.Class]
    VALUES_SIZE: typing.Final = 5
    MOVEABLE: typing.Final = 255
    """
    Moveable relocation.
    """

    TYPE_MASK: typing.Final = 15
    """
    A mask indicating that the low-order nibble is the type.
    """

    TYPE_LO_BYTE: typing.Final = 0
    """
    low byte at the specified address.
    """

    TYPE_SEGMENT: typing.Final = 2
    """
    16-bit selector.
    """

    TYPE_FAR_ADDR: typing.Final = 3
    """
    32-bit pointer.
    """

    TYPE_OFFSET: typing.Final = 5
    """
    16-bit pointer.
    """

    TYPE_FAR_ADDR_48: typing.Final = 12
    """
    48-bit pointer.
    """

    TYPE_OFFSET_32: typing.Final = 13
    """
    32-bit offset.
    """

    TYPE_STRINGS: typing.Final[jpype.JArray[java.lang.String]]
    """
    The names of the available relocations.
    """

    TYPE_LENGTHS: typing.Final[jpype.JArray[jpype.JInt]]
    """
    The number of bytes required to perform relocation
    """

    FLAG_TARGET_MASK: typing.Final = 3
    """
    A mask indicating that the low-order two-bits is the type.
    """

    FLAG_INTERNAL_REF: typing.Final = 0
    """
    Internal reference relocation.
    """

    FLAG_IMPORT_ORDINAL: typing.Final = 1
    """
    Import ordinal relocation.
    """

    FLAG_IMPORT_NAME: typing.Final = 2
    """
    Import name relocation.
    """

    FLAG_OS_FIXUP: typing.Final = 3
    """
    Operating system fixup relocation.
    """

    FLAG_ADDITIVE: typing.Final = 4
    """
    Additive relocaiton.
    """


    def getFlagByte(self) -> int:
        """
        Returns the relocation flags.
        
        :return: the relocation flags
        :rtype: int
        """

    def getOffset(self) -> int:
        """
        Returns the relocation offset.
        
        :return: the relocation offset
        :rtype: int
        """

    def getTargetOffset(self) -> int:
        """
        Returns the relocation target offset.
        
        :return: the relocation target offset
        :rtype: int
        """

    def getTargetSegment(self) -> int:
        """
        Returns the relocation target segment.
        
        :return: the relocation target segment
        :rtype: int
        """

    def getType(self) -> int:
        """
        Returns the relocation type.
        
        :return: the relocation type
        :rtype: int
        """

    def getValues(self) -> jpype.JArray[jpype.JLong]:
        """
        Returns values required to reconstruct this object.
        
        :return: values required to reconstruct this object
        :rtype: jpype.JArray[jpype.JLong]
        """

    def isAdditive(self) -> bool:
        """
        Returns true if this relocation is additive.
        If this bit is set, then add relocation to existing value.
        Otherwise overwrite the existing value.
        
        :return: true if this relocation is additive.
        :rtype: bool
        """

    def isImportName(self) -> bool:
        """
        Returns true if this relocation is an import by name.
        
        :return: true if this relocation is an import by name
        :rtype: bool
        """

    def isImportOrdinal(self) -> bool:
        """
        Returns true if this relocation is an import by ordinal.
        
        :return: true if this relocation is an import by ordinal
        :rtype: bool
        """

    def isInternalRef(self) -> bool:
        """
        Returns true if this relocation is an internal reference.
        
        :return: true if this relocation is an internal reference
        :rtype: bool
        """

    def isOpSysFixup(self) -> bool:
        """
        Returns true if this relocation is an operating system fixup.
        
        :return: true if this relocation is an operating system fixup
        :rtype: bool
        """

    @property
    def opSysFixup(self) -> jpype.JBoolean:
        ...

    @property
    def offset(self) -> jpype.JShort:
        ...

    @property
    def values(self) -> jpype.JArray[jpype.JLong]:
        ...

    @property
    def importName(self) -> jpype.JBoolean:
        ...

    @property
    def targetSegment(self) -> jpype.JShort:
        ...

    @property
    def importOrdinal(self) -> jpype.JBoolean:
        ...

    @property
    def type(self) -> jpype.JByte:
        ...

    @property
    def targetOffset(self) -> jpype.JShort:
        ...

    @property
    def flagByte(self) -> jpype.JByte:
        ...

    @property
    def internalRef(self) -> jpype.JBoolean:
        ...

    @property
    def additive(self) -> jpype.JBoolean:
        ...



__all__ = ["ImportedNameTable", "RelocationImportedOrdinal", "EntryPoint", "RelocationInternalRef", "NonResidentNameTable", "ResourceName", "WindowsHeader", "LengthStringOrdinalSet", "RelocationOSFixup", "NewExecutable", "ResidentNameTable", "Segment", "Resource", "ResourceType", "EntryTableBundle", "ResourceStringTable", "EntryTable", "ModuleReferenceTable", "InvalidWindowsHeaderException", "LengthStringSet", "SegmentTable", "InformationBlock", "RelocationImportedName", "ResourceTable", "SegmentRelocation"]
