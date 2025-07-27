from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.util.bin
import ghidra.app.util.bin.format.elf
import ghidra.framework.options
import ghidra.program.model.address
import ghidra.program.model.data
import ghidra.program.model.listing
import ghidra.program.model.mem
import ghidra.util.classfinder
import ghidra.util.task
import java.lang # type: ignore
import java.util # type: ignore


T = typing.TypeVar("T")


class ElfInfoProducer(ghidra.util.classfinder.ExtensionPoint):
    """
    Something that adds nice-to-have markup and program info to Elf binaries.
     
    
    Classes that implement this ExtensionPoint must have names that end with "ElfInfoProducer" for
    the class searcher to find them.
     
    
    Instances are created for each Elf binary that is being loaded.
    """

    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def getElfInfoProducers(elfLoadHelper: ghidra.app.util.bin.format.elf.ElfLoadHelper) -> java.util.List[ElfInfoProducer]:
        """
        Returns a sorted list of new and initialized ElfInfoProducer instances.
        
        :param ghidra.app.util.bin.format.elf.ElfLoadHelper elfLoadHelper: :obj:`ElfLoadHelper` with contents of file being loaded
        :return: List of ElfInfoProducers
        :rtype: java.util.List[ElfInfoProducer]
        """

    def init(self, elfLoadHelper: ghidra.app.util.bin.format.elf.ElfLoadHelper):
        """
        Initializes this instance.
        
        :param ghidra.app.util.bin.format.elf.ElfLoadHelper elfLoadHelper: the Elf binary
        """

    def markupElfInfo(self, monitor: ghidra.util.task.TaskMonitor):
        """
        Called by the Elf loader to give this ElfInfoProducer the opportunity to markup the Elf
        binary.
        
        :param ghidra.util.task.TaskMonitor monitor: :obj:`TaskMonitor`
        """


class NoteGnuBuildId(ElfNote):
    """
    An ELF note that specifies the build-id (sha1/md5/etc hash or manually specified bytes that 
    can be hex-ified) of the containing program.
     
    
    The hex values of the build-id are useful to find an external debug file.
    """

    class_: typing.ClassVar[java.lang.Class]
    SECTION_NAME: typing.Final = ".note.gnu.build-id"

    @staticmethod
    def fromProgram(program: ghidra.program.model.listing.Program) -> NoteGnuBuildId:
        """
        Reads a NoteGnuBuildId from the standard ".note.gnu.build-id" section in the 
        specified Program.
        
        :param ghidra.program.model.listing.Program program: Program to read from
        :return: new instance, or null if not found or data error
        :rtype: NoteGnuBuildId
        """

    @staticmethod
    def read(note: ElfNote, program: ghidra.program.model.listing.Program) -> NoteGnuBuildId:
        """
        Deserializes a NoteGnuBuildId from an already read generic Note.
        
        :param ElfNote note: generic Note
        :param ghidra.program.model.listing.Program program: context
        :return: new NoteGnuBuildId instance, never null
        :rtype: NoteGnuBuildId
        :raises IOException: if data error
        """


class StandardElfInfoProducer(ElfInfoProducer):
    """
    Handles marking up and program info for basic ELF note (and note-like) sections.
     
    * NoteAbiTag
    * NoteGnuBuildId
    * NoteGnuProperty
    * GnuDebugLink (not a note)
    * ElfComment (not a note)
    
     
    
    Runs after other ElfInfoProducers that have a normal priority.
    """

    class_: typing.ClassVar[java.lang.Class]
    ELF_CATEGORYPATH: typing.Final[ghidra.program.model.data.CategoryPath]

    def __init__(self):
        ...


class NoteGnuProperty(ElfNote):
    """
    An ELF note that contains a list of enumerated "properties".
     
    
    Currently known property types are stack_size and no_copy_on_protected (flag).
     
    array of Elf_Prop {
        word pr_type;
        word pr_datasz;
        byte pr_data[pr_datasz];
        byte padding[]
    }
    """

    class NotePropertyElement(java.lang.Record):
        """
        Contains the information of an individual note property.
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, type: typing.Union[jpype.JInt, int], typeName: typing.Union[java.lang.String, str], value: typing.Union[java.lang.String, str], length: typing.Union[jpype.JInt, int]):
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def length(self) -> int:
            ...

        def toString(self) -> str:
            ...

        def type(self) -> int:
            ...

        def typeName(self) -> str:
            ...

        def value(self) -> str:
            ...


    class_: typing.ClassVar[java.lang.Class]
    SECTION_NAME: typing.Final = ".note.gnu.property"

    def __init__(self, nameLen: typing.Union[jpype.JInt, int], name: typing.Union[java.lang.String, str], vendorType: typing.Union[jpype.JInt, int], elements: java.util.List[NoteGnuProperty.NotePropertyElement]):
        """
        Creates a instance using the specified values.
        
        :param java.lang.String or str name: name of property
        :param jpype.JInt or int vendorType: vendor type of property
        :param java.util.List[NoteGnuProperty.NotePropertyElement] elements: list of NotePropertyElements
        """

    @staticmethod
    def fromProgram(program: ghidra.program.model.listing.Program) -> NoteGnuProperty:
        """
        Returns a NoteGnuProperty instance containing the information found in the program's
        ".note.gnu.property" section, or null if there is no section.
        
        :param ghidra.program.model.listing.Program program: :obj:`Program` to read from
        :return: :obj:`NoteGnuProperty`
        :rtype: NoteGnuProperty
        """

    @staticmethod
    def read(note: ElfNote, program: ghidra.program.model.listing.Program) -> NoteGnuProperty:
        """
        Parses a NoteGnuProperty instance from the specified generic note.
        
        :param ElfNote note: generic note that contains the data from a .note.gnu.property section
        :param ghidra.program.model.listing.Program program: Program that contains the note section
        :return: :obj:`NoteGnuProperty` instance
        :rtype: NoteGnuProperty
        :raises IOException: if IO error parsing data
        """


class NoteAbiTag(ElfNote):
    """
    An ELF note that specifies the minimum kernel ABI required by this binary
    """

    class_: typing.ClassVar[java.lang.Class]
    SECTION_NAME: typing.Final = ".note.ABI-tag"

    def __init__(self, nameLen: typing.Union[jpype.JInt, int], name: typing.Union[java.lang.String, str], vendorType: typing.Union[jpype.JInt, int], abiType: typing.Union[jpype.JInt, int], requiredKernelVersion: jpype.JArray[jpype.JInt]):
        ...

    @staticmethod
    def fromProgram(program: ghidra.program.model.listing.Program) -> NoteAbiTag:
        """
        Reads a NoteAbiTag from the standard ".note.ABI-tag" section in the specified Program.
        
        :param ghidra.program.model.listing.Program program: Program to read from
        :return: new instance, or null if not found or data error
        :rtype: NoteAbiTag
        """

    def getAbiType(self) -> int:
        ...

    def getAbiTypeString(self) -> str:
        ...

    def getRequiredKernelVersion(self) -> str:
        ...

    @staticmethod
    def read(note: ElfNote, program: ghidra.program.model.listing.Program) -> NoteAbiTag:
        """
        Deserializes a NoteAbiTag from an already read generic Note.
        
        :param ElfNote note: generic Note
        :param ghidra.program.model.listing.Program program: context
        :return: new NoteAbiTag instance, never null
        :rtype: NoteAbiTag
        :raises IOException: if data error
        """

    @property
    def requiredKernelVersion(self) -> java.lang.String:
        ...

    @property
    def abiType(self) -> jpype.JInt:
        ...

    @property
    def abiTypeString(self) -> java.lang.String:
        ...


class GnuDebugLink(ElfInfoItem):
    """
    An ELF section (almost like a :obj:`ElfNote`) that contains information about an external
    DWARF debug file.
     
    
    External DWARF debug files can also be specified with a :obj:`NoteGnuBuildId`.
    """

    class_: typing.ClassVar[java.lang.Class]
    SECTION_NAME: typing.Final = ".gnu_debuglink"

    def __init__(self, filenameLen: typing.Union[jpype.JInt, int], filename: typing.Union[java.lang.String, str], crc: typing.Union[jpype.JInt, int]):
        ...

    @staticmethod
    def fromProgram(program: ghidra.program.model.listing.Program) -> GnuDebugLink:
        """
        Reads a GnuDebugLink from the standard ".gnu_debuglink" section in the specified Program.
        
        :param ghidra.program.model.listing.Program program: Program to read from
        :return: new instance, or null if not found or data error
        :rtype: GnuDebugLink
        """

    def getCrc(self) -> int:
        ...

    def getFilename(self) -> str:
        ...

    def getFilenameLen(self) -> int:
        ...

    @staticmethod
    def read(br: ghidra.app.util.bin.BinaryReader, program: ghidra.program.model.listing.Program) -> GnuDebugLink:
        """
        Reads a GnuDebugLink from the specified BinaryReader.
        
        :param ghidra.app.util.bin.BinaryReader br: BinaryReader to read from
        :param ghidra.program.model.listing.Program program: unused, present to match the signature of :obj:`ElfInfoItem.ReaderFunc`
        :return: new instance, or null if data error
        :rtype: GnuDebugLink
        """

    @property
    def filename(self) -> java.lang.String:
        ...

    @property
    def crc(self) -> jpype.JInt:
        ...

    @property
    def filenameLen(self) -> jpype.JInt:
        ...


class ElfNote(ElfInfoItem):
    """
    ELF note sections have a well-defined format that combines identity information along with a 
    binary blob that is specific to each type of note.
     
    
    Notes are identified by the combination of a name string and vendorType number, and are usually
    stored in a ELF section with a specific name.
    """

    class NoteReaderFunc(java.lang.Object, typing.Generic[T]):

        class_: typing.ClassVar[java.lang.Class]

        def read(self, note: ElfNote, program: ghidra.program.model.listing.Program) -> T:
            """
            Returns a more specific Note type, typically using the data found in the generic note's
            :meth:`ElfNote.getDescription() <ElfNote.getDescription>` and the supplied Program.
            
            :param ElfNote note: generic note instance
            :param ghidra.program.model.listing.Program program: Program containing the note
            :return: new note instance
            :rtype: T
            :raises IOException: if error reading
            """


    class_: typing.ClassVar[java.lang.Class]

    def decorateProgramInfo(self, programInfoOptions: ghidra.framework.options.Options):
        """
        Adds a single entry to the Options, built from the :meth:`getProgramInfoKey() <.getProgramInfoKey>` value and
        :meth:`getNoteValueString() <.getNoteValueString>` value.
        
        :param ghidra.framework.options.Options programInfoOptions: :obj:`Options` to add entry to
        """

    def getDescription(self) -> jpype.JArray[jpype.JByte]:
        """
        Returns the bytes in the description portion of the note.
        
        :return: byte array
        :rtype: jpype.JArray[jpype.JByte]
        """

    def getDescriptionAsHexString(self) -> str:
        """
        Returns a hex string of the description bytes.
        
        :return: hex string
        :rtype: str
        """

    def getDescriptionLen(self) -> int:
        ...

    def getDescriptionReader(self, isLittleEndian: typing.Union[jpype.JBoolean, bool]) -> ghidra.app.util.bin.BinaryReader:
        """
        Returns a :obj:`BinaryReader` that reads from this note's description blob.
        
        :param jpype.JBoolean or bool isLittleEndian: flag, see :meth:`BinaryReader.BinaryReader(ByteProvider, boolean) <BinaryReader.BinaryReader>`
        :return: new BinaryReader
        :rtype: ghidra.app.util.bin.BinaryReader
        """

    def getName(self) -> str:
        """
        Returns the name value of this note.
        
        :return: string name
        :rtype: str
        """

    def getNameLen(self) -> int:
        ...

    def getNoteTypeName(self) -> str:
        """
        Returns a string that describes this note's type, used when creating the default
        :meth:`getProgramInfoKey() <.getProgramInfoKey>` value.
         
        
        Specific Note subclasses can override this to return a better string than this default
        implementation, or can override the :meth:`getProgramInfoKey() <.getProgramInfoKey>` method.
        
        :return: descriptive string
        :rtype: str
        """

    def getNoteValueString(self) -> str:
        """
        Returns a string representation of this note's 'value', used when creating the
        PROGRAM_INFO entry.
          
        
        Specific Note subclasses should override this to return a better string than this default
        implementation.
        
        :return: string describing this note's value
        :rtype: str
        """

    def getProgramInfoKey(self) -> str:
        """
        Returns a string that is used to build a PROGRAM_INFO entry's key.
         
        
        Specific Note subclasses can override this to return a better key string.
        
        :return: key string (avoid using '.' characters as they will be converted to '_'s)
        :rtype: str
        """

    def getVendorType(self) -> int:
        """
        Returns the vendor type 'enum' value of this note.
        
        :return: vendor type 'enum' value
        :rtype: int
        """

    def isGnu(self) -> bool:
        """
        Shortcut test of name == "GNU"
        
        :return: true if name is "GNU"
        :rtype: bool
        """

    @staticmethod
    def read(reader: ghidra.app.util.bin.BinaryReader) -> ElfNote:
        """
        Reads a generic :obj:`ElfNote` instance from the supplied BinaryReader.
        
        :param ghidra.app.util.bin.BinaryReader reader: BinaryReader to read from
        :return: new :obj:`ElfNote` instance, never null
        :rtype: ElfNote
        :raises IOException: if bad data or error reading
        """

    def toStructure(self, dtm: ghidra.program.model.data.DataTypeManager) -> ghidra.program.model.data.StructureDataType:
        """
        Returns a Structure datatype that matches the format of this ElfNote, or null if this
        ElfNote shouldn't be represented/marked up.
        
        :param ghidra.program.model.data.DataTypeManager dtm: :obj:`DataTypeManager` that will receive the structure
        :return: StructureDataType that specifies the layout of the ElfNote, or null
        :rtype: ghidra.program.model.data.StructureDataType
        """

    @property
    def vendorType(self) -> jpype.JInt:
        ...

    @property
    def descriptionLen(self) -> jpype.JInt:
        ...

    @property
    def programInfoKey(self) -> java.lang.String:
        ...

    @property
    def noteValueString(self) -> java.lang.String:
        ...

    @property
    def nameLen(self) -> jpype.JInt:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def description(self) -> jpype.JArray[jpype.JByte]:
        ...

    @property
    def noteTypeName(self) -> java.lang.String:
        ...

    @property
    def descriptionAsHexString(self) -> java.lang.String:
        ...

    @property
    def descriptionReader(self) -> ghidra.app.util.bin.BinaryReader:
        ...

    @property
    def gnu(self) -> jpype.JBoolean:
        ...


class ElfComment(ElfInfoItem):
    """
    An Elf section that contains null-terminated strings, typically added by the compiler to
    the binary
    """

    class_: typing.ClassVar[java.lang.Class]
    SECTION_NAME: typing.Final = ".comment"

    def __init__(self, commentStrings: java.util.List[java.lang.String], commentStringLengths: java.util.List[java.lang.Integer]):
        ...

    @staticmethod
    def fromProgram(program: ghidra.program.model.listing.Program) -> ElfComment:
        """
        Reads an ElfComment from the standard ".comment" section in the specified Program.
        
        :param ghidra.program.model.listing.Program program: Program to read from
        :return: new instance, or null if not found or data error
        :rtype: ElfComment
        """

    def getCommentStrings(self) -> java.util.List[java.lang.String]:
        ...

    @staticmethod
    def read(br: ghidra.app.util.bin.BinaryReader, program: ghidra.program.model.listing.Program) -> ElfComment:
        """
        Reads a ElfComment from the specified BinaryReader.
        
        :param ghidra.app.util.bin.BinaryReader br: BinaryReader to read from
        :param ghidra.program.model.listing.Program program: unused, present to match the signature of :obj:`ElfInfoItem.ReaderFunc`
        :return: new instance, or null if data error
        :rtype: ElfComment
        """

    @property
    def commentStrings(self) -> java.util.List[java.lang.String]:
        ...


class ElfInfoItem(java.lang.Object):
    """
    Interface and helper functions to read and markup things that have been read from an
    Elf program.
    """

    class ItemWithAddress(java.lang.Record, typing.Generic[T]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, item: T, address: ghidra.program.model.address.Address):
            ...

        def address(self) -> ghidra.program.model.address.Address:
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def item(self) -> T:
            ...

        def toString(self) -> str:
            ...


    class ReaderFunc(java.lang.Object, typing.Generic[T]):

        class_: typing.ClassVar[java.lang.Class]

        def read(self, br: ghidra.app.util.bin.BinaryReader, program: ghidra.program.model.listing.Program) -> T:
            ...


    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def markupElfInfoItemSection(program: ghidra.program.model.listing.Program, sectionName: typing.Union[java.lang.String, str], readFunc: ElfInfoItem.ReaderFunc[ElfInfoItem]):
        """
        Helper method to markup a program if it contains the specified item in the specified
        memory section.
        
        :param ghidra.program.model.listing.Program program: :obj:`Program`
        :param java.lang.String or str sectionName: name of memory section that contains the item
        :param ElfInfoItem.ReaderFunc[ElfInfoItem] readFunc: :obj:`ReaderFunc` that will deserialize an instance of the item
        """

    def markupProgram(self, program: ghidra.program.model.listing.Program, address: ghidra.program.model.address.Address):
        """
        Markup a program's info and memory with this item.
        
        :param ghidra.program.model.listing.Program program: :obj:`Program` to markup
        :param ghidra.program.model.address.Address address: :obj:`Address` of the item in the program
        """

    @staticmethod
    @typing.overload
    def readItemFromSection(program: ghidra.program.model.listing.Program, sectionName: typing.Union[java.lang.String, str], readFunc: ElfInfoItem.ReaderFunc[T]) -> ElfInfoItem.ItemWithAddress[T]:
        """
        Helper method to read an item from a program's memory section.
        
        :param T: type of the item that will be read:param ghidra.program.model.listing.Program program: :obj:`Program` to read from
        :param java.lang.String or str sectionName: name of memory section that contains the item
        :param ElfInfoItem.ReaderFunc[T] readFunc: :obj:`ReaderFunc` that will deserialize an instance of the item
        :return: a wrapped instance of the item, or null if the memory section does not exist
        or there was an error while reading the item from the section
        :rtype: ElfInfoItem.ItemWithAddress[T]
        """

    @staticmethod
    @typing.overload
    def readItemFromSection(program: ghidra.program.model.listing.Program, memBlock: ghidra.program.model.mem.MemoryBlock, readFunc: ElfInfoItem.ReaderFunc[T]) -> ElfInfoItem.ItemWithAddress[T]:
        ...



__all__ = ["ElfInfoProducer", "NoteGnuBuildId", "StandardElfInfoProducer", "NoteGnuProperty", "NoteAbiTag", "GnuDebugLink", "ElfNote", "ElfComment", "ElfInfoItem"]
