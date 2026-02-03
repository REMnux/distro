from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.util.bin
import ghidra.app.util.bin.format.swift.types
import ghidra.app.util.importer
import ghidra.program.model.address
import ghidra.program.model.data
import ghidra.program.model.listing
import ghidra.program.model.mem
import ghidra.util.task
import java.lang # type: ignore
import java.util # type: ignore


class SwiftUtils(java.lang.Object):
    """
    Swift-related utility methods
    """

    class_: typing.ClassVar[java.lang.Class]
    SWIFT_COMPILER: typing.Final = "swift"
    PTR_RELATIVE: typing.Final[ghidra.program.model.data.PointerTypedef]
    """
    A :obj:`pointer <PointerTypedef>` to a relative 4-byte offset
    """

    PTR_STRING: typing.Final[ghidra.program.model.data.PointerTypedef]
    """
    A :obj:`string pointer <PointerTypedef>` to a 4-byte relative offset
    """


    def __init__(self):
        ...

    @staticmethod
    def getSwiftBlocks(section: SwiftSection, program: ghidra.program.model.listing.Program) -> java.util.List[ghidra.program.model.mem.MemoryBlock]:
        """
        Gets a :obj:`List` of :obj:`MemoryBlock`s that match the given :obj:`SwiftSection`
        
        :param SwiftSection section: The :obj:`SwiftSection`
        :param ghidra.program.model.listing.Program program: The :obj:`Program`
        :return: A :obj:`List` of :obj:`MemoryBlock`s that match the given :obj:`SwiftSection`
        :rtype: java.util.List[ghidra.program.model.mem.MemoryBlock]
        """

    @staticmethod
    @typing.overload
    def isSwift(program: ghidra.program.model.listing.Program) -> bool:
        """
        Checks if the given :obj:`Program` is a Swift program
        
        :param ghidra.program.model.listing.Program program: The :obj:`Program` to check
        :return: True if the given :obj:`Program` is a Swift program; otherwise, false
        :rtype: bool
        """

    @staticmethod
    @typing.overload
    def isSwift(sectionNames: java.util.List[java.lang.String]) -> bool:
        """
        Checks if the given :obj:`List` of section names contains a Swift section name
        
        :param java.util.List[java.lang.String] sectionNames: The :obj:`List` of section names to check
        :return: True if the given :obj:`List` of section names contains a Swift section name; otherwise, 
        false
        :rtype: bool
        """

    @staticmethod
    def relativeString(reader: ghidra.app.util.bin.BinaryReader) -> str:
        """
        Reads the integer at the current index and uses it as a relative pointer to read and
        return a string at that location.  When the read completes, the :obj:`BinaryReader` will
        be positioned directly after the initial relative pointer that was read.
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of relative string pointer
        :return: The read string
        :rtype: str
        :raises IOException: if there was an IO-related problem during the reads
        """


class SwiftTypeMetadata(java.lang.Object):
    """
    Parses marks up, and provide access to Swift type metadata
    """

    @typing.type_check_only
    class SwiftStructureAddress(java.lang.Record):
        """
        The :obj:`Address` of a :obj:`SwiftTypeMetadataStructure` and the optional :obj:`Address` 
        of its pointer
        """

        class_: typing.ClassVar[java.lang.Class]

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def pointerAddr(self) -> ghidra.program.model.address.Address:
            ...

        def structAddr(self) -> ghidra.program.model.address.Address:
            ...

        def toString(self) -> str:
            ...


    @typing.type_check_only
    class SwiftStructureInfo(java.lang.Record):
        """
        Information about a :obj:`SwiftTypeMetadataStructure`
        """

        class_: typing.ClassVar[java.lang.Class]

        def addr(self) -> SwiftTypeMetadata.SwiftStructureAddress:
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def struct(self) -> SwiftTypeMetadataStructure:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, program: ghidra.program.model.listing.Program, monitor: ghidra.util.task.TaskMonitor, log: ghidra.app.util.importer.MessageLog):
        """
        Creates a new :obj:`SwiftTypeMetadata`
        
        :param ghidra.program.model.listing.Program program: The :obj:`Program`
        :param ghidra.util.task.TaskMonitor monitor: A cancellable task monitor
        :param ghidra.app.util.importer.MessageLog log: The log
        :raises IOException: if there was an IO-related error
        :raises CancelledException: if the user cancelled the operation
        """

    def getAssociatedTypeDescriptor(self) -> java.util.List[ghidra.app.util.bin.format.swift.types.AssociatedTypeDescriptor]:
        """
        :return: the associated type descriptors
        :rtype: java.util.List[ghidra.app.util.bin.format.swift.types.AssociatedTypeDescriptor]
        """

    def getBuiltinTypeDescriptors(self) -> java.util.List[ghidra.app.util.bin.format.swift.types.BuiltinTypeDescriptor]:
        """
        :return: the built-in type descriptors
        :rtype: java.util.List[ghidra.app.util.bin.format.swift.types.BuiltinTypeDescriptor]
        """

    def getCaptureDescriptors(self) -> java.util.List[ghidra.app.util.bin.format.swift.types.CaptureDescriptor]:
        """
        :return: the capture descriptors
        :rtype: java.util.List[ghidra.app.util.bin.format.swift.types.CaptureDescriptor]
        """

    def getEntryPoints(self) -> java.util.List[ghidra.app.util.bin.format.swift.types.EntryPoint]:
        """
        :return: the entry points
        :rtype: java.util.List[ghidra.app.util.bin.format.swift.types.EntryPoint]
        """

    def getFieldDescriptors(self) -> java.util.Map[java.lang.Long, ghidra.app.util.bin.format.swift.types.FieldDescriptor]:
        """
        :return: the field descriptors
        :rtype: java.util.Map[java.lang.Long, ghidra.app.util.bin.format.swift.types.FieldDescriptor]
        """

    def getMultiPayloadEnumDescriptors(self) -> java.util.List[ghidra.app.util.bin.format.swift.types.MultiPayloadEnumDescriptor]:
        """
        :return: the multi-payload enum descriptors
        :rtype: java.util.List[ghidra.app.util.bin.format.swift.types.MultiPayloadEnumDescriptor]
        """

    def getTargetProtocolConformanceDescriptors(self) -> java.util.List[ghidra.app.util.bin.format.swift.types.TargetProtocolConformanceDescriptor]:
        """
        :return: the target protocol conformance descriptors
        :rtype: java.util.List[ghidra.app.util.bin.format.swift.types.TargetProtocolConformanceDescriptor]
        """

    def getTargetProtocolDescriptors(self) -> java.util.List[ghidra.app.util.bin.format.swift.types.TargetProtocolDescriptor]:
        """
        :return: the target protocol descriptors
        :rtype: java.util.List[ghidra.app.util.bin.format.swift.types.TargetProtocolDescriptor]
        """

    def getTargetTypeContextDescriptors(self) -> java.util.Map[java.lang.String, ghidra.app.util.bin.format.swift.types.TargetTypeContextDescriptor]:
        """
        :return: the type descriptors
        :rtype: java.util.Map[java.lang.String, ghidra.app.util.bin.format.swift.types.TargetTypeContextDescriptor]
        """

    def markup(self):
        """
        Marks up this :obj:`SwiftTypeMetadata` with data structures and comments
        
        :raises CancelledException: if the user cancelled the operation
        """

    @property
    def targetProtocolDescriptors(self) -> java.util.List[ghidra.app.util.bin.format.swift.types.TargetProtocolDescriptor]:
        ...

    @property
    def entryPoints(self) -> java.util.List[ghidra.app.util.bin.format.swift.types.EntryPoint]:
        ...

    @property
    def fieldDescriptors(self) -> java.util.Map[java.lang.Long, ghidra.app.util.bin.format.swift.types.FieldDescriptor]:
        ...

    @property
    def associatedTypeDescriptor(self) -> java.util.List[ghidra.app.util.bin.format.swift.types.AssociatedTypeDescriptor]:
        ...

    @property
    def targetTypeContextDescriptors(self) -> java.util.Map[java.lang.String, ghidra.app.util.bin.format.swift.types.TargetTypeContextDescriptor]:
        ...

    @property
    def builtinTypeDescriptors(self) -> java.util.List[ghidra.app.util.bin.format.swift.types.BuiltinTypeDescriptor]:
        ...

    @property
    def multiPayloadEnumDescriptors(self) -> java.util.List[ghidra.app.util.bin.format.swift.types.MultiPayloadEnumDescriptor]:
        ...

    @property
    def captureDescriptors(self) -> java.util.List[ghidra.app.util.bin.format.swift.types.CaptureDescriptor]:
        ...

    @property
    def targetProtocolConformanceDescriptors(self) -> java.util.List[ghidra.app.util.bin.format.swift.types.TargetProtocolConformanceDescriptor]:
        ...


class SwiftTypeMetadataStructure(ghidra.app.util.bin.StructConverter):
    """
    Implemented by all Swift type metadata structures
    """

    class_: typing.ClassVar[java.lang.Class]
    DATA_TYPE_CATEGORY: typing.Final = "/SwiftTypeMetadata"

    def __init__(self, base: typing.Union[jpype.JLong, int]):
        ...

    def getBase(self) -> int:
        """
        Gets the base "address" of this :obj:`SwiftTypeMetadataStructure`
        
        :return: The base "address" of this :obj:`SwiftTypeMetadataStructure`
        :rtype: int
        """

    def getDescription(self) -> str:
        """
        Gets a short description of the :obj:`SwiftTypeMetadataStructure`
        
        :return: A short description of the :obj:`SwiftTypeMetadataStructure`
        :rtype: str
        """

    def getStructureName(self) -> str:
        """
        Gets the name of the :obj:`SwiftTypeMetadataStructure`
        
        :return: The name of the :obj:`SwiftTypeMetadataStructure`
        :rtype: str
        """

    @property
    def structureName(self) -> java.lang.String:
        ...

    @property
    def description(self) -> java.lang.String:
        ...

    @property
    def base(self) -> jpype.JLong:
        ...


class SwiftSection(java.lang.Enum[SwiftSection]):
    """
    Used to refer to a Swift section, which can have different names depending on the platform
    
    
    .. seealso::
    
        | `llvm/BinaryFormat/Swift.def <https://github.com/llvm/llvm-project/blob/main/llvm/include/llvm/BinaryFormat/Swift.def>`_
    """

    class_: typing.ClassVar[java.lang.Class]
    BLOCK_FIELDMD: typing.Final[SwiftSection]
    BLOCK_ASSOCTY: typing.Final[SwiftSection]
    BLOCK_BUILTIN: typing.Final[SwiftSection]
    BLOCK_CAPTURE: typing.Final[SwiftSection]
    BLOCK_TYPEREF: typing.Final[SwiftSection]
    BLOCK_REFLSTR: typing.Final[SwiftSection]
    BLOCK_CONFORM: typing.Final[SwiftSection]
    BLOCK_PROTOCS: typing.Final[SwiftSection]
    BLOCK_ACFUNCS: typing.Final[SwiftSection]
    BLOCK_MPENUM: typing.Final[SwiftSection]
    BLOCK_TYPES: typing.Final[SwiftSection]
    BLOCK_ENTRY: typing.Final[SwiftSection]
    BLOCK_SWIFTAST: typing.Final[SwiftSection]

    def getSwiftSectionNames(self) -> java.util.List[java.lang.String]:
        """
        Gets a :obj:`List` of the :obj:`SwiftSection`'s names
        
        :return: A :obj:`List` of the :obj:`SwiftSection`'s names
        :rtype: java.util.List[java.lang.String]
        """

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> SwiftSection:
        ...

    @staticmethod
    def values() -> jpype.JArray[SwiftSection]:
        ...

    @property
    def swiftSectionNames(self) -> java.util.List[java.lang.String]:
        ...



__all__ = ["SwiftUtils", "SwiftTypeMetadata", "SwiftTypeMetadataStructure", "SwiftSection"]
