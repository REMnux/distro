from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.util.bin
import ghidra.app.util.bin.format.pe
import ghidra.app.util.bin.format.pe.cli
import ghidra.app.util.bin.format.pe.cli.streams
import ghidra.program.model.data
import java.lang # type: ignore


class CliTableMethodSpec(CliAbstractTable):
    """
    Describes the MethodSpec table. Each row is a unique instantiation of a generic method.
    """

    class CliMethodSpecRow(CliAbstractTableRow):

        class_: typing.ClassVar[java.lang.Class]
        methodIndex: jpype.JInt
        instantiationIndex: jpype.JInt

        def __init__(self, methodIndex: typing.Union[jpype.JInt, int], instantiationIndex: typing.Union[jpype.JInt, int]):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, stream: ghidra.app.util.bin.format.pe.cli.streams.CliStreamMetadata, tableId: CliTypeTable):
        ...


class CliTableNestedClass(CliAbstractTable):
    """
    Describes the NestedClass table. Each row is a nested class.
    """

    class CliNestedClassRow(CliAbstractTableRow):

        class_: typing.ClassVar[java.lang.Class]
        nestedClassIndex: jpype.JInt
        enclosingClassIndex: jpype.JInt

        def __init__(self, nestedClassIndex: typing.Union[jpype.JInt, int], enclosingClassIndex: typing.Union[jpype.JInt, int]):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, stream: ghidra.app.util.bin.format.pe.cli.streams.CliStreamMetadata, tableId: CliTypeTable):
        ...


class CliTableModuleRef(CliAbstractTable):
    """
    Describes the ModuleRef table. Each row is a reference to an external module.
    """

    class CliModuleRefRow(CliAbstractTableRow):

        class_: typing.ClassVar[java.lang.Class]
        nameIndex: jpype.JInt

        def __init__(self, nameIndex: typing.Union[jpype.JInt, int]):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, stream: ghidra.app.util.bin.format.pe.cli.streams.CliStreamMetadata, tableId: CliTypeTable):
        ...


class CliTableMethodSemantics(CliAbstractTable):
    """
    Describes the MethodSemantics table. Each row is a link between a property or event and a specific method.
    Events are routinely associated with more than one method, and properties use this for get/set methods.
    """

    class CliMethodSemanticsRow(CliAbstractTableRow):

        class_: typing.ClassVar[java.lang.Class]
        semantics: jpype.JShort
        methodIndex: jpype.JInt
        associationIndex: jpype.JInt

        def __init__(self, semantics: typing.Union[jpype.JShort, int], methodIndex: typing.Union[jpype.JInt, int], associationIndex: typing.Union[jpype.JInt, int]):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, stream: ghidra.app.util.bin.format.pe.cli.streams.CliStreamMetadata, tableId: CliTypeTable):
        ...


class CliTableConstant(CliAbstractTable):
    """
    Describes the Constant table. Each row represents a constant value for a Param, Field, or Property.
    """

    class CliConstantRow(CliAbstractTableRow):

        class_: typing.ClassVar[java.lang.Class]
        type: jpype.JByte
        reserved: jpype.JByte
        parentIndex: jpype.JInt
        valueIndex: jpype.JInt

        def __init__(self, type: typing.Union[jpype.JByte, int], reserved: typing.Union[jpype.JByte, int], parentIndex: typing.Union[jpype.JInt, int], valueIndex: typing.Union[jpype.JInt, int]):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, stream: ghidra.app.util.bin.format.pe.cli.streams.CliStreamMetadata, tableId: CliTypeTable):
        ...


class CliTypeTable(java.lang.Enum[CliTypeTable]):
    """
    Possible Metadata table types.
    """

    class_: typing.ClassVar[java.lang.Class]
    Module: typing.Final[CliTypeTable]
    TypeRef: typing.Final[CliTypeTable]
    TypeDef: typing.Final[CliTypeTable]
    Field: typing.Final[CliTypeTable]
    MethodDef: typing.Final[CliTypeTable]
    Param: typing.Final[CliTypeTable]
    InterfaceImpl: typing.Final[CliTypeTable]
    MemberRef: typing.Final[CliTypeTable]
    Constant: typing.Final[CliTypeTable]
    CustomAttribute: typing.Final[CliTypeTable]
    FieldMarshal: typing.Final[CliTypeTable]
    DeclSecurity: typing.Final[CliTypeTable]
    ClassLayout: typing.Final[CliTypeTable]
    FieldLayout: typing.Final[CliTypeTable]
    StandAloneSig: typing.Final[CliTypeTable]
    EventMap: typing.Final[CliTypeTable]
    Event: typing.Final[CliTypeTable]
    PropertyMap: typing.Final[CliTypeTable]
    Property: typing.Final[CliTypeTable]
    MethodSemantics: typing.Final[CliTypeTable]
    MethodImpl: typing.Final[CliTypeTable]
    ModuleRef: typing.Final[CliTypeTable]
    TypeSpec: typing.Final[CliTypeTable]
    ImplMap: typing.Final[CliTypeTable]
    FieldRVA: typing.Final[CliTypeTable]
    Assembly: typing.Final[CliTypeTable]
    AssemblyProcessor: typing.Final[CliTypeTable]
    AssemblyOS: typing.Final[CliTypeTable]
    AssemblyRef: typing.Final[CliTypeTable]
    AssemblyRefProcessor: typing.Final[CliTypeTable]
    AssemblyRefOS: typing.Final[CliTypeTable]
    File: typing.Final[CliTypeTable]
    ExportedType: typing.Final[CliTypeTable]
    ManifestResource: typing.Final[CliTypeTable]
    NestedClass: typing.Final[CliTypeTable]
    GenericParam: typing.Final[CliTypeTable]
    MethodSpec: typing.Final[CliTypeTable]
    GenericParamConstraint: typing.Final[CliTypeTable]

    @staticmethod
    def fromId(id: typing.Union[jpype.JInt, int]) -> CliTypeTable:
        """
        Gets a table type from the given ID.
        
        :param jpype.JInt or int id: The ID of the table type to get.
        :return: A table type with the given ID, or null if one doesn't exist.
        :rtype: CliTypeTable
        """

    def id(self) -> int:
        """
        Gets the ID associated with this table type.
        
        :return: The ID associated with this table type.
        :rtype: int
        """

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> CliTypeTable:
        ...

    @staticmethod
    def values() -> jpype.JArray[CliTypeTable]:
        ...


class CliTableGenericParam(CliAbstractTable):
    """
    Describes the GenericParam table.
    """

    class CliGenericParamRow(CliAbstractTableRow):

        class_: typing.ClassVar[java.lang.Class]
        number: jpype.JShort
        flags: jpype.JShort
        ownerIndex: jpype.JInt
        nameIndex: jpype.JInt

        def __init__(self, number: typing.Union[jpype.JShort, int], flags: typing.Union[jpype.JShort, int], ownerIndex: typing.Union[jpype.JInt, int], nameIndex: typing.Union[jpype.JInt, int]):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, stream: ghidra.app.util.bin.format.pe.cli.streams.CliStreamMetadata, tableId: CliTypeTable):
        ...


class CliTableImplMap(CliAbstractTable):
    """
    Describes the ImplMap table.
    """

    class CliImplMapRow(CliAbstractTableRow):

        class_: typing.ClassVar[java.lang.Class]
        mappingFlags: jpype.JShort
        memberForwardedIndex: jpype.JInt
        importNameIndex: jpype.JInt
        importScopeIndex: jpype.JInt

        def __init__(self, mappingFlags: typing.Union[jpype.JShort, int], memberForwardedIndex: typing.Union[jpype.JInt, int], importNameIndex: typing.Union[jpype.JInt, int], importScopeIndex: typing.Union[jpype.JInt, int]):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, stream: ghidra.app.util.bin.format.pe.cli.streams.CliStreamMetadata, tableId: CliTypeTable):
        ...


class CliTableParam(CliAbstractTable):
    """
    Describes the Param table. Each row represents a method's parameter.
    """

    class CliParamRow(CliAbstractTableRow):

        class_: typing.ClassVar[java.lang.Class]
        flags: jpype.JShort
        sequence: jpype.JShort
        nameIndex: jpype.JInt

        def __init__(self, flags: typing.Union[jpype.JShort, int], sequence: typing.Union[jpype.JShort, int], nameIndex: typing.Union[jpype.JInt, int]):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, stream: ghidra.app.util.bin.format.pe.cli.streams.CliStreamMetadata, tableId: CliTypeTable):
        ...


class CliAbstractTable(ghidra.app.util.bin.StructConverter, ghidra.app.util.bin.format.pe.PeMarkupable):
    """
    Generic Metadata table.  Subclasses should provided implementations for the actual
    tables.
    """

    class_: typing.ClassVar[java.lang.Class]
    PATH: typing.Final = "/PE/CLI/Metadata/Tables"

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, metadataStream: ghidra.app.util.bin.format.pe.cli.streams.CliStreamMetadata, tableType: CliTypeTable):
        """
        Creates a new generic CLI metadata table.  This is intended to be called by a subclass
        metadata table during its creation.
        
        :param ghidra.app.util.bin.BinaryReader reader: A reader that is used to read the table.
        :param ghidra.app.util.bin.format.pe.cli.streams.CliStreamMetadata metadataStream: The metadata stream that the table lives in.
        :param CliTypeTable tableType: The type of table to create.
        """

    def getNumRows(self) -> int:
        """
        Gets the number of rows in this table.
         
        return The number of rows in this table.
        """

    def getRow(self, rowIndex: typing.Union[jpype.JInt, int]) -> CliAbstractTableRow:
        """
        Gets the row at the given index.
         
        
        NOTE: Per ISO/IEC 23271:2012(E) III.1.9, Row indices start from 1, while heap/stream indices start from 0.
        
        :param jpype.JInt or int rowIndex: The index of the row to get (starting at 1).
        :return: The row at the given index.
        :rtype: CliAbstractTableRow
        :raises java.lang.IndexOutOfBoundsException: if the row index is invalid.
        """

    def getRowDataType(self) -> ghidra.program.model.data.DataType:
        """
        Gets the data type of a row in this table.
        
        :return: The data type of a row in this table.
        :rtype: ghidra.program.model.data.DataType
        """

    def getRowSize(self) -> int:
        """
        Gets the size in bytes of a row in this table.
         
        return The size in bytes of a row in this table.
        """

    def getTableSize(self) -> int:
        """
        Gets the size in bytes of this table.
        
        :return: The size in bytes of this table.
        :rtype: int
        """

    def getTableType(self) -> CliTypeTable:
        """
        Gets this table's table type.
        
        :return: This table's table type.
        :rtype: CliTypeTable
        """

    @property
    def tableType(self) -> CliTypeTable:
        ...

    @property
    def rowDataType(self) -> ghidra.program.model.data.DataType:
        ...

    @property
    def numRows(self) -> jpype.JInt:
        ...

    @property
    def tableSize(self) -> jpype.JInt:
        ...

    @property
    def row(self) -> CliAbstractTableRow:
        ...

    @property
    def rowSize(self) -> jpype.JInt:
        ...


class CliTableField(CliAbstractTable):
    """
    Describes the Field table. Each row represents a field in a TypeDef class. Fields are stored one after the other, grouped by class.
    References to the Field table encode where the fields for a class start and end.
    """

    class CliFieldRow(CliAbstractTableRow):

        class_: typing.ClassVar[java.lang.Class]
        flags: jpype.JShort
        nameIndex: jpype.JInt
        sigIndex: jpype.JInt
        TYPEDEF_OWNER_INIT_VALUE: typing.Final = -1
        typeDefOwnerIndex: jpype.JInt

        def __init__(self, flags: typing.Union[jpype.JShort, int], nameIndex: typing.Union[jpype.JInt, int], sigIndex: typing.Union[jpype.JInt, int]):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, stream: ghidra.app.util.bin.format.pe.cli.streams.CliStreamMetadata, tableId: CliTypeTable):
        ...


class CliTableAssembly(CliAbstractTable):
    """
    Describes the Assembly table. One-row table stores information about the current assembly.
    """

    class CliAssemblyRow(CliAbstractTableRow):

        class_: typing.ClassVar[java.lang.Class]
        hashAlg: jpype.JInt
        majorVersion: jpype.JShort
        minorVersion: jpype.JShort
        buildNumber: jpype.JShort
        revisionNumber: jpype.JShort
        flags: jpype.JInt
        publicKeyIndex: jpype.JInt
        nameIndex: jpype.JInt
        cultureIndex: jpype.JInt

        def __init__(self, hashAlg: typing.Union[jpype.JInt, int], majorVersion: typing.Union[jpype.JShort, int], minorVersion: typing.Union[jpype.JShort, int], buildNumber: typing.Union[jpype.JShort, int], revisionNumber: typing.Union[jpype.JShort, int], flags: typing.Union[jpype.JInt, int], publicKeyIndex: typing.Union[jpype.JInt, int], nameIndex: typing.Union[jpype.JInt, int], cultureIndex: typing.Union[jpype.JInt, int]):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, stream: ghidra.app.util.bin.format.pe.cli.streams.CliStreamMetadata, tableId: CliTypeTable):
        ...


class CliTableEventMap(CliAbstractTable):
    """
    Describes the EventMap table. Each row is an event list for a class.
    """

    class CliEventMapRow(CliAbstractTableRow):

        class_: typing.ClassVar[java.lang.Class]
        parentIndex: jpype.JInt
        eventIndex: jpype.JInt

        def __init__(self, parentIndex: typing.Union[jpype.JInt, int], eventIndex: typing.Union[jpype.JInt, int]):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, stream: ghidra.app.util.bin.format.pe.cli.streams.CliStreamMetadata, tableId: CliTypeTable):
        ...


class CliTableProperty(CliAbstractTable):
    """
    Describes the Property table. Each row describes a property. Indices into this table point to contiguous runs of properties
    ending with the next index from the PropertyMap table or with the end of this table.
    """

    @typing.type_check_only
    class CliPropertyRow(CliAbstractTableRow):

        class_: typing.ClassVar[java.lang.Class]
        flags: jpype.JShort
        nameIndex: jpype.JInt
        sigIndex: jpype.JInt

        def __init__(self, flags: typing.Union[jpype.JShort, int], nameIndex: typing.Union[jpype.JInt, int], sigIndex: typing.Union[jpype.JInt, int]):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, stream: ghidra.app.util.bin.format.pe.cli.streams.CliStreamMetadata, tableId: CliTypeTable):
        ...


class CliAbstractTableRow(ghidra.app.util.bin.format.pe.cli.CliRepresentable):
    """
    Generic Metadata table row.  Subclasses should provided implementations for the actual
    table rows.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class CliTableMethodDef(CliAbstractTable):
    """
    Describes the MethodDef table. Each row represents a method in a specific class. Each row is stored one after the other grouped by class.
    References to the MethodDef table are coded to indicate where the methods for a class start and end.
    """

    class CliMethodDefRow(CliAbstractTableRow):

        class_: typing.ClassVar[java.lang.Class]
        RVA: jpype.JInt
        ImplFlags: jpype.JShort
        Flags: jpype.JShort
        nameIndex: jpype.JInt
        sigIndex: jpype.JInt

        def __init__(self, rva: typing.Union[jpype.JInt, int], implFlags: typing.Union[jpype.JShort, int], flags: typing.Union[jpype.JShort, int], nameIndex: typing.Union[jpype.JInt, int], sigIndex: typing.Union[jpype.JInt, int], paramIndex: typing.Union[jpype.JInt, int]):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, stream: ghidra.app.util.bin.format.pe.cli.streams.CliStreamMetadata, tableId: CliTypeTable):
        ...


class CliTableManifestResource(CliAbstractTable):
    """
    Describes the ManifestResources table. Each row is a reference to an external or internal resource.
    """

    class CliManifestResourceRow(CliAbstractTableRow):

        class_: typing.ClassVar[java.lang.Class]
        offset: jpype.JInt
        flags: jpype.JInt
        nameIndex: jpype.JInt
        implIndex: jpype.JInt

        def __init__(self, offset: typing.Union[jpype.JInt, int], flags: typing.Union[jpype.JInt, int], nameIndex: typing.Union[jpype.JInt, int], implIndex: typing.Union[jpype.JInt, int]):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, stream: ghidra.app.util.bin.format.pe.cli.streams.CliStreamMetadata, tableId: CliTypeTable):
        ...


class CliTableExportedType(CliAbstractTable):
    """
    Describes the ExportedType table.
    """

    class CliExportedTypeRow(CliAbstractTableRow):

        class_: typing.ClassVar[java.lang.Class]
        flags: jpype.JInt
        typeDefIdIndex: jpype.JInt
        typeNameIndex: jpype.JInt
        typeNamespaceIndex: jpype.JInt
        implementationIndex: jpype.JInt

        def __init__(self, flags: typing.Union[jpype.JInt, int], typeDefIdIndex: typing.Union[jpype.JInt, int], typeNameIndex: typing.Union[jpype.JInt, int], typeNamespaceIndex: typing.Union[jpype.JInt, int], implementationIndex: typing.Union[jpype.JInt, int]):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, stream: ghidra.app.util.bin.format.pe.cli.streams.CliStreamMetadata, tableId: CliTypeTable):
        ...


class CliTableInterfaceImpl(CliAbstractTable):
    """
    Describes the InterfaceImpl table. Each row informs the framework of a class that implements a specific interface.
    """

    class CliInterfaceImplRow(CliAbstractTableRow):

        class_: typing.ClassVar[java.lang.Class]
        classIndex: jpype.JInt
        interfaceIndex: jpype.JInt

        def __init__(self, classIndex: typing.Union[jpype.JInt, int], interfaceIndex: typing.Union[jpype.JInt, int]):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, stream: ghidra.app.util.bin.format.pe.cli.streams.CliStreamMetadata, tableId: CliTypeTable):
        ...


class CliTableModule(CliAbstractTable):
    """
    Describes the Module Table, which contains information about the current assembly.
    """

    class CliModuleRow(CliAbstractTableRow):

        class_: typing.ClassVar[java.lang.Class]
        generation: jpype.JShort
        nameIndex: jpype.JInt
        mvIdIndex: jpype.JInt
        encIdIndex: jpype.JInt
        encBaseIdIndex: jpype.JInt

        def __init__(self, generation: typing.Union[jpype.JShort, int], nameIndex: typing.Union[jpype.JInt, int], mvIdIndex: typing.Union[jpype.JInt, int], encIdIndex: typing.Union[jpype.JInt, int], encBaseIdIndex: typing.Union[jpype.JInt, int]):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, stream: ghidra.app.util.bin.format.pe.cli.streams.CliStreamMetadata, tableId: CliTypeTable):
        ...


class CliTableEvent(CliAbstractTable):
    """
    Describes the Event table. Each row represents an event. References to this table are to contiguous runs of events.
    The "run" begins at the specified index and ends at the next place a reference from EventMap points, or the end of this table.
    """

    class CliEventRow(CliAbstractTableRow):

        class_: typing.ClassVar[java.lang.Class]
        eventFlags: jpype.JShort
        nameIndex: jpype.JInt
        eventTypeIndex: jpype.JInt

        def __init__(self, eventFlags: typing.Union[jpype.JShort, int], nameIndex: typing.Union[jpype.JInt, int], eventTypeIndex: typing.Union[jpype.JInt, int]):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, stream: ghidra.app.util.bin.format.pe.cli.streams.CliStreamMetadata, tableId: CliTypeTable):
        ...


class CliTableStandAloneSig(CliAbstractTable):
    """
    Describes the StandAloneSig table. Each row represents a signature that isn't referenced by any other Table.
    """

    class CliStandAloneSigRow(CliAbstractTableRow):

        class_: typing.ClassVar[java.lang.Class]
        signatureIndex: jpype.JInt

        def __init__(self, signatureIndex: typing.Union[jpype.JInt, int]):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, stream: ghidra.app.util.bin.format.pe.cli.streams.CliStreamMetadata, tableId: CliTypeTable):
        ...


class CliTableAssemblyOS(CliAbstractTable):
    """
    Describes the AssemblyOS table. Apparently it is ignored by the CLI and shouldn't be found in an Assembly.
    """

    class CliAssemblyOSRow(CliAbstractTableRow):

        class_: typing.ClassVar[java.lang.Class]
        osPlatformID: jpype.JInt
        osMajorVersion: jpype.JInt
        osMinorVersion: jpype.JInt

        def __init__(self, osPlatformID: typing.Union[jpype.JInt, int], osMajorVersion: typing.Union[jpype.JInt, int], osMinorVersion: typing.Union[jpype.JInt, int]):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, stream: ghidra.app.util.bin.format.pe.cli.streams.CliStreamMetadata, tableId: CliTypeTable):
        ...


class CliTableCustomAttribute(CliAbstractTable):
    """
    Describes the CustomAttribute table.
    """

    class CliCustomAttributeRow(CliAbstractTableRow):

        class_: typing.ClassVar[java.lang.Class]
        parentIndex: jpype.JInt
        typeIndex: jpype.JInt
        valueIndex: jpype.JInt

        def __init__(self, parentIndex: typing.Union[jpype.JInt, int], typeIndex: typing.Union[jpype.JInt, int], valueIndex: typing.Union[jpype.JInt, int]):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, stream: ghidra.app.util.bin.format.pe.cli.streams.CliStreamMetadata, tableId: CliTypeTable):
        ...


class CliTableAssemblyRefProcessor(CliAbstractTable):
    """
    Describes the AssemblyRefProcessor table. Apparently it is ignored by the CLI and shouldn't be present in an assembly.
    """

    class CliAssemblyRefProcessorRow(CliAbstractTableRow):

        class_: typing.ClassVar[java.lang.Class]
        processor: jpype.JInt
        assemblyRefIndex: jpype.JInt

        def __init__(self, processor: typing.Union[jpype.JInt, int], assemblyRefIndex: typing.Union[jpype.JInt, int]):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, stream: ghidra.app.util.bin.format.pe.cli.streams.CliStreamMetadata, tableId: CliTypeTable):
        ...


class CliTableFile(CliAbstractTable):
    """
    Describes the File table. Each row is a reference to an external file.
    """

    class CliFileRow(CliAbstractTableRow):

        class_: typing.ClassVar[java.lang.Class]
        flags: jpype.JInt
        nameIndex: jpype.JInt
        hashIndex: jpype.JInt

        def __init__(self, flags: typing.Union[jpype.JInt, int], nameIndex: typing.Union[jpype.JInt, int], hashIndex: typing.Union[jpype.JInt, int]):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, stream: ghidra.app.util.bin.format.pe.cli.streams.CliStreamMetadata, tableId: CliTypeTable):
        ...


class CliTableAssemblyRef(CliAbstractTable):
    """
    Describes the AssemblyRef table. Each row is a reference to an external assembly.
    """

    class CliAssemblyRefRow(CliAbstractTableRow):

        class_: typing.ClassVar[java.lang.Class]
        majorVersion: jpype.JShort
        minorVersion: jpype.JShort
        buildNumber: jpype.JShort
        revisionNumber: jpype.JShort
        flags: jpype.JInt
        publicKeyOrTokenIndex: jpype.JInt
        nameIndex: jpype.JInt
        cultureIndex: jpype.JInt
        hashValueIndex: jpype.JInt

        def __init__(self, majorVersion: typing.Union[jpype.JShort, int], minorVersion: typing.Union[jpype.JShort, int], buildNumber: typing.Union[jpype.JShort, int], revisionNumber: typing.Union[jpype.JShort, int], flags: typing.Union[jpype.JInt, int], publicKeyOrTokenIndex: typing.Union[jpype.JInt, int], nameIndex: typing.Union[jpype.JInt, int], cultureIndex: typing.Union[jpype.JInt, int], hashValueIndex: typing.Union[jpype.JInt, int]):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, stream: ghidra.app.util.bin.format.pe.cli.streams.CliStreamMetadata, tableId: CliTypeTable):
        ...


class CliTableTypeRef(CliAbstractTable):
    """
    Describes the TypeRef table. Each row represents an imported class, its namespace, and the assembly which contains it.
    """

    class CliTypeRefRow(CliAbstractTableRow):

        class_: typing.ClassVar[java.lang.Class]
        resolutionScopeIndex: jpype.JInt
        typeNameIndex: jpype.JInt
        typeNamespaceIndex: jpype.JInt

        def __init__(self, resolutionScopeIndex: typing.Union[jpype.JInt, int], typeNameIndex: typing.Union[jpype.JInt, int], typeNamespaceIndex: typing.Union[jpype.JInt, int]):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, stream: ghidra.app.util.bin.format.pe.cli.streams.CliStreamMetadata, tableId: CliTypeTable):
        ...


class CliTableFieldRVA(CliAbstractTable):
    """
    Describes the FieldRVA table. Each row gives the RVA location of an initial value for each Field.
    """

    class CliFieldRVARow(CliAbstractTableRow):

        class_: typing.ClassVar[java.lang.Class]
        rva: jpype.JInt
        fieldIndex: jpype.JInt

        def __init__(self, rva: typing.Union[jpype.JInt, int], fieldIndex: typing.Union[jpype.JInt, int]):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, stream: ghidra.app.util.bin.format.pe.cli.streams.CliStreamMetadata, tableId: CliTypeTable):
        ...


class CliTablePropertyMap(CliAbstractTable):
    """
    Describes the PropertyMap class. Each row points to a list of properties in the Property table owned by a class.
    """

    class CliPropertyMapRow(CliAbstractTableRow):

        class_: typing.ClassVar[java.lang.Class]
        parentIndex: jpype.JInt
        propertyListIndex: jpype.JInt

        def __init__(self, parentIndex: typing.Union[jpype.JInt, int], propertyListIndex: typing.Union[jpype.JInt, int]):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, stream: ghidra.app.util.bin.format.pe.cli.streams.CliStreamMetadata, tableId: CliTypeTable):
        ...


class CliTableFieldLayout(CliAbstractTable):
    """
    Describes the FieldLayout table. Serves a similar purpose to ClassLayout; it's useful when passing to unmanaged code.
    """

    class CliFieldLayoutRow(CliAbstractTableRow):

        class_: typing.ClassVar[java.lang.Class]
        offset: jpype.JInt
        fieldIndex: jpype.JInt

        def __init__(self, offset: typing.Union[jpype.JInt, int], fieldIndex: typing.Union[jpype.JInt, int]):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, stream: ghidra.app.util.bin.format.pe.cli.streams.CliStreamMetadata, tableId: CliTypeTable):
        ...


class CliTableTypeSpec(CliAbstractTable):
    """
    Describes the TypeSpec table. Each row represents a specification for a TypeDef or TypeRef which is contained in the Blob stream.
    """

    class CliTypeSpecRow(CliAbstractTableRow):

        class_: typing.ClassVar[java.lang.Class]
        signatureIndex: jpype.JInt

        def __init__(self, signatureIndex: typing.Union[jpype.JInt, int]):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, stream: ghidra.app.util.bin.format.pe.cli.streams.CliStreamMetadata, tableId: CliTypeTable):
        ...


class CliTableMemberRef(CliAbstractTable):
    """
    Describes the MemberRef/MethodRef table. Each row represents an imported method.
    """

    class CliMemberRefRow(CliAbstractTableRow):

        class_: typing.ClassVar[java.lang.Class]
        classIndex: jpype.JInt
        nameIndex: jpype.JInt
        signatureIndex: jpype.JInt

        def __init__(self, classIndex: typing.Union[jpype.JInt, int], nameIndex: typing.Union[jpype.JInt, int], signatureIndex: typing.Union[jpype.JInt, int]):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, stream: ghidra.app.util.bin.format.pe.cli.streams.CliStreamMetadata, tableId: CliTypeTable):
        ...


class CliTableDeclSecurity(CliAbstractTable):
    """
    Describes the DeclSecurity table. Each row attaches security attributes to a class, method, or assembly.
    """

    class CliDeclSecurityRow(CliAbstractTableRow):

        class_: typing.ClassVar[java.lang.Class]
        action: jpype.JShort
        parentIndex: jpype.JInt
        permissionSetIndex: jpype.JInt

        def __init__(self, action: typing.Union[jpype.JShort, int], parentIndex: typing.Union[jpype.JInt, int], permissionSetIndex: typing.Union[jpype.JInt, int]):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, stream: ghidra.app.util.bin.format.pe.cli.streams.CliStreamMetadata, tableId: CliTypeTable):
        ...


class CliTableAssemblyProcessor(CliAbstractTable):
    """
    Describes the AssemblyProcessor table. It is apparently ignored by the CLI and shouldn't be found in an assembly.
    """

    class CliAssemblyProcessorRow(CliAbstractTableRow):

        class_: typing.ClassVar[java.lang.Class]
        processor: jpype.JInt

        def __init__(self, processor: typing.Union[jpype.JInt, int]):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, stream: ghidra.app.util.bin.format.pe.cli.streams.CliStreamMetadata, tableId: CliTypeTable):
        ...


class CliTableAssemblyRefOS(CliAbstractTable):
    """
    Describes the AssemblyRefOS table. Apparently it is ignored by the CLI and shouldn't be found in an assembly.
    """

    class CliAssemblyRefOSRow(CliAbstractTableRow):

        class_: typing.ClassVar[java.lang.Class]
        osPlatformID: jpype.JInt
        osMajorVersion: jpype.JInt
        osMinorVersion: jpype.JInt
        assemblyRefIndex: jpype.JInt

        def __init__(self, osPlatformID: typing.Union[jpype.JInt, int], osMajorVersion: typing.Union[jpype.JInt, int], osMinorVersion: typing.Union[jpype.JInt, int], assemblyRefIndex: typing.Union[jpype.JInt, int]):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, stream: ghidra.app.util.bin.format.pe.cli.streams.CliStreamMetadata, tableId: CliTypeTable):
        ...


class CliTableMethodImpl(CliAbstractTable):
    """
    Describes the MethodImpl table.
    """

    class CliMethodImplRow(CliAbstractTableRow):

        class_: typing.ClassVar[java.lang.Class]
        classIndex: jpype.JInt
        methodBodyIndex: jpype.JInt
        methodDeclarationIndex: jpype.JInt

        def __init__(self, classIndex: typing.Union[jpype.JInt, int], methodBodyIndex: typing.Union[jpype.JInt, int], methodDeclarationIndex: typing.Union[jpype.JInt, int]):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, stream: ghidra.app.util.bin.format.pe.cli.streams.CliStreamMetadata, tableId: CliTypeTable):
        ...


class CliTableClassLayout(CliAbstractTable):
    """
    Describes the ClassLayout table. Each row has information that's useful when handing something from managed to unmanaged code.
    """

    class CliClassLayoutRow(CliAbstractTableRow):

        class_: typing.ClassVar[java.lang.Class]
        packingSize: jpype.JShort
        classSize: jpype.JInt
        parentIndex: jpype.JInt

        def __init__(self, packingSize: typing.Union[jpype.JShort, int], classSize: typing.Union[jpype.JInt, int], parentIndex: typing.Union[jpype.JInt, int]):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, stream: ghidra.app.util.bin.format.pe.cli.streams.CliStreamMetadata, tableId: CliTypeTable):
        ...


class CliTableGenericParamConstraint(CliAbstractTable):
    """
    Describes the GenericParamConstraint table.
    """

    class CliGenericParamConstraintRow(CliAbstractTableRow):

        class_: typing.ClassVar[java.lang.Class]
        ownerIndex: jpype.JInt
        constraintIndex: jpype.JInt

        def __init__(self, ownerIndex: typing.Union[jpype.JInt, int], constraintIndex: typing.Union[jpype.JInt, int]):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, stream: ghidra.app.util.bin.format.pe.cli.streams.CliStreamMetadata, tableId: CliTypeTable):
        ...


class CliTableTypeDef(CliAbstractTable):
    """
    Describes the TypeDef table. Each row represents a class in the current assembly.
    """

    class CliTypeDefRow(CliAbstractTableRow):

        class_: typing.ClassVar[java.lang.Class]
        flags: jpype.JInt
        typeNameIndex: jpype.JInt
        typeNamespaceIndex: jpype.JInt
        extendsIndex: jpype.JInt
        fieldListIndex: jpype.JInt
        methodListIndex: jpype.JInt

        def __init__(self, flags: typing.Union[jpype.JInt, int], typeNameIndex: typing.Union[jpype.JInt, int], typeNamespaceIndex: typing.Union[jpype.JInt, int], extendsIndex: typing.Union[jpype.JInt, int], fieldListIndex: typing.Union[jpype.JInt, int], methodListIndex: typing.Union[jpype.JInt, int]):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, stream: ghidra.app.util.bin.format.pe.cli.streams.CliStreamMetadata, tableId: CliTypeTable):
        ...

    def getOwnerOfFieldIndex(self, fieldIndex: typing.Union[jpype.JInt, int]) -> int:
        ...

    @property
    def ownerOfFieldIndex(self) -> jpype.JInt:
        ...


class CliTableFieldMarshall(CliAbstractTable):
    """
    Describes the FieldMarshall table. Each row indicates how a Param or Field should be treated when calling from or to unmanaged code.
    """

    class CliFieldMarshallRow(CliAbstractTableRow):

        class_: typing.ClassVar[java.lang.Class]
        parentIndex: jpype.JInt
        nativeTypeIndex: jpype.JInt

        def __init__(self, parentIndex: typing.Union[jpype.JInt, int], nativeTypeIndex: typing.Union[jpype.JInt, int]):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, stream: ghidra.app.util.bin.format.pe.cli.streams.CliStreamMetadata, tableId: CliTypeTable):
        ...



__all__ = ["CliTableMethodSpec", "CliTableNestedClass", "CliTableModuleRef", "CliTableMethodSemantics", "CliTableConstant", "CliTypeTable", "CliTableGenericParam", "CliTableImplMap", "CliTableParam", "CliAbstractTable", "CliTableField", "CliTableAssembly", "CliTableEventMap", "CliTableProperty", "CliAbstractTableRow", "CliTableMethodDef", "CliTableManifestResource", "CliTableExportedType", "CliTableInterfaceImpl", "CliTableModule", "CliTableEvent", "CliTableStandAloneSig", "CliTableAssemblyOS", "CliTableCustomAttribute", "CliTableAssemblyRefProcessor", "CliTableFile", "CliTableAssemblyRef", "CliTableTypeRef", "CliTableFieldRVA", "CliTablePropertyMap", "CliTableFieldLayout", "CliTableTypeSpec", "CliTableMemberRef", "CliTableDeclSecurity", "CliTableAssemblyProcessor", "CliTableAssemblyRefOS", "CliTableMethodImpl", "CliTableClassLayout", "CliTableGenericParamConstraint", "CliTableTypeDef", "CliTableFieldMarshall"]
