from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.util.bin
import ghidra.app.util.bin.format.swift
import java.lang # type: ignore
import java.util # type: ignore


class FieldRecord(ghidra.app.util.bin.format.swift.SwiftTypeMetadataStructure):
    """
    Represents a Swift FieldRecord structure
    
    
    .. seealso::
    
        | `swift/RemoteInspection/Records.h <https://github.com/swiftlang/swift/blob/main/include/swift/RemoteInspection/Records.h>`_
    """

    class_: typing.ClassVar[java.lang.Class]
    SIZE: typing.Final = 12
    """
    The size (in bytes) of a :obj:`FieldRecord` structure
    """


    def __init__(self, reader: ghidra.app.util.bin.BinaryReader):
        """
        Creates a new :obj:`FieldRecord`
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of the structure
        :raises IOException: if there was an IO-related problem creating the structure
        """

    def getFieldName(self) -> str:
        """
        Gets the field name
        
        :return: The field name
        :rtype: str
        """

    def getFlags(self) -> int:
        """
        Gets the flags
        
        :return: The flags
        :rtype: int
        """

    def getMangledTypeName(self) -> str:
        """
        Gets the mangled type name
        
        :return: The mangled type name
        :rtype: str
        """

    @property
    def fieldName(self) -> java.lang.String:
        ...

    @property
    def mangledTypeName(self) -> java.lang.String:
        ...

    @property
    def flags(self) -> jpype.JInt:
        ...


class EntryPoint(ghidra.app.util.bin.format.swift.SwiftTypeMetadataStructure):
    """
    Represents a Swift entry point
    """

    class_: typing.ClassVar[java.lang.Class]
    SIZE: typing.Final = 4
    """
    The size (in bytes) of an :obj:`EntryPoint` structure
    """


    def __init__(self, reader: ghidra.app.util.bin.BinaryReader):
        """
        Creates a new :obj:`EntryPoint`
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of the structure
        :raises IOException: if there was an IO-related problem creating the structure
        """

    def getEntryPoint(self) -> int:
        """
        Gets the entry point
        
        :return: The entry point
        :rtype: int
        """

    @property
    def entryPoint(self) -> jpype.JInt:
        ...


class TargetEnumDescriptor(TargetTypeContextDescriptor):
    """
    Represents a Swift TargetEnumDescriptor structure
    
    
    .. seealso::
    
        | `swift/ABI/Metadata.h <https://github.com/swiftlang/swift/blob/main/include/swift/ABI/Metadata.h>`_
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader):
        """
        Creates a new :obj:`TargetEnumDescriptor`
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of the structure
        :raises IOException: if there was an IO-related problem creating the structure
        """

    def getNumEmptyCases(self) -> int:
        """
        Gets the number of empty cases in the enum
        
        :return: The number of empty cases in the enum
        :rtype: int
        """

    def getNumPayloadCasesAndPayloadSizeOffset(self) -> int:
        """
        Gets the number of non-empty cases in the enum are in the low 24 bits; the offset of the 
        payload size in the metadata record in words, if any, is stored in the high 8 bits;
        
        :return: The number of non-empty cases in the enum and the offset of the payload size
        :rtype: int
        """

    @property
    def numPayloadCasesAndPayloadSizeOffset(self) -> jpype.JInt:
        ...

    @property
    def numEmptyCases(self) -> jpype.JInt:
        ...


class MultiPayloadEnumDescriptor(ghidra.app.util.bin.format.swift.SwiftTypeMetadataStructure):
    """
    Represents a Swift MultiPayloadEnumDescriptor structure
    
    
    .. seealso::
    
        | `swift/RemoteInspection/Records.h <https://github.com/swiftlang/swift/blob/main/include/swift/RemoteInspection/Records.h>`_
    """

    class_: typing.ClassVar[java.lang.Class]
    SIZE: typing.Final = 4
    """
    The size (in bytes) of a :obj:`MultiPayloadEnumDescriptor` structure.  This size does not
    take into account the size of the ``contents`` array.
    
    
    .. seealso::
    
        | :obj:`.getContentsSize()`
    """


    def __init__(self, reader: ghidra.app.util.bin.BinaryReader):
        """
        Creates a new :obj:`MultiPayloadEnumDescriptor`
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of the structure
        :raises IOException: if there was an IO-related problem creating the structure
        """

    def getContents(self) -> jpype.JArray[jpype.JInt]:
        """
        Gets the contents
        
        :return: The contents
        :rtype: jpype.JArray[jpype.JInt]
        """

    def getContentsSize(self) -> int:
        """
        Gets the size of the contents in bytes
        
        :return: The size of the contents in bytes
        :rtype: int
        """

    def getTypeName(self) -> str:
        """
        Gets the type name
        
        :return: The type name
        :rtype: str
        """

    @property
    def contentsSize(self) -> jpype.JLong:
        ...

    @property
    def contents(self) -> jpype.JArray[jpype.JInt]:
        ...

    @property
    def typeName(self) -> java.lang.String:
        ...


class TargetProtocolConformanceDescriptor(ghidra.app.util.bin.format.swift.SwiftTypeMetadataStructure):
    """
    Represents a Swift TargetProtocolConformanceDescriptor structure
    
    
    .. seealso::
    
        | `swift/ABI/Metadata.h <https://github.com/swiftlang/swift/blob/main/include/swift/ABI/Metadata.h>`_
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader):
        """
        Creates a new :obj:`TargetProtocolConformanceDescriptor`
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of the structure
        :raises IOException: if there was an IO-related problem creating the structure
        """

    def getConformanceFlags(self) -> int:
        """
        Gets various flags, including the kind of conformance
        
        :return: Various flags, including the kind of conformance
        :rtype: int
        """

    def getNominalTypeDescriptor(self) -> int:
        """
        Gets some description of the type that conforms to the protocol
        
        :return: Some description of the type that conforms to the protocol
        :rtype: int
        """

    def getProtocolDescriptor(self) -> int:
        """
        Gets the protocol being conformed to
        
        :return: The protocol being conformed to
        :rtype: int
        """

    def getProtocolWitnessTable(self) -> int:
        """
        Gets the witness table pattern, which may also serve as the witness table
        
        :return: The witness table pattern, which may also serve as the witness table
        :rtype: int
        """

    @property
    def nominalTypeDescriptor(self) -> jpype.JInt:
        ...

    @property
    def protocolDescriptor(self) -> jpype.JInt:
        ...

    @property
    def protocolWitnessTable(self) -> jpype.JInt:
        ...

    @property
    def conformanceFlags(self) -> jpype.JInt:
        ...


class CaptureDescriptor(ghidra.app.util.bin.format.swift.SwiftTypeMetadataStructure):
    """
    Represents a Swift CaptureDescriptor structure
    
    
    .. seealso::
    
        | `swift/RemoteInspection/Records.h <https://github.com/swiftlang/swift/blob/main/include/swift/RemoteInspection/Records.h>`_
    """

    class_: typing.ClassVar[java.lang.Class]
    SIZE: typing.Final = 12
    """
    The size (in bytes) of a :obj:`CaptureDescriptor` structure
    """


    def __init__(self, reader: ghidra.app.util.bin.BinaryReader):
        """
        Creates a new :obj:`CaptureDescriptor`
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of the structure
        :raises IOException: if there was an IO-related problem creating the structure
        """

    def getCaptureTypeRecords(self) -> java.util.List[CaptureTypeRecord]:
        """
        Gets the :obj:`List` of :obj:`CaptureTypeRecord`s
        
        :return: The :obj:`List` of :obj:`CaptureTypeRecord`s
        :rtype: java.util.List[CaptureTypeRecord]
        """

    def getMetadataSourceRecords(self) -> java.util.List[MetadataSourceRecord]:
        """
        Gets the :obj:`List` of :obj:`MetadataSourceRecord`s
        
        :return: The :obj:`List` of :obj:`MetadataSourceRecord`s
        :rtype: java.util.List[MetadataSourceRecord]
        """

    def getNumBindings(self) -> int:
        """
        Gets the number of bindings
        
        :return: The number of bindings
        :rtype: int
        """

    def getNumCaptureTypes(self) -> int:
        """
        Gets the number of capture types
        
        :return: The number of capture types
        :rtype: int
        """

    def getNumMetadataSources(self) -> int:
        """
        Gets the number of metadata sources
        
        :return: The number of metadata sources
        :rtype: int
        """

    @property
    def numCaptureTypes(self) -> jpype.JInt:
        ...

    @property
    def numBindings(self) -> jpype.JInt:
        ...

    @property
    def metadataSourceRecords(self) -> java.util.List[MetadataSourceRecord]:
        ...

    @property
    def captureTypeRecords(self) -> java.util.List[CaptureTypeRecord]:
        ...

    @property
    def numMetadataSources(self) -> jpype.JInt:
        ...


class ContextDescriptorKind(java.lang.Object):
    """
    Swift ContextDescriptorKind values
    
    
    .. seealso::
    
        | `swift/ABI/MetadataValues.h <https://github.com/swiftlang/swift/blob/main/include/swift/ABI/MetadataValues.h>`_
    """

    class_: typing.ClassVar[java.lang.Class]
    MODULE: typing.Final = 0
    """
    This context descriptor represents a module
    """

    EXTENSION: typing.Final = 1
    """
    This context descriptor represents an extension
    """

    ANONYMOUS: typing.Final = 2
    """
    This context descriptor represents an anonymous possibly-generic context such as a function
    body
    """

    PROTOCOL: typing.Final = 3
    """
    This context descriptor represents a protocol context
    """

    OPAQUE_TYPE: typing.Final = 4
    """
    This context descriptor represents an opaque type alias
    """

    TYPE_FIRST: typing.Final = 16
    """
    First kind that represents a type of any sort
    """

    CLASS: typing.Final = 16
    """
    This context descriptor represents a class
    """

    STRUCT: typing.Final = 17
    """
    This context descriptor represents a struct
    """

    ENUM: typing.Final = 18
    """
    This context descriptor represents an enum
    """

    TYPE_LAST: typing.Final = 31
    """
    Last kind that represents a type of any sort
    """


    def __init__(self):
        ...

    @staticmethod
    def getKind(flags: typing.Union[jpype.JInt, int]) -> int:
        """
        Gets the :obj:`ContextDescriptorKind` value from the 
        :meth:`flags <TargetContextDescriptor.getFlags>`
        
        :param jpype.JInt or int flags: The :meth:`flags <TargetContextDescriptor.getFlags>` that contain the kind
        :return: The :obj:`ContextDescriptorKind` value
        :rtype: int
        """


class TargetStructDescriptor(TargetTypeContextDescriptor):
    """
    Represents a Swift TargetStructDescriptor structure
    
    
    .. seealso::
    
        | `swift/ABI/Metadata.h <https://github.com/swiftlang/swift/blob/main/include/swift/ABI/Metadata.h>`_
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader):
        """
        Creates a new :obj:`TargetStructDescriptor`
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of the structure
        :raises IOException: if there was an IO-related problem creating the structure
        """

    def getFieldOffsetVectorOffset(self) -> int:
        """
        Gets the offset of the field offset vector for this struct's stored properties in its 
        metadata, if any. 0 means there is no field offset vector.
        
        :return: The offset of the field offset vector for this struct's stored properties in its 
        metadata, if any. 0 means there is no field offset vector.
        :rtype: int
        """

    def getNumFields(self) -> int:
        """
        Gets the number of stored properties in the struct. If there is a field offset vector, 
        this is its length.
        
        :return: The number of stored properties in the struct. If there is a field offset vector, 
        this is its length.
        :rtype: int
        """

    @property
    def fieldOffsetVectorOffset(self) -> jpype.JInt:
        ...

    @property
    def numFields(self) -> jpype.JInt:
        ...


class BuiltinTypeDescriptor(ghidra.app.util.bin.format.swift.SwiftTypeMetadataStructure):
    """
    Represents a Swift BuiltinTypeDescriptor structure
    
    
    .. seealso::
    
        | `swift/RemoteInspection/Records.h <https://github.com/swiftlang/swift/blob/main/include/swift/RemoteInspection/Records.h>`_
    """

    class_: typing.ClassVar[java.lang.Class]
    SIZE: typing.Final = 20
    """
    The size (in bytes) of a :obj:`BuiltinTypeDescriptor` structure
    """


    def __init__(self, reader: ghidra.app.util.bin.BinaryReader):
        """
        Creates a new :obj:`BuiltinTypeDescriptor`
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of the structure
        :raises IOException: if there was an IO-related problem creating the structure
        """

    def getAlignmentAndFlags(self) -> int:
        """
        Gets the alignment and flags
        
        :return: The alignment and flags
        :rtype: int
        """

    def getNumExtraInhabitants(self) -> int:
        """
        Gets the number of extra inhabitants
        
        :return: The number of extra inhabitants
        :rtype: int
        """

    def getSize(self) -> int:
        """
        Gets the size
        
        :return: The size
        :rtype: int
        """

    def getStride(self) -> int:
        """
        Gets the stride
        
        :return: The stride
        :rtype: int
        """

    def getTypeName(self) -> str:
        """
        Gets the type name
        
        :return: The type name
        :rtype: str
        """

    @property
    def size(self) -> jpype.JInt:
        ...

    @property
    def typeName(self) -> java.lang.String:
        ...

    @property
    def alignmentAndFlags(self) -> jpype.JInt:
        ...

    @property
    def stride(self) -> jpype.JInt:
        ...

    @property
    def numExtraInhabitants(self) -> jpype.JInt:
        ...


class TargetClassDescriptor(TargetTypeContextDescriptor):
    """
    Represents a Swift TargetClassDescriptor structure
    
    
    .. seealso::
    
        | `swift/ABI/Metadata.h <https://github.com/swiftlang/swift/blob/main/include/swift/ABI/Metadata.h>`_
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader):
        """
        Creates a new :obj:`TargetClassDescriptor`
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of the structure
        :raises IOException: if there was an IO-related problem creating the structure
        """

    def getMetadataNegativeSizeInWords(self) -> int:
        """
        If this descriptor does not have a resilient superclass, this is the negative size of 
        metadata objects of this class (in words). If this descriptor has a resilient superclass, 
        this is a reference to a cache holding the metadata's extents.
        
        :return: The negative size of metadata objects of this class (in words) or a reference to a 
        cache holding the metadata's extents
        :rtype: int
        """

    def getMetadataPositiveSizeInWords(self) -> int:
        """
        If this descriptor does not have a resilient superclass, this is the positive size of 
        metadata objects of this class (in words). Otherwise, these flags are used to do things like 
        indicate the presence of an Objective-C resilient class stub.
        
        :return: The positive size of metadata objects of this class (in words) or flags used to do
        things like indicate the presence of an Objective-C resilient class stub.
        :rtype: int
        """

    def getNumFields(self) -> int:
        """
        Gets the number of stored properties in the class, not including its superclasses. If there 
        is a field offset vector, this is its length.
        
        :return: The number of stored properties in the class, not including its superclasses. 
        If there is a field offset vector, this is its length.
        :rtype: int
        """

    def getNumImmediateMembers(self) -> int:
        """
        Gets the number of additional members added by this class to the class metadata
        
        :return: The number of additional members added by this class to the class metadata
        :rtype: int
        """

    def getSuperclassType(self) -> int:
        """
        Gets the type of the superclass, expressed as a mangled type name that can refer to the 
        generic arguments of the subclass type
        
        :return: The type of the superclass, expressed as a mangled type name that can refer to the 
        generic arguments of the subclass type
        :rtype: int
        """

    @property
    def superclassType(self) -> jpype.JInt:
        ...

    @property
    def metadataPositiveSizeInWords(self) -> jpype.JInt:
        ...

    @property
    def numFields(self) -> jpype.JInt:
        ...

    @property
    def numImmediateMembers(self) -> jpype.JInt:
        ...

    @property
    def metadataNegativeSizeInWords(self) -> jpype.JInt:
        ...


class FieldDescriptor(ghidra.app.util.bin.format.swift.SwiftTypeMetadataStructure):
    """
    Represents a Swift FieldDescriptor structure
    
    
    .. seealso::
    
        | `swift/RemoteInspection/Records.h <https://github.com/swiftlang/swift/blob/main/include/swift/RemoteInspection/Records.h>`_
    """

    class_: typing.ClassVar[java.lang.Class]
    SIZE: typing.Final = 16
    """
    The size (in bytes) of a :obj:`FieldDescriptor` structure
    """


    def __init__(self, reader: ghidra.app.util.bin.BinaryReader):
        """
        Creates a new :obj:`FieldDescriptor`
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of the structure
        :raises IOException: if there was an IO-related problem creating the structure
        """

    def getFieldRecordSize(self) -> int:
        """
        Gets the field record size
        
        :return: The field record size
        :rtype: int
        """

    def getFieldRecords(self) -> java.util.List[FieldRecord]:
        """
        Gets the :obj:`List` of :obj:`FieldRecord`s
        
        :return: The :obj:`List` of :obj:`FieldRecord`s
        :rtype: java.util.List[FieldRecord]
        """

    def getKind(self) -> int:
        """
        Gets the kind
        
        :return: The kind
        :rtype: int
        """

    def getMangledTypeName(self) -> str:
        """
        Gets the mangled type name
        
        :return: The mangled type name
        :rtype: str
        """

    def getNumFields(self) -> int:
        """
        Gets the number of fields
        
        :return: The number of fields
        :rtype: int
        """

    def getSuperclass(self) -> int:
        """
        Gets the superclass
        
        :return: The superclass
        :rtype: int
        """

    @property
    def fieldRecordSize(self) -> jpype.JInt:
        ...

    @property
    def superclass(self) -> jpype.JInt:
        ...

    @property
    def kind(self) -> jpype.JInt:
        ...

    @property
    def mangledTypeName(self) -> java.lang.String:
        ...

    @property
    def fieldRecords(self) -> java.util.List[FieldRecord]:
        ...

    @property
    def numFields(self) -> jpype.JInt:
        ...


class AssociatedTypeRecord(ghidra.app.util.bin.format.swift.SwiftTypeMetadataStructure):
    """
    Represents a Swift AssociatedTypeRecord structure
    
    
    .. seealso::
    
        | `swift/RemoteInspection/Records.h <https://github.com/swiftlang/swift/blob/main/include/swift/RemoteInspection/Records.h>`_
    """

    class_: typing.ClassVar[java.lang.Class]
    SIZE: typing.Final = 8
    """
    The size (in bytes) of an :obj:`AssociatedTypeRecord` structure
    """


    def __init__(self, reader: ghidra.app.util.bin.BinaryReader):
        """
        Creates a new :obj:`AssociatedTypeRecord`
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of the structure
        :raises IOException: if there was an IO-related problem creating the structure
        """

    def getName(self) -> str:
        """
        Gets the name
        
        :return: The name
        :rtype: str
        """

    def getSubstitutedTypeName(self) -> str:
        """
        Gets the substituted type name
        
        :return: The substituted type name
        :rtype: str
        """

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def substitutedTypeName(self) -> java.lang.String:
        ...


class TargetProtocolDescriptor(TargetContextDescriptor):
    """
    Represents a Swift TargetProtocolDescriptor structure
    
    
    .. seealso::
    
        | `swift/ABI/Metadata.h <https://github.com/swiftlang/swift/blob/main/include/swift/ABI/Metadata.h>`_
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader):
        """
        Creates a new :obj:`TargetProtocolDescriptor`
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of the structure
        :raises IOException: if there was an IO-related problem creating the structure
        """

    def getAssociatedTypeNames(self) -> int:
        """
        Gets the associated type names
        
        :return: The associated type names
        :rtype: int
        """

    def getName(self) -> str:
        """
        Gets the name of the protocol
        
        :return: The name of the protocol
        :rtype: str
        """

    def getNumRequirements(self) -> int:
        """
        Gets the number of requirements in the protocol
        
        :return: The number of requirements in the protocol
        :rtype: int
        """

    def getNumRequirementsInSignature(self) -> int:
        """
        Gets the number of generic requirements in the requirement signature of the protocol
        
        :return: The number of generic requirements in the requirement signature of the protocol
        :rtype: int
        """

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def numRequirementsInSignature(self) -> jpype.JInt:
        ...

    @property
    def numRequirements(self) -> jpype.JInt:
        ...

    @property
    def associatedTypeNames(self) -> jpype.JInt:
        ...


class TargetContextDescriptor(ghidra.app.util.bin.format.swift.SwiftTypeMetadataStructure):
    """
    Represents a Swift TargetContextDescriptor structure
    
    
    .. seealso::
    
        | `swift/ABI/Metadata.h <https://github.com/swiftlang/swift/blob/main/include/swift/ABI/Metadata.h>`_
    """

    class_: typing.ClassVar[java.lang.Class]
    SIZE: typing.Final = 8
    """
    The size (in bytes) of a :obj:`TargetContextDescriptor` structure
    """


    def __init__(self, reader: ghidra.app.util.bin.BinaryReader):
        """
        Create a new :obj:`TargetContextDescriptor`
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of the structure
        :raises IOException: if there was an IO-related problem creating the structure
        """

    def getFlags(self) -> int:
        """
        Gets the flags
        
        :return: The flags
        :rtype: int
        """

    def getParent(self) -> int:
        """
        Gets the parent's relative offset
        
        :return: The parent's relative offset
        :rtype: int
        """

    @property
    def parent(self) -> jpype.JInt:
        ...

    @property
    def flags(self) -> jpype.JInt:
        ...


class TargetTypeContextDescriptor(TargetContextDescriptor):
    """
    Represents a Swift TargetTypeContextDescriptor structure
    
    
    .. seealso::
    
        | `swift/ABI/Metadata.h <https://github.com/swiftlang/swift/blob/main/include/swift/ABI/Metadata.h>`_
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader):
        """
        Creates a new :obj:`TargetTypeContextDescriptor`
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of the structure
        :raises IOException: if there was an IO-related problem creating the structure
        """

    def getAccessFunctionPtr(self) -> int:
        """
        Gets the pointer to the metadata access function for this type
        
        :return: The pointer to the metadata access function for this type
        :rtype: int
        """

    def getFieldDescriptor(self, fieldDescriptors: collections.abc.Mapping) -> FieldDescriptor:
        """
        Gets this :obj:`TargetTypeContextDescriptor`'s :obj:`FieldDescriptor`
        
        :param collections.abc.Mapping fieldDescriptors: A :obj:`Map` of :obj:`FieldDescriptor`'s keyed by their base
        addresses
        :return: This :obj:`TargetTypeContextDescriptor`'s :obj:`FieldDescriptor`, or null if it
        doesn't have one
        :rtype: FieldDescriptor
        """

    def getFields(self) -> int:
        """
        Gets the pointer to the field descriptor for the type, if any
        
        :return: The pointer to the field descriptor for the type, if any
        :rtype: int
        """

    def getName(self) -> str:
        """
        Gets the name of the type
        
        :return: The name of the type
        :rtype: str
        """

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def fieldDescriptor(self) -> FieldDescriptor:
        ...

    @property
    def fields(self) -> jpype.JInt:
        ...

    @property
    def accessFunctionPtr(self) -> jpype.JInt:
        ...


class AssociatedTypeDescriptor(ghidra.app.util.bin.format.swift.SwiftTypeMetadataStructure):
    """
    Represents a Swift AssociatedTypeDescriptor structure
    
    
    .. seealso::
    
        | `swift/RemoteInspection/Records.h <https://github.com/swiftlang/swift/blob/main/include/swift/RemoteInspection/Records.h>`_
    """

    class_: typing.ClassVar[java.lang.Class]
    SIZE: typing.Final = 16
    """
    The size (in bytes) of an :obj:`AssociatedTypeDescriptor` structure
    """


    def __init__(self, reader: ghidra.app.util.bin.BinaryReader):
        """
        Creates a new :obj:`AssociatedTypeDescriptor`
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of the structure
        :raises IOException: if there was an IO-related problem creating the structure
        """

    def getAssociatedTypeRecordSize(self) -> int:
        """
        Gets the associated type record size
        
        :return: The associated type record size
        :rtype: int
        """

    def getAssociatedTypeRecords(self) -> java.util.List[AssociatedTypeRecord]:
        """
        Gets the :obj:`List` of :obj:`AssociatedTypeRecord`s
        
        :return: The :obj:`List` of :obj:`AssociatedTypeRecord`s
        :rtype: java.util.List[AssociatedTypeRecord]
        """

    def getConformingTypeName(self) -> str:
        """
        Gets the conforming type name
        
        :return: The conforming type name
        :rtype: str
        """

    def getNumAssociatedTypes(self) -> int:
        """
        Gets the number of associated types
        
        :return: The number of associated types
        :rtype: int
        """

    def getProtocolTypeName(self) -> str:
        """
        Gets the protocol type name
        
        :return: The protocol type name
        :rtype: str
        """

    @property
    def associatedTypeRecordSize(self) -> jpype.JInt:
        ...

    @property
    def protocolTypeName(self) -> java.lang.String:
        ...

    @property
    def associatedTypeRecords(self) -> java.util.List[AssociatedTypeRecord]:
        ...

    @property
    def numAssociatedTypes(self) -> jpype.JInt:
        ...

    @property
    def conformingTypeName(self) -> java.lang.String:
        ...


class CaptureTypeRecord(ghidra.app.util.bin.format.swift.SwiftTypeMetadataStructure):
    """
    Represents a Swift CaptureTypeRecord structure
    
    
    .. seealso::
    
        | `swift/RemoteInspection/Records.h <https://github.com/swiftlang/swift/blob/main/include/swift/RemoteInspection/Records.h>`_
    """

    class_: typing.ClassVar[java.lang.Class]
    SIZE: typing.Final = 4
    """
    The size (in bytes) of a :obj:`CaptureTypeRecord` structure
    """


    def __init__(self, reader: ghidra.app.util.bin.BinaryReader):
        """
        Creates a new :obj:`CaptureTypeRecord`
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of the structure
        :raises IOException: if there was an IO-related problem creating the structure
        """

    def getMangledTypeName(self) -> str:
        """
        Gets the mangled type name
        
        :return: The mangled type name
        :rtype: str
        """

    @property
    def mangledTypeName(self) -> java.lang.String:
        ...


class MetadataSourceRecord(ghidra.app.util.bin.format.swift.SwiftTypeMetadataStructure):
    """
    Represents a Swift MetadataSourceRecord structure
    
    
    .. seealso::
    
        | `swift/RemoteInspection/Records.h <https://github.com/swiftlang/swift/blob/main/include/swift/RemoteInspection/Records.h>`_
    """

    class_: typing.ClassVar[java.lang.Class]
    SIZE: typing.Final = 8
    """
    The size (in bytes) of a :obj:`MetadataSourceRecord` structure
    """


    def __init__(self, reader: ghidra.app.util.bin.BinaryReader):
        """
        Creates a new :obj:`MetadataSourceRecord`
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of the structure
        :raises IOException: if there was an IO-related problem creating the structure
        """

    def getMangledMetadataSource(self) -> str:
        """
        Gets the mangled metadata source
        
        :return: The mangled metadata source
        :rtype: str
        """

    def getMangledTypeName(self) -> str:
        """
        Gets the mangled type name
        
        :return: The mangled type name
        :rtype: str
        """

    @property
    def mangledMetadataSource(self) -> java.lang.String:
        ...

    @property
    def mangledTypeName(self) -> java.lang.String:
        ...



__all__ = ["FieldRecord", "EntryPoint", "TargetEnumDescriptor", "MultiPayloadEnumDescriptor", "TargetProtocolConformanceDescriptor", "CaptureDescriptor", "ContextDescriptorKind", "TargetStructDescriptor", "BuiltinTypeDescriptor", "TargetClassDescriptor", "FieldDescriptor", "AssociatedTypeRecord", "TargetProtocolDescriptor", "TargetContextDescriptor", "TargetTypeContextDescriptor", "AssociatedTypeDescriptor", "CaptureTypeRecord", "MetadataSourceRecord"]
