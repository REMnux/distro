from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.util.bin
import ghidra.app.util.bin.format.swift
import ghidra.program.model.data
import java.lang # type: ignore
import java.util # type: ignore


class TargetGenericWitnessTable(ghidra.app.util.bin.format.swift.SwiftTypeMetadataStructure):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader) -> None:
        """
        Creates a new :obj:`TargetGenericWitnessTable`
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of the structure
        :raises IOException: if there was an IO-related problem creating the structure
        """

    def getInstantiator(self) -> int:
        """
        :return: the instantiation function, which is called after the template is copied
        :rtype: int
        """

    def getPrivateData(self) -> int:
        """
        :return: the private data for the instantiator
        :rtype: int
        
         
        
        Might be null with building with ``-disable-preallocated-instantiation-caches``.
        """

    def getWitnessTablePrivateSizeInWordsAndRequiresInstantiation(self) -> int:
        """
        :return: the amount of private storage to allocate before the address point, in words
        :rtype: int
        
         
        
        This memory is zeroed out in the instantiated witness table template. The low bit is used to
        indicate whether this witness table is known to require instantiation.
        """

    def getWitnessTableSizeInWords(self) -> int:
        """
        :return: the size of the witness table in words
        :rtype: int
        
         
        
        The amount is copied from the witness table template into the instantiated witness table.
        """

    @property
    def privateData(self) -> jpype.JInt:
        ...

    @property
    def witnessTableSizeInWords(self) -> jpype.JInt:
        ...

    @property
    def instantiator(self) -> jpype.JInt:
        ...

    @property
    def witnessTablePrivateSizeInWordsAndRequiresInstantiation(self) -> jpype.JInt:
        ...


class TargetSingletonMetadataInitialization(ghidra.app.util.bin.format.swift.SwiftTypeMetadataStructure):
    """
    Represents a Swift ``TargetSingletonMetadataInitialization`` structure
    
    
    .. seealso::
    
        | `swift/ABI/Metadata.h <https://github.com/swiftlang/swift/blob/main/include/swift/ABI/Metadata.h>`_
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, flags: ContextDescriptorFlags) -> None:
        """
        Creates a new :obj:`TargetSingletonMetadataInitialization`
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of the structure
        :param ContextDescriptorFlags flags: The :obj:`ContextDescriptorFlags`
        :raises IOException: if there was an IO-related problem creating the structure
        """

    def getCompletionFunction(self) -> int:
        """
        :return: the completion function (the pattern will always be null, even for a resilient 
        class)
        :rtype: int
        """

    def getIncompleteMetadata(self) -> int:
        """
        :return: the incomplete metadata for structs, enums, and classes if there is no resilient
        ancestry; otherwise, 0
        :rtype: int
        """

    def getInitializationCache(self) -> int:
        """
        :return: the initialization cache
        :rtype: int
        """

    def getResilientPattern(self) -> int:
        """
        :return: a pattern used to allocation and initialize metadata for this class if there is a
        resilient superclass; otherwise, 0
        :rtype: int
        """

    @property
    def completionFunction(self) -> jpype.JInt:
        ...

    @property
    def resilientPattern(self) -> jpype.JInt:
        ...

    @property
    def initializationCache(self) -> jpype.JInt:
        ...

    @property
    def incompleteMetadata(self) -> jpype.JInt:
        ...


class TargetGenericRequirementsDescriptor(ghidra.app.util.bin.format.swift.SwiftTypeMetadataStructure):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader) -> None:
        """
        Creates a new :obj:`TargetGenericRequirementsDescriptor`
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of the structure
        :raises IOException: if there was an IO-related problem creating the structure
        """

    def getFlags(self) -> GenericRequirementFlags:
        """
        :return: the flags
        :rtype: GenericRequirementFlags
        """

    def getGenericParamIndex(self) -> int:
        """
        :return: the index of the generic parameter whose set of invertible protocols has disabled
        checks
        :rtype: int
        
         
        
        Only valid if the requirement has :obj:`GenericRequirementKind.IntertedProtocol` kind
        """

    def getLayout(self) -> GenericRequirementLayoutKind:
        """
        :return: the layout if the requirement has Layout kind; otherwise, ``null``
        :rtype: GenericRequirementLayoutKind
        """

    def getParam(self) -> int:
        """
        :return: the type that's constrained, described as a mangled name
        :rtype: int
        """

    def getProtocols(self) -> int:
        """
        :return: the set of invertible protocols whose check is disabled
        :rtype: int
        
         
        
        Only valid if the requirement has :obj:`GenericRequirementKind.IntertedProtocol` kind
        """

    def getThing(self) -> int:
        """
        :return: the thing (same-type, class, protocol, conformance) the param is constrained to
        :rtype: int
        """

    @property
    def layout(self) -> GenericRequirementLayoutKind:
        ...

    @property
    def param(self) -> jpype.JInt:
        ...

    @property
    def flags(self) -> GenericRequirementFlags:
        ...

    @property
    def protocols(self) -> jpype.JInt:
        ...

    @property
    def genericParamIndex(self) -> jpype.JInt:
        ...

    @property
    def thing(self) -> jpype.JInt:
        ...


class TargetMethodOverrideDescriptor(ghidra.app.util.bin.format.swift.SwiftTypeMetadataStructure):
    """
    Represents a Swift ``TargetMethodOverrideDescriptor`` structure
    
    
    .. seealso::
    
        | `swift/ABI/Metadata.h <https://github.com/swiftlang/swift/blob/main/include/swift/ABI/Metadata.h>`_
    """

    class_: typing.ClassVar[java.lang.Class]
    SIZE: typing.Final = 8
    """
    The size (in bytes) of a :obj:`TargetMethodOverrideDescriptor` structure
    """


    def __init__(self, reader: ghidra.app.util.bin.BinaryReader) -> None:
        """
        Creates a new :obj:`TargetMethodOverrideDescriptor`
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of the structure
        :raises IOException: if there was an IO-related problem creating the structure
        """

    def getClassPtr(self) -> int:
        """
        :return: the class containing the base method
        :rtype: int
        """

    def getImpl(self) -> int:
        """
        :return: the implementation of the override
        :rtype: int
        """

    def getMethodPtr(self) -> int:
        """
        :return: the base method
        :rtype: int
        """

    @property
    def impl(self) -> jpype.JInt:
        ...

    @property
    def methodPtr(self) -> jpype.JInt:
        ...

    @property
    def classPtr(self) -> jpype.JInt:
        ...


class FieldRecord(ghidra.app.util.bin.format.swift.SwiftTypeMetadataStructure):
    """
    Represents a Swift ``FieldRecord`` structure
    
    
    .. seealso::
    
        | `swift/RemoteInspection/Records.h <https://github.com/swiftlang/swift/blob/main/include/swift/RemoteInspection/Records.h>`_
    """

    class_: typing.ClassVar[java.lang.Class]
    SIZE: typing.Final = 12
    """
    The size (in bytes) of a :obj:`FieldRecord` structure
    """


    def __init__(self, reader: ghidra.app.util.bin.BinaryReader) -> None:
        """
        Creates a new :obj:`FieldRecord`
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of the structure
        :raises IOException: if there was an IO-related problem creating the structure
        """

    def getFieldName(self) -> str:
        """
        :return: the field name
        :rtype: str
        """

    def getFlags(self) -> int:
        """
        :return: the flags
        :rtype: int
        """

    def getMangledTypeName(self) -> str:
        """
        :return: the mangled type name
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


    def __init__(self, reader: ghidra.app.util.bin.BinaryReader) -> None:
        """
        Creates a new :obj:`EntryPoint`
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of the structure
        :raises IOException: if there was an IO-related problem creating the structure
        """

    def getEntryPoint(self) -> int:
        """
        :return: the entry point
        :rtype: int
        """

    @property
    def entryPoint(self) -> jpype.JInt:
        ...


class TargetEnumDescriptor(TargetTypeContextDescriptor):
    """
    Represents a Swift ``TargetEnumDescriptor`` structure
    
    
    .. seealso::
    
        | `swift/ABI/Metadata.h <https://github.com/swiftlang/swift/blob/main/include/swift/ABI/Metadata.h>`_
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader) -> None:
        """
        Creates a new :obj:`TargetEnumDescriptor`
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of the structure
        :raises IOException: if there was an IO-related problem creating the structure
        """

    def getGenericHeader(self) -> TargetTypeGenericContextDescriptorHeader:
        """
        :return: the :obj:`TargetTypeGenericContextDescriptorHeader`, or ``null`` if it doesn't 
        exist
        :rtype: TargetTypeGenericContextDescriptorHeader
        """

    def getInvertibleProtocolSet(self) -> InvertibleProtocolSet:
        """
        :return: the :obj:`InvertibleProtocolSet`, or ``null`` if it doens't exist
        :rtype: InvertibleProtocolSet
        """

    def getNumEmptyCases(self) -> int:
        """
        :return: the number of empty cases in the enum
        :rtype: int
        """

    def getNumPayloadCasesAndPayloadSizeOffset(self) -> int:
        """
        Gets the number of non-empty cases in the enum are in the low 24 bits; the offset of the 
        payload size in the metadata record in words, if any, is stored in the high 8 bits;
        
        :return: The number of non-empty cases in the enum and the offset of the payload size
        :rtype: int
        """

    def getTargetForeignMetadataInitialization(self) -> TargetForeignMetadataInitialization:
        """
        :return: the :obj:`TargetForeignMetadataInitialization`, or ``null`` if it doesn't
        exist
        :rtype: TargetForeignMetadataInitialization
        """

    def getTargetSingletonMetadataInitialization(self) -> TargetSingletonMetadataInitialization:
        """
        :return: the :obj:`TargetSingletonMetadataInitialization`, or ``null`` if it doesn't
        exist
        :rtype: TargetSingletonMetadataInitialization
        """

    @property
    def numPayloadCasesAndPayloadSizeOffset(self) -> jpype.JInt:
        ...

    @property
    def invertibleProtocolSet(self) -> InvertibleProtocolSet:
        ...

    @property
    def targetSingletonMetadataInitialization(self) -> TargetSingletonMetadataInitialization:
        ...

    @property
    def numEmptyCases(self) -> jpype.JInt:
        ...

    @property
    def genericHeader(self) -> TargetTypeGenericContextDescriptorHeader:
        ...

    @property
    def targetForeignMetadataInitialization(self) -> TargetForeignMetadataInitialization:
        ...


class TargetObjCResilientClassStubInfo(ghidra.app.util.bin.format.swift.SwiftTypeMetadataStructure):
    """
    Represents a Swift ``TargetObjCResilientClassStubInfo`` structure
    
    
    .. seealso::
    
        | `swift/ABI/Metadata.h <https://github.com/swiftlang/swift/blob/main/include/swift/ABI/Metadata.h>`_
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader) -> None:
        """
        Create a new :obj:`TargetObjCResilientClassStubInfo`
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of the structure
        :raises IOException: if there was an IO-related problem creating the structure
        """

    def getStub(self) -> int:
        """
        :return: a relative pointer to an Objective-C resilient class stub
        :rtype: int
        """

    @property
    def stub(self) -> jpype.JInt:
        ...


class ExtraClassDescriptorFlags(ghidra.app.util.bin.format.swift.SwiftTypeMetadataStructure):
    """
    Represents a Swift ``ExtraClassDescriptorFlags`` enum
    
    
    .. seealso::
    
        | `swift/ABI/MetadataValues.h <https://github.com/swiftlang/swift/blob/main/include/swift/ABI/MetadataValues.h>`_
    """

    class_: typing.ClassVar[java.lang.Class]
    SIZE: typing.Final = 4
    """
    The size (in bytes) of a :obj:`ExtraClassDescriptorFlags` structure
    """


    def __init__(self, reader: ghidra.app.util.bin.BinaryReader) -> None:
        """
        Creates a new :obj:`ExtraClassDescriptorFlags`
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of the structure
        :raises IOException: if there was an IO-related problem creating the structure
        """

    def getFlags(self) -> int:
        """
        :return: the flags
        :rtype: int
        """

    def hasObjcResilientClassStub(self) -> bool:
        """
        :return: whether or not the context descriptor includes a pointer to an Objective-C resilient class stub structure
        :rtype: bool
        
         
        
        Only meaningful for class descriptors when Objective-C interop is enabled.
        """

    @property
    def flags(self) -> jpype.JInt:
        ...


class GenericRequirementKind(java.lang.Enum[GenericRequirementKind], ghidra.app.util.bin.StructConverter):
    """
    Swift ``GenericRequirementKind`` values
    
    
    .. seealso::
    
        | `swift/ABI/MetadataValues.h <https://github.com/swiftlang/swift/blob/main/include/swift/ABI/MetadataValues.h>`_
    """

    class_: typing.ClassVar[java.lang.Class]
    Protocol: typing.Final[GenericRequirementKind]
    SameType: typing.Final[GenericRequirementKind]
    BaseClass: typing.Final[GenericRequirementKind]
    SameConformance: typing.Final[GenericRequirementKind]
    SameShape: typing.Final[GenericRequirementKind]
    IntertedProtocol: typing.Final[GenericRequirementKind]
    Layout: typing.Final[GenericRequirementKind]

    def getValue(self) -> int:
        """
        :return: the kind value
        :rtype: int
        """

    @staticmethod
    @typing.overload
    def valueOf(name: typing.Union[java.lang.String, str]) -> GenericRequirementKind:
        ...

    @staticmethod
    @typing.overload
    def valueOf(value: typing.Union[jpype.JInt, int]) -> GenericRequirementKind:
        """
        :return: the :obj:`GenericRequirementKind` with the given kind value, or ``null`` if it 
        does not exist
        :rtype: GenericRequirementKind
        
        
        :param jpype.JInt or int value: The kind value to get the value of
        """

    @staticmethod
    def values() -> jpype.JArray[GenericRequirementKind]:
        ...

    @property
    def value(self) -> jpype.JInt:
        ...


class GenericRequirementLayoutKind(java.lang.Enum[GenericRequirementLayoutKind], ghidra.app.util.bin.StructConverter):
    """
    Swift ``GenericRequirementLayoutKind`` values
    
    
    .. seealso::
    
        | `swift/ABI/MetadataValues.h <https://github.com/swiftlang/swift/blob/main/include/swift/ABI/MetadataValues.h>`_
    """

    class_: typing.ClassVar[java.lang.Class]
    Class: typing.Final[GenericRequirementLayoutKind]

    def getValue(self) -> int:
        """
        :return: the kind value
        :rtype: int
        """

    @staticmethod
    @typing.overload
    def valueOf(name: typing.Union[java.lang.String, str]) -> GenericRequirementLayoutKind:
        ...

    @staticmethod
    @typing.overload
    def valueOf(value: typing.Union[jpype.JInt, int]) -> GenericRequirementLayoutKind:
        """
        :return: the :obj:`GenericRequirementLayoutKind` with the given kind value, or ``null`` 
        if it does not exist
        :rtype: GenericRequirementLayoutKind
        
        
        :param jpype.JInt or int value: The kind value to get the value of
        """

    @staticmethod
    def values() -> jpype.JArray[GenericRequirementLayoutKind]:
        ...

    @property
    def value(self) -> jpype.JInt:
        ...


class MultiPayloadEnumDescriptor(ghidra.app.util.bin.format.swift.SwiftTypeMetadataStructure):
    """
    Represents a Swift ``MultiPayloadEnumDescriptor`` structure
    
    
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

    PEEK_SIZE: typing.Final = 8
    """
    How many bytes it requires to peek at size of the ``contents`` array
    """


    def __init__(self, reader: ghidra.app.util.bin.BinaryReader) -> None:
        """
        Creates a new :obj:`MultiPayloadEnumDescriptor`
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of the structure
        :raises IOException: if there was an IO-related problem creating the structure
        """

    def getContents(self) -> jpype.JArray[jpype.JInt]:
        """
        :return: the contents
        :rtype: jpype.JArray[jpype.JInt]
        """

    def getContentsSize(self) -> int:
        """
        :return: the size of the contents in bytes
        :rtype: int
        """

    def getTypeName(self) -> str:
        """
        :return: the type name
        :rtype: str
        """

    @staticmethod
    def peekContentsSize(reader: ghidra.app.util.bin.BinaryReader) -> int:
        """
        :return: the size of the contents in bytes, without reading the contents
        :rtype: int
        
         
        
        This method will leave the :obj:`BinaryReader`'s position unaffected.
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of the structure
        :raises IOException: if there was an IO-related problem creating the structure
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
    Represents a Swift ``TargetProtocolConformanceDescriptor`` structure
    
    
    .. seealso::
    
        | `swift/ABI/Metadata.h <https://github.com/swiftlang/swift/blob/main/include/swift/ABI/Metadata.h>`_
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader) -> None:
        """
        Creates a new :obj:`TargetProtocolConformanceDescriptor`
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of the structure
        :raises IOException: if there was an IO-related problem creating the structure
        """

    def getConformanceFlags(self) -> ConformanceFlags:
        """
        :return: various flags, including the kind of conformance
        :rtype: ConformanceFlags
        """

    def getGenericWitnessTable(self) -> TargetGenericWitnessTable:
        """
        :return: the :obj:`TargetGenericWitnessTable`, or ``null`` if it doesn't exist
        :rtype: TargetGenericWitnessTable
        """

    def getProtocol(self) -> int:
        """
        :return: the protocol being conformed to
        :rtype: int
        """

    def getResilientWitnessHeader(self) -> TargetResilientWitnessHeader:
        """
        :return: the :obj:`TargetResilientWitnessHeader`, or ``null`` if it doesn't exist
        :rtype: TargetResilientWitnessHeader
        """

    def getResilientWitnesses(self) -> java.util.List[TargetResilientWitness]:
        """
        :return: the :obj:`List` of resilient witnesses
        :rtype: java.util.List[TargetResilientWitness]
        """

    def getRetroactiveContext(self) -> TargetRelativeContextPointer:
        """
        :return: the :obj:`retroactive context <TargetRelativeContextPointer>`, or ``null`` if it 
        doesn't exist
        :rtype: TargetRelativeContextPointer
        """

    def getTypeRef(self) -> int:
        """
        :return: some description of the type that conforms to the protocol
        :rtype: int
        """

    def getWitnessTablePattern(self) -> int:
        """
        :return: the witness table pattern, which may also serve as the witness table
        :rtype: int
        """

    @property
    def protocol(self) -> jpype.JInt:
        ...

    @property
    def retroactiveContext(self) -> TargetRelativeContextPointer:
        ...

    @property
    def resilientWitnessHeader(self) -> TargetResilientWitnessHeader:
        ...

    @property
    def witnessTablePattern(self) -> jpype.JInt:
        ...

    @property
    def resilientWitnesses(self) -> java.util.List[TargetResilientWitness]:
        ...

    @property
    def genericWitnessTable(self) -> TargetGenericWitnessTable:
        ...

    @property
    def conformanceFlags(self) -> ConformanceFlags:
        ...

    @property
    def typeRef(self) -> jpype.JInt:
        ...


class TargetGenericContextDescriptorHeader(ghidra.app.util.bin.format.swift.SwiftTypeMetadataStructure):
    """
    Represents a Swift ``TargetGenericContextDescriptorHeader`` structure
    
    
    .. seealso::
    
        | `swift/ABI/GenericContext.h <https://github.com/swiftlang/swift/blob/main/include/swift/ABI/GenericContext.h>`_
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader) -> None:
        """
        Creates a new :obj:`TargetGenericContextDescriptorHeader`
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of the structure
        :raises IOException: if there was an IO-related problem creating the structure
        """

    def getFlags(self) -> GenericContextDescriptorFlags:
        """
        :return: the flags
        :rtype: GenericContextDescriptorFlags
        """

    def getNumKeyArguments(self) -> int:
        """
        :return: the size of the "key" area of the argument layout, in words
        :rtype: int
        
         
        
        Key arguments include shape classes, generic parameters, and conformance requirements which
        are part of the identity of the context.
        """

    def getNumParams(self) -> int:
        """
        :return: the number of (source-written) generic parameters, and thus the number of 
        GenericParamDescriptors associated with this context
        :rtype: int
        """

    def getNumRequirements(self) -> int:
        """
        :return: the number of GenericRequirementDescriptors in this generic signature
        :rtype: int
        """

    def getParams(self) -> java.util.List[GenericParamDescriptor]:
        """
        :return: the :obj:`List` of generic parameter descriptors
        :rtype: java.util.List[GenericParamDescriptor]
        """

    def getRequirements(self) -> java.util.List[TargetGenericRequirementsDescriptor]:
        """
        :return: the :obj:`List` of generic requirements descriptors
        :rtype: java.util.List[TargetGenericRequirementsDescriptor]
        """

    @property
    def requirements(self) -> java.util.List[TargetGenericRequirementsDescriptor]:
        ...

    @property
    def numParams(self) -> jpype.JInt:
        ...

    @property
    def numKeyArguments(self) -> jpype.JInt:
        ...

    @property
    def flags(self) -> GenericContextDescriptorFlags:
        ...

    @property
    def numRequirements(self) -> jpype.JInt:
        ...

    @property
    def params(self) -> java.util.List[GenericParamDescriptor]:
        ...


class CaptureDescriptor(ghidra.app.util.bin.format.swift.SwiftTypeMetadataStructure):
    """
    Represents a Swift ``CaptureDescriptor`` structure
    
    
    .. seealso::
    
        | `swift/RemoteInspection/Records.h <https://github.com/swiftlang/swift/blob/main/include/swift/RemoteInspection/Records.h>`_
    """

    class_: typing.ClassVar[java.lang.Class]
    SIZE: typing.Final = 12
    """
    The size (in bytes) of a :obj:`CaptureDescriptor` structure
    """


    def __init__(self, reader: ghidra.app.util.bin.BinaryReader) -> None:
        """
        Creates a new :obj:`CaptureDescriptor`
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of the structure
        :raises IOException: if there was an IO-related problem creating the structure
        """

    def getCaptureTypeRecords(self) -> java.util.List[CaptureTypeRecord]:
        """
        :return: the :obj:`List` of :obj:`CaptureTypeRecord`s
        :rtype: java.util.List[CaptureTypeRecord]
        """

    def getMetadataSourceRecords(self) -> java.util.List[MetadataSourceRecord]:
        """
        :return: the :obj:`List` of :obj:`MetadataSourceRecord`s
        :rtype: java.util.List[MetadataSourceRecord]
        """

    def getNumBindings(self) -> int:
        """
        :return: the number of bindings
        :rtype: int
        """

    def getNumCaptureTypes(self) -> int:
        """
        :return: the number of capture types
        :rtype: int
        """

    def getNumMetadataSources(self) -> int:
        """
        :return: the number of metadata sources
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


class ContextDescriptorKind(java.lang.Enum[ContextDescriptorKind], ghidra.app.util.bin.StructConverter):
    """
    Swift ``ContextDescriptorKind`` values
    
    
    .. seealso::
    
        | `swift/ABI/MetadataValues.h <https://github.com/swiftlang/swift/blob/main/include/swift/ABI/MetadataValues.h>`_
    """

    class_: typing.ClassVar[java.lang.Class]
    Module: typing.Final[ContextDescriptorKind]
    """
    This context descriptor represents a module
    """

    Extension: typing.Final[ContextDescriptorKind]
    """
    This context descriptor represents an extension
    """

    Anonymous: typing.Final[ContextDescriptorKind]
    """
    This context descriptor represents an anonymous possibly-generic context such as a function
    body
    """

    Protocol: typing.Final[ContextDescriptorKind]
    """
    This context descriptor represents a protocol context
    """

    OpaqueType: typing.Final[ContextDescriptorKind]
    """
    This context descriptor represents an opaque type alias
    """

    Class: typing.Final[ContextDescriptorKind]
    """
    This context descriptor represents a class
    """

    Struct: typing.Final[ContextDescriptorKind]
    """
    This context descriptor represents a struct
    """

    Enum: typing.Final[ContextDescriptorKind]
    """
    This context descriptor represents an enum
    """


    def getValue(self) -> int:
        """
        :return: the kind value
        :rtype: int
        """

    @staticmethod
    @typing.overload
    def valueOf(name: typing.Union[java.lang.String, str]) -> ContextDescriptorKind:
        ...

    @staticmethod
    @typing.overload
    def valueOf(value: typing.Union[jpype.JInt, int]) -> ContextDescriptorKind:
        """
        :return: the :obj:`ContextDescriptorKind` with the given kind value, or ``null`` if it 
        does not exist
        :rtype: ContextDescriptorKind
        
        
        :param jpype.JInt or int value: The kind value to get the value of
        """

    @staticmethod
    def values() -> jpype.JArray[ContextDescriptorKind]:
        ...

    @property
    def value(self) -> jpype.JInt:
        ...


class TargetMethodDescriptor(ghidra.app.util.bin.format.swift.SwiftTypeMetadataStructure):
    """
    Represents a Swift ``TargetMethodDescriptor`` structure
    
    
    .. seealso::
    
        | `swift/ABI/Metadata.h <https://github.com/swiftlang/swift/blob/main/include/swift/ABI/Metadata.h>`_
    """

    class_: typing.ClassVar[java.lang.Class]
    SIZE: typing.Final = 8
    """
    The size (in bytes) of a :obj:`TargetMethodDescriptor` structure
    """


    def __init__(self, reader: ghidra.app.util.bin.BinaryReader) -> None:
        """
        Creates a new :obj:`TargetMethodDescriptor`
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of the structure
        :raises IOException: if there was an IO-related problem creating the structure
        """

    def getFlags(self) -> MethodDescriptorFlags:
        """
        :return: the flags
        :rtype: MethodDescriptorFlags
        """

    def getImpl(self) -> int:
        """
        :return: the method implementation's relative offset
        :rtype: int
        """

    @property
    def impl(self) -> jpype.JInt:
        ...

    @property
    def flags(self) -> MethodDescriptorFlags:
        ...


class MethodDescriptorFlags(ghidra.app.util.bin.format.swift.SwiftTypeMetadataStructure):
    """
    Represents a Swift ``MethodDescriptorFlags`` structure
    
    
    .. seealso::
    
        | `swift/ABI/MetadataValues.h <https://github.com/swiftlang/swift/blob/main/include/swift/ABI/MetadataValues.h>`_
    """

    class_: typing.ClassVar[java.lang.Class]
    SIZE: typing.Final = 4
    """
    The size (in bytes) of a :obj:`MethodDescriptorFlags` structure
    """


    def __init__(self, reader: ghidra.app.util.bin.BinaryReader) -> None:
        """
        Create a new :obj:`MethodDescriptorFlags`
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of the structure
        :raises IOException: if there was an IO-related problem creating the structure
        """

    def getExtraDescriminator(self) -> int:
        """
        :return: the extra descriminator
        :rtype: int
        """

    def getFlags(self) -> int:
        """
        :return: the flags
        :rtype: int
        """

    def getKind(self) -> MethodDescriptorKind:
        """
        :return: the :obj:`MethodDescriptorKind`
        :rtype: MethodDescriptorKind
        """

    def isAnsyc(self) -> bool:
        """
        :return: whether or not the method is async
        :rtype: bool
        """

    def isDynamic(self) -> bool:
        """
        :return: whether or not the method is dynamic
        :rtype: bool
        """

    def isInstance(self) -> bool:
        """
        :return: whether or not the method is an instance method
        :rtype: bool
        """

    @property
    def extraDescriminator(self) -> jpype.JInt:
        ...

    @property
    def instance(self) -> jpype.JBoolean:
        ...

    @property
    def kind(self) -> MethodDescriptorKind:
        ...

    @property
    def flags(self) -> jpype.JInt:
        ...

    @property
    def dynamic(self) -> jpype.JBoolean:
        ...

    @property
    def ansyc(self) -> jpype.JBoolean:
        ...


class ProtocolRequirementKind(java.lang.Enum[ProtocolRequirementKind], ghidra.app.util.bin.StructConverter):
    """
    Swift ``ProtocolRequirementFlags.Kind`` values
    
    
    .. seealso::
    
        | `swift/ABI/MetadataValues.h <https://github.com/swiftlang/swift/blob/main/include/swift/ABI/MetadataValues.h>`_
    """

    class_: typing.ClassVar[java.lang.Class]
    BaseProtocol: typing.Final[ProtocolRequirementKind]
    Method: typing.Final[ProtocolRequirementKind]
    Init: typing.Final[ProtocolRequirementKind]
    Getter: typing.Final[ProtocolRequirementKind]
    Setter: typing.Final[ProtocolRequirementKind]
    ReadCoroutine: typing.Final[ProtocolRequirementKind]
    ModifyCoroutine: typing.Final[ProtocolRequirementKind]
    AssociatedTypeAccessFunction: typing.Final[ProtocolRequirementKind]
    AssociatedConformanceAccessFunction: typing.Final[ProtocolRequirementKind]

    def getValue(self) -> int:
        """
        :return: the kind value
        :rtype: int
        """

    @staticmethod
    @typing.overload
    def valueOf(name: typing.Union[java.lang.String, str]) -> ProtocolRequirementKind:
        ...

    @staticmethod
    @typing.overload
    def valueOf(value: typing.Union[jpype.JInt, int]) -> ProtocolRequirementKind:
        """
        :return: the :obj:`ProtocolRequirementKind` with the given kind value, or ``null`` if it 
        does not exist
        :rtype: ProtocolRequirementKind
        
        
        :param jpype.JInt or int value: The kind value to get the value of
        """

    @staticmethod
    def values() -> jpype.JArray[ProtocolRequirementKind]:
        ...

    @property
    def value(self) -> jpype.JInt:
        ...


class TargetRelativeProtocolRequirementPointer(ghidra.app.util.bin.format.swift.SwiftTypeMetadataStructure):
    """
    Represents a Swift ``TargetRelativeContextPointer`` structure
    
    
    .. seealso::
    
        | `swift/ABI/Metadata.h <https://github.com/swiftlang/swift/blob/main/include/swift/ABI/Metadata.h>`_
    """

    class_: typing.ClassVar[java.lang.Class]
    dataType: typing.Final[ghidra.program.model.data.TypeDef]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader) -> None:
        """
        Creates a new :obj:`TargetRelativeProtocolRequirementPointer`
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of the structure
        :raises IOException: if there was an IO-related problem creating the structure
        """

    def getValue(self) -> int:
        """
        :return: the pointer value
        :rtype: int
        """

    @property
    def value(self) -> jpype.JLong:
        ...


class TargetStructDescriptor(TargetTypeContextDescriptor):
    """
    Represents a Swift ``TargetStructDescriptor`` structure
    
    
    .. seealso::
    
        | `swift/ABI/Metadata.h <https://github.com/swiftlang/swift/blob/main/include/swift/ABI/Metadata.h>`_
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader) -> None:
        """
        Creates a new :obj:`TargetStructDescriptor`
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of the structure
        :raises IOException: if there was an IO-related problem creating the structure
        """

    def getFieldOffsetVectorOffset(self) -> int:
        """
        :return: the offset of the field offset vector for this struct's stored properties in its 
        metadata, if any. 0 means there is no field offset vector
        :rtype: int
        """

    def getGenericHeader(self) -> TargetTypeGenericContextDescriptorHeader:
        """
        :return: the :obj:`TargetTypeGenericContextDescriptorHeader`, or ``null`` if it doesn't 
        exist
        :rtype: TargetTypeGenericContextDescriptorHeader
        """

    def getInvertibleProtocolSet(self) -> InvertibleProtocolSet:
        """
        :return: the :obj:`InvertibleProtocolSet`, or ``null`` if it doens't exist
        :rtype: InvertibleProtocolSet
        """

    def getNumFields(self) -> int:
        """
        :return: the number of stored properties in the struct (if there is a field offset vector, 
        this is its length
        :rtype: int
        """

    def getTargetForeignMetadataInitialization(self) -> TargetForeignMetadataInitialization:
        """
        :return: the :obj:`TargetForeignMetadataInitialization`, or ``null`` if it doesn't
        exist
        :rtype: TargetForeignMetadataInitialization
        """

    def getTargetSingletonMetadataInitialization(self) -> TargetSingletonMetadataInitialization:
        """
        :return: the :obj:`TargetSingletonMetadataInitialization`, or ``null`` if it doesn't
        exist
        :rtype: TargetSingletonMetadataInitialization
        """

    @property
    def fieldOffsetVectorOffset(self) -> jpype.JInt:
        ...

    @property
    def invertibleProtocolSet(self) -> InvertibleProtocolSet:
        ...

    @property
    def targetSingletonMetadataInitialization(self) -> TargetSingletonMetadataInitialization:
        ...

    @property
    def genericHeader(self) -> TargetTypeGenericContextDescriptorHeader:
        ...

    @property
    def numFields(self) -> jpype.JInt:
        ...

    @property
    def targetForeignMetadataInitialization(self) -> TargetForeignMetadataInitialization:
        ...


class TargetResilientWitnessHeader(ghidra.app.util.bin.format.swift.SwiftTypeMetadataStructure):
    """
    Represents a Swift ``TargetResilientWitnessHeader`` structure
    
    
    .. seealso::
    
        | `swift/ABI/Metadata.h <https://github.com/swiftlang/swift/blob/main/include/swift/ABI/Metadata.h>`_
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader) -> None:
        """
        Creates a new :obj:`TargetResilientWitnessHeader`
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of the structure
        :raises IOException: if there was an IO-related problem creating the structure
        """

    def getNumWitnesses(self) -> int:
        """
        :return: the number of witnesses
        :rtype: int
        """

    @property
    def numWitnesses(self) -> jpype.JLong:
        ...


class TargetResilientSuperclass(ghidra.app.util.bin.format.swift.SwiftTypeMetadataStructure):
    """
    Represents a Swift ``TargetResilientSuperclass`` structure
    
    
    .. seealso::
    
        | `swift/ABI/Metadata.h <https://github.com/swiftlang/swift/blob/main/include/swift/ABI/Metadata.h>`_
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader) -> None:
        """
        Create a new :obj:`TargetResilientSuperclass`
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of the structure
        :raises IOException: if there was an IO-related problem creating the structure
        """

    def getSuperclass(self) -> int:
        """
        :return: the superclass of this class, or 0 if there isn't one
        :rtype: int
        """

    @property
    def superclass(self) -> jpype.JInt:
        ...


class BuiltinTypeDescriptor(ghidra.app.util.bin.format.swift.SwiftTypeMetadataStructure):
    """
    Represents a Swift ``BuiltinTypeDescriptor`` structure
    
    
    .. seealso::
    
        | `swift/RemoteInspection/Records.h <https://github.com/swiftlang/swift/blob/main/include/swift/RemoteInspection/Records.h>`_
    """

    class_: typing.ClassVar[java.lang.Class]
    SIZE: typing.Final = 20
    """
    The size (in bytes) of a :obj:`BuiltinTypeDescriptor` structure
    """


    def __init__(self, reader: ghidra.app.util.bin.BinaryReader) -> None:
        """
        Creates a new :obj:`BuiltinTypeDescriptor`
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of the structure
        :raises IOException: if there was an IO-related problem creating the structure
        """

    def getAlignmentAndFlags(self) -> int:
        """
        :return: the alignment and flags
        :rtype: int
        """

    def getNumExtraInhabitants(self) -> int:
        """
        :return: the number of extra inhabitants
        :rtype: int
        """

    def getSize(self) -> int:
        """
        :return: the size
        :rtype: int
        """

    def getStride(self) -> int:
        """
        :return: the stride
        :rtype: int
        """

    def getTypeName(self) -> str:
        """
        :return: the type name
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


class TargetForeignMetadataInitialization(ghidra.app.util.bin.format.swift.SwiftTypeMetadataStructure):
    """
    Represents a Swift ``TargetForeignMetadataInitialization`` structure
    
    
    .. seealso::
    
        | `swift/ABI/Metadata.h <https://github.com/swiftlang/swift/blob/main/include/swift/ABI/Metadata.h>`_
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader) -> None:
        """
        Creates a new :obj:`TargetForeignMetadataInitialization`
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of the structure
        :raises IOException: if there was an IO-related problem creating the structure
        """

    def getCompletionFunction(self) -> int:
        """
        :return: the completion function (the pattern will always be null)
        :rtype: int
        """

    @property
    def completionFunction(self) -> jpype.JInt:
        ...


class InvertibleProtocolSet(ghidra.app.util.bin.format.swift.SwiftTypeMetadataStructure):
    """
    Represents a Swift ``InvertibleProtocolSet`` structure
    
    
    .. seealso::
    
        | `swift/ABI/InvertibleProtocols.h <https://github.com/swiftlang/swift/blob/main/include/swift/ABI/InvertibleProtocols.h>`_
    """

    class_: typing.ClassVar[java.lang.Class]
    SIZE: typing.Final = 2
    """
    The size (in bytes) of a :obj:`InvertibleProtocolSet` structure
    """


    def __init__(self, reader: ghidra.app.util.bin.BinaryReader) -> None:
        """
        Create a new :obj:`InvertibleProtocolSet`
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of the structure
        :raises IOException: if there was an IO-related problem creating the structure
        """

    def getRawBits(self) -> int:
        """
        :return: the raw bits
        :rtype: int
        """

    @property
    def rawBits(self) -> jpype.JShort:
        ...


class TypeReferenceKind(java.lang.Enum[TypeReferenceKind], ghidra.app.util.bin.StructConverter):
    """
    Swift ``TypeReferenceKind`` values
    
    
    .. seealso::
    
        | `swift/ABI/MetadataValues.h <https://github.com/swiftlang/swift/blob/main/include/swift/ABI/MetadataValues.h>`_
    """

    class_: typing.ClassVar[java.lang.Class]
    DirectTypeDescriptor: typing.Final[TypeReferenceKind]
    IndirectTypeDescriptor: typing.Final[TypeReferenceKind]
    DirectObjCClassName: typing.Final[TypeReferenceKind]
    IndirectObjCClass: typing.Final[TypeReferenceKind]

    def getValue(self) -> int:
        """
        :return: the kind value
        :rtype: int
        """

    @staticmethod
    @typing.overload
    def valueOf(name: typing.Union[java.lang.String, str]) -> TypeReferenceKind:
        ...

    @staticmethod
    @typing.overload
    def valueOf(value: typing.Union[jpype.JInt, int]) -> TypeReferenceKind:
        """
        :return: the :obj:`TypeReferenceKind` with the given kind value, or ``null`` if it 
        does not exist
        :rtype: TypeReferenceKind
        
        
        :param jpype.JInt or int value: The kind value to get the value of
        """

    @staticmethod
    def values() -> jpype.JArray[TypeReferenceKind]:
        ...

    @property
    def value(self) -> jpype.JInt:
        ...


class GenericRequirementFlags(ghidra.app.util.bin.format.swift.SwiftTypeMetadataStructure):
    """
    Represents a Swift ``GenericRequirementFlags`` structure
    
    
    .. seealso::
    
        | `swift/ABI/MetadataValues.h <https://github.com/swiftlang/swift/blob/main/include/swift/ABI/MetadataValues.h>`_
    """

    class_: typing.ClassVar[java.lang.Class]
    SIZE: typing.Final = 4
    """
    The size (in bytes) of a :obj:`GenericRequirementFlags` structure
    """


    def __init__(self, reader: ghidra.app.util.bin.BinaryReader) -> None:
        """
        Create a new :obj:`GenericRequirementFlags`
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of the structure
        :raises IOException: if there was an IO-related problem creating the structure
        """

    def getFlags(self) -> int:
        """
        :return: the flags
        :rtype: int
        """

    def getKind(self) -> GenericRequirementKind:
        """
        :return: the :obj:`GenericRequirementKind`
        :rtype: GenericRequirementKind
        """

    def hasKeyArgument(self) -> bool:
        """
        :return: whether or not the subject type of the requirement has a key argument
        :rtype: bool
        """

    def isPackRequirement(self) -> bool:
        """
        :return: whether or not the subject type of the requirement is a pack
        :rtype: bool
        """

    def isValueRequirement(self) -> bool:
        """
        :return: whether or not the subject type of the requirement is a value
        :rtype: bool
        """

    @property
    def kind(self) -> GenericRequirementKind:
        ...

    @property
    def flags(self) -> jpype.JInt:
        ...

    @property
    def valueRequirement(self) -> jpype.JBoolean:
        ...

    @property
    def packRequirement(self) -> jpype.JBoolean:
        ...


class ConformanceFlags(ghidra.app.util.bin.format.swift.SwiftTypeMetadataStructure):
    """
    Represents a Swift ``ConformanceFlags`` structure
    
    
    .. seealso::
    
        | `swift/ABI/MetadataValues.h <https://github.com/swiftlang/swift/blob/main/include/swift/ABI/MetadataValues.h>`_
    """

    class_: typing.ClassVar[java.lang.Class]
    SIZE: typing.Final = 4
    """
    The size (in bytes) of a :obj:`ConformanceFlags` structure
    """


    def __init__(self, reader: ghidra.app.util.bin.BinaryReader) -> None:
        """
        Create a new :obj:`ConformanceFlags`
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of the structure
        :raises IOException: if there was an IO-related problem creating the structure
        """

    def getFlags(self) -> int:
        """
        :return: the flags
        :rtype: int
        """

    def getKind(self) -> TypeReferenceKind:
        """
        :return: the :obj:`TypeReferenceKind`
        :rtype: TypeReferenceKind
        """

    def getNumConditionalPackDescriptor(self) -> int:
        """
        :return: the number of conditional pack descriptors
        :rtype: int
        """

    def getNumConditionalRequirements(self) -> int:
        """
        :return: the number of conditional requirements
        :rtype: int
        """

    def hasGenericWitnessTable(self) -> bool:
        """
        :return: whether or not it a generic witness table
        :rtype: bool
        """

    def hasGlobalActorIsolation(self) -> bool:
        """
        :return: whether or not it has global actor isolation
        :rtype: bool
        """

    def hasResilientWitnesses(self) -> bool:
        """
        :return: whether or not it has resilient witnesses
        :rtype: bool
        """

    def isConformanceOfProtocol(self) -> bool:
        """
        :return: whether or not it is conformance of protocol
        :rtype: bool
        """

    def isRetroactive(self) -> bool:
        """
        :return: whether or not it is retroactive
        :rtype: bool
        """

    def isSynthesizedNonUnique(self) -> bool:
        """
        :return: whether or not it is synthesized non-unique
        :rtype: bool
        """

    @property
    def numConditionalRequirements(self) -> jpype.JInt:
        ...

    @property
    def kind(self) -> TypeReferenceKind:
        ...

    @property
    def retroactive(self) -> jpype.JBoolean:
        ...

    @property
    def flags(self) -> jpype.JInt:
        ...

    @property
    def numConditionalPackDescriptor(self) -> jpype.JInt:
        ...

    @property
    def synthesizedNonUnique(self) -> jpype.JBoolean:
        ...

    @property
    def conformanceOfProtocol(self) -> jpype.JBoolean:
        ...


class TargetTypeGenericContextDescriptorHeader(ghidra.app.util.bin.format.swift.SwiftTypeMetadataStructure):
    """
    Represents a Swift ``TargetTypeGenericContextDescriptorHeader`` structure
    
    
    .. seealso::
    
        | `swift/ABI/Metadata.h <https://github.com/swiftlang/swift/blob/main/include/swift/ABI/Metadata.h>`_
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader) -> None:
        """
        Creates a new :obj:`TargetTypeGenericContextDescriptorHeader`
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of the structure
        :raises IOException: if there was an IO-related problem creating the structure
        """

    def getBaseHeader(self) -> TargetGenericContextDescriptorHeader:
        """
        :return: the base header
        :rtype: TargetGenericContextDescriptorHeader
        """

    def getDefaultInstallationPattern(self) -> int:
        """
        :return: the default instantiation pattern
        :rtype: int
        """

    def getInstantiationCache(self) -> int:
        """
        :return: the metadata instantiation cache
        :rtype: int
        """

    @property
    def instantiationCache(self) -> jpype.JInt:
        ...

    @property
    def defaultInstallationPattern(self) -> jpype.JInt:
        ...

    @property
    def baseHeader(self) -> TargetGenericContextDescriptorHeader:
        ...


class TargetOverrideTableHeader(ghidra.app.util.bin.format.swift.SwiftTypeMetadataStructure):
    """
    Represents a Swift ``TargetOverrideTableHeader`` structure
    
    
    .. seealso::
    
        | `swift/ABI/Metadata.h <https://github.com/swiftlang/swift/blob/main/include/swift/ABI/Metadata.h>`_
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader) -> None:
        """
        Creates a new :obj:`TargetOverrideTableHeader`
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of the structure
        :raises IOException: if there was an IO-related problem creating the structure
        """

    def getNumEntries(self) -> int:
        """
        :return: the number of MethodOverrideDescriptor records following the vtable override header
        in the class's nominal type descriptor
        :rtype: int
        """

    @property
    def numEntries(self) -> jpype.JLong:
        ...


class TargetClassDescriptor(TargetTypeContextDescriptor):
    """
    Represents a Swift ``TargetClassDescriptor`` structure
    
    
    .. seealso::
    
        | `swift/ABI/Metadata.h <https://github.com/swiftlang/swift/blob/main/include/swift/ABI/Metadata.h>`_
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader) -> None:
        """
        Creates a new :obj:`TargetClassDescriptor`
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of the structure
        :raises IOException: if there was an IO-related problem creating the structure
        """

    def getExtraClassDescriptorFlags(self) -> ExtraClassDescriptorFlags:
        """
        :return: flags used to do things like indicate the presence of an Objective-C resilient class
        stub if this descriptor has a resilient superclass; otherwise, ``null``
        :rtype: ExtraClassDescriptorFlags
        """

    def getFieldOffsetVectorOffset(self) -> int:
        """
        :return: the offset of the field offset vector for this class's stored properties in its
        metadata, in words (0 means there is no field offset vector)
        :rtype: int
        """

    def getGenericHeader(self) -> TargetTypeGenericContextDescriptorHeader:
        """
        :return: the :obj:`TargetTypeGenericContextDescriptorHeader`, or ``null`` if it doesn't 
        exist
        :rtype: TargetTypeGenericContextDescriptorHeader
        """

    def getInvertibleProtocolSet(self) -> InvertibleProtocolSet:
        """
        :return: the :obj:`InvertibleProtocolSet`, or ``null`` if it doens't exist
        :rtype: InvertibleProtocolSet
        """

    def getMetadataNegativeSizeInWords(self) -> int:
        """
        :return: the negative size of metadata objects of this class (in words) if this descriptor 
        does not have a resilient superclass
        :rtype: int
        """

    def getMetadataPositiveSizeInWords(self) -> int:
        """
        :return: the positive size of metadata objects of this class (in words) if this descriptor 
        does not have a resilient superclass
        :rtype: int
        """

    def getMethodDescriptors(self) -> java.util.List[TargetMethodDescriptor]:
        """
        :return: the :obj:`List` of method descriptors
        :rtype: java.util.List[TargetMethodDescriptor]
        """

    def getMethodOverrideDescriptors(self) -> java.util.List[TargetMethodOverrideDescriptor]:
        """
        :return: the :obj:`List` of method override descriptors
        :rtype: java.util.List[TargetMethodOverrideDescriptor]
        """

    def getNumFields(self) -> int:
        """
        :return: the number of stored properties in the class, not including its superclasses
        :rtype: int
        
         
        
        If there is a field offset vector, this is its length.
        """

    def getNumImmediateMembers(self) -> int:
        """
        :return: the number of additional members added by this class to the class metadata
        :rtype: int
        """

    def getObjcResilientClassStub(self) -> TargetObjCResilientClassStubInfo:
        """
        :return: the :obj:`TargetObjCResilientClassStubInfo`, or ``null`` if it doesn't exist
        :rtype: TargetObjCResilientClassStubInfo
        """

    def getResilientMetadataBounds(self) -> int:
        """
        :return: a reference to a cache holding the metadata's extents if this descriptor has a
        resilient superclass; otherwise, 0
        :rtype: int
        """

    def getResilientSuperclass(self) -> TargetResilientSuperclass:
        """
        :return: the :obj:`TargetResilientSuperclass`, or ``null`` if it doesn't exist
        :rtype: TargetResilientSuperclass
        """

    def getSuperclassType(self) -> int:
        """
        :return: the type of the superclass, expressed as a mangled type name that can refer to the 
        generic arguments of the subclass type
        :rtype: int
        """

    def getTargetForeignMetadataInitialization(self) -> TargetForeignMetadataInitialization:
        """
        :return: the :obj:`TargetForeignMetadataInitialization`, or ``null`` if it doesn't
        exist
        :rtype: TargetForeignMetadataInitialization
        """

    def getTargetOverrideTableHeader(self) -> TargetOverrideTableHeader:
        """
        :return: the :obj:`TargetOverrideTableHeader`, or ``null`` if it doesn't exist
        :rtype: TargetOverrideTableHeader
        """

    def getTargetSingletonMetadataInitialization(self) -> TargetSingletonMetadataInitialization:
        """
        :return: the :obj:`TargetSingletonMetadataInitialization`, or ``null`` if it doesn't
        exist
        :rtype: TargetSingletonMetadataInitialization
        """

    def getVTableDescriptorHeader(self) -> TargetVTableDescriptorHeader:
        """
        :return: the :obj:`TargetVTableDescriptorHeader`, or ``null`` if it doesn't exist
        :rtype: TargetVTableDescriptorHeader
        """

    @property
    def superclassType(self) -> jpype.JInt:
        ...

    @property
    def resilientMetadataBounds(self) -> jpype.JInt:
        ...

    @property
    def fieldOffsetVectorOffset(self) -> jpype.JInt:
        ...

    @property
    def metadataPositiveSizeInWords(self) -> jpype.JInt:
        ...

    @property
    def genericHeader(self) -> TargetTypeGenericContextDescriptorHeader:
        ...

    @property
    def vTableDescriptorHeader(self) -> TargetVTableDescriptorHeader:
        ...

    @property
    def objcResilientClassStub(self) -> TargetObjCResilientClassStubInfo:
        ...

    @property
    def numImmediateMembers(self) -> jpype.JInt:
        ...

    @property
    def metadataNegativeSizeInWords(self) -> jpype.JInt:
        ...

    @property
    def invertibleProtocolSet(self) -> InvertibleProtocolSet:
        ...

    @property
    def targetSingletonMetadataInitialization(self) -> TargetSingletonMetadataInitialization:
        ...

    @property
    def methodOverrideDescriptors(self) -> java.util.List[TargetMethodOverrideDescriptor]:
        ...

    @property
    def targetOverrideTableHeader(self) -> TargetOverrideTableHeader:
        ...

    @property
    def methodDescriptors(self) -> java.util.List[TargetMethodDescriptor]:
        ...

    @property
    def resilientSuperclass(self) -> TargetResilientSuperclass:
        ...

    @property
    def numFields(self) -> jpype.JInt:
        ...

    @property
    def extraClassDescriptorFlags(self) -> ExtraClassDescriptorFlags:
        ...

    @property
    def targetForeignMetadataInitialization(self) -> TargetForeignMetadataInitialization:
        ...


class GenericParamKind(java.lang.Enum[GenericParamKind], ghidra.app.util.bin.StructConverter):
    """
    Swift ``GenericParamKind`` values
    
    
    .. seealso::
    
        | `swift/ABI/MetadataValues.h <https://github.com/swiftlang/swift/blob/main/include/swift/ABI/MetadataValues.h>`_
    """

    class_: typing.ClassVar[java.lang.Class]
    Type: typing.Final[GenericParamKind]
    TypePack: typing.Final[GenericParamKind]
    Value: typing.Final[GenericParamKind]

    def getValue(self) -> int:
        """
        :return: the kind value
        :rtype: int
        """

    @staticmethod
    @typing.overload
    def valueOf(name: typing.Union[java.lang.String, str]) -> GenericParamKind:
        ...

    @staticmethod
    @typing.overload
    def valueOf(value: typing.Union[jpype.JInt, int]) -> GenericParamKind:
        """
        :return: the :obj:`GenericParamKind` with the given kind value, or ``null`` if it 
        does not exist
        :rtype: GenericParamKind
        
        
        :param jpype.JInt or int value: The kind value to get the value of
        """

    @staticmethod
    def values() -> jpype.JArray[GenericParamKind]:
        ...

    @property
    def value(self) -> jpype.JInt:
        ...


class TargetRelativeContextPointer(ghidra.app.util.bin.format.swift.SwiftTypeMetadataStructure):
    """
    Represents a Swift ``TargetRelativeContextPointer`` structure
    
    
    .. seealso::
    
        | `swift/ABI/MetadataRef.h <https://github.com/swiftlang/swift/blob/main/include/swift/ABI/MetadataRef.h>`_
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader) -> None:
        """
        Creates a new :obj:`TargetRelativeContextPointer`
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of the structure
        :raises IOException: if there was an IO-related problem creating the structure
        """

    def getValue(self) -> int:
        """
        :return: the pointer value
        :rtype: int
        """

    @property
    def value(self) -> jpype.JLong:
        ...


class FieldDescriptor(ghidra.app.util.bin.format.swift.SwiftTypeMetadataStructure):
    """
    Represents a Swift ``FieldDescriptor`` structure
    
    
    .. seealso::
    
        | `swift/RemoteInspection/Records.h <https://github.com/swiftlang/swift/blob/main/include/swift/RemoteInspection/Records.h>`_
    """

    class_: typing.ClassVar[java.lang.Class]
    SIZE: typing.Final = 16
    """
    The size (in bytes) of a :obj:`FieldDescriptor` structure
    """


    def __init__(self, reader: ghidra.app.util.bin.BinaryReader) -> None:
        """
        Creates a new :obj:`FieldDescriptor`
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of the structure
        :raises IOException: if there was an IO-related problem creating the structure
        """

    def getFieldRecordSize(self) -> int:
        """
        :return: the field record size
        :rtype: int
        """

    def getFieldRecords(self) -> java.util.List[FieldRecord]:
        """
        :return: the :obj:`List` of :obj:`FieldRecord`s
        :rtype: java.util.List[FieldRecord]
        """

    def getKind(self) -> int:
        """
        :return: the kind
        :rtype: int
        """

    def getMangledTypeName(self) -> str:
        """
        :return: the mangled type name
        :rtype: str
        """

    def getNumFields(self) -> int:
        """
        :return: the number of fields
        :rtype: int
        """

    def getSuperclass(self) -> int:
        """
        :return: the superclass
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


class MetadataInitializationKind(java.lang.Enum[MetadataInitializationKind], ghidra.app.util.bin.StructConverter):
    """
    Swift ``MetadataInitializationKind`` values
    
    
    .. seealso::
    
        | `swift/ABI/MetadataValues.h <https://github.com/swiftlang/swift/blob/main/include/swift/ABI/MetadataValues.h>`_
    """

    class_: typing.ClassVar[java.lang.Class]
    NoMetadataInitialization: typing.Final[MetadataInitializationKind]
    SingletonMetadataInitialization: typing.Final[MetadataInitializationKind]
    ForeignMetadataInitialization: typing.Final[MetadataInitializationKind]

    def getValue(self) -> int:
        """
        :return: the kind value
        :rtype: int
        """

    @staticmethod
    @typing.overload
    def valueOf(name: typing.Union[java.lang.String, str]) -> MetadataInitializationKind:
        ...

    @staticmethod
    @typing.overload
    def valueOf(value: typing.Union[jpype.JInt, int]) -> MetadataInitializationKind:
        """
        :return: the :obj:`MetadataInitializationKind` with the given kind value, or ``null`` if it 
        does not exist
        :rtype: MetadataInitializationKind
        
        
        :param jpype.JInt or int value: The kind value to get the value of
        """

    @staticmethod
    def values() -> jpype.JArray[MetadataInitializationKind]:
        ...

    @property
    def value(self) -> jpype.JInt:
        ...


class AssociatedTypeRecord(ghidra.app.util.bin.format.swift.SwiftTypeMetadataStructure):
    """
    Represents a Swift ``AssociatedTypeRecord`` structure
    
    
    .. seealso::
    
        | `swift/RemoteInspection/Records.h <https://github.com/swiftlang/swift/blob/main/include/swift/RemoteInspection/Records.h>`_
    """

    class_: typing.ClassVar[java.lang.Class]
    SIZE: typing.Final = 8
    """
    The size (in bytes) of an :obj:`AssociatedTypeRecord` structure
    """


    def __init__(self, reader: ghidra.app.util.bin.BinaryReader) -> None:
        """
        Creates a new :obj:`AssociatedTypeRecord`
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of the structure
        :raises IOException: if there was an IO-related problem creating the structure
        """

    def getName(self) -> str:
        """
        :return: the name
        :rtype: str
        """

    def getSubstitutedTypeName(self) -> str:
        """
        :return: the substituted type name
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
    Represents a Swift ``TargetProtocolDescriptor`` structure
    
    
    .. seealso::
    
        | `swift/ABI/Metadata.h <https://github.com/swiftlang/swift/blob/main/include/swift/ABI/Metadata.h>`_
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader) -> None:
        """
        Creates a new :obj:`TargetProtocolDescriptor`
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of the structure
        :raises IOException: if there was an IO-related problem creating the structure
        """

    def getAssociatedTypeNames(self) -> int:
        """
        
        
        :return: the associated type names}
        :rtype: int
        """

    def getName(self) -> str:
        """
        :return: the name of the protocol
        :rtype: str
        """

    def getNumRequirements(self) -> int:
        """
        :return: the number of requirements in the protocol
        :rtype: int
        """

    def getNumRequirementsInSignature(self) -> int:
        """
        :return: the number of generic requirements in the requirement signature of the protocol
        :rtype: int
        """

    def getRequirements(self) -> java.util.List[TargetProtocolRequirement]:
        """
        :return: a :obj:`List` of requirements in the protocol
        :rtype: java.util.List[TargetProtocolRequirement]
        """

    def getRequirementsInSignature(self) -> java.util.List[TargetGenericRequirementsDescriptor]:
        """
        :return: a :obj:`List` of generic requirements in the requirement signature of the protocol
        :rtype: java.util.List[TargetGenericRequirementsDescriptor]
        """

    @property
    def requirements(self) -> java.util.List[TargetProtocolRequirement]:
        ...

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

    @property
    def requirementsInSignature(self) -> java.util.List[TargetGenericRequirementsDescriptor]:
        ...


class GenericParamDescriptor(ghidra.app.util.bin.format.swift.SwiftTypeMetadataStructure):
    """
    Represents a Swift ``GenericParamDescriptor`` structure
    
    
    .. seealso::
    
        | `swift/ABI/MetadataValues.h <https://github.com/swiftlang/swift/blob/main/include/swift/ABI/MetadataValues.h>`_
    """

    class_: typing.ClassVar[java.lang.Class]
    SIZE: typing.Final = 1
    """
    The size (in bytes) of a :obj:`GenericParamDescriptor` structure
    """


    def __init__(self, reader: ghidra.app.util.bin.BinaryReader) -> None:
        """
        Create a new :obj:`GenericParamDescriptor`
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of the structure
        :raises IOException: if there was an IO-related problem creating the structure
        """

    def getKind(self) -> GenericParamKind:
        """
        :return: the :obj:`GenericParamKind`
        :rtype: GenericParamKind
        """

    def getValue(self) -> int:
        """
        :return: the value
        :rtype: int
        """

    def hasKeyArgument(self) -> bool:
        """
        :return: whether or not the subject type of the requirement has a key argument
        :rtype: bool
        """

    @property
    def kind(self) -> GenericParamKind:
        ...

    @property
    def value(self) -> jpype.JInt:
        ...


class ProtocolRequirementFlags(ghidra.app.util.bin.format.swift.SwiftTypeMetadataStructure):
    """
    Represents a Swift ``ProtocolRequirementFlags`` structure
    
    
    .. seealso::
    
        | `swift/ABI/MetadataValues.h <https://github.com/swiftlang/swift/blob/main/include/swift/ABI/MetadataValues.h>`_
    """

    class_: typing.ClassVar[java.lang.Class]
    SIZE: typing.Final = 4
    """
    The size (in bytes) of a :obj:`ProtocolRequirementFlags` structure
    """


    def __init__(self, reader: ghidra.app.util.bin.BinaryReader) -> None:
        """
        Create a new :obj:`ProtocolRequirementFlags`
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of the structure
        :raises IOException: if there was an IO-related problem creating the structure
        """

    def getExtraDescriminator(self) -> int:
        """
        :return: the extra descriminator
        :rtype: int
        """

    def getFlags(self) -> int:
        """
        :return: the flags
        :rtype: int
        """

    def getKind(self) -> ProtocolRequirementKind:
        """
        :return: the :obj:`ProtocolRequirementKind`
        :rtype: ProtocolRequirementKind
        """

    def isAnsyc(self) -> bool:
        """
        :return: whether or not the protocol requirement is async
        :rtype: bool
        """

    def isInstance(self) -> bool:
        """
        :return: whether or not the protocol requirement is instance
        :rtype: bool
        """

    @property
    def extraDescriminator(self) -> jpype.JInt:
        ...

    @property
    def instance(self) -> jpype.JBoolean:
        ...

    @property
    def kind(self) -> ProtocolRequirementKind:
        ...

    @property
    def flags(self) -> jpype.JInt:
        ...

    @property
    def ansyc(self) -> jpype.JBoolean:
        ...


class TargetVTableDescriptorHeader(ghidra.app.util.bin.format.swift.SwiftTypeMetadataStructure):
    """
    Represents a Swift ``TargetVTableDescriptorHeader`` structure
    
    
    .. seealso::
    
        | `swift/ABI/Metadata.h <https://github.com/swiftlang/swift/blob/main/include/swift/ABI/Metadata.h>`_
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader) -> None:
        """
        Creates a new :obj:`TargetVTableDescriptorHeader`
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of the structure
        :raises IOException: if there was an IO-related problem creating the structure
        """

    def getVTableOffset(self) -> int:
        """
        :return: the offset of the vtable for this class in its metadata, if any, in words
        :rtype: int
        """

    def getVTableSize(self) -> int:
        """
        :return: the number of vtable entries
        :rtype: int
        """

    @property
    def vTableOffset(self) -> jpype.JLong:
        ...

    @property
    def vTableSize(self) -> jpype.JLong:
        ...


class TargetContextDescriptor(ghidra.app.util.bin.format.swift.SwiftTypeMetadataStructure):
    """
    Represents a Swift ``TargetContextDescriptor`` structure
    
    
    .. seealso::
    
        | `swift/ABI/Metadata.h <https://github.com/swiftlang/swift/blob/main/include/swift/ABI/Metadata.h>`_
    """

    class_: typing.ClassVar[java.lang.Class]
    SIZE: typing.Final = 8
    """
    The size (in bytes) of a :obj:`TargetContextDescriptor` structure
    """


    def __init__(self, reader: ghidra.app.util.bin.BinaryReader) -> None:
        """
        Create a new :obj:`TargetContextDescriptor`
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of the structure
        :raises IOException: if there was an IO-related problem creating the structure
        """

    def getFlags(self) -> ContextDescriptorFlags:
        """
        :return: the flags
        :rtype: ContextDescriptorFlags
        """

    def getParent(self) -> int:
        """
        :return: the parent's relative offset
        :rtype: int
        """

    @property
    def parent(self) -> jpype.JInt:
        ...

    @property
    def flags(self) -> ContextDescriptorFlags:
        ...


class InvertibleProtocolKind(java.lang.Enum[InvertibleProtocolKind], ghidra.app.util.bin.StructConverter):
    """
    Swift ``InvertibleProtocolKind`` values
    
    
    .. seealso::
    
        | `swift/ABI/InvertibleProtocols.h <https://github.com/swiftlang/swift/blob/main/include/swift/ABI/InvertibleProtocols.h>`_
    
        | `swift/ABI/InvertibleProtocols.def <https://github.com/swiftlang/swift/blob/main/include/swift/ABI/InvertibleProtocols.def>`_
    """

    class_: typing.ClassVar[java.lang.Class]
    Copyable: typing.Final[InvertibleProtocolKind]
    Escapable: typing.Final[InvertibleProtocolKind]

    def getBit(self) -> int:
        """
        :return: the bit number that represents the kind
        :rtype: int
        """

    @staticmethod
    @typing.overload
    def valueOf(name: typing.Union[java.lang.String, str]) -> InvertibleProtocolKind:
        ...

    @staticmethod
    @typing.overload
    def valueOf(value: typing.Union[jpype.JShort, int]) -> java.util.Set[InvertibleProtocolKind]:
        """
        :return: the :obj:`Set` of :obj:`InvertibleProtocolKind`s that map to the given kind value
        :rtype: java.util.Set[InvertibleProtocolKind]
        
        
        :param jpype.JShort or int value: The kind value to get the value of
        """

    @staticmethod
    def values() -> jpype.JArray[InvertibleProtocolKind]:
        ...

    @property
    def bit(self) -> jpype.JInt:
        ...


class GenericContextDescriptorFlags(ghidra.app.util.bin.format.swift.SwiftTypeMetadataStructure):
    """
    Represents a Swift ``GenericRequirementFlags`` structure
    
    
    .. seealso::
    
        | `swift/ABI/MetadataValues.h <https://github.com/swiftlang/swift/blob/main/include/swift/ABI/MetadataValues.h>`_
    """

    class_: typing.ClassVar[java.lang.Class]
    SIZE: typing.Final = 2
    """
    The size (in bytes) of a :obj:`GenericContextDescriptorFlags` structure
    """


    def __init__(self, reader: ghidra.app.util.bin.BinaryReader) -> None:
        """
        Create a new :obj:`GenericContextDescriptorFlags`
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of the structure
        :raises IOException: if there was an IO-related problem creating the structure
        """

    def getFlags(self) -> int:
        """
        :return: the flags
        :rtype: int
        """

    def hasConditionalInvertedProtocols(self) -> bool:
        """
        :return: whether or not the generic context has any conditional conformances to inverted
        protocols, in which case the generic context will have a trailing InvertibleProtocolSet and
        conditional requirements
        :rtype: bool
        """

    def hasTypePacks(self) -> bool:
        """
        :return: whether or not the generic context has at least one type parameter pack, in which
        case the generic context will have a trailing GenericPackShapeHeader
        :rtype: bool
        """

    def hasValues(self) -> bool:
        """
        :return: whether or not the generic context has at least one value parameter, in which case
        the generic context will have a trailing GenericValueHeader
        :rtype: bool
        """

    @property
    def flags(self) -> jpype.JShort:
        ...


class MethodDescriptorKind(java.lang.Enum[MethodDescriptorKind], ghidra.app.util.bin.StructConverter):
    """
    Swift ``MethodDescriptorFlags.Kind`` values
    
    
    .. seealso::
    
        | `swift/ABI/MetadataValues.h <https://github.com/swiftlang/swift/blob/main/include/swift/ABI/MetadataValues.h>`_
    """

    class_: typing.ClassVar[java.lang.Class]
    Method: typing.Final[MethodDescriptorKind]
    Init: typing.Final[MethodDescriptorKind]
    Getter: typing.Final[MethodDescriptorKind]
    Setter: typing.Final[MethodDescriptorKind]
    ModifyCoroutine: typing.Final[MethodDescriptorKind]
    ReadCoroutine: typing.Final[MethodDescriptorKind]

    def getValue(self) -> int:
        """
        :return: the kind value
        :rtype: int
        """

    @staticmethod
    @typing.overload
    def valueOf(name: typing.Union[java.lang.String, str]) -> MethodDescriptorKind:
        ...

    @staticmethod
    @typing.overload
    def valueOf(value: typing.Union[jpype.JInt, int]) -> MethodDescriptorKind:
        """
        :return: the :obj:`MethodDescriptorKind` with the given kind value, or ``null`` if it 
        does not exist
        :rtype: MethodDescriptorKind
        
        
        :param jpype.JInt or int value: The kind value to get the value of
        """

    @staticmethod
    def values() -> jpype.JArray[MethodDescriptorKind]:
        ...

    @property
    def value(self) -> jpype.JInt:
        ...


class TargetProtocolRequirement(ghidra.app.util.bin.format.swift.SwiftTypeMetadataStructure):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader) -> None:
        """
        Creates a new :obj:`TargetProtocolRequirement`
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of the structure
        :raises IOException: if there was an IO-related problem creating the structure
        """

    def getFlags(self) -> ProtocolRequirementFlags:
        """
        :return: the flags
        :rtype: ProtocolRequirementFlags
        """

    def getImpl(self) -> int:
        """
        :return: the optional default implementation of the protocol
        :rtype: int
        """

    @property
    def impl(self) -> jpype.JInt:
        ...

    @property
    def flags(self) -> ProtocolRequirementFlags:
        ...


class TargetTypeContextDescriptor(TargetContextDescriptor):
    """
    Represents a Swift ``TargetTypeContextDescriptor`` structure
    
    
    .. seealso::
    
        | `swift/ABI/Metadata.h <https://github.com/swiftlang/swift/blob/main/include/swift/ABI/Metadata.h>`_
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader) -> None:
        """
        Creates a new :obj:`TargetTypeContextDescriptor`
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of the structure
        :raises IOException: if there was an IO-related problem creating the structure
        """

    def getAccessFunctionPtr(self) -> int:
        """
        :return: the pointer to the metadata access function for this type
        :rtype: int
        """

    def getFieldDescriptor(self, fieldDescriptors: collections.abc.Mapping) -> FieldDescriptor:
        """
        :return: this :obj:`TargetTypeContextDescriptor`'s :obj:`FieldDescriptor`, or ``null``
        if it doesn't have one
        :rtype: FieldDescriptor
        
        
        :param collections.abc.Mapping fieldDescriptors: A :obj:`Map` of :obj:`FieldDescriptor`'s keyed by their base
        addresses
        """

    def getFields(self) -> int:
        """
        :return: the pointer to the field descriptor for the type, if any
        :rtype: int
        """

    def getName(self) -> str:
        """
        :return: the name of the type
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
    Represents a Swift ``AssociatedTypeDescriptor`` structure
    
    
    .. seealso::
    
        | `swift/RemoteInspection/Records.h <https://github.com/swiftlang/swift/blob/main/include/swift/RemoteInspection/Records.h>`_
    """

    class_: typing.ClassVar[java.lang.Class]
    SIZE: typing.Final = 16
    """
    The size (in bytes) of an :obj:`AssociatedTypeDescriptor` structure
    """


    def __init__(self, reader: ghidra.app.util.bin.BinaryReader) -> None:
        """
        Creates a new :obj:`AssociatedTypeDescriptor`
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of the structure
        :raises IOException: if there was an IO-related problem creating the structure
        """

    def getAssociatedTypeRecordSize(self) -> int:
        """
        :return: the associated type record size
        :rtype: int
        """

    def getAssociatedTypeRecords(self) -> java.util.List[AssociatedTypeRecord]:
        """
        :return: The :obj:`List` of :obj:`AssociatedTypeRecord`s
        :rtype: java.util.List[AssociatedTypeRecord]
        """

    def getConformingTypeName(self) -> str:
        """
        :return: the conforming type name
        :rtype: str
        """

    def getNumAssociatedTypes(self) -> int:
        """
        :return: the number of associated types
        :rtype: int
        """

    def getProtocolTypeName(self) -> str:
        """
        :return: the protocol type name
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
    Represents a Swift ``CaptureTypeRecord`` structure
    
    
    .. seealso::
    
        | `swift/RemoteInspection/Records.h <https://github.com/swiftlang/swift/blob/main/include/swift/RemoteInspection/Records.h>`_
    """

    class_: typing.ClassVar[java.lang.Class]
    SIZE: typing.Final = 4
    """
    The size (in bytes) of a :obj:`CaptureTypeRecord` structure
    """


    def __init__(self, reader: ghidra.app.util.bin.BinaryReader) -> None:
        """
        Creates a new :obj:`CaptureTypeRecord`
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of the structure
        :raises IOException: if there was an IO-related problem creating the structure
        """

    def getMangledTypeName(self) -> str:
        """
        :return: the mangled type name
        :rtype: str
        """

    @property
    def mangledTypeName(self) -> java.lang.String:
        ...


class ContextDescriptorFlags(ghidra.app.util.bin.format.swift.SwiftTypeMetadataStructure):
    """
    Represents a Swift ``ContextDescriptorFlags`` structure
    
    
    .. seealso::
    
        | `swift/ABI/MetadataValues.h <https://github.com/swiftlang/swift/blob/main/include/swift/ABI/MetadataValues.h>`_
    """

    class_: typing.ClassVar[java.lang.Class]
    SIZE: typing.Final = 4
    """
    The size (in bytes) of a :obj:`ContextDescriptorFlags` structure
    """


    def __init__(self, reader: ghidra.app.util.bin.BinaryReader) -> None:
        """
        Create a new :obj:`ContextDescriptorFlags`
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of the structure
        :raises IOException: if there was an IO-related problem creating the structure
        """

    def areClassImmediateMembersNegative(self) -> bool:
        """
        :return: whether the immediate class members in this metadata are allocated at negative 
        offsets
        :rtype: bool
        """

    def getClassResilientSuperclassReferenceKind(self) -> int:
        """
        :return: the kind of reference that this class makes to its resilient superclass descriptor. 
        A TypeReferenceKind.
        :rtype: int
        """

    def getFlags(self) -> int:
        """
        :return: the flags
        :rtype: int
        """

    def getKind(self) -> ContextDescriptorKind:
        """
        :return: the :obj:`ContextDescriptorKind`
        :rtype: ContextDescriptorKind
        """

    def getMetadataInitialization(self) -> MetadataInitializationKind:
        """
        :return: whether there's something unusual about how the metadata is initialized
        :rtype: MetadataInitializationKind
        """

    def hasCanonicalMetadataPrespecializationsOrSingletonMetadataPonter(self) -> bool:
        """
        :return: whether or not the generic type descriptor has a pointer to a list of canonical 
        prespecializations, or the non-generic type descriptor has a pointer to its singleton 
        metadata
        :rtype: bool
        """

    def hasClassDefaultOverrideTable(self) -> bool:
        """
        :return: whether or not the class has a default override table
        :rtype: bool
        """

    def hasClassOverrideTable(self) -> bool:
        """
        :return: whether or not the context descriptor includes metadata for dynamically installing 
        method overrides at metadata instantiation time
        :rtype: bool
        """

    def hasClassResilientSuperclass(self) -> bool:
        """
        :return: Whether or not the context descriptor is for a class with resilient ancestry
        :rtype: bool
        """

    def hasClassVTable(self) -> bool:
        """
        :return: whether or not the context descriptor includes metadata for dynamically constructing
        a class's vtables at metadata instantiation time
        :rtype: bool
        """

    def hasImportInfo(self) -> bool:
        """
        :return: whether or not the type has extended import information
        :rtype: bool
        """

    def hasInvertableProtocols(self) -> bool:
        """
        :return: whether or not the context has information about invertable protocols, which will 
        show up as a trailing field in the context descriptor
        :rtype: bool
        """

    def hasLayoutString(self) -> bool:
        """
        :return: whether or not the metadata contains a pointer to a layout string
        :rtype: bool
        """

    def isClassActor(self) -> bool:
        """
        :return: whether or not the class is an actor
        :rtype: bool
        """

    def isClassDefaultActor(self) -> bool:
        """
        :return: whether or not the class is a default actor
        :rtype: bool
        """

    def isGeneric(self) -> bool:
        """
        :return: whether the context being described is generic
        :rtype: bool
        """

    def isUnique(self) -> bool:
        """
        :return: whether this is a unique record describing the referenced context
        :rtype: bool
        """

    @property
    def classResilientSuperclassReferenceKind(self) -> jpype.JInt:
        ...

    @property
    def kind(self) -> ContextDescriptorKind:
        ...

    @property
    def unique(self) -> jpype.JBoolean:
        ...

    @property
    def flags(self) -> jpype.JInt:
        ...

    @property
    def classActor(self) -> jpype.JBoolean:
        ...

    @property
    def classDefaultActor(self) -> jpype.JBoolean:
        ...

    @property
    def metadataInitialization(self) -> MetadataInitializationKind:
        ...

    @property
    def generic(self) -> jpype.JBoolean:
        ...


class MetadataSourceRecord(ghidra.app.util.bin.format.swift.SwiftTypeMetadataStructure):
    """
    Represents a Swift ``MetadataSourceRecord`` structure
    
    
    .. seealso::
    
        | `swift/RemoteInspection/Records.h <https://github.com/swiftlang/swift/blob/main/include/swift/RemoteInspection/Records.h>`_
    """

    class_: typing.ClassVar[java.lang.Class]
    SIZE: typing.Final = 8
    """
    The size (in bytes) of a :obj:`MetadataSourceRecord` structure
    """


    def __init__(self, reader: ghidra.app.util.bin.BinaryReader) -> None:
        """
        Creates a new :obj:`MetadataSourceRecord`
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of the structure
        :raises IOException: if there was an IO-related problem creating the structure
        """

    def getMangledMetadataSource(self) -> str:
        """
        :return: the mangled metadata source
        :rtype: str
        """

    def getMangledTypeName(self) -> str:
        """
        :return: the mangled type name
        :rtype: str
        """

    @property
    def mangledMetadataSource(self) -> java.lang.String:
        ...

    @property
    def mangledTypeName(self) -> java.lang.String:
        ...


class TargetResilientWitness(ghidra.app.util.bin.format.swift.SwiftTypeMetadataStructure):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader) -> None:
        """
        Creates a new :obj:`TargetResilientWitness`
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of the structure
        :raises IOException: if there was an IO-related problem creating the structure
        """

    def getImpl(self) -> int:
        """
        :return: the implementation
        :rtype: int
        """

    def getRequirement(self) -> TargetRelativeProtocolRequirementPointer:
        """
        :return: the requirement
        :rtype: TargetRelativeProtocolRequirementPointer
        """

    @property
    def impl(self) -> jpype.JInt:
        ...

    @property
    def requirement(self) -> TargetRelativeProtocolRequirementPointer:
        ...



__all__ = ["TargetGenericWitnessTable", "TargetSingletonMetadataInitialization", "TargetGenericRequirementsDescriptor", "TargetMethodOverrideDescriptor", "FieldRecord", "EntryPoint", "TargetEnumDescriptor", "TargetObjCResilientClassStubInfo", "ExtraClassDescriptorFlags", "GenericRequirementKind", "GenericRequirementLayoutKind", "MultiPayloadEnumDescriptor", "TargetProtocolConformanceDescriptor", "TargetGenericContextDescriptorHeader", "CaptureDescriptor", "ContextDescriptorKind", "TargetMethodDescriptor", "MethodDescriptorFlags", "ProtocolRequirementKind", "TargetRelativeProtocolRequirementPointer", "TargetStructDescriptor", "TargetResilientWitnessHeader", "TargetResilientSuperclass", "BuiltinTypeDescriptor", "TargetForeignMetadataInitialization", "InvertibleProtocolSet", "TypeReferenceKind", "GenericRequirementFlags", "ConformanceFlags", "TargetTypeGenericContextDescriptorHeader", "TargetOverrideTableHeader", "TargetClassDescriptor", "GenericParamKind", "TargetRelativeContextPointer", "FieldDescriptor", "MetadataInitializationKind", "AssociatedTypeRecord", "TargetProtocolDescriptor", "GenericParamDescriptor", "ProtocolRequirementFlags", "TargetVTableDescriptorHeader", "TargetContextDescriptor", "InvertibleProtocolKind", "GenericContextDescriptorFlags", "MethodDescriptorKind", "TargetProtocolRequirement", "TargetTypeContextDescriptor", "AssociatedTypeDescriptor", "CaptureTypeRecord", "ContextDescriptorFlags", "MetadataSourceRecord", "TargetResilientWitness"]
