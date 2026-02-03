from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.util.bin
import ghidra.app.util.bin.format.pe.cli
import ghidra.app.util.bin.format.pe.cli.streams
import ghidra.app.util.bin.format.pe.cli.tables
import ghidra.program.model.data
import java.lang # type: ignore
import java.util # type: ignore


class CliSigConstant(CliAbstractSig):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, blob: CliBlob, elementType: CliAbstractSig.CliElementType):
        ...


class CliBlobMarshalSpec(CliBlob):

    class CliNativeType(java.lang.Enum[CliBlobMarshalSpec.CliNativeType]):

        class_: typing.ClassVar[java.lang.Class]
        NATIVE_TYPE_END: typing.Final[CliBlobMarshalSpec.CliNativeType]
        NATIVE_TYPE_VOID: typing.Final[CliBlobMarshalSpec.CliNativeType]
        NATIVE_TYPE_BOOLEAN: typing.Final[CliBlobMarshalSpec.CliNativeType]
        NATIVE_TYPE_I1: typing.Final[CliBlobMarshalSpec.CliNativeType]
        NATIVE_TYPE_U1: typing.Final[CliBlobMarshalSpec.CliNativeType]
        NATIVE_TYPE_I2: typing.Final[CliBlobMarshalSpec.CliNativeType]
        NATIVE_TYPE_U2: typing.Final[CliBlobMarshalSpec.CliNativeType]
        NATIVE_TYPE_I4: typing.Final[CliBlobMarshalSpec.CliNativeType]
        NATIVE_TYPE_U4: typing.Final[CliBlobMarshalSpec.CliNativeType]
        NATIVE_TYPE_I8: typing.Final[CliBlobMarshalSpec.CliNativeType]
        NATIVE_TYPE_U8: typing.Final[CliBlobMarshalSpec.CliNativeType]
        NATIVE_TYPE_R4: typing.Final[CliBlobMarshalSpec.CliNativeType]
        NATIVE_TYPE_R8: typing.Final[CliBlobMarshalSpec.CliNativeType]
        NATIVE_TYPE_SYSCHAR: typing.Final[CliBlobMarshalSpec.CliNativeType]
        NATIVE_TYPE_VARIANT: typing.Final[CliBlobMarshalSpec.CliNativeType]
        NATIVE_TYPE_CURRENCY: typing.Final[CliBlobMarshalSpec.CliNativeType]
        NATIVE_TYPE_PTR: typing.Final[CliBlobMarshalSpec.CliNativeType]
        NATIVE_TYPE_DECIMAL: typing.Final[CliBlobMarshalSpec.CliNativeType]
        NATIVE_TYPE_DATE: typing.Final[CliBlobMarshalSpec.CliNativeType]
        NATIVE_TYPE_BSTR: typing.Final[CliBlobMarshalSpec.CliNativeType]
        NATIVE_TYPE_LPSTR: typing.Final[CliBlobMarshalSpec.CliNativeType]
        NATIVE_TYPE_LPWSTR: typing.Final[CliBlobMarshalSpec.CliNativeType]
        NATIVE_TYPE_LPTSTR: typing.Final[CliBlobMarshalSpec.CliNativeType]
        NATIVE_TYPE_FIXEDSYSSTRING: typing.Final[CliBlobMarshalSpec.CliNativeType]
        NATIVE_TYPE_OBJECTREF: typing.Final[CliBlobMarshalSpec.CliNativeType]
        NATIVE_TYPE_IUNKNOWN: typing.Final[CliBlobMarshalSpec.CliNativeType]
        NATIVE_TYPE_IDISPATCH: typing.Final[CliBlobMarshalSpec.CliNativeType]
        NATIVE_TYPE_STRUCT: typing.Final[CliBlobMarshalSpec.CliNativeType]
        NATIVE_TYPE_INTF: typing.Final[CliBlobMarshalSpec.CliNativeType]
        NATIVE_TYPE_SAFEARRAY: typing.Final[CliBlobMarshalSpec.CliNativeType]
        NATIVE_TYPE_FIXEDARRAY: typing.Final[CliBlobMarshalSpec.CliNativeType]
        NATIVE_TYPE_INT: typing.Final[CliBlobMarshalSpec.CliNativeType]
        NATIVE_TYPE_UINT: typing.Final[CliBlobMarshalSpec.CliNativeType]
        NATIVE_TYPE_NESTEDSTRUCT: typing.Final[CliBlobMarshalSpec.CliNativeType]
        NATIVE_TYPE_BYVALSTR: typing.Final[CliBlobMarshalSpec.CliNativeType]
        NATIVE_TYPE_ANSIBSTR: typing.Final[CliBlobMarshalSpec.CliNativeType]
        NATIVE_TYPE_TBSTR: typing.Final[CliBlobMarshalSpec.CliNativeType]
        NATIVE_TYPE_VARIANTBOOL: typing.Final[CliBlobMarshalSpec.CliNativeType]
        NATIVE_TYPE_FUNC: typing.Final[CliBlobMarshalSpec.CliNativeType]
        NATIVE_TYPE_ASANY: typing.Final[CliBlobMarshalSpec.CliNativeType]
        NATIVE_TYPE_ARRAY: typing.Final[CliBlobMarshalSpec.CliNativeType]
        NATIVE_TYPE_LPSTRUCT: typing.Final[CliBlobMarshalSpec.CliNativeType]
        NATIVE_TYPE_CUSTOMMARSHALER: typing.Final[CliBlobMarshalSpec.CliNativeType]
        NATIVE_TYPE_ERROR: typing.Final[CliBlobMarshalSpec.CliNativeType]
        NATIVE_TYPE_IINSPECTABLE: typing.Final[CliBlobMarshalSpec.CliNativeType]
        NATIVE_TYPE_HSTRING: typing.Final[CliBlobMarshalSpec.CliNativeType]
        NATIVE_TYPE_MAX: typing.Final[CliBlobMarshalSpec.CliNativeType]

        @staticmethod
        def fromInt(id: typing.Union[jpype.JInt, int]) -> CliBlobMarshalSpec.CliNativeType:
            ...

        def id(self) -> int:
            ...

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> CliBlobMarshalSpec.CliNativeType:
            ...

        @staticmethod
        def values() -> jpype.JArray[CliBlobMarshalSpec.CliNativeType]:
            ...


    class CliSafeArrayElemType(java.lang.Enum[CliBlobMarshalSpec.CliSafeArrayElemType]):

        class_: typing.ClassVar[java.lang.Class]
        VT_I2: typing.Final[CliBlobMarshalSpec.CliSafeArrayElemType]
        VT_I4: typing.Final[CliBlobMarshalSpec.CliSafeArrayElemType]
        VT_R4: typing.Final[CliBlobMarshalSpec.CliSafeArrayElemType]
        VT_R8: typing.Final[CliBlobMarshalSpec.CliSafeArrayElemType]
        VT_CY: typing.Final[CliBlobMarshalSpec.CliSafeArrayElemType]
        VT_DATE: typing.Final[CliBlobMarshalSpec.CliSafeArrayElemType]
        VT_BSTR: typing.Final[CliBlobMarshalSpec.CliSafeArrayElemType]
        VT_DISPATCH: typing.Final[CliBlobMarshalSpec.CliSafeArrayElemType]
        VT_ERROR: typing.Final[CliBlobMarshalSpec.CliSafeArrayElemType]
        VT_BOOL: typing.Final[CliBlobMarshalSpec.CliSafeArrayElemType]
        VT_VARIANT: typing.Final[CliBlobMarshalSpec.CliSafeArrayElemType]
        VT_UNKNOWN: typing.Final[CliBlobMarshalSpec.CliSafeArrayElemType]
        VT_DECIMAL: typing.Final[CliBlobMarshalSpec.CliSafeArrayElemType]
        VT_I1: typing.Final[CliBlobMarshalSpec.CliSafeArrayElemType]
        VT_UI1: typing.Final[CliBlobMarshalSpec.CliSafeArrayElemType]
        VT_UI2: typing.Final[CliBlobMarshalSpec.CliSafeArrayElemType]
        VT_UI4: typing.Final[CliBlobMarshalSpec.CliSafeArrayElemType]
        VT_INT: typing.Final[CliBlobMarshalSpec.CliSafeArrayElemType]
        VT_UINT: typing.Final[CliBlobMarshalSpec.CliSafeArrayElemType]

        @staticmethod
        def fromInt(id: typing.Union[jpype.JInt, int]) -> CliBlobMarshalSpec.CliSafeArrayElemType:
            ...

        def id(self) -> int:
            ...

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> CliBlobMarshalSpec.CliSafeArrayElemType:
            ...

        @staticmethod
        def values() -> jpype.JArray[CliBlobMarshalSpec.CliSafeArrayElemType]:
            ...


    class CliNativeTypeDataType(ghidra.program.model.data.EnumDataType):

        class_: typing.ClassVar[java.lang.Class]
        dataType: typing.Final[CliBlobMarshalSpec.CliNativeTypeDataType]

        def __init__(self):
            ...


    class CliSafeArrayElemTypeDataType(ghidra.program.model.data.EnumDataType):

        class_: typing.ClassVar[java.lang.Class]
        dataType: typing.Final[CliBlobMarshalSpec.CliNativeTypeDataType]

        def __init__(self):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, blob: CliBlob):
        ...


class CliSigAssembly(CliAbstractSig):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, blob: CliBlob):
        ...


class CliSigProperty(CliAbstractSig):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, blob: CliBlob):
        ...

    def hasThis(self) -> bool:
        ...


class CliSigLocalVar(CliAbstractSig):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, blob: CliBlob):
        ...

    @staticmethod
    def isLocalVarSig(blob: CliBlob) -> bool:
        """
        Checks whether this could *possibly* be a LocalVarSig. Only looks at the identifier byte. Useful for signature index
        that could be to different kinds of signatures.
        
        :param CliBlob blob: 
        :return: 
        :rtype: bool
        :raises IOException:
        """


class CliSigStandAloneMethod(CliAbstractSig):

    class CallingConvention(java.lang.Enum[CliSigStandAloneMethod.CallingConvention]):

        class_: typing.ClassVar[java.lang.Class]
        MANAGED: typing.Final[CliSigStandAloneMethod.CallingConvention]
        C: typing.Final[CliSigStandAloneMethod.CallingConvention]
        STDCALL: typing.Final[CliSigStandAloneMethod.CallingConvention]
        THISCALL: typing.Final[CliSigStandAloneMethod.CallingConvention]
        FASTCALL: typing.Final[CliSigStandAloneMethod.CallingConvention]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> CliSigStandAloneMethod.CallingConvention:
            ...

        @staticmethod
        def values() -> jpype.JArray[CliSigStandAloneMethod.CallingConvention]:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, blob: CliBlob):
        ...

    def getCallingConvention(self) -> CliSigStandAloneMethod.CallingConvention:
        ...

    def getParams(self) -> jpype.JArray[CliAbstractSig.CliParam]:
        ...

    def getReturnType(self) -> CliAbstractSig.CliRetType:
        ...

    def hasExplicitThis(self) -> bool:
        ...

    def hasThis(self) -> bool:
        ...

    def hasVarArgs(self) -> bool:
        ...

    @property
    def callingConvention(self) -> CliSigStandAloneMethod.CallingConvention:
        ...

    @property
    def params(self) -> jpype.JArray[CliAbstractSig.CliParam]:
        ...

    @property
    def returnType(self) -> CliAbstractSig.CliRetType:
        ...


class CliBlob(ghidra.app.util.bin.StructConverter):
    """
    Describes a blob in the #Blob heap. Format is a coded size then the blob contents.
     
    
    Paraphrasing from ISO 23271:2012 11.24.2.4 (p272):
    - If the first one byte of the 'blob' is 0bbbbbbb_2: size is bbbbbbb_2 bytes.
    - If the first two bytes are 10bbbbbb_2 and x: size is (bbbbbb_2 << 8 + x) bytes.
    - If the first four bytes are 110bbbbb_2, x, y, and z: size is (bbbbb_2<<24 + x<<16 + y<<8 + z) bytes.
    The first entry in the heap is the empty 'blob' consisting of a single zero byte.
    """

    class_: typing.ClassVar[java.lang.Class]
    PATH: typing.Final = "/PE/CLI/Blobs"

    def __init__(self, streamIndex: typing.Union[jpype.JInt, int], reader: ghidra.app.util.bin.BinaryReader):
        """
        Creates a new blob from the given reader, which should be positioned at the start
        of the blob.  The reader will be positioned directly after the blob upon completion
        of the constructor.
        
        :param jpype.JInt or int streamIndex: The blob's stream index.
        :param ghidra.app.util.bin.BinaryReader reader: The reader to use to read the blob.
        :raises IOException: if there was a problem reading the blob.
        """

    @staticmethod
    @typing.overload
    def decodeCompressedSigned(codedSize: typing.Union[jpype.JByte, int]) -> int:
        ...

    @staticmethod
    @typing.overload
    def decodeCompressedSigned(codedSize: typing.Union[jpype.JShort, int]) -> int:
        ...

    @staticmethod
    @typing.overload
    def decodeCompressedSigned(codedSize: typing.Union[jpype.JInt, int]) -> int:
        ...

    @staticmethod
    def decodeCompressedSignedInt(reader: ghidra.app.util.bin.BinaryReader) -> int:
        ...

    @staticmethod
    @typing.overload
    def decodeCompressedUnsigned(codedSize: typing.Union[jpype.JByte, int]) -> int:
        ...

    @staticmethod
    @typing.overload
    def decodeCompressedUnsigned(codedSize: typing.Union[jpype.JShort, int]) -> int:
        ...

    @staticmethod
    @typing.overload
    def decodeCompressedUnsigned(codedSize: typing.Union[jpype.JInt, int]) -> int:
        ...

    @staticmethod
    def decodeCompressedUnsignedInt(reader: ghidra.app.util.bin.BinaryReader) -> int:
        ...

    def getContents(self) -> jpype.JArray[jpype.JByte]:
        """
        Gets the blob's contents.
        
        :return: the blob's contents.  Could be null if there was a problem reading the 
        contents.
        :rtype: jpype.JArray[jpype.JByte]
        """

    def getContentsComment(self) -> str:
        """
        Gets the comment associated with this blob's contents.
        
        :return: The comment associated with this blob's contents.
        :rtype: str
        """

    def getContentsDataType(self) -> ghidra.program.model.data.DataType:
        """
        Gets the data type associated with this blob's contents.
        
        :return: The data type associated with this blob's contents.
        :rtype: ghidra.program.model.data.DataType
        """

    def getContentsName(self) -> str:
        """
        Gets the name associated with this blob's contents.
        
        :return: The name associated with this blob's contents.
        :rtype: str
        """

    def getContentsReader(self) -> ghidra.app.util.bin.BinaryReader:
        """
        Gets a new binary reader positioned at the start of this blob's contents.
        
        :return: A new binary reader positioned at the start of this blob's contents.
        :rtype: ghidra.app.util.bin.BinaryReader
        """

    def getContentsSize(self) -> int:
        """
        Gets the blob's contents size in bytes.
        
        :return: The blob's contents size in bytes.
        :rtype: int
        """

    @staticmethod
    def getDataTypeForBytes(numBytes: typing.Union[jpype.JInt, int]) -> ghidra.program.model.data.DataType:
        ...

    def getName(self) -> str:
        """
        Gets the name of this blob.
        
        :return: The name of this blob.
        :rtype: str
        """

    def getRepresentation(self) -> str:
        """
        Gets the string representation of this blob.
        
        :return: The string representation of this blob.
        :rtype: str
        """

    def getSize(self) -> int:
        """
        Gets the blob's size in bytes (includes all fields).
        
        :return: The blob's size in bytes.
        :rtype: int
        """

    def getSizeDataType(self) -> ghidra.program.model.data.DataType:
        """
        Gets the proper data type for the blob's size field.
        
        :return: The proper data type for the blob's size field.
        :rtype: ghidra.program.model.data.DataType
        """

    def getStreamIndex(self) -> int:
        """
        Gets the index into the blob stream of this blob.
        
        :return: The index into the blob stream of this blob.
        :rtype: int
        """

    def isLittleEndian(self) -> bool:
        """
        Checks to see whether or not this blob is little endian.
        
        :return: True if this blob is little endian; false if big endian.
        :rtype: bool
        """

    @staticmethod
    def testSizeDecoding():
        ...

    def toDataType(self, dtm: ghidra.program.model.data.DataTypeManager) -> ghidra.program.model.data.DataType:
        """
        Create CLI Blob structure.
        NOTE: This form is provided to reduce resolution time when target datatype manager is known.
        
        :param ghidra.program.model.data.DataTypeManager dtm: datatype manager or null if target datatype manager is unknown.
        :return: blob structure
        :rtype: ghidra.program.model.data.DataType
        """

    @property
    def sizeDataType(self) -> ghidra.program.model.data.DataType:
        ...

    @property
    def size(self) -> jpype.JInt:
        ...

    @property
    def contentsSize(self) -> jpype.JInt:
        ...

    @property
    def contentsComment(self) -> java.lang.String:
        ...

    @property
    def contents(self) -> jpype.JArray[jpype.JByte]:
        ...

    @property
    def contentsReader(self) -> ghidra.app.util.bin.BinaryReader:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def contentsName(self) -> java.lang.String:
        ...

    @property
    def littleEndian(self) -> jpype.JBoolean:
        ...

    @property
    def streamIndex(self) -> jpype.JInt:
        ...

    @property
    def contentsDataType(self) -> ghidra.program.model.data.DataType:
        ...

    @property
    def representation(self) -> java.lang.String:
        ...


class CliSigMethodSpec(CliAbstractSig):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, blob: CliBlob):
        ...


class CliSigAssemblyRef(CliAbstractSig):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, blob: CliBlob):
        ...


class CliSigMethodDef(CliAbstractSig):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, blob: CliBlob):
        ...

    def getParamTypes(self) -> jpype.JArray[CliAbstractSig.CliParam]:
        ...

    def getReturnType(self) -> CliAbstractSig.CliRetType:
        ...

    def hasExplicitThis(self) -> bool:
        ...

    def hasGenericArgs(self) -> bool:
        ...

    def hasThis(self) -> bool:
        ...

    def hasVarArgs(self) -> bool:
        ...

    @property
    def paramTypes(self) -> jpype.JArray[CliAbstractSig.CliParam]:
        ...

    @property
    def returnType(self) -> CliAbstractSig.CliRetType:
        ...


class CliSigField(CliAbstractSig):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, blob: CliBlob):
        ...

    def getType(self) -> CliAbstractSig.CliParam:
        ...

    @staticmethod
    def isFieldSig(blob: CliBlob) -> bool:
        """
        Checks whether this could *possibly* be a FieldSig. Only looks at the identifier byte. Useful for signature index
        that could be to different kinds of signatures.
        
        :param CliBlob blob: 
        :return: 
        :rtype: bool
        :raises IOException:
        """

    @property
    def type(self) -> CliAbstractSig.CliParam:
        ...


class CliSigTypeSpec(CliAbstractSig):

    class_: typing.ClassVar[java.lang.Class]
    type: CliAbstractSig.CliSigType

    def __init__(self, blob: CliBlob):
        ...


class CliSigMethodRef(CliAbstractSig):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, blob: CliBlob):
        ...

    def getParams(self) -> jpype.JArray[CliAbstractSig.CliParam]:
        ...

    def getReturnType(self) -> CliAbstractSig.CliRetType:
        ...

    def hasExplicitThis(self) -> bool:
        ...

    def hasThis(self) -> bool:
        ...

    def hasVarArgs(self) -> bool:
        ...

    @property
    def params(self) -> jpype.JArray[CliAbstractSig.CliParam]:
        ...

    @property
    def returnType(self) -> CliAbstractSig.CliRetType:
        ...


class CliAbstractSig(CliBlob, ghidra.app.util.bin.format.pe.cli.CliRepresentable):

    class CliTypeCodeDataType(ghidra.program.model.data.EnumDataType):

        class_: typing.ClassVar[java.lang.Class]
        PATH: typing.Final = "/PE/CLI/Types"
        dataType: typing.Final[CliAbstractSig.CliTypeCodeDataType]

        def __init__(self):
            ...


    class CliElementType(java.lang.Enum[CliAbstractSig.CliElementType]):

        class_: typing.ClassVar[java.lang.Class]
        ELEMENT_TYPE_END: typing.Final[CliAbstractSig.CliElementType]
        ELEMENT_TYPE_VOID: typing.Final[CliAbstractSig.CliElementType]
        ELEMENT_TYPE_BOOLEAN: typing.Final[CliAbstractSig.CliElementType]
        ELEMENT_TYPE_CHAR: typing.Final[CliAbstractSig.CliElementType]
        ELEMENT_TYPE_I1: typing.Final[CliAbstractSig.CliElementType]
        ELEMENT_TYPE_U1: typing.Final[CliAbstractSig.CliElementType]
        ELEMENT_TYPE_I2: typing.Final[CliAbstractSig.CliElementType]
        ELEMENT_TYPE_U2: typing.Final[CliAbstractSig.CliElementType]
        ELEMENT_TYPE_I4: typing.Final[CliAbstractSig.CliElementType]
        ELEMENT_TYPE_U4: typing.Final[CliAbstractSig.CliElementType]
        ELEMENT_TYPE_I8: typing.Final[CliAbstractSig.CliElementType]
        ELEMENT_TYPE_U8: typing.Final[CliAbstractSig.CliElementType]
        ELEMENT_TYPE_R4: typing.Final[CliAbstractSig.CliElementType]
        ELEMENT_TYPE_R8: typing.Final[CliAbstractSig.CliElementType]
        ELEMENT_TYPE_STRING: typing.Final[CliAbstractSig.CliElementType]
        ELEMENT_TYPE_PTR: typing.Final[CliAbstractSig.CliElementType]
        ELEMENT_TYPE_BYREF: typing.Final[CliAbstractSig.CliElementType]
        ELEMENT_TYPE_VALUETYPE: typing.Final[CliAbstractSig.CliElementType]
        ELEMENT_TYPE_CLASS: typing.Final[CliAbstractSig.CliElementType]
        ELEMENT_TYPE_VAR: typing.Final[CliAbstractSig.CliElementType]
        ELEMENT_TYPE_ARRAY: typing.Final[CliAbstractSig.CliElementType]
        ELEMENT_TYPE_GENERICINST: typing.Final[CliAbstractSig.CliElementType]
        ELEMENT_TYPE_TYPEDBYREF: typing.Final[CliAbstractSig.CliElementType]
        ELEMENT_TYPE_I: typing.Final[CliAbstractSig.CliElementType]
        ELEMENT_TYPE_U: typing.Final[CliAbstractSig.CliElementType]
        ELEMENT_TYPE_FNPTR: typing.Final[CliAbstractSig.CliElementType]
        ELEMENT_TYPE_OBJECT: typing.Final[CliAbstractSig.CliElementType]
        ELEMENT_TYPE_SZARRAY: typing.Final[CliAbstractSig.CliElementType]
        ELEMENT_TYPE_MVAR: typing.Final[CliAbstractSig.CliElementType]
        ELEMENT_TYPE_CMOD_REQD: typing.Final[CliAbstractSig.CliElementType]
        ELEMENT_TYPE_CMOD_OPT: typing.Final[CliAbstractSig.CliElementType]
        ELEMENT_TYPE_INTERNAL: typing.Final[CliAbstractSig.CliElementType]
        ELEMENT_TYPE_MAX: typing.Final[CliAbstractSig.CliElementType]
        ELEMENT_TYPE_MODIFIER: typing.Final[CliAbstractSig.CliElementType]
        ELEMENT_TYPE_SENTINEL: typing.Final[CliAbstractSig.CliElementType]
        ELEMENT_TYPE_PINNED: typing.Final[CliAbstractSig.CliElementType]

        @staticmethod
        def fromInt(id: typing.Union[jpype.JInt, int]) -> CliAbstractSig.CliElementType:
            ...

        def id(self) -> int:
            ...

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> CliAbstractSig.CliElementType:
            ...

        @staticmethod
        def values() -> jpype.JArray[CliAbstractSig.CliElementType]:
            ...


    class CliSigType(ghidra.app.util.bin.format.pe.cli.CliRepresentable):

        class_: typing.ClassVar[java.lang.Class]
        PATH: typing.Final = "/PE/CLI/Types"

        def __init__(self, typeCode: CliAbstractSig.CliElementType):
            ...

        def getDefinitionDataType(self) -> ghidra.program.model.data.DataType:
            ...

        def getExecutionDataType(self) -> ghidra.program.model.data.DataType:
            ...

        @property
        def definitionDataType(self) -> ghidra.program.model.data.DataType:
            ...

        @property
        def executionDataType(self) -> ghidra.program.model.data.DataType:
            ...


    class CliTypePrimitive(CliAbstractSig.CliSigType):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, typeCode: CliAbstractSig.CliElementType):
            ...


    class CliTypeArray(CliAbstractSig.CliSigType):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, reader: ghidra.app.util.bin.BinaryReader, typeCode: CliAbstractSig.CliElementType):
            ...


    class CliTypeClass(CliAbstractSig.CliSigType):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, reader: ghidra.app.util.bin.BinaryReader, typeCode: CliAbstractSig.CliElementType):
            ...


    class CliTypeFnPtr(CliAbstractSig.CliSigType):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, reader: ghidra.app.util.bin.BinaryReader, typeCode: CliAbstractSig.CliElementType):
            ...


    class CliTypeGenericInst(CliAbstractSig.CliSigType):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, reader: ghidra.app.util.bin.BinaryReader, typeCode: CliAbstractSig.CliElementType):
            ...


    class CliTypeVarOrMvar(CliAbstractSig.CliSigType):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, reader: ghidra.app.util.bin.BinaryReader, typeCode: CliAbstractSig.CliElementType):
            ...


    class CliTypePtr(CliAbstractSig.CliSigType):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, reader: ghidra.app.util.bin.BinaryReader, typeCode: CliAbstractSig.CliElementType):
            ...

        def getType(self) -> CliAbstractSig.CliSigType:
            ...

        @property
        def type(self) -> CliAbstractSig.CliSigType:
            ...


    class CliTypeSzArray(CliAbstractSig.CliSigType):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, reader: ghidra.app.util.bin.BinaryReader, typeCode: CliAbstractSig.CliElementType):
            ...


    class CliTypeValueType(CliAbstractSig.CliSigType):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, reader: ghidra.app.util.bin.BinaryReader, typeCode: CliAbstractSig.CliElementType):
            ...

        def getRepresentation(self, stream: ghidra.app.util.bin.format.pe.cli.streams.CliStreamMetadata, shortRep: typing.Union[jpype.JBoolean, bool]) -> str:
            ...

        def getRowIndex(self) -> int:
            ...

        def getTable(self) -> ghidra.app.util.bin.format.pe.cli.tables.CliTypeTable:
            ...

        @property
        def rowIndex(self) -> jpype.JInt:
            ...

        @property
        def table(self) -> ghidra.app.util.bin.format.pe.cli.tables.CliTypeTable:
            ...


    class CliCustomMod(ghidra.app.util.bin.format.pe.cli.CliRepresentable):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, reader: ghidra.app.util.bin.BinaryReader):
            ...

        def getCMOD(self) -> CliAbstractSig.CliElementType:
            ...

        def getDefinitionDataType(self) -> ghidra.program.model.data.DataType:
            ...

        def getRow(self, stream: ghidra.app.util.bin.format.pe.cli.streams.CliStreamMetadata) -> ghidra.app.util.bin.format.pe.cli.tables.CliAbstractTableRow:
            ...

        def getRowIndex(self) -> int:
            ...

        def getTable(self) -> ghidra.app.util.bin.format.pe.cli.tables.CliTypeTable:
            ...

        def getTypeEncoded(self) -> int:
            ...

        @staticmethod
        def isCustomMod(reader: ghidra.app.util.bin.BinaryReader) -> bool:
            ...

        @property
        def cMOD(self) -> CliAbstractSig.CliElementType:
            ...

        @property
        def definitionDataType(self) -> ghidra.program.model.data.DataType:
            ...

        @property
        def rowIndex(self) -> jpype.JInt:
            ...

        @property
        def row(self) -> ghidra.app.util.bin.format.pe.cli.tables.CliAbstractTableRow:
            ...

        @property
        def typeEncoded(self) -> jpype.JInt:
            ...

        @property
        def table(self) -> ghidra.app.util.bin.format.pe.cli.tables.CliTypeTable:
            ...


    class CliConstraint(ghidra.app.util.bin.format.pe.cli.CliRepresentable):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, reader: ghidra.app.util.bin.BinaryReader):
            ...

        def getConstraint(self) -> CliAbstractSig.CliElementType:
            ...

        @staticmethod
        def isConstraint(reader: ghidra.app.util.bin.BinaryReader) -> bool:
            ...

        @property
        def constraint(self) -> CliAbstractSig.CliElementType:
            ...


    class CliByRef(ghidra.app.util.bin.format.pe.cli.CliRepresentable):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, reader: ghidra.app.util.bin.BinaryReader):
            ...

        def getByRef(self) -> CliAbstractSig.CliElementType:
            ...

        @staticmethod
        def isByRef(reader: ghidra.app.util.bin.BinaryReader) -> bool:
            ...

        @property
        def byRef(self) -> CliAbstractSig.CliElementType:
            ...


    class CliTypeBase(ghidra.app.util.bin.format.pe.cli.CliRepresentable):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, reader: ghidra.app.util.bin.BinaryReader, isRetType: typing.Union[jpype.JBoolean, bool]):
            ...

        def getCustomMods(self) -> java.util.List[CliAbstractSig.CliCustomMod]:
            ...

        def getDefinitionDataType(self) -> ghidra.program.model.data.DataType:
            ...

        def getExecutionDataType(self) -> ghidra.program.model.data.DataType:
            ...

        def getType(self) -> CliAbstractSig.CliSigType:
            ...

        def isByRef(self) -> bool:
            ...

        def isConstrained(self) -> bool:
            ...

        @property
        def byRef(self) -> jpype.JBoolean:
            ...

        @property
        def customMods(self) -> java.util.List[CliAbstractSig.CliCustomMod]:
            ...

        @property
        def definitionDataType(self) -> ghidra.program.model.data.DataType:
            ...

        @property
        def executionDataType(self) -> ghidra.program.model.data.DataType:
            ...

        @property
        def type(self) -> CliAbstractSig.CliSigType:
            ...

        @property
        def constrained(self) -> jpype.JBoolean:
            ...


    class CliParam(CliAbstractSig.CliTypeBase):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, reader: ghidra.app.util.bin.BinaryReader):
            ...


    class CliRetType(CliAbstractSig.CliTypeBase):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, reader: ghidra.app.util.bin.BinaryReader):
            ...


    class CliArrayShape(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, reader: ghidra.app.util.bin.BinaryReader):
            ...

        def getDefinitionDataType(self) -> ghidra.program.model.data.DataType:
            ...

        def getRepresentation(self) -> str:
            ...

        @property
        def definitionDataType(self) -> ghidra.program.model.data.DataType:
            ...

        @property
        def representation(self) -> java.lang.String:
            ...


    class_: typing.ClassVar[java.lang.Class]
    PATH: typing.Final = "/PE/CLI/Blobs/Signatures"

    def __init__(self, blob: CliBlob):
        ...

    @staticmethod
    def convertTypeCodeToDataType(typeCode: CliAbstractSig.CliElementType) -> ghidra.program.model.data.DataType:
        ...

    def readCliType(self, reader: ghidra.app.util.bin.BinaryReader) -> CliAbstractSig.CliSigType:
        ...


class CliBlobCustomAttrib(CliBlob):

    @typing.type_check_only
    class CliFixedArg(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, elem: CliAbstractSig.CliElementType, value: java.lang.Object):
            ...

        def getElem(self) -> CliAbstractSig.CliElementType:
            ...

        def getValue(self) -> java.lang.Object:
            ...

        @property
        def elem(self) -> CliAbstractSig.CliElementType:
            ...

        @property
        def value(self) -> java.lang.Object:
            ...


    @typing.type_check_only
    class CliNamedArg(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, fieldOrProp: typing.Union[jpype.JInt, int], fieldOrPropType: CliAbstractSig.CliElementType, fieldOrPropName: typing.Union[java.lang.String, str]):
            ...

        def getFieldOrProp(self) -> int:
            ...

        def getFieldOrPropName(self) -> str:
            ...

        def getFieldOrPropType(self) -> CliAbstractSig.CliElementType:
            ...

        @property
        def fieldOrPropName(self) -> java.lang.String:
            ...

        @property
        def fieldOrProp(self) -> jpype.JInt:
            ...

        @property
        def fieldOrPropType(self) -> CliAbstractSig.CliElementType:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, blob: CliBlob, row: ghidra.app.util.bin.format.pe.cli.tables.CliTableCustomAttribute.CliCustomAttributeRow, metadataStream: ghidra.app.util.bin.format.pe.cli.streams.CliStreamMetadata):
        ...



__all__ = ["CliSigConstant", "CliBlobMarshalSpec", "CliSigAssembly", "CliSigProperty", "CliSigLocalVar", "CliSigStandAloneMethod", "CliBlob", "CliSigMethodSpec", "CliSigAssemblyRef", "CliSigMethodDef", "CliSigField", "CliSigTypeSpec", "CliSigMethodRef", "CliAbstractSig", "CliBlobCustomAttrib"]
