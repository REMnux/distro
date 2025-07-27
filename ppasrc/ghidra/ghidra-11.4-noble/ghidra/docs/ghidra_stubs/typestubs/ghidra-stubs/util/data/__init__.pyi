from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.services
import ghidra.program.model.data
import java.lang # type: ignore


class DataTypeParser(java.lang.Object):

    class AllowedDataTypes(java.lang.Enum[DataTypeParser.AllowedDataTypes]):

        class_: typing.ClassVar[java.lang.Class]
        ALL: typing.Final[DataTypeParser.AllowedDataTypes]
        """
        All data-types are permitted (excluding bitfields)
        """

        DYNAMIC: typing.Final[DataTypeParser.AllowedDataTypes]
        """
        All data-types, excluding factory data-types are permitted
        """

        SIZABLE_DYNAMIC: typing.Final[DataTypeParser.AllowedDataTypes]
        """
        All fixed-length data-types and sizable Dynamic(i.e., canSpecifyLength) data-types
        """

        SIZABLE_DYNAMIC_AND_BITFIELD: typing.Final[DataTypeParser.AllowedDataTypes]
        """
        All fixed-length data-types, sizable Dynamic data-types.
        In addition a bitfield specification may be specified (e.g., int:2) 
        for use when defining structure and union components only
        (see :obj:`ProxyBitFieldDataType`).  Parser must be properly constructed
        with the intended :obj:`DataTypeParser.destinationDataTypeManager`.
        If a bitfield is returned special handling is required.
        """

        FIXED_LENGTH: typing.Final[DataTypeParser.AllowedDataTypes]
        """
        Only Fixed-length data-types
        """

        STRINGS_AND_FIXED_LENGTH: typing.Final[DataTypeParser.AllowedDataTypes]
        """
        Only Fixed-length data types and string data types
        """

        BITFIELD_BASE_TYPE: typing.Final[DataTypeParser.AllowedDataTypes]
        """
        Only Enums, Integer types and those Typedefs based on them
        for use as a bitfield base datatype
        """


        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> DataTypeParser.AllowedDataTypes:
            ...

        @staticmethod
        def values() -> jpype.JArray[DataTypeParser.AllowedDataTypes]:
            ...


    @typing.type_check_only
    class ProxyBitFieldDataType(ghidra.program.model.data.BitFieldDataType):
        """
        ``ProxyBitFieldDataType`` provides acts as a proxy bitfield
        whose specification may be used when defining a structure or 
        union bitfield.  This datatype may not be directly applied to a program.
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class DtPiece(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class BitfieldSpecPiece(DataTypeParser.DtPiece):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ArraySpecPiece(DataTypeParser.DtPiece):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class PointerSpecPiece(DataTypeParser.DtPiece):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ElementSizeSpecPiece(DataTypeParser.DtPiece):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, dataTypeManagerService: ghidra.app.services.DataTypeQueryService, allowedTypes: DataTypeParser.AllowedDataTypes):
        """
        A constructor that does not use the source or destination data type managers.  In terms of
        the source data type manager, this means that all data type managers will be used when
        resolving data types.
        
        :param ghidra.app.services.DataTypeQueryService dataTypeManagerService: data-type manager tool service, or null
        :param DataTypeParser.AllowedDataTypes allowedTypes: constrains which data-types may be parsed
        """

    @typing.overload
    def __init__(self, sourceDataTypeManager: ghidra.program.model.data.DataTypeManager, destinationDataTypeManager: ghidra.program.model.data.DataTypeManager, dataTypeManagerService: ghidra.app.services.DataTypeQueryService, allowedTypes: DataTypeParser.AllowedDataTypes):
        """
        Constructor
        
        :param ghidra.program.model.data.DataTypeManager sourceDataTypeManager: preferred source data-type manager, or null
        :param ghidra.program.model.data.DataTypeManager destinationDataTypeManager: target data-type manager, or null
        :param ghidra.app.services.DataTypeQueryService dataTypeManagerService: data-type manager tool service, or null
        :param DataTypeParser.AllowedDataTypes allowedTypes: constrains which data-types may be parsed
        
        .. seealso::
        
            | :obj:`.DataTypeParser(DataTypeQueryService, AllowedDataTypes)`
        """

    @staticmethod
    def ensureIsAllowableType(dt: ghidra.program.model.data.DataType, allowedTypes: DataTypeParser.AllowedDataTypes):
        """
        Throws exception if the data type does not match the specified :obj:`AllowedDataTypes`.
        
        :param ghidra.program.model.data.DataType dt: :obj:`DataType` to check
        :param DataTypeParser.AllowedDataTypes allowedTypes: :obj:`enum <AllowedDataTypes>` specifying what category of data types are ok
        :raises InvalidDataTypeException: if dt violates the specified allowedTypes
        """

    @typing.overload
    def parse(self, dataTypeString: typing.Union[java.lang.String, str]) -> ghidra.program.model.data.DataType:
        """
        Parse a data-type string specification
        
        :param java.lang.String or str dataTypeString: a known data-type name followed by zero or more pointer/array decorations.
        :return: parsed data-type or null if not found
        :rtype: ghidra.program.model.data.DataType
        :raises InvalidDataTypeException: if data-type string is invalid or length exceeds specified maxSize
        :raises CancelledException: parse cancelled through user interaction
        """

    @typing.overload
    def parse(self, dataTypeString: typing.Union[java.lang.String, str], category: ghidra.program.model.data.CategoryPath) -> ghidra.program.model.data.DataType:
        """
        Parse a data type string specification with category path.  If category is not null,
        the dataTypeManagerService will not be queried.
        
        :param java.lang.String or str dataTypeString: a known data-type name followed by zero or more pointer/array decorations.
        :param ghidra.program.model.data.CategoryPath category: known path of data-type or null if unknown
        :return: parsed data-type or null if not found
        :rtype: ghidra.program.model.data.DataType
        :raises InvalidDataTypeException: if data type string is invalid or length exceeds specified 
                maxSize
        :raises CancelledException: parse cancelled through user interaction (only if parser 
                constructed with service)
        """

    @typing.overload
    def parse(self, dataTypeString: typing.Union[java.lang.String, str], suggestedBaseDataType: ghidra.program.model.data.DataType) -> ghidra.program.model.data.DataType:
        """
        Parse a data type string specification using the specified baseDatatype.
        
        :param ghidra.program.model.data.DataType suggestedBaseDataType: base data type (may be null), this will be used as the base 
                data-type if its name matches the base name in the specified dataTypeString.
        :param java.lang.String or str dataTypeString: a base data-type followed by a sequence of zero or more pointer/array 
                decorations to be applied.
        The string may start with the baseDataType's name.
        :return: parsed data-type or null if not found
        :rtype: ghidra.program.model.data.DataType
        :raises InvalidDataTypeException: if data-type string is invalid or length exceeds specified 
                maxSize
        :raises CancelledException: parse cancelled through user interaction (only if parser 
                constructed with service)
        """



__all__ = ["DataTypeParser"]
