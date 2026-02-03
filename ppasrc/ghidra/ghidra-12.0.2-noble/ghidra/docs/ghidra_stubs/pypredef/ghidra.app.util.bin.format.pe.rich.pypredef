from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.program.model.data
import java.lang # type: ignore
import java.util # type: ignore
import org.xml.sax # type: ignore


class MSProductType(java.lang.Enum[MSProductType]):

    class_: typing.ClassVar[java.lang.Class]
    CXX_Compiler: typing.Final[MSProductType]
    C_Compiler: typing.Final[MSProductType]
    Assembler: typing.Final[MSProductType]
    Import: typing.Final[MSProductType]
    Export: typing.Final[MSProductType]
    ImportExport: typing.Final[MSProductType]
    Linker: typing.Final[MSProductType]
    CVTRes: typing.Final[MSProductType]
    Unknown: typing.Final[MSProductType]

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> MSProductType:
        ...

    @staticmethod
    def values() -> jpype.JArray[MSProductType]:
        ...


class RichHeaderUtils(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def getProduct(id: typing.Union[jpype.JInt, int]) -> RichProduct:
        ...


@typing.type_check_only
class MSRichProductInfoDataType(ghidra.program.model.data.StructureDataType):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, compid: CompId):
        ...

    @typing.overload
    def __init__(self, compid: CompId, dtm: ghidra.program.model.data.DataTypeManager):
        ...


@typing.type_check_only
class RichObjectCountDataType(ghidra.program.model.data.DataTypeImpl):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, count: typing.Union[jpype.JInt, int]):
        ...

    @typing.overload
    def __init__(self, count: typing.Union[jpype.JInt, int], dtm: ghidra.program.model.data.DataTypeManager):
        ...


class RichHeaderRecord(java.lang.Object):
    """
    An element of a :obj:`RichTable`
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, recordIndex: typing.Union[jpype.JInt, int], compid: typing.Union[jpype.JInt, int], count: typing.Union[jpype.JInt, int]):
        ...

    def getCompId(self) -> CompId:
        ...

    def getIndex(self) -> int:
        ...

    def getObjectCount(self) -> int:
        ...

    @property
    def objectCount(self) -> jpype.JInt:
        ...

    @property
    def compId(self) -> CompId:
        ...

    @property
    def index(self) -> jpype.JInt:
        ...


class RichProduct(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, compid: typing.Union[jpype.JInt, int], version: typing.Union[java.lang.String, str], type: MSProductType):
        ...

    def getCompid(self) -> CompId:
        ...

    def getProductType(self) -> MSProductType:
        ...

    def getProductVersion(self) -> str:
        ...

    @property
    def productVersion(self) -> java.lang.String:
        ...

    @property
    def compid(self) -> CompId:
        ...

    @property
    def productType(self) -> MSProductType:
        ...


class PERichTableDataType(ghidra.program.model.data.DynamicDataType):

    @typing.type_check_only
    class PERichDanSDataType(ghidra.program.model.data.BuiltIn):

        class_: typing.ClassVar[java.lang.Class]

        @typing.overload
        def __init__(self, mask: typing.Union[jpype.JInt, int]):
            ...

        @typing.overload
        def __init__(self, dtm: ghidra.program.model.data.DataTypeManager, mask: typing.Union[jpype.JInt, int]):
            ...


    @typing.type_check_only
    class PERichSignatureDataType(ghidra.program.model.data.BuiltIn):

        class_: typing.ClassVar[java.lang.Class]

        @typing.overload
        def __init__(self):
            ...

        @typing.overload
        def __init__(self, dtm: ghidra.program.model.data.DataTypeManager):
            ...


    @typing.type_check_only
    class PERichXorDataType(ghidra.program.model.data.BuiltIn):

        class_: typing.ClassVar[java.lang.Class]

        @typing.overload
        def __init__(self, mask: typing.Union[jpype.JInt, int]):
            ...

        @typing.overload
        def __init__(self, dtm: ghidra.program.model.data.DataTypeManager, mask: typing.Union[jpype.JInt, int]):
            ...


    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, dtm: ghidra.program.model.data.DataTypeManager):
        ...


@typing.type_check_only
class MSRichProductIDDataType(ghidra.program.model.data.DataTypeImpl):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, compid: CompId):
        ...

    @typing.overload
    def __init__(self, compid: CompId, dtm: ghidra.program.model.data.DataTypeManager):
        ...


@typing.type_check_only
class RichTableRecordDataType(ghidra.program.model.data.StructureDataType):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, record: RichHeaderRecord):
        ...

    @typing.overload
    def __init__(self, dtm: ghidra.program.model.data.DataTypeManager, record: RichHeaderRecord):
        ...


class CompId(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, id: typing.Union[jpype.JInt, int]):
        ...

    def getBuildNumber(self) -> int:
        ...

    def getProductDescription(self) -> str:
        ...

    def getProductId(self) -> int:
        ...

    def getValue(self) -> int:
        ...

    @property
    def productId(self) -> jpype.JInt:
        ...

    @property
    def value(self) -> jpype.JInt:
        ...

    @property
    def buildNumber(self) -> jpype.JInt:
        ...

    @property
    def productDescription(self) -> java.lang.String:
        ...


@typing.type_check_only
class MSRichProductBuildNumberDataType(ghidra.program.model.data.DataTypeImpl):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, compid: CompId):
        ...

    @typing.overload
    def __init__(self, compid: CompId, dtm: ghidra.program.model.data.DataTypeManager):
        ...


@typing.type_check_only
class RichProductIdLoader(java.lang.Object):

    @typing.type_check_only
    class XMLErrorHandler(org.xml.sax.ErrorHandler):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def loadProductIdStore() -> java.util.Map[java.lang.Integer, RichProduct]:
        ...



__all__ = ["MSProductType", "RichHeaderUtils", "MSRichProductInfoDataType", "RichObjectCountDataType", "RichHeaderRecord", "RichProduct", "PERichTableDataType", "MSRichProductIDDataType", "RichTableRecordDataType", "CompId", "MSRichProductBuildNumberDataType", "RichProductIdLoader"]
