from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.util
import ghidra.program.model.data
import java.lang # type: ignore


class ClassUtils(java.lang.Object):
    """
    Utility class for Class-related software modeling.
    """

    class_: typing.ClassVar[java.lang.Class]
    VBPTR: typing.Final = "{vbptr}"
    """
    Standard field name for a virtual base table pointer found within a class
    """

    VFPTR: typing.Final = "{vfptr}"
    """
    Standard field name for a virtual function table pointer found within a class
    """

    VXPTR_TYPE: typing.Final[ghidra.program.model.data.PointerDataType]
    """
    Type used for :obj:`.VBPTR` and :obj:`.VFPTR` fields in a class
    """


    @staticmethod
    def getBaseClassDataTypePath(composite: ghidra.program.model.data.Composite) -> ghidra.program.model.data.DataTypePath:
        """
        Returns the data type path for a suitable base class
        
        :param ghidra.program.model.data.Composite composite: the class composite
        :return: the base class data type path
        :rtype: ghidra.program.model.data.DataTypePath
        """

    @staticmethod
    @typing.overload
    def getClassInternalsPath(composite: ghidra.program.model.data.Composite) -> ghidra.program.model.data.CategoryPath:
        """
        Returns the category for class internals
        
        :param ghidra.program.model.data.Composite composite: the class composite
        :return: the category path
        :rtype: ghidra.program.model.data.CategoryPath
        """

    @staticmethod
    @typing.overload
    def getClassInternalsPath(id: ClassID) -> ghidra.program.model.data.CategoryPath:
        """
        Returns the category for class internals for the ClassID
        
        :param ClassID id: the class ID
        :return: the category path
        :rtype: ghidra.program.model.data.CategoryPath
        """

    @staticmethod
    @typing.overload
    def getClassInternalsPath(path: ghidra.program.model.data.CategoryPath, className: typing.Union[java.lang.String, str]) -> ghidra.program.model.data.CategoryPath:
        """
        Returns the category for class internals
        
        :param ghidra.program.model.data.CategoryPath path: the category path of the class composite
        :param java.lang.String or str className: the name of the class
        :return: the category path
        :rtype: ghidra.program.model.data.CategoryPath
        """

    @staticmethod
    def getSelfBaseType(composite: ghidra.program.model.data.Composite) -> ghidra.program.model.data.Composite:
        """
        Returns the "self-base" composite for the specified class composite.  This could be
        the composite argument itself of could be a component of it
        
        :param ghidra.program.model.data.Composite composite: the main class type
        :return: the self-base composite
        :rtype: ghidra.program.model.data.Composite
        """

    @staticmethod
    def getSpecialVxTableName(ptrOffsetInClass: typing.Union[jpype.JLong, int]) -> str:
        """
        Provides the standard special name for a virtual table (e.g., vbtable, vftable) that is
        keyed off of by the Decompiler during flattening and replacing of types within a class
        structure.  More details to come
        
        :param jpype.JLong or int ptrOffsetInClass: the offset of the special field within the class
        :return: the special name
        :rtype: str
        """

    @staticmethod
    def getVbtDefaultEntry(dtm: ghidra.program.model.data.DataTypeManager) -> ghidra.program.model.data.DataType:
        ...

    @staticmethod
    def getVbtEntrySize(dtm: ghidra.program.model.data.DataTypeManager) -> int:
        ...

    @staticmethod
    def getVftDefaultEntry(dtm: ghidra.program.model.data.DataTypeManager) -> ghidra.program.model.data.DataType:
        ...

    @staticmethod
    def getVftEntrySize(dtm: ghidra.program.model.data.DataTypeManager) -> int:
        ...

    @staticmethod
    def isVTable(type: ghidra.program.model.data.DataType) -> bool:
        """
        Indicates whether a label satisfies the format of a vxtable label
        
        :param ghidra.program.model.data.DataType type: the data type
        :return: ``true`` if is a vxtable label format
        :rtype: bool
        """


class ClassID(java.lang.Comparable[ClassID]):
    """
    Unique ID of a Program Class Type.  Not sure if there will be different implementation for
    definition vs. compiled vs. program vs. debug.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, categoryPath: ghidra.program.model.data.CategoryPath, symbolPath: ghidra.app.util.SymbolPath):
        """
        Constructor
        
        :param ghidra.program.model.data.CategoryPath categoryPath: the category path for the claass
        :param ghidra.app.util.SymbolPath symbolPath: the symbol path for the class
        """

    def getCategoryPath(self) -> ghidra.program.model.data.CategoryPath:
        """
        Returns the category path
        
        :return: the category path
        :rtype: ghidra.program.model.data.CategoryPath
        """

    def getSymbolPath(self) -> ghidra.app.util.SymbolPath:
        """
        Returns the symbol path
        
        :return: the symbol path
        :rtype: ghidra.app.util.SymbolPath
        """

    @property
    def categoryPath(self) -> ghidra.program.model.data.CategoryPath:
        ...

    @property
    def symbolPath(self) -> ghidra.app.util.SymbolPath:
        ...



__all__ = ["ClassUtils", "ClassID"]
