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
import java.util # type: ignore


class ClassUtils(java.lang.Object):
    """
    Utility class for Class-related software modeling.
     
    
    This class is experimental and subject to unannounced changes, including changes to processing
    philosophies and removal of methods
    """

    class NameAndPointer(java.lang.Record):
        """
        Record containing a name and a pointer data type
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, name: typing.Union[java.lang.String, str], pointer: ghidra.program.model.data.DataType) -> None:
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def name(self) -> str:
            ...

        def pointer(self) -> ghidra.program.model.data.DataType:
            ...

        def toString(self) -> str:
            ...


    class_: typing.ClassVar[java.lang.Class]
    VTABLE: typing.Final = "vtable"
    """
    Standard field name for a class virtual table
    """

    VBTABLE: typing.Final = "vbtable"
    """
    Standard field name for a class virtual base table
    """

    VFTABLE: typing.Final = "vftable"
    """
    Standard field name for a class virtual function table
    """

    VTPTR: typing.Final = "vtptr"
    """
    Standard field name for a virtual table pointer found within a class
    """

    VBPTR: typing.Final = "vbptr"
    """
    Standard field name for a virtual base table pointer found within a class
    """

    VFPTR: typing.Final = "vfptr"
    """
    Standard field name for a virtual function table pointer found within a class
    """

    VXPTR_TYPE: typing.Final[ghidra.program.model.data.PointerDataType]
    """
    Type used for :obj:`.VBPTR` and :obj:`.VFPTR` fields in a class
    """


    @staticmethod
    def createVxTableDescriptionOffsetTag(ptrOffsetInClass: typing.Union[jpype.JLong, int]) -> str:
        """
        Provides the __TEMPORARY__ standard special Description string for a virtual table (e.g.,
        vtable, vbtable, vftable) that is keyed off of by the Decompiler during flattening and
        replacement of types within a class structure.  This is __TEMPORARY__ in that we hope
        to use some special attribute in the future.  More details to come
        
        :param jpype.JLong or int ptrOffsetInClass: the offset of the special field within the class
        :return: the special name
        :rtype: str
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
        Returns the category path for class internals
        
        :param ghidra.program.model.data.Composite composite: the class composite
        :return: the category path
        :rtype: ghidra.program.model.data.CategoryPath
        """

    @staticmethod
    @typing.overload
    def getClassInternalsPath(category: ghidra.program.model.data.CategoryPath) -> ghidra.program.model.data.CategoryPath:
        """
        Returns the category path for class internals for the Class CategoryPath
        
        :param ghidra.program.model.data.CategoryPath category: the class category path
        :return: the category path
        :rtype: ghidra.program.model.data.CategoryPath
        """

    @staticmethod
    @typing.overload
    def getClassInternalsPath(id: ClassID) -> ghidra.program.model.data.CategoryPath:
        """
        Returns the category path for class internals for the ClassID
        
        :param ClassID id: the class ID
        :return: the category path
        :rtype: ghidra.program.model.data.CategoryPath
        """

    @staticmethod
    @typing.overload
    def getClassInternalsPath(path: ghidra.program.model.data.CategoryPath, className: typing.Union[java.lang.String, str]) -> ghidra.program.model.data.CategoryPath:
        """
        Returns the category path for class internals
        
        :param ghidra.program.model.data.CategoryPath path: the category path of the class composite
        :param java.lang.String or str className: the name of the class
        :return: the category path
        :rtype: ghidra.program.model.data.CategoryPath
        """

    @staticmethod
    @typing.overload
    def getClassPath(composite: ghidra.program.model.data.Composite) -> ghidra.program.model.data.CategoryPath:
        """
        Returns the category path for items belonging to this class, such as vxtables
        
        :param ghidra.program.model.data.Composite composite: the class composite
        :return: the category path
        :rtype: ghidra.program.model.data.CategoryPath
        """

    @staticmethod
    @typing.overload
    def getClassPath(id: ClassID) -> ghidra.program.model.data.CategoryPath:
        """
        Returns the category path for class for the ClassID
        
        :param ClassID id: the class ID
        :return: the category path
        :rtype: ghidra.program.model.data.CategoryPath
        """

    @staticmethod
    def getReplacementPointers(dtm: ghidra.program.model.data.DataTypeManager, type: ghidra.program.model.data.Structure) -> java.util.Map[java.lang.Long, ghidra.program.model.data.Pointer]:
        """
        Finds and returns list of replacement pointer types for the specified owner class structure
        
        :param ghidra.program.model.data.DataTypeManager dtm: the data type manager
        :param ghidra.program.model.data.Structure type: the class structure type
        :return: the map of offset to owner replacement types
        :rtype: java.util.Map[java.lang.Long, ghidra.program.model.data.Pointer]
        """

    @staticmethod
    @typing.overload
    def getReplacementType(component: ghidra.program.model.data.DataTypeComponent, accumulatedOffset: typing.Union[jpype.JLong, int], ownerVxtptrs: collections.abc.Mapping) -> ClassUtils.NameAndPointer:
        """
        Tries to provide an appropriate data type replacement for special components, particularly
        for class objects such as virtual function table and virtual base table pointers within
        a flattened class structure
        
        :param ghidra.program.model.data.DataTypeComponent component: the component to be checked
        :param jpype.JLong or int accumulatedOffset: the accumulated offset of the component due to flattening
        :param collections.abc.Mapping ownerVxtptrs: the map of offset to owner vxtptr types
        :return: the replacement data type or the original type if there is no replacement needed
        :rtype: ClassUtils.NameAndPointer
        """

    @staticmethod
    @typing.overload
    def getReplacementType(structure: ghidra.program.model.data.Structure, enabled: typing.Union[jpype.JBoolean, bool]) -> ghidra.program.model.data.Structure:
        """
        Tries to provide an appropriate data type replacement for special components, particularly
        for class objects such as virtual function table and virtual base table pointers within
        a flattened class structure.  The ``structure`` argument becomes the return type if
        ``enabled`` is ``false``, if the argument structure does not have class
        attributes, or if there is no suitable replacement for it
        
        :param ghidra.program.model.data.Structure structure: the structure to process
        :param jpype.JBoolean or bool enabled: ``false`` will immediately return the argument type
        :return: the replacement data type or null if could not or did not need to be replaced
        :rtype: ghidra.program.model.data.Structure
        """

    @staticmethod
    @typing.overload
    def getReplacementType(structure: ghidra.program.model.data.Structure) -> ghidra.program.model.data.Structure:
        """
        Tries to provide an appropriate data type replacement for special components, particularly
        for class objects such as virtual function table and virtual base table pointers within
        a flattened class structure
        
        :param ghidra.program.model.data.Structure structure: the structure to process
        :return: the replacement data type or null if could not or did not need to be replaced
        :rtype: ghidra.program.model.data.Structure
        """

    @staticmethod
    @typing.overload
    def getSelfBaseType(composite: ghidra.program.model.data.Composite) -> ghidra.program.model.data.Composite:
        """
        Returns the "self-base" composite for the specified class composite.  This could be
        the composite argument itself of could be a component of it
        
        :param ghidra.program.model.data.Composite composite: the main class type
        :return: the self-base composite
        :rtype: ghidra.program.model.data.Composite
        """

    @staticmethod
    @typing.overload
    def getSelfBaseType(dtm: ghidra.program.model.data.DataTypeManager, id: ClassID) -> ghidra.program.model.data.Composite:
        """
        Returns the "self-base" composite for the specified class ID
        
        :param ghidra.program.model.data.DataTypeManager dtm: the data type manager
        :param ClassID id: the class id
        :return: the self-base composite
        :rtype: ghidra.program.model.data.Composite
        """

    @staticmethod
    def getVbtDefaultEntry(dtm: ghidra.program.model.data.DataTypeManager) -> ghidra.program.model.data.DataType:
        """
        Returns a default data type for a VBT
        
        :param ghidra.program.model.data.DataTypeManager dtm: the data type manager
        :return: the data type
        :rtype: ghidra.program.model.data.DataType
        """

    @staticmethod
    def getVbtEntrySize(dtm: ghidra.program.model.data.DataTypeManager) -> int:
        """
        Returns the size of the default data type for a VBT entry
        
        :param ghidra.program.model.data.DataTypeManager dtm: the data type manager
        :return: the size
        :rtype: int
        """

    @staticmethod
    def getVftDefaultEntry(dtm: ghidra.program.model.data.DataTypeManager) -> ghidra.program.model.data.PointerDataType:
        """
        Returns a default data type for a VFT
        
        :param ghidra.program.model.data.DataTypeManager dtm: the data type manager
        :return: the pointer data type
        :rtype: ghidra.program.model.data.PointerDataType
        """

    @staticmethod
    def getVftEntrySize(dtm: ghidra.program.model.data.DataTypeManager) -> int:
        """
        Returns the size of the default pointer data type for a VFT entry
        
        :param ghidra.program.model.data.DataTypeManager dtm: the data type manager
        :return: the size
        :rtype: int
        """

    @staticmethod
    def hasClassAttribute(structure: ghidra.program.model.data.Structure) -> bool:
        """
        This method returns true if the argument structure has a class attribute
        
        :param ghidra.program.model.data.Structure structure: the structure under question
        :return: ``true`` if has a class attribute
        :rtype: bool
        """

    @staticmethod
    def isVTable(type: ghidra.program.model.data.DataType) -> bool:
        """
        Indicates whether a label satisfies the format of a vxtable label
        
        :param ghidra.program.model.data.DataType type: the data type
        :return: ``true`` if is a vxtable label format
        :rtype: bool
        """

    @staticmethod
    def validateVtableDescriptionOffsetTag(description: typing.Union[java.lang.String, str]) -> int:
        """
        Validates a Vtable description and returns the encoded offset value
        
        :param java.lang.String or str description: the description string
        :return: the offset or ``null`` if invalid name
        :rtype: int
        """


class ClassID(java.lang.Comparable[ClassID]):
    """
    Unique ID of a Program Class Type.  Not sure if there will be different implementation for
    definition vs. compiled vs. program vs. debug.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, categoryPath: ghidra.program.model.data.CategoryPath, symbolPath: ghidra.app.util.SymbolPath) -> None:
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
