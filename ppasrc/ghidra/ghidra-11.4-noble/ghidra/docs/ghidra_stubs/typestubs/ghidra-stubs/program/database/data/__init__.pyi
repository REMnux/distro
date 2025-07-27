from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import db
import db.util
import ghidra
import ghidra.docking.settings
import ghidra.framework.data
import ghidra.program.database
import ghidra.program.database.map
import ghidra.program.database.util
import ghidra.program.model.address
import ghidra.program.model.data
import ghidra.program.model.listing
import ghidra.program.model.mem
import ghidra.program.model.symbol
import ghidra.util
import ghidra.util.datastruct
import ghidra.util.task
import java.io # type: ignore
import java.lang # type: ignore
import java.util # type: ignore
import javax.swing # type: ignore


K = typing.TypeVar("K")
T = typing.TypeVar("T")
V = typing.TypeVar("V")


class PointerTypedefInspector(java.lang.Object):
    """
    ``PointerTypeDefInspector`` provides utilities for inspecting :obj:`Pointer` - :obj:`TypeDef`s.  
    These special typedefs allow a modified-pointer datatype to be used for special situations where
    a simple pointer will not suffice and special stored pointer interpretation/handling is required.  
     
    
    The various :obj:`Pointer` modifiers on the associated :obj:`TypeDef` are achieved through the use of various
    :obj:`TypeDefSettingsDefinition`.  The :obj:`PointerTypedefBuilder` may be used to simplify the creation
    of these pointer-typedefs.
    """

    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def getPointerAddressSpace(pointerTypeDef: ghidra.program.model.data.TypeDef, addrFactory: ghidra.program.model.address.AddressFactory) -> ghidra.program.model.address.AddressSpace:
        """
        Determine the referenced address space for specified pointerTypeDef based upon
        its default settings.
        
        :param ghidra.program.model.data.TypeDef pointerTypeDef: Pointer TypeDef
        :param ghidra.program.model.address.AddressFactory addrFactory: target address factory
        :return: referenced address space or null if not specified or address space
        lookup fails.
        :rtype: ghidra.program.model.address.AddressSpace
        """

    @staticmethod
    def getPointerBitMask(pointerTypeDef: ghidra.program.model.data.TypeDef) -> int:
        """
        Determine the pointer bit-mask for the specified pointerTypeDef based upon
        its default settings. If specified, bit-mask will be AND-ed with stored 
        offset prior to any specified bit-shift.
        
        :param ghidra.program.model.data.TypeDef pointerTypeDef: Pointer TypeDef
        :return: pointer bit-shift or 0 if unspecified or not applicable
        :rtype: int
        """

    @staticmethod
    def getPointerBitShift(pointerTypeDef: ghidra.program.model.data.TypeDef) -> int:
        """
        Determine the pointer bit-shift for the specified pointerTypeDef based upon
        its default settings. A right-shift is specified by a positive value while
        a left-shift is specified by a negative value.
        If specified, bit-shift will be applied after applying any specified bit-mask.
        
        :param ghidra.program.model.data.TypeDef pointerTypeDef: Pointer TypeDef
        :return: pointer bit-shift or 0 if unspecified or not applicable
        :rtype: int
        """

    @staticmethod
    def getPointerComponentOffset(pointerTypeDef: ghidra.program.model.data.TypeDef) -> int:
        """
        Determine the component-offset for the specified pointerTypeDef based upon
        its default settings.
        
        :param ghidra.program.model.data.TypeDef pointerTypeDef: Pointer TypeDef
        :return: pointer component offset or 0 if unspecified or not applicable
        :rtype: int
        """

    @staticmethod
    def getPointerType(pointerTypeDef: ghidra.program.model.data.TypeDef) -> ghidra.program.model.data.PointerType:
        """
        Get the pointer type (see :obj:`PointerType`).
        
        :param ghidra.program.model.data.TypeDef pointerTypeDef: Pointer TypeDef
        :return: pointer type or null if not a pointer
        :rtype: ghidra.program.model.data.PointerType
        """

    @staticmethod
    def hasPointerBitMask(pointerTypeDef: ghidra.program.model.data.TypeDef) -> bool:
        """
        Determine if the specified pointerTypeDef has a pointer bit-mask specified.
        
        :param ghidra.program.model.data.TypeDef pointerTypeDef: Pointer TypeDef
        :return: true if a bit-mask setting exists, else false
        :rtype: bool
        """

    @staticmethod
    def hasPointerBitShift(pointerTypeDef: ghidra.program.model.data.TypeDef) -> bool:
        """
        Determine if the specified pointerTypeDef has a pointer bit-shift specified.
        
        :param ghidra.program.model.data.TypeDef pointerTypeDef: Pointer TypeDef
        :return: true if non-zero bit-shift setting exists, else false
        :rtype: bool
        """


@typing.type_check_only
class UnionDB(CompositeDB, ghidra.program.model.data.UnionInternal):
    """
    Database implementation for the Union data type.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, dataMgr: DataTypeManagerDB, cache: ghidra.program.database.DBObjectCache[DataTypeDB], compositeAdapter: CompositeDBAdapter, componentAdapter: ComponentDBAdapter, record: db.DBRecord):
        """
        Constructor
        
        :param DataTypeManagerDB dataMgr: 
        :param ghidra.program.database.DBObjectCache[DataTypeDB] cache: 
        :param CompositeDBAdapter compositeAdapter: 
        :param ComponentDBAdapter componentAdapter: 
        :param db.DBRecord record:
        """


@typing.type_check_only
class ComponentDBAdapterV0(ComponentDBAdapter):
    """
    Version 0 implementation for accessing the Component database table.
    """

    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class ParameterDefinitionDB(ghidra.program.model.data.ParameterDefinition):
    """
    Database implementation for a Parameter.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getParent(self) -> ghidra.program.model.data.FunctionDefinition:
        ...

    @property
    def parent(self) -> ghidra.program.model.data.FunctionDefinition:
        ...


@typing.type_check_only
class DataTypeDB(ghidra.program.database.DatabaseObject, ghidra.program.model.data.DataType):
    """
    Base class for data types that are Database objects.
    """

    class_: typing.ClassVar[java.lang.Class]

    def setDescription(self, description: typing.Union[java.lang.String, str]):
        """
        Sets a String briefly describing this DataType. 
        
        If a data type that extends this class wants to allow the description to be changed, then it
        must override this method.
        
        :param java.lang.String or str description: a one-liner describing this DataType.
        """

    def setValue(self, buf: ghidra.program.model.mem.MemBuffer, settings: ghidra.docking.settings.Settings, length: typing.Union[jpype.JInt, int], value: java.lang.Object):
        """
        Set the data in the form of the appropriate Object for this DataType.
        
        :param ghidra.program.model.mem.MemBuffer buf: the data buffer.
        :param ghidra.docking.settings.Settings settings: the display settings for the current value.
        :param jpype.JInt or int length: the number of bytes to set the value from.
        :param java.lang.Object value: the new value to set object
        """


@typing.type_check_only
class FunctionParameterAdapterV0(FunctionParameterAdapter, db.RecordTranslator):
    """
    Version 0 implementation for accessing the Function Definition Parameters database table.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, handle: db.DBHandle):
        """
        Gets a version 0 adapter for the Function Definition Parameter database table.
        
        :param db.DBHandle handle: handle to the database containing the table.
        :raises VersionException: if the table's version does not match the expected version
        for this adapter.
        """


@typing.type_check_only
class CompositeDBAdapterV2V4(CompositeDBAdapter, db.RecordTranslator):
    """
    Version 2-4 implementation for accessing the Composite database table.
    """

    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class ParentChildDBAdapterV0(ParentChildAdapter):
    """
    Version 0 implementation for accessing the datatype parent/child database table. 
     
    NOTE: Use of tablePrefix introduced with this adapter version.
    """

    class_: typing.ClassVar[java.lang.Class]

    def setNeedsInitializing(self):
        ...


class DataTypeManagerDB(ghidra.program.model.data.DataTypeManager):
    """
    Base class for DB-backed data type managers. 
    
    Important Notes:
     
    * When invoking :meth:`DataType.isEquivalent(DataType) <DataType.isEquivalent>` involving
    DataTypeDB objects it is important to invoke the method on DataTypeDB. This
    will ensure that the internal optimization mechanisms are used.
    * It is important that the use of :meth:`DataType.clone(DataTypeManager) <DataType.clone>`
    and:meth:`DataType.copy(DataTypeManager) <DataType.copy>` be avoided when possible to ensure
    full benefit of the:obj:`.equivalenceCache` and :obj:`.resolveCache`.
    """

    @typing.type_check_only
    class ResolvePair(java.lang.Comparable[DataTypeManagerDB.ResolvePair]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class DataTypeIterator(java.util.Iterator[T], typing.Generic[T]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class DedupedConflicts(java.lang.Record):

        class_: typing.ClassVar[java.lang.Class]

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def processCnt(self) -> int:
            ...

        def replaceCnt(self) -> int:
            ...

        def toString(self) -> str:
            ...


    @typing.type_check_only
    class EquivalenceCache(java.lang.Object):
        """
        ``EquivalenceCache`` - DataTypeDB equivalence cache
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class IdsToDataTypeMap(java.lang.Object):
        """
        ``IdsToDataTypeMap`` - DataType resolve cache map
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class DbErrorHandler(db.util.ErrorHandler):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]
    UNKNOWN_CALLING_CONVENTION_ID: typing.Final = 0
    DEFAULT_CALLING_CONVENTION_ID: typing.Final = 1

    def dataTypeChanged(self, dt: ghidra.program.model.data.DataType, isAutoChange: typing.Union[jpype.JBoolean, bool]):
        """
        Notification when data type is changed.
        
        :param ghidra.program.model.data.DataType dt: data type that is changed
        :param jpype.JBoolean or bool isAutoChange: true if change was an automatic change in response to
        another datatype's change (e.g., size, alignment).
        """

    def dataTypeSettingsChanged(self, dt: ghidra.program.model.data.DataType):
        """
        Notification when data type settings have changed.
        
        :param ghidra.program.model.data.DataType dt: data type that is changed
        """

    def dbError(self, e: java.io.IOException):
        """
        Handles IOExceptions
        
        :param java.io.IOException e: the exception to handle
        """

    def dedupeAllConflicts(self, monitor: ghidra.util.task.TaskMonitor):
        """
        De-duplicate equivalent conflict datatypes which share a common base data type name and
        are found to be equivalent.
        
        :param ghidra.util.task.TaskMonitor monitor: task monitor
        :raises CancelledException: if task is cancelled
        """

    def dedupeConflicts(self, dataType: ghidra.program.model.data.DataType) -> bool:
        """
        De-duplicate equivalent conflict datatypes which share a common base data type name and
        are found to be equivalent.
        
        :param ghidra.program.model.data.DataType dataType: data type whose related conflict types should be de-duplicated
        :return: true if one or more datatypes were de-duplicted or dde-conflicted, else false
        :rtype: bool
        """

    def dispose(self):
        ...

    def fixupComposites(self, monitor: ghidra.util.task.TaskMonitor):
        """
        Fixup all composites and thier components which may be affected by a data organization
        change include primitive type size changes and alignment changes.  It is highly recommended
        that this program be open with exclusive access before invoking this method to avoid 
        excessive merge conflicts with other users.
        
        :param ghidra.util.task.TaskMonitor monitor: task monitor
        :raises CancelledException: if processing cancelled - data types may not properly reflect
        updated compiler specification
        """

    def getCallingConventionID(self, name: typing.Union[java.lang.String, str], restrictive: typing.Union[jpype.JBoolean, bool]) -> int:
        """
        Get (and assign if needed thus requiring open transaction) the ID associated with the 
        specified calling convention name.  If name is a new convention and the number of stored
        convention names exceeds 127 the returned ID will correspond to the unknown calling 
        convention.
        
        :param java.lang.String or str name: calling convention name
        :param jpype.JBoolean or bool restrictive: if true an error will be thrown if name is not defined by 
        :obj:`GenericCallingConvention` or the associated compiler specification if 
        datatype manager has an associated program architecture.
        :return: calling convention ID
        :rtype: int
        :raises IOException: if database IO error occurs
        :raises InvalidInputException: if restrictive is true and name is not defined by 
        :obj:`GenericCallingConvention` or the associated compiler specification if 
        datatype manager has an associated program architecture.
        """

    def getCallingConventionName(self, id: typing.Union[jpype.JByte, int]) -> str:
        """
        Get calling convention name corresponding to existing specified id.
        
        :param jpype.JByte or int id: calling convention ID
        :return: calling convention name if found else unknown
        :rtype: str
        """

    def getCategory(self, id: typing.Union[jpype.JLong, int]) -> ghidra.program.model.data.Category:
        """
        Get the category for the given ID.
        
        :return: null if no category exists with the given ID.
        :rtype: ghidra.program.model.data.Category
        """

    def getDataTypes(self, path: ghidra.program.model.data.CategoryPath) -> jpype.JArray[ghidra.program.model.data.DataType]:
        """
        Gets the datatypes in the given category path
        
        :param ghidra.program.model.data.CategoryPath path: the category path in which to look for datatypes
        :return: array of datatypes contained with specified category
        :rtype: jpype.JArray[ghidra.program.model.data.DataType]
        """

    def getSourceArchive(self, fileID: typing.Union[java.lang.String, str]) -> ghidra.program.model.data.SourceArchive:
        ...

    @typing.overload
    def getUnusedConflictName(self, dt: ghidra.program.model.data.DataType) -> str:
        """
        This method gets a ".conflict" name that is not currently used by any data
        types in the datatype's category within this data type manager.  If the baseName without
        conflict suffix is not used that name will be returned.
         
        
        NOTE: The original datatype name will be returned unchanged for pointers and arrays since 
        they cannot be renamed.
        
        :param ghidra.program.model.data.DataType dt: datatype who name is used to establish non-conflict base name
        :return: the unused conflict name or original name for datatypes whose name is automatic
        :rtype: str
        """

    @typing.overload
    def getUnusedConflictName(self, path: ghidra.program.model.data.CategoryPath, dt: ghidra.program.model.data.DataType) -> str:
        """
        This method gets a ".conflict" name that is not currently used by any data
        types in the indicated category within this data type manager.  If the baseName without
        conflict suffix is not used that name will be returned.
         
        
        NOTE: The original datatype name will be returned unchanged for pointers and arrays since 
        they cannot be renamed.
         
        
        NOTE: Otherwise, if category does not exist the non-conflict name will be returned.
        
        :param ghidra.program.model.data.CategoryPath path: the category path of the category where the new data type live in
                    the data type manager.
        :param ghidra.program.model.data.DataType dt: datatype who name is used to establish non-conflict base name
        :return: the unused conflict name
        :rtype: str
        """

    def invalidateCache(self):
        """
        Invalidates the cache.
        """

    def isChanged(self) -> bool:
        ...

    def notifyRestored(self):
        """
        This method should be invoked following an undo/redo or a transaction rollback situation.
        This will notify :obj:`DataTypeManagerChangeListenerHandler` and its listeners that this 
        manager has just been restored (e.g., undo/redo/rollback).
        """

    def replaceSourceArchive(self, oldSourceArchive: ghidra.program.model.data.SourceArchive, newSourceArchive: ghidra.program.model.data.SourceArchive):
        """
        Replace one source archive (oldDTM) with another (newDTM). Any data types
        whose source was the oldDTM will be changed to have a source that is the
        newDTM. The oldDTM will no longer be referenced as a source by this data type
        manager.
        
        :param ghidra.program.model.data.SourceArchive oldSourceArchive: data type manager for the old source archive
        :param ghidra.program.model.data.SourceArchive newSourceArchive: data type manager for the new source archive
        :raises IllegalArgumentException: if the oldDTM isn't currently a source
                                        archive for this data type manager or if the
                                        old and new source archives already have the
                                        same unique ID.
        """

    def sourceArchiveChanged(self, sourceArchiveID: ghidra.util.UniversalID):
        ...

    def updateID(self):
        ...

    @property
    def unusedConflictName(self) -> java.lang.String:
        ...

    @property
    def dataTypes(self) -> jpype.JArray[ghidra.program.model.data.DataType]:
        ...

    @property
    def callingConventionName(self) -> java.lang.String:
        ...

    @property
    def sourceArchive(self) -> ghidra.program.model.data.SourceArchive:
        ...

    @property
    def category(self) -> ghidra.program.model.data.Category:
        ...

    @property
    def changed(self) -> jpype.JBoolean:
        ...


class DataTypeArchiveTransformerPanel(javax.swing.JPanel):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class DataTypeUtilities(java.lang.Object):

    @typing.type_check_only
    class CategoryMatchType(java.lang.Enum[DataTypeUtilities.CategoryMatchType]):

        class_: typing.ClassVar[java.lang.Class]
        NONE: typing.Final[DataTypeUtilities.CategoryMatchType]
        SECONDARY: typing.Final[DataTypeUtilities.CategoryMatchType]
        PREFERRED: typing.Final[DataTypeUtilities.CategoryMatchType]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> DataTypeUtilities.CategoryMatchType:
            ...

        @staticmethod
        def values() -> jpype.JArray[DataTypeUtilities.CategoryMatchType]:
            ...


    @typing.type_check_only
    class NamespaceMatcher(java.lang.Object):
        """
        ``NamespaceMatcher`` is used to check data type categoryPath for match against
        preferred namespace.
        """

        class_: typing.ClassVar[java.lang.Class]

        def getMatchType(self, path: ghidra.program.model.data.CategoryPath) -> DataTypeUtilities.CategoryMatchType:
            """
            Score category path match.
            
            :param ghidra.program.model.data.CategoryPath path: category path
            :return: path match type
            :rtype: DataTypeUtilities.CategoryMatchType
            """

        @property
        def matchType(self) -> DataTypeUtilities.CategoryMatchType:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def equalsIgnoreConflict(name1: typing.Union[java.lang.String, str], name2: typing.Union[java.lang.String, str]) -> bool:
        """
        Compares two data type name strings to determine if they are equivalent names, ignoring
        conflict patterns present.
        
        :param java.lang.String or str name1: the first name
        :param java.lang.String or str name2: the second name
        :return: true if the names are equivalent when conflict suffixes are ignored.
        :rtype: bool
        """

    @staticmethod
    def findDataType(dataTypeManager: ghidra.program.model.data.DataTypeManager, namespace: ghidra.program.model.symbol.Namespace, dtName: typing.Union[java.lang.String, str], classConstraint: java.lang.Class[T]) -> T:
        """
        Attempt to find the data type whose dtName and specified namespace match a stored data type
        within the specified dataTypeManager. The first match which satisfies the category path 
        requirement will be returned.  If a non-root namespace is specified the datatype's trailing 
        category path must match the specified namespace path.
        
        :param ghidra.program.model.data.DataTypeManager dataTypeManager: data type manager
        :param ghidra.program.model.symbol.Namespace namespace: namespace associated with dtName (null indicates no namespace constraint)
        :param java.lang.String or str dtName: name of data type
        :param java.lang.Class[T] classConstraint: optional data type interface constraint (e.g., Structure), or null
        :return: best matching data type
        :rtype: T
        """

    @staticmethod
    def findExistingClassStruct(dataTypeManager: ghidra.program.model.data.DataTypeManager, classNamespace: ghidra.program.model.listing.GhidraClass) -> ghidra.program.model.data.Structure:
        """
        Find the structure data type which corresponds to the specified class namespace
        within the specified data type manager.
        The structure must utilize a namespace-based category path, however,
        the match criteria can be fuzzy and relies primarily on the full class namespace.  
        A properly named class structure must reside within a category whose trailing 
        path either matches the class namespace or the class-parent's namespace.  
        Preference is given to it residing within the class-parent's namespace.
        
        :param ghidra.program.model.data.DataTypeManager dataTypeManager: data type manager which should be searched.
        :param ghidra.program.model.listing.GhidraClass classNamespace: class namespace
        :return: existing structure which resides within matching category.
        :rtype: ghidra.program.model.data.Structure
        """

    @staticmethod
    def findNamespaceQualifiedDataType(dataTypeManager: ghidra.program.model.data.DataTypeManager, dtNameWithNamespace: typing.Union[java.lang.String, str], classConstraint: java.lang.Class[T]) -> T:
        """
        Attempt to find the data type whose dtNameWithNamespace match a stored data type within the
        specified dataTypeManager. The namespace will be used in checking data type parent categories.  
        NOTE: name parsing assumes :: namespace delimiter which can be thrown off if name includes 
        template information which could contain namespaces (see :meth:`SymbolPathParser.parse(String) <SymbolPathParser.parse>`).
        
        :param ghidra.program.model.data.DataTypeManager dataTypeManager: data type manager
        :param java.lang.String or str dtNameWithNamespace: name of data type qualified with namespace (e.g.,
                    ns1::ns2::dtname)
        :param java.lang.Class[T] classConstraint: optional data type interface constraint (e.g., Structure), or null
        :return: best matching data type
        :rtype: T
        """

    @staticmethod
    def getArrayBaseDataType(arrayDt: ghidra.program.model.data.Array) -> ghidra.program.model.data.DataType:
        ...

    @staticmethod
    def getBaseDataType(dt: ghidra.program.model.data.DataType) -> ghidra.program.model.data.DataType:
        """
        Get the base data type for the specified data type stripping away pointers and arrays only. A
        null will be returned for a default pointer.
        
        :param ghidra.program.model.data.DataType dt: the data type whose base data type is to be determined.
        :return: the base data type (may be null for default pointer).
        :rtype: ghidra.program.model.data.DataType
        """

    @staticmethod
    def getCPrimitiveDataType(dataTypeName: typing.Union[java.lang.String, str]) -> ghidra.program.model.data.DataType:
        """
        Return the appropriate datatype for a given C primitive datatype name.
        
        :param java.lang.String or str dataTypeName: the datatype name (e.g. "unsigned int", "long long")
        :return: the appropriate datatype for a given C primitive datatype name.
        :rtype: ghidra.program.model.data.DataType
        """

    @staticmethod
    @typing.overload
    def getConflictValue(dataType: ghidra.program.model.data.DataType) -> int:
        """
        Get the conflict value string associated with a conflict datatype name.
        
        :param ghidra.program.model.data.DataType dataType: datatype to be checked
        :return: conflict value:
         
        1. -1: when type does not have a conflict name,
        2. 0: when conflict name does not have a number (i.e., ``.conflict``), or
        3. a positive value which corresponds to the conflict number in the name 
        (e.g., returns 2 for``.conflict2``).
        
        :rtype: int
        """

    @staticmethod
    @typing.overload
    def getConflictValue(dataTypeName: typing.Union[java.lang.String, str]) -> int:
        """
        Get the conflict value associated with a conflict datatype name.
        
        :param java.lang.String or str dataTypeName: datatype name to be checked
        :return: conflict value:
         
        1. -1: when name is not have a conflict name,
        2. 0: when conflict name does not have a number (i.e., ``.conflict``), or
        3. a positive value which corresponds to the conflict number in the name 
        (e.g., returns 2 for``.conflict2``).
        
        :rtype: int
        """

    @staticmethod
    def getContainedDataTypes(rootDataType: ghidra.program.model.data.DataType) -> java.util.Collection[ghidra.program.model.data.DataType]:
        ...

    @staticmethod
    def getDataTypeCategoryPath(baseCategory: ghidra.program.model.data.CategoryPath, namespace: ghidra.program.model.symbol.Namespace) -> ghidra.program.model.data.CategoryPath:
        """
        Create a data type category path derived from the specified namespace and rooted from the
        specified baseCategory
        
        :param ghidra.program.model.data.CategoryPath baseCategory: category path from which to root the namespace-base path
        :param ghidra.program.model.symbol.Namespace namespace: the namespace
        :return: namespace derived category path
        :rtype: ghidra.program.model.data.CategoryPath
        """

    @staticmethod
    def getDisplayName(arrayDt: ghidra.program.model.data.Array, showBaseSizeForDynamics: typing.Union[jpype.JBoolean, bool]) -> str:
        ...

    @staticmethod
    def getMnemonic(arrayDt: ghidra.program.model.data.Array, showBaseSizeForDynamics: typing.Union[jpype.JBoolean, bool], settings: ghidra.docking.settings.Settings) -> str:
        ...

    @staticmethod
    def getName(arrayDt: ghidra.program.model.data.Array, showBaseSizeForDynamics: typing.Union[jpype.JBoolean, bool]) -> str:
        ...

    @staticmethod
    @typing.overload
    def getNameWithoutConflict(dataType: ghidra.program.model.data.DataType, includeCategoryPath: typing.Union[jpype.JBoolean, bool]) -> str:
        """
        Get the name of a data type with all conflict naming patterns removed.
        
        :param ghidra.program.model.data.DataType dataType: data type
        :param jpype.JBoolean or bool includeCategoryPath: if true, the category path will be included with the
        returned name (e.g., /mypath/mydt) and any occurance of a forward slash within individual 
        path components, including the data type name, will be escaped (e.g., ``"\/"``).
        :return: name with optional category path included
        :rtype: str
        """

    @staticmethod
    @typing.overload
    def getNameWithoutConflict(dataTypeName: typing.Union[java.lang.String, str]) -> str:
        """
        Get the name of a data type with all conflict naming patterns removed.
        
        :param java.lang.String or str dataTypeName: data type name with optional category path included
        :return: name with optional category path included
        :rtype: str
        """

    @staticmethod
    @typing.overload
    def getNameWithoutConflict(dt: ghidra.program.model.data.DataType) -> str:
        """
        Get a datatype's name without conflict suffix.
        
        :param ghidra.program.model.data.DataType dt: datatype (pointer and array permitted)
        :return: datatype's name without conflict suffix
        :rtype: str
        """

    @staticmethod
    def isConflictDataType(dt: ghidra.program.model.data.DataType) -> bool:
        """
        Determine if the specified data type has a conflict name.
        
        :param ghidra.program.model.data.DataType dt: datatype (pointer and array permitted)
        :return: true if data type has a conflict name.
        :rtype: bool
        """

    @staticmethod
    def isConflictDataTypeName(dataTypeName: typing.Union[java.lang.String, str]) -> bool:
        """
        Determine if the specified data type name is a conflict name.
        
        :param java.lang.String or str dataTypeName: datatype name
        :return: true if data type name is a conflict name.
        :rtype: bool
        """

    @staticmethod
    def isSameDataType(dataType1: ghidra.program.model.data.DataType, dataType2: ghidra.program.model.data.DataType) -> bool:
        """
        Returns true if the two dataTypes have the same sourceArchive and the same UniversalID
        
        :param ghidra.program.model.data.DataType dataType1: first data type
        :param ghidra.program.model.data.DataType dataType2: second data type
        :return: true if types correspond to the same type from a source archive
        :rtype: bool
        """

    @staticmethod
    def isSameKindDataType(dataType1: ghidra.program.model.data.DataType, dataType2: ghidra.program.model.data.DataType) -> bool:
        """
        Determine if two dataTypes are the same kind of datatype without considering naming or
        component makeup.  The use of Typedefs is ignored and stripped away for comparison.
        This method also ignores details about most built-in types, pointers and arrays 
        (e.g., number of elements or size).  Implementations of the following abstract classes
        will be treated as the same kind as another datatype which extends the same abstract
        class:
         
        * :obj:`AbstractIntegerDataType`
        * :obj:`AbstractFloatDataType`
        * :obj:`AbstractStringDataType`
        
        Other uses of :obj:`BuiltInDataType` must match the specific implementation class.
        
        :param ghidra.program.model.data.DataType dataType1: first data type
        :param ghidra.program.model.data.DataType dataType2: second data type
        :return: true if the two dataTypes are the same basic kind else false
        :rtype: bool
        """

    @staticmethod
    def isSameOrEquivalentDataType(dataType1: ghidra.program.model.data.DataType, dataType2: ghidra.program.model.data.DataType) -> bool:
        """
        Returns true if two dataTypes have the same sourceArchive and the same UniversalID OR are
        equivalent
        
        :param ghidra.program.model.data.DataType dataType1: first data type (if invoked by DB object or manager, this argument must
                    correspond to the DataTypeDB).
        :param ghidra.program.model.data.DataType dataType2: second data type
        :return: true if types correspond to the same type from a source archive or they are
                equivelent, otherwise false
        :rtype: bool
        """

    @staticmethod
    def isSecondPartOfFirst(firstDataType: ghidra.program.model.data.DataType, secondDataType: ghidra.program.model.data.DataType) -> bool:
        """
        Check to see if the second data type is the same as the first data type or is part of it.
         
        
        Note: pointers to the second data type are references and therefore are not considered to be
        part of the first and won't cause true to be returned. If you pass a pointer to this method
        for the first or second parameter, it will return false.
        
        :param ghidra.program.model.data.DataType firstDataType: the data type whose components or base type should be checked to see if
                    the second data type is part of it.
        :param ghidra.program.model.data.DataType secondDataType: the data type to be checked for in the first data type.
        :return: true if the second data type is the first data type or is part of it.
        :rtype: bool
        """


@typing.type_check_only
class CategoryDBAdapterV0(CategoryDBAdapter):
    ...
    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class FunctionDefinitionDBAdapterV0(FunctionDefinitionDBAdapter, db.RecordTranslator):
    """
    Version 0 implementation for accessing the Function Signature Definition database table.
    """

    class_: typing.ClassVar[java.lang.Class]


class EnumSignedState(java.lang.Enum[EnumSignedState]):
    """
    Keeps track of the signed state of an enum datatype. Enum are fundamentally either signed or
    unsigned, but sometimes you can't tell based on the values they contain. Once a negative value
    is added, then the enum becomes locked as signed, preventing high unsigned values (those values
    that are too big for signed value of the enum size) from being added. Once a high value unsigned 
    value is added, then it becomes locked as unsigned value. If neither a negative value or high 
    unsigned value has been added, then the enum is not locked as either signed or unsigned.
    """

    class_: typing.ClassVar[java.lang.Class]
    SIGNED: typing.Final[EnumSignedState]
    UNSIGNED: typing.Final[EnumSignedState]
    NONE: typing.Final[EnumSignedState]
    INVALID: typing.Final[EnumSignedState]

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> EnumSignedState:
        ...

    @staticmethod
    def values() -> jpype.JArray[EnumSignedState]:
        ...


@typing.type_check_only
class FunctionDefinitionDBAdapterV2(FunctionDefinitionDBAdapter):
    """
    Version 2 implementation for accessing the Function Signature Definition database table.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, handle: db.DBHandle, tablePrefix: typing.Union[java.lang.String, str], create: typing.Union[jpype.JBoolean, bool]):
        """
        Gets a version 2 adapter for the Function Definition database table.
        
        :param db.DBHandle handle: handle to the database containing the table.
        :param java.lang.String or str tablePrefix: prefix to be used with default table name
        :param jpype.JBoolean or bool create: true if this constructor should create the table.
        :raises VersionException: if the table's version does not match the expected version
        for this adapter.
        :raises IOException: if an IO error occurs
        """


@typing.type_check_only
class CallingConventionDBAdapter(java.lang.Object):
    """
    Adapter to access the Function Calling Conventions tables.
    """

    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class TypedefDBAdapterV1(TypedefDBAdapter, db.RecordTranslator):
    """
    Version 1 implementation for accessing the Typedef database table.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, handle: db.DBHandle):
        """
        Gets a version 1 adapter for the Typedef database table.
        
        :param db.DBHandle handle: handle to the database containing the table.
        :raises VersionException: if the table's version does not match the expected version
        for this adapter.
        """


@typing.type_check_only
class FunctionDefinitionDB(DataTypeDB, ghidra.program.model.data.FunctionDefinition):
    ...
    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class EnumDBAdapterV0(EnumDBAdapter, db.RecordTranslator):
    """
    Version 0 implementation for accessing the Enumeration database table.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, handle: db.DBHandle):
        """
        Gets a version 0 adapter for the Enumeration database table.
        
        :param db.DBHandle handle: handle to the database containing the table.
        :raises VersionException: if the table's version does not match the expected version
        for this adapter.
        """


@typing.type_check_only
class EnumValueDBAdapterNoTable(EnumValueDBAdapter):
    """
    Adapter needed for a read-only version of data type manager that is not going
    to be upgraded, and there is no Enumeration Data Type Values table in the data type manager.
    """

    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class SettingDB(java.lang.Object):
    """
    Setting DBRecord wrapper for cache use
    """

    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class FunctionParameterAdapter(java.lang.Object):
    """
    Adapter to access the Function Signature Definition Parameters database table.
    """

    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class CompositeDBAdapter(ghidra.program.database.util.DBRecordAdapter):
    """
    Adapter to access the Composite database table.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getRecordCount(self) -> int:
        """
        Get the number of composite datatype records
        
        :return: total number of composite records
        :rtype: int
        """

    def getRecords(self) -> db.RecordIterator:
        """
        Gets an iterator over all composite (structure and union) data type records.
        
        :return: the composite data type record iterator.
        :rtype: db.RecordIterator
        :raises IOException: if the database can't be accessed.
        """

    @property
    def records(self) -> db.RecordIterator:
        ...

    @property
    def recordCount(self) -> jpype.JInt:
        ...


@typing.type_check_only
class FunctionParameterAdapterV1(FunctionParameterAdapter):
    """
    Version 1 implementation for accessing the Function Definition Parameters database table. 
     
    NOTE: Use of tablePrefix introduced with this adapter version.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, handle: db.DBHandle, tablePrefix: typing.Union[java.lang.String, str], create: typing.Union[jpype.JBoolean, bool]):
        """
        Gets a version 1 adapter for the Function Definition Parameter database table.
        
        :param db.DBHandle handle: handle to the database containing the table.
        :param java.lang.String or str tablePrefix: prefix to be used with default table name
        :param jpype.JBoolean or bool create: true if this constructor should create the table.
        :raises VersionException: if the table's version does not match the expected version
        for this adapter.
        :raises IOException: if an IO error occurs
        """


class DataTypeArchiveTransformer(ghidra.GhidraLaunchable):
    """
    DataTypeArchiveTransformer changes (transforms) a new archive file so that it appears to be
    an updated copy of a previously existing data type archive. This allows us to parse a new
    version of each standard GDT file we supply. This class changes the IDs on the data types
    so they will match the previous version's IDs. This allows the new data type archive and
    its data types to become the associated data types where the previous version data types
    were applied.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def fixupGUI():
        ...

    @staticmethod
    def transform(oldFile: jpype.protocol.SupportsPath, newFile: jpype.protocol.SupportsPath, destinationFile: jpype.protocol.SupportsPath, useOldFileID: typing.Union[jpype.JBoolean, bool], monitor: ghidra.util.task.TaskMonitor):
        ...


@typing.type_check_only
class StructureDB(CompositeDB, ghidra.program.model.data.StructureInternal):
    """
    Structure database implementation.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, dataMgr: DataTypeManagerDB, cache: ghidra.program.database.DBObjectCache[DataTypeDB], compositeAdapter: CompositeDBAdapter, componentAdapter: ComponentDBAdapter, record: db.DBRecord):
        ...

    def clone(self, dtm: ghidra.program.model.data.DataTypeManager) -> ghidra.program.model.data.Structure:
        """
        Create cloned structure for target data type manager preserving source archive information.
         
        
        WARNING! cloning non-packed structures which contain bitfields can produce invalid results
        when switching endianness due to the differences in packing order.
        
        :param ghidra.program.model.data.DataTypeManager dtm: target data type manager
        :return: cloned structure
        :rtype: ghidra.program.model.data.Structure
        """

    def copy(self, dtm: ghidra.program.model.data.DataTypeManager) -> ghidra.program.model.data.DataType:
        """
        Create copy of structure for target data type manager (source archive information is
        discarded).
         
        
        WARNING! copying non-packed structures which contain bitfields can produce invalid results
        when switching endianness due to the differences in packing order.
        
        :param ghidra.program.model.data.DataTypeManager dtm: target data type manager
        :return: cloned structure
        :rtype: ghidra.program.model.data.DataType
        """

    def replaceWith(self, dataType: ghidra.program.model.data.DataType):
        """
        Replaces the internal components of this structure with components of the given structure.
        
        :param ghidra.program.model.data.DataType dataType: the structure to get the component information from.
        :raises IllegalArgumentException: if any of the component data types are not allowed to
        replace a component in this composite data type. For example, suppose dt1 contains dt2.
        Therefore it is not valid to replace a dt2 component with dt1 since this would cause a
        cyclic dependency.
        
        .. seealso::
        
            | :obj:`DataTypeDB.replaceWith(DataType)`
        """


@typing.type_check_only
class TypedefDB(DataTypeDB, ghidra.program.model.data.TypeDef):
    """
    Database implementation for a Typedef data type.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, dataMgr: DataTypeManagerDB, cache: ghidra.program.database.DBObjectCache[DataTypeDB], adapter: TypedefDBAdapter, record: db.DBRecord):
        """
        Construct TypeDefDB instance
        
        :param DataTypeManagerDB dataMgr: datatype manager
        :param ghidra.program.database.DBObjectCache[DataTypeDB] cache: DataTypeDB cache
        :param TypedefDBAdapter adapter: TypeDef record adapter
        :param db.DBRecord record: TypeDefDB record
        """


@typing.type_check_only
class SettingsDBAdapter(java.lang.Object):
    """
    Adapter to access settings database tables.
    """

    class_: typing.ClassVar[java.lang.Class]


class SourceArchiveDB(ghidra.program.database.DatabaseObject, ghidra.program.model.data.SourceArchive):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, dtMgr: DataTypeManagerDB, cache: ghidra.program.database.DBObjectCache[SourceArchiveDB], adapter: SourceArchiveAdapter, record: db.DBRecord):
        ...

    def getArchiveType(self) -> ghidra.program.model.data.ArchiveType:
        """
        Gets an indicator for the type of data type archive.
        (PROGRAM_TYPE, PROJECT_TYPE, FILE_TYPE)
        
        :return: the type
        :rtype: ghidra.program.model.data.ArchiveType
        """

    def getDomainFileID(self) -> str:
        """
        Gets the ID used to uniquely identify the domain file for the data type archive.
        
        :return: the domain file identifier
        :rtype: str
        """

    def getLastSyncTime(self) -> int:
        ...

    def getName(self) -> str:
        ...

    def getSourceArchiveID(self) -> ghidra.util.UniversalID:
        """
        Gets the ID that the program has associated with the data type archive.
        
        :return: the data type archive ID
        :rtype: ghidra.util.UniversalID
        """

    def isDirty(self) -> bool:
        ...

    def setDirtyFlag(self, isDirty: typing.Union[jpype.JBoolean, bool]):
        ...

    def setLastSyncTime(self, syncTime: typing.Union[jpype.JLong, int]):
        ...

    def setName(self, newName: typing.Union[java.lang.String, str]):
        ...

    @property
    def dirty(self) -> jpype.JBoolean:
        ...

    @property
    def archiveType(self) -> ghidra.program.model.data.ArchiveType:
        ...

    @property
    def lastSyncTime(self) -> jpype.JLong:
        ...

    @lastSyncTime.setter
    def lastSyncTime(self, value: jpype.JLong):
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @name.setter
    def name(self, value: java.lang.String):
        ...

    @property
    def sourceArchiveID(self) -> ghidra.util.UniversalID:
        ...

    @property
    def domainFileID(self) -> java.lang.String:
        ...


@typing.type_check_only
class ComponentDBAdapter(java.lang.Object):
    """
    Adapter to access the Component database table.
    """

    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class PointerDBAdapter(db.RecordTranslator):
    """
    Adapter to access the Pointer database table for Pointer data types.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getRecordCount(self) -> int:
        """
        Get the number of pointer datatype records
        
        :return: total number of composite records
        :rtype: int
        """

    @property
    def recordCount(self) -> jpype.JInt:
        ...


@typing.type_check_only
class FunctionDefinitionDBAdapterNoTable(FunctionDefinitionDBAdapter):
    """
    Adapter needed for a read-only version of data type manager that is not going
    to be upgraded, and there is no Function Signature Definition table in the data type manager.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, handle: db.DBHandle):
        """
        Gets a pre-table version of the adapter for the Function Definition database table.
        
        :param db.DBHandle handle: handle to the database which doesn't contain the table.
        """


@typing.type_check_only
class CompositeDB(DataTypeDB, ghidra.program.model.data.CompositeInternal):
    """
    Database implementation for a structure or union.
    """

    class_: typing.ClassVar[java.lang.Class]

    def isNotYetDefined(self) -> bool:
        """
        Determine if this composite should be treated as undefined.
         
        
        A composite is considered undefined with a zero-length when it has 
        no components and packing is disabled.  A :obj:`DataTypeComponent` defined by an
        an datatype which is not-yet-defined (i.e., :meth:`DataType.isNotYetDefined() <DataType.isNotYetDefined>` is true) 
        will always have a size of 1.  If an empty composite should be treated as 
        fully specified, packing on the composite should be enabled to ensure that 
        a zero-length component is used should the occassion arise (e.g., empty structure 
        placed within union as a component).
        """

    @property
    def notYetDefined(self) -> jpype.JBoolean:
        ...


@typing.type_check_only
class SourceArchiveAdapter(java.lang.Object):
    """
    Adapter to access the data type archive identifier table.
    This table holds an ID entry for each archive that has provided a data type to the 
    data type manager for the program.
    """

    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class CallingConventionDBAdapterV0(CallingConventionDBAdapter):
    """
    Version 0 implementation for the calling conventions tables adapter.
    """

    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class CategoryDBAdapter(java.lang.Object):
    ...
    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class EnumDBAdapterV1(EnumDBAdapter):
    """
    Version 1 implementation for accessing the Enumeration database table. 
     
    NOTE: Use of tablePrefix introduced with this adapter version.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, handle: db.DBHandle, tablePrefix: typing.Union[java.lang.String, str], create: typing.Union[jpype.JBoolean, bool]):
        """
        Gets a version 1 adapter for the Enumeration database table.
        
        :param db.DBHandle handle: handle to the database containing the table.
        :param java.lang.String or str tablePrefix: prefix to be used with default table name
        :param jpype.JBoolean or bool create: true if this constructor should create the table.
        :raises VersionException: if the table's version does not match the expected version
        for this adapter.
        :raises IOException: an IO error occured during table creation
        """


@typing.type_check_only
class EnumDBAdapter(java.lang.Object):
    """
    Adapter to access the Enumeration data types tables.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getRecordCount(self) -> int:
        """
        Get the number of enum datatype records
        
        :return: total number of composite records
        :rtype: int
        """

    @property
    def recordCount(self) -> jpype.JInt:
        ...


@typing.type_check_only
class TypedefDBAdapterV0(TypedefDBAdapter, db.RecordTranslator):
    """
    Version 0 implementation for accessing the Typedef database table.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, handle: db.DBHandle):
        """
        Gets a version 0 adapter for the Typedef database table.
        
        :param db.DBHandle handle: handle to the database containing the table.
        :raises VersionException: if the table's version does not match the expected version
        for this adapter.
        """


class ProgramBasedDataTypeManagerDB(DataTypeManagerDB, ghidra.program.model.data.ProgramBasedDataTypeManager):
    """
    DB-based Program datatype manager implementation
    which has the concept of an address-based listing and corresponding
    datatype instance settings.
    """

    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def getDataSettingsAddress(data: ghidra.program.model.listing.Data) -> ghidra.program.model.address.Address:
        ...


@typing.type_check_only
class TypedefDBAdapterV2(TypedefDBAdapter):
    """
    Version 2 implementation for accessing the Typedef database table. 
     
    NOTE: Use of tablePrefix introduced with this adapter version.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, handle: db.DBHandle, tablePrefix: typing.Union[java.lang.String, str], create: typing.Union[jpype.JBoolean, bool]):
        """
        Gets a version 1 adapter for the Typedef database table.
        
        :param db.DBHandle handle: handle to the database containing the table.
        :param java.lang.String or str tablePrefix: prefix to be used with default table name
        :param jpype.JBoolean or bool create: true if this constructor should create the table.
        :raises VersionException: if the table's version does not match the expected version
        for this adapter.
        :raises IOException: if IO error occurs
        """


@typing.type_check_only
class TypedefDBAdapter(java.lang.Object):
    """
    Adapter to access the database table for typedef data types.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getRecordCount(self) -> int:
        """
        Get the number of typedef datatype records
        
        :return: total number of composite records
        :rtype: int
        """

    @property
    def recordCount(self) -> jpype.JInt:
        ...


class LazyLoadingCachingMap(java.lang.Object, typing.Generic[K, V]):
    """
    Instances of this class will provide a simple map interface to a cached set of key,value
    pairs.  This class requires that the map can be generated from scratch at any time and
    that adding/removing items from this map is just a mirroring of those changes elsewhere.
    This map is lazy in that it won't load the data until needed and it will use a soft reference
    to maintain the map until such time as the java garbage collector decides to reclaim it.
     
    
    This class uses a ghidra Lock object to coordinate threaded access when loading the
    underlying map data.  It manages both the lock and its own synchronization to avoid
    race conditions and deadlocks.
    """

    class_: typing.ClassVar[java.lang.Class]

    def clear(self):
        """
        Removes any cached map of values and restores the map to its initial state.
        """

    def get(self, key: K) -> V:
        """
        Retrieves the value for the given key.  This will currently load the map if not already
        loaded.
        
        :param K key: the key for whose value to retrieve.
        :return: the value for the given key.
        :rtype: V
        """

    def put(self, key: K, value: V):
        """
        Adds the key,value pair to the map.  If the map is not loaded, this method will do nothing.
        
        :param K key: the key
        :param V value: the value that is associated with the key.
        """

    def remove(self, key: K):
        """
        Removes the key,value pair from the map as specified by the given key.  If the map is
        currently not loaded, this method will do nothing.
        
        :param K key: the key to remove from the map.
        """

    def values(self) -> java.util.Collection[V]:
        """
        Returns an unmodifiable view of the values in this map.
        
        :return: an unmodifiable view of the values in this map.
        :rtype: java.util.Collection[V]
        """


@typing.type_check_only
class FunctionDefinitionDBAdapterV1(FunctionDefinitionDBAdapter, db.RecordTranslator):
    """
    Version 1 implementation for accessing the Function Signature Definition database table. 
     
    NOTE: Use of tablePrefix introduced with this adapter version.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, handle: db.DBHandle, tablePrefix: typing.Union[java.lang.String, str], callConvAdapter: CallingConventionDBAdapter):
        """
        Gets a version 1 read-only adapter for the Function Definition database table.
        
        :param db.DBHandle handle: handle to the database containing the table.
        :param java.lang.String or str tablePrefix: prefix to be used with default table name
        :param CallingConventionDBAdapter callConvAdapter: calling convention table adapter suitable to add new conventions
        (e.g., this adapter being used during upgrade operation).  Should be null if not performing
        an upgrade in which case calling convention IDs will reflect generic convention ordinals.
        :raises VersionException: if the table's version does not match the expected version
        for this adapter.
        """


@typing.type_check_only
class ArrayDBAdapterV1(ArrayDBAdapter):
    """
    To change the template for this generated type comment go to
    Window>Preferences>Java>Code Generation>Code and Comments
     
    NOTE: Use of tablePrefix introduced with this adapter version.
    """

    class_: typing.ClassVar[java.lang.Class]
    V1_SCHEMA: typing.Final[db.Schema]

    def __init__(self, handle: db.DBHandle, tablePrefix: typing.Union[java.lang.String, str], create: typing.Union[jpype.JBoolean, bool]):
        """
        Gets a version 1 adapter for the :obj:`ArrayDB` database table.
        
        :param db.DBHandle handle: handle to the database containing the table.
        :param java.lang.String or str tablePrefix: prefix to be used with default table name
        :param jpype.JBoolean or bool create: create table if true else acquire for read-only or update use
        :raises VersionException: if the table's version does not match the expected version
        for this adapter.
        :raises IOException: an IO error occured during table creation
        """


@typing.type_check_only
class EnumDB(DataTypeDB, ghidra.program.model.data.Enum):
    """
    Database implementation for the enumerated data type.
    """

    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class CompositeDBAdapterV1(CompositeDBAdapter, db.RecordTranslator):
    """
    Version 1 implementation for accessing the Composite database table.
    """

    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class BitFieldDBDataType(ghidra.program.model.data.BitFieldDataType):
    """
    ``BitFieldDBDataType`` extends BitFieldDataType for DataTypeManagerDB use.
    This class provides the ability to generate a datatype ID and reconstruct a bit-field
    datatype from an ID.
    """

    @typing.type_check_only
    class BaseDatatypeKind(java.lang.Enum[BitFieldDBDataType.BaseDatatypeKind]):

        class_: typing.ClassVar[java.lang.Class]
        NONE: typing.Final[BitFieldDBDataType.BaseDatatypeKind]
        TYPEDEF: typing.Final[BitFieldDBDataType.BaseDatatypeKind]
        ENUM: typing.Final[BitFieldDBDataType.BaseDatatypeKind]
        INTEGER: typing.Final[BitFieldDBDataType.BaseDatatypeKind]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> BitFieldDBDataType.BaseDatatypeKind:
            ...

        @staticmethod
        def values() -> jpype.JArray[BitFieldDBDataType.BaseDatatypeKind]:
            ...


    class_: typing.ClassVar[java.lang.Class]
    MAX_DATATYPE_INDEX: typing.Final = 4294967295


@typing.type_check_only
class FunctionParameterAdapterNoTable(FunctionParameterAdapter):
    """
    Adapter needed for a read-only version of data type manager that is not going
    to be upgraded, and there is no Function Definition Parameters table in the data type manager.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, handle: db.DBHandle):
        """
        Gets a pre-table version of the adapter for the Function Definition Parameters database table.
        
        :param db.DBHandle handle: handle to the database which doesn't contain the table.
        :raises VersionException: if the table's version does not match the expected version
        for this adapter.
        """


@typing.type_check_only
class CompositeDBAdapterV5V6(CompositeDBAdapter):
    """
    Version 5 and 6 implementation for accessing the Composite database table. 
    Version 5 introduced the retained computed alignment to reduce the
    need for recalculation and to allow for improved change detection.
    Version 6 did not change the schema but corresponds to the elimination
    of Structure flex-arrays which are supported in read-only mode under
    the older version 5 adapter version.
     
    NOTE: Use of tablePrefix introduced with adapter V6.
    """

    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class EnumValueDBAdapterV1(EnumValueDBAdapter):
    """
    Version 1 implementation for the enumeration tables adapter.
     
    NOTE: Use of tablePrefix introduced with this adapter version.
    """

    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class ArrayDBAdapter(java.lang.Object):
    """
    Adapter to access the Array database table for array data types.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getRecordCount(self) -> int:
        """
        Get the number of array datatype records
        
        :return: total number of composite records
        :rtype: int
        """

    @property
    def recordCount(self) -> jpype.JInt:
        ...


@typing.type_check_only
class DataTypeProxyComponentDB(DataTypeComponentDB):
    """
    ``DataTypeProxyComponentDB`` facilitates a datatype/component substitution when a 
    DataTypeManagerDB is constructed for read-only use and datatype migration is required.  
    An example of this is the :obj:`StructureDB` migration of flex-arrays to a zero-element array.
    """

    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class BuiltinDBAdapterV0(BuiltinDBAdapter):
    """
    Version 0 implementation of the adapter for accessing the built-ins table.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, handle: db.DBHandle, tablePrefix: typing.Union[java.lang.String, str], create: typing.Union[jpype.JBoolean, bool]):
        """
        Gets a version 0 adapter for the Built-Ins database table.
        
        :param db.DBHandle handle: handle to the database containing the table.
        :param java.lang.String or str tablePrefix: prefix to be used with default table name
        :param jpype.JBoolean or bool create: create table if true else acquire for read-only or update use
        :raises VersionException: if the table's version does not match the expected version
        for this adapter.
        :raises IOException: if there is trouble accessing the database.
        """


@typing.type_check_only
class CategoryCache(ghidra.util.datastruct.FixedSizeHashMap[java.lang.String, ghidra.program.model.data.Category]):
    ...
    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class SourceArchiveAdapterNoTable(SourceArchiveAdapter):
    """
    Adapter needed for a read-only version of data type manager that is not going
    to be upgraded, and there is no Data Type Archive ID table in the data type manager.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, handle: db.DBHandle):
        """
        Gets a pre-table version of the adapter for the data type archive ID database table.
        
        :param db.DBHandle handle: handle to the database which doesn't contain the table.
        :raises VersionException: if the table's version does not match the expected version
        for this adapter.
        """


@typing.type_check_only
class PointerDB(DataTypeDB, ghidra.program.model.data.Pointer):
    """
    Database implementation for a Pointer data type.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, dataMgr: DataTypeManagerDB, cache: ghidra.program.database.DBObjectCache[DataTypeDB], adapter: PointerDBAdapter, record: db.DBRecord):
        """
        Constructor
        
        :param DataTypeManagerDB dataMgr: 
        :param ghidra.program.database.DBObjectCache[DataTypeDB] cache: 
        :param PointerDBAdapter adapter: 
        :param db.DBRecord record:
        """


@typing.type_check_only
class SettingsDBAdapterV1(SettingsDBAdapter):
    """
    Version 1 implementation for the accessing the data type settings database table.
    This version stores settings name as an index in each record which corresponds 
    to an entry in the into a second table for
    """

    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class ParentChildAdapter(java.lang.Object):
    """
    Adapter for the custom format table.
    """

    class_: typing.ClassVar[java.lang.Class]


class ProgramDataTypeManager(ProgramBasedDataTypeManagerDB, ghidra.program.database.ManagerDB):
    """
    Class for managing data types in a program
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, handle: db.DBHandle, addrMap: ghidra.program.database.map.AddressMap, openMode: ghidra.framework.data.OpenMode, errHandler: db.util.ErrorHandler, lock: ghidra.util.Lock, monitor: ghidra.util.task.TaskMonitor):
        """
        Constructor
        
        :param db.DBHandle handle: open database  handle
        :param ghidra.program.database.map.AddressMap addrMap: the address map
        :param ghidra.framework.data.OpenMode openMode: the program open mode
        :param db.util.ErrorHandler errHandler: the database io error handler
        :param ghidra.util.Lock lock: the program synchronization lock
        :param ghidra.util.task.TaskMonitor monitor: the progress monitor
        :raises CancelledException: if the user cancels an upgrade
        :raises VersionException: if the database does not match the expected version.
        :raises IOException: if a database IO error occurs.
        """

    def languageChanged(self, monitor: ghidra.util.task.TaskMonitor):
        """
        Update program-architecture information following a language upgrade/change
        
        :param ghidra.util.task.TaskMonitor monitor: task monitor
        :raises IOException: if IO error occurs
        :raises CancelledException: if task monitor cancelled
        """

    def saveDataOrganization(self):
        """
        Save the current data organization to facilitate future change detection and 
        upgrades.  This method must be invoked by :obj:`ProgramDB` during the final
        stage of program creation (i.e., openMode == CREATE).
        
        :raises IOException: if failure occured while saving data organization.
        """


@typing.type_check_only
class PointerDBAdapterV1(PointerDBAdapter):
    """
    Version 1 adapter for the Pointer table.
    """

    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class EnumDBAdapterNoTable(EnumDBAdapter):
    """
    Adapter needed for a read-only version of data type manager that is not going
    to be upgraded, and there is no Enumeration table in the data type manager.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, handle: db.DBHandle):
        """
        
        
        :param db.DBHandle handle: 
        :param openMode:
        """


@typing.type_check_only
class EnumValueDBAdapterV0(EnumValueDBAdapter):
    """
    Version 0 implementation for the enumeration tables adapter.
    """

    class_: typing.ClassVar[java.lang.Class]


class BuiltinDBAdapter(java.lang.Object):
    """
    Database adapter for managing built-in data types.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def getRecordCount(self) -> int:
        """
        Get the number of built-in datatype records
        
        :return: total number of composite records
        :rtype: int
        """

    @property
    def recordCount(self) -> jpype.JInt:
        ...


@typing.type_check_only
class DataTypeSettingsDB(ghidra.docking.settings.Settings):
    """
    Default :obj:`Settings` handler for those datatypes managed
    by an associated :obj:`DataTypeManagerDB`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def setDefaultSettings(self, settings: ghidra.docking.settings.Settings):
        ...


@typing.type_check_only
class EnumValueDBAdapter(db.RecordTranslator):
    """
    Adapter to access the Enumeration data type values tables.
    """

    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class ArrayDBAdapterV0(ArrayDBAdapter):

    @typing.type_check_only
    class TranslatedRecordIterator(db.RecordIterator):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, handle: db.DBHandle):
        """
        Gets a version 0 read-only adapter for the :obj:`ArrayDB` database table.
        
        :param db.DBHandle handle: handle to the database containing the table.
        :raises VersionException: if the table's version does not match the expected version
        for this adapter.
        """


@typing.type_check_only
class CompositeDBAdapterV0(CompositeDBAdapter, db.RecordTranslator):
    """
    Version 0 implementation for accessing the Composite database table.
    """

    class_: typing.ClassVar[java.lang.Class]


class DataTypeIDConverter(ghidra.GhidraLaunchable):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


@typing.type_check_only
class ParentChildDBAdapterNoTable(ParentChildAdapter):
    ...
    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class DataTypeComponentDB(ghidra.program.model.data.InternalDataTypeComponent):
    """
    Database implementation for a DataTypeComponent. If this
    component is for an undefined data type, then the record object is
    null.
    """

    @typing.type_check_only
    class ComponentDBSettings(ghidra.docking.settings.Settings):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def getKey(self) -> int:
        """
        Get record key
        
        :return: record key or -1 for undefined component without a record
        :rtype: int
        """

    @property
    def key(self) -> jpype.JLong:
        ...


@typing.type_check_only
class PointerDBAdapterV0(PointerDBAdapter):
    """
    Version 0 implementation for the accessing the pointer database table.
    """

    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class CallingConventionDBAdapterNoTable(CallingConventionDBAdapter):
    """
    Adapter when no Calling Convention table exists.
    """

    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class SettingsDBAdapterV0(SettingsDBAdapter):
    """
    Version 0 implementation for the accessing the data type settings database table.
    This version stored settings name as a string within each record.
    """

    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class ArrayDB(DataTypeDB, ghidra.program.model.data.Array):
    """
    Database implementation of an Array data type.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, dataMgr: DataTypeManagerDB, cache: ghidra.program.database.DBObjectCache[DataTypeDB], adapter: ArrayDBAdapter, record: db.DBRecord):
        """
        Constructor
        
        :param DataTypeManagerDB dataMgr: 
        :param ghidra.program.database.DBObjectCache[DataTypeDB] cache: 
        :param ArrayDBAdapter adapter: 
        :param db.DBRecord record:
        """


@typing.type_check_only
class FunctionDefinitionDBAdapter(ghidra.program.database.util.DBRecordAdapter):
    """
    Adapter to access the Function Signature Definition database table.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getRecords(self) -> db.RecordIterator:
        """
        Gets an iterator over all function signature definition data type records.
        
        :return: the function definition data type record iterator.
        :rtype: db.RecordIterator
        :raises IOException: if the database can't be accessed.
        """

    @property
    def records(self) -> db.RecordIterator:
        ...


@typing.type_check_only
class CategoryDB(ghidra.program.database.DatabaseObject, ghidra.program.model.data.Category):
    """
    Database implementation for Category.
    """

    @typing.type_check_only
    class ConflictMap(LazyLoadingCachingMap[java.lang.String, java.util.Map[java.lang.String, ghidra.program.model.data.DataType]]):
        """
        Class to handle the complexities of having a map as the value in a LazyLoadingCachingMap
        This map uses the data type's base name as the key (i.e. all .conflict suffixes stripped off.)
        The value is another map that maps the actual data type's name to the data type. This map
        effectively provides an efficient way to get all data types in a category that have the
        same name, but possibly have had their name modified (by appending .conflict) to get around
        the requirement that names have to be unique in the same category.
        """

        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def getCategoryPathName(self) -> str:
        """
        Get the fully qualified name for this category.
        """

    def getDataTypeManager(self) -> ghidra.program.model.data.DataTypeManager:
        """
        Get the data type manager associated with this category.
        """

    def getRoot(self) -> ghidra.program.model.data.Category:
        """
        Get the root category.
        """

    @property
    def root(self) -> ghidra.program.model.data.Category:
        ...

    @property
    def categoryPathName(self) -> java.lang.String:
        ...

    @property
    def dataTypeManager(self) -> ghidra.program.model.data.DataTypeManager:
        ...


@typing.type_check_only
class SourceArchiveAdapterV0(SourceArchiveAdapter):
    """
    Version 0 implementation for accessing the Data Type Archive ID database table. 
     
    NOTE: Use of tablePrefix introduced with this adapter version.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, handle: db.DBHandle, tablePrefix: typing.Union[java.lang.String, str], create: typing.Union[jpype.JBoolean, bool]):
        """
        Gets a version 1 adapter for the Data Type Archive ID table.
        
        :param db.DBHandle handle: handle to the database containing the table.
        :param java.lang.String or str tablePrefix: prefix to be used with default table name
        :param jpype.JBoolean or bool create: true if this constructor should create the table.
        :raises VersionException: if the table's version does not match the expected version
        for this adapter.
        :raises IOException: if an IO errr occurs
        """


class SourceArchiveUpgradeMap(java.lang.Object):

    @typing.type_check_only
    class SourceArchiveImpl(ghidra.program.model.data.SourceArchive):

        class_: typing.ClassVar[java.lang.Class]

        @typing.overload
        def __init__(self, id: ghidra.util.UniversalID, archiveName: typing.Union[java.lang.String, str]):
            ...

        @typing.overload
        def __init__(self):
            ...

        def getArchiveType(self) -> ghidra.program.model.data.ArchiveType:
            ...

        def getDomainFileID(self) -> str:
            ...

        def getLastSyncTime(self) -> int:
            ...

        def getName(self) -> str:
            ...

        def getSourceArchiveID(self) -> ghidra.util.UniversalID:
            ...

        def isDirty(self) -> bool:
            ...

        def setDirtyFlag(self, dirty: typing.Union[jpype.JBoolean, bool]):
            ...

        def setLastSyncTime(self, time: typing.Union[jpype.JLong, int]):
            ...

        def setName(self, name: typing.Union[java.lang.String, str]):
            ...

        @property
        def dirty(self) -> jpype.JBoolean:
            ...

        @property
        def archiveType(self) -> ghidra.program.model.data.ArchiveType:
            ...

        @property
        def lastSyncTime(self) -> jpype.JLong:
            ...

        @lastSyncTime.setter
        def lastSyncTime(self, value: jpype.JLong):
            ...

        @property
        def name(self) -> java.lang.String:
            ...

        @name.setter
        def name(self, value: java.lang.String):
            ...

        @property
        def sourceArchiveID(self) -> ghidra.util.UniversalID:
            ...

        @property
        def domainFileID(self) -> java.lang.String:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def getMappedSourceArchive(self, sourceArchive: ghidra.program.model.data.SourceArchive) -> ghidra.program.model.data.SourceArchive:
        ...

    @staticmethod
    def getTypedefReplacements() -> jpype.JArray[java.lang.String]:
        ...

    @staticmethod
    def isReplacedSourceArchive(id: typing.Union[jpype.JLong, int]) -> bool:
        ...

    @property
    def mappedSourceArchive(self) -> ghidra.program.model.data.SourceArchive:
        ...


@typing.type_check_only
class PointerDBAdapterV2(PointerDBAdapter):
    """
    Version 2 implementation for accessing the PointerDB database table. 
     
    NOTE: Use of tablePrefix introduced with this adapter version.
    """

    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class SettingsCache(java.lang.Object, typing.Generic[K]):

    @typing.type_check_only
    class IdNamePair(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def remove(self, id: K, name: typing.Union[java.lang.String, str]):
        """
        Remove specific setting record from cache
        
        :param K id: association ID object (e.g., Address, DataType ID)
        :param java.lang.String or str name: name of setting
        """



__all__ = ["PointerTypedefInspector", "UnionDB", "ComponentDBAdapterV0", "ParameterDefinitionDB", "DataTypeDB", "FunctionParameterAdapterV0", "CompositeDBAdapterV2V4", "ParentChildDBAdapterV0", "DataTypeManagerDB", "DataTypeArchiveTransformerPanel", "DataTypeUtilities", "CategoryDBAdapterV0", "FunctionDefinitionDBAdapterV0", "EnumSignedState", "FunctionDefinitionDBAdapterV2", "CallingConventionDBAdapter", "TypedefDBAdapterV1", "FunctionDefinitionDB", "EnumDBAdapterV0", "EnumValueDBAdapterNoTable", "SettingDB", "FunctionParameterAdapter", "CompositeDBAdapter", "FunctionParameterAdapterV1", "DataTypeArchiveTransformer", "StructureDB", "TypedefDB", "SettingsDBAdapter", "SourceArchiveDB", "ComponentDBAdapter", "PointerDBAdapter", "FunctionDefinitionDBAdapterNoTable", "CompositeDB", "SourceArchiveAdapter", "CallingConventionDBAdapterV0", "CategoryDBAdapter", "EnumDBAdapterV1", "EnumDBAdapter", "TypedefDBAdapterV0", "ProgramBasedDataTypeManagerDB", "TypedefDBAdapterV2", "TypedefDBAdapter", "LazyLoadingCachingMap", "FunctionDefinitionDBAdapterV1", "ArrayDBAdapterV1", "EnumDB", "CompositeDBAdapterV1", "BitFieldDBDataType", "FunctionParameterAdapterNoTable", "CompositeDBAdapterV5V6", "EnumValueDBAdapterV1", "ArrayDBAdapter", "DataTypeProxyComponentDB", "BuiltinDBAdapterV0", "CategoryCache", "SourceArchiveAdapterNoTable", "PointerDB", "SettingsDBAdapterV1", "ParentChildAdapter", "ProgramDataTypeManager", "PointerDBAdapterV1", "EnumDBAdapterNoTable", "EnumValueDBAdapterV0", "BuiltinDBAdapter", "DataTypeSettingsDB", "EnumValueDBAdapter", "ArrayDBAdapterV0", "CompositeDBAdapterV0", "DataTypeIDConverter", "ParentChildDBAdapterNoTable", "DataTypeComponentDB", "PointerDBAdapterV0", "CallingConventionDBAdapterNoTable", "SettingsDBAdapterV0", "ArrayDB", "FunctionDefinitionDBAdapter", "CategoryDB", "SourceArchiveAdapterV0", "SourceArchiveUpgradeMap", "PointerDBAdapterV2", "SettingsCache"]
