from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import db
import db.util
import ghidra.framework.data
import ghidra.program.database
import ghidra.program.database.function
import ghidra.program.database.map
import ghidra.program.database.util
import ghidra.program.model.address
import ghidra.program.model.data
import ghidra.program.model.lang
import ghidra.program.model.listing
import ghidra.program.model.symbol
import ghidra.program.util
import ghidra.util
import ghidra.util.task
import java.lang # type: ignore
import java.util # type: ignore


class SymbolDB(ghidra.program.database.DatabaseObject, ghidra.program.model.symbol.Symbol):
    """
    Base class for symbols
    """

    class_: typing.ClassVar[java.lang.Class]

    def doSetNameAndNamespace(self, newName: typing.Union[java.lang.String, str], newNamespace: ghidra.program.model.symbol.Namespace, source: ghidra.program.model.symbol.SourceType, checkForDuplicates: typing.Union[jpype.JBoolean, bool]):
        ...

    def getDataTypeId(self) -> int:
        ...

    def getSymbolStringData(self) -> str:
        """
        Returns the symbol's string data which has different meanings depending on the symbol type
        and whether or not it is external
        
        :return: the symbol's string data
        :rtype: str
        """

    def isDeleting(self) -> bool:
        ...

    def setDataTypeId(self, value: typing.Union[jpype.JLong, int]):
        """
        Sets the generic symbol data 1.
        
        :param jpype.JLong or int value: the value to set as symbol data 1.
        """

    def setSource(self, newSource: ghidra.program.model.symbol.SourceType):
        """
        Sets this symbol's source as specified.
        
        :param ghidra.program.model.symbol.SourceType newSource: the new source type (IMPORTED, ANALYSIS, USER_DEFINED)
        :raises IllegalArgumentException: if you try to change the source from default or to default
        """

    def setSymbolStringData(self, stringData: typing.Union[java.lang.String, str]):
        """
        Sets the symbol's string data field. This field's data has different uses depending on the 
        symbol type and whether or not it is external.
        
        :param java.lang.String or str stringData: the string to store in the string data field
        """

    def setVariableOffset(self, offset: typing.Union[jpype.JInt, int]):
        """
        Sets the symbol's variable offset. For parameters, this is the ordinal, for locals, it is 
        the first use offset
        
        :param jpype.JInt or int offset: the value to set as the symbols variable offset.
        """

    @property
    def deleting(self) -> jpype.JBoolean:
        ...

    @property
    def dataTypeId(self) -> jpype.JLong:
        ...

    @dataTypeId.setter
    def dataTypeId(self, value: jpype.JLong):
        ...

    @property
    def symbolStringData(self) -> java.lang.String:
        ...

    @symbolStringData.setter
    def symbolStringData(self, value: java.lang.String):
        ...


class EquateManager(ghidra.program.model.symbol.EquateTable, db.util.ErrorHandler, ghidra.program.database.ManagerDB):
    """
    Implementation of the Equate Table
    """

    @typing.type_check_only
    class EquateIterator(java.util.Iterator[ghidra.program.model.symbol.Equate]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]
    DATATYPE_TAG: typing.Final = "dtID"
    ERROR_TAG: typing.Final = "<BAD EQUATE>"
    FORMAT_DELIMITER: typing.Final = ":"

    def __init__(self, handle: db.DBHandle, addrMap: ghidra.program.database.map.AddressMap, openMode: ghidra.framework.data.OpenMode, lock: ghidra.util.Lock, monitor: ghidra.util.task.TaskMonitor):
        """
        Constructor
        
        :param db.DBHandle handle: database handle
        :param ghidra.program.database.map.AddressMap addrMap: map that converts addresses to longs and longs to addresses
        :param ghidra.framework.data.OpenMode openMode: one of ProgramDB.CREATE, UPDATE, UPGRADE, or READ_ONLY
        :param ghidra.util.Lock lock: the program synchronization lock
        :param ghidra.util.task.TaskMonitor monitor: the progress monitor used when upgrading.
        :raises VersionException: if the database version doesn't match the current version.
        :raises IOException: if a database error occurs.
        """

    @staticmethod
    def formatNameForEquate(dtID: ghidra.util.UniversalID, equateValue: typing.Union[jpype.JLong, int]) -> str:
        """
        Formats a string to the equate format given the enum UUID and the value for the equate. The
        formatted strings are used when setting equates from datatypes so that information can be
        stored with an equate to point back to that datatype.
        
        :param ghidra.util.UniversalID dtID: The enum's data type UUID
        :param jpype.JLong or int equateValue: The value intended for the equate
        :return: The formatted equate name
        :rtype: str
        """

    @staticmethod
    def formatNameForEquateError(equateValue: typing.Union[jpype.JLong, int]) -> str:
        """
        Formats a string to the equate error format given the value. Used for rendering formatted
        equates that do not point back to a datatype.
        
        :param jpype.JLong or int equateValue: The value of the equate
        :return: The error formatted equate name
        :rtype: str
        """

    @staticmethod
    def getDataTypeUUID(formattedEquateName: typing.Union[java.lang.String, str]) -> ghidra.util.UniversalID:
        """
        Pulls out the enum data type UUID given a formatted equate name. This UUID should point back
        to a datatype.
        
        :param java.lang.String or str formattedEquateName: The formatted equate name to pull the UUID from
        :return: The enum data type UUID or null if the given name is not formatted.
        :rtype: ghidra.util.UniversalID
        """

    @staticmethod
    def getEquateValueFromFormattedName(formattedEquateName: typing.Union[java.lang.String, str]) -> int:
        """
        Pulls out the value of the equate given the formatted equate name. The value stored in the
        equate info is a decimal.
        
        :param java.lang.String or str formattedEquateName: The formatted equate name to pull the value from
        :return: The value of the equate, or -1 if the given name is not formatted.
        :rtype: int
        """


class ClassSymbol(SymbolDB):
    """
    Symbols that represent classes
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, symbolMgr: SymbolManager, cache: ghidra.program.database.DBObjectCache[SymbolDB], address: ghidra.program.model.address.Address, record: db.DBRecord):
        """
        Construct a new Class Symbol
        
        :param SymbolManager symbolMgr: the symbol manager
        :param ghidra.program.database.DBObjectCache[SymbolDB] cache: symbol object cache
        :param ghidra.program.model.address.Address address: the address to associate with the symbol
        :param db.DBRecord record: the record associated with the symbol.
        """


class FunctionSymbol(SymbolDB):
    """
    Symbol class for functions.
     
    Symbol Data Usage:
    EXTERNAL:
        String stringData - external memory address/label
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, symbolMgr: SymbolManager, cache: ghidra.program.database.DBObjectCache[SymbolDB], address: ghidra.program.model.address.Address, record: db.DBRecord):
        """
        Construct a new FunctionSymbol
        
        :param SymbolManager symbolMgr: the symbol manager.
        :param ghidra.program.database.DBObjectCache[SymbolDB] cache: symbol object cache
        :param ghidra.program.model.address.Address address: the address for this symbol.
        :param db.DBRecord record: the record for this symbol.
        """


@typing.type_check_only
class SymbolDatabaseAdapterV3(SymbolDatabaseAdapter):
    """
    SymbolDatabaseAdapter for version 3
     
    This version provides for fast symbol lookup by namespace and name.
    It was created in June 2021 with ProgramDB version 24. 
    It will be included in Ghidra starting at version 10.1
    """

    @typing.type_check_only
    class AnchoredSymbolRecordFilter(ghidra.program.database.util.RecordFilter):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class EquateRefDBAdapterV1(EquateRefDBAdapter):
    """
    Implementation for Version 0 of the equate references table.
    """

    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class NamespaceDB(ghidra.program.model.symbol.Namespace):
    """
    Class to represent a set of related symbols. Symbols within a namespace must have 
    unique names.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getBody(self) -> ghidra.program.model.address.AddressSetView:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.model.symbol.Namespace.getBody()`
        """

    def getID(self) -> int:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.model.symbol.Namespace.getID()`
        """

    @typing.overload
    def getName(self) -> str:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.model.symbol.Namespace.getName()`
        """

    @typing.overload
    def getName(self, includeNamespacePath: typing.Union[jpype.JBoolean, bool]) -> str:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.model.symbol.Namespace.getName(boolean)`
        """

    def getParentNamespace(self) -> ghidra.program.model.symbol.Namespace:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.model.symbol.Namespace.getParentNamespace()`
        """

    def getSymbol(self) -> ghidra.program.model.symbol.Symbol:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.model.symbol.Namespace.getSymbol()`
        """

    def setParentNamespace(self, parentNamespace: ghidra.program.model.symbol.Namespace):
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.model.symbol.Namespace.setParentNamespace(ghidra.program.model.symbol.Namespace)`
        """

    @property
    def symbol(self) -> ghidra.program.model.symbol.Symbol:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def parentNamespace(self) -> ghidra.program.model.symbol.Namespace:
        ...

    @parentNamespace.setter
    def parentNamespace(self, value: ghidra.program.model.symbol.Namespace):
        ...

    @property
    def iD(self) -> jpype.JLong:
        ...

    @property
    def body(self) -> ghidra.program.model.address.AddressSetView:
        ...


class CodeSymbol(SymbolDB):
    """
    Symbols that represent "labels"
    
    Symbol data usage:
    EXTERNAL:
        String stringData - external memory address/label
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, mgr: SymbolManager, cache: ghidra.program.database.DBObjectCache[SymbolDB], addr: ghidra.program.model.address.Address, record: db.DBRecord):
        """
        Constructs a new CodeSymbol
        
        :param SymbolManager mgr: the symbol manager
        :param ghidra.program.database.DBObjectCache[SymbolDB] cache: symbol object cache
        :param ghidra.program.model.address.Address addr: the address associated with the symbol
        :param db.DBRecord record: the record for this symbol
        """

    @typing.overload
    def __init__(self, mgr: SymbolManager, cache: ghidra.program.database.DBObjectCache[SymbolDB], addr: ghidra.program.model.address.Address, key: typing.Union[jpype.JLong, int]):
        """
        Constructs a new CodeSymbol for a default/dynamic label.
        
        :param SymbolManager mgr: the symbol manager
        :param ghidra.program.database.DBObjectCache[SymbolDB] cache: symbol object cache
        :param ghidra.program.model.address.Address addr: the address associated with the symbol
        :param jpype.JLong or int key: this must be the absolute encoding of addr
        """

    def delete(self, keepReferences: typing.Union[jpype.JBoolean, bool]) -> bool:
        """
        Delete code/label symbol
        
        :param jpype.JBoolean or bool keepReferences: if false all references to this symbols address will be removed,
        otherwise associated references will simply be disassociated following symbol removal
        (see :meth:`SymbolManager.doRemoveSymbol(SymbolDB) <SymbolManager.doRemoveSymbol>`.
        :return: true if symbol successfully removed
        :rtype: bool
        """


@typing.type_check_only
class SymbolDatabaseAdapterV1(SymbolDatabaseAdapter):
    """
    SymbolDatabaseAdapter for version 1
    """

    @typing.type_check_only
    class V1ConvertedRecordIterator(db.ConvertedRecordIterator):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]


class VariableStorageManager(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def getVariableStorageAddress(self, storage: ghidra.program.model.listing.VariableStorage, create: typing.Union[jpype.JBoolean, bool]) -> ghidra.program.model.address.Address:
        """
        Get a variable address for the given storage specification.
        
        :param ghidra.program.model.listing.VariableStorage storage: variable storage specification
        :param jpype.JBoolean or bool create: if true a new variable address will be allocated if needed
        :return: variable address which corresponds to the storage specification or null if not found
        and create is false.
        :rtype: ghidra.program.model.address.Address
        :raises IOException: if an IO error occurs
        """


class OverlappingNamespaceException(java.lang.Exception):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, start: ghidra.program.model.address.Address, end: ghidra.program.model.address.Address):
        ...

    def getEnd(self) -> ghidra.program.model.address.Address:
        ...

    def getStart(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def start(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def end(self) -> ghidra.program.model.address.Address:
        ...


@typing.type_check_only
class OldVariableStorageDBAdapterV0V1(java.lang.Object):
    """
    ``OldVariableStorageDBAdapterV0V1`` provide legacy variable storage 
    table support where each variable storage record was namespace-specific and
    provided storage address only.  In a later revision this was deemed inadequate 
    since size information and support for storage binding was needed.
    """

    class_: typing.ClassVar[java.lang.Class]


class SymbolManager(ghidra.program.model.symbol.SymbolTable, ghidra.program.database.ManagerDB):

    @typing.type_check_only
    class SingleSymbolIterator(ghidra.program.model.symbol.SymbolIterator):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class IncludeDynamicSymbolIterator(ghidra.program.model.symbol.SymbolIterator):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class SymbolRecordIterator(ghidra.program.model.symbol.SymbolIterator):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class SymbolQueryIterator(ghidra.program.model.symbol.SymbolIterator):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class AbstractSymbolNameRecordIterator(ghidra.program.model.symbol.SymbolIterator):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class SymbolNameRecordIterator(SymbolManager.AbstractSymbolNameRecordIterator):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class SymbolNameScanningIterator(SymbolManager.AbstractSymbolNameRecordIterator):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, startName: typing.Union[java.lang.String, str]):
            ...


    @typing.type_check_only
    class ExternalSymbolNameRecordIterator(ghidra.program.model.symbol.SymbolIterator):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class LabelHistoryIterator(java.util.Iterator[ghidra.program.model.symbol.LabelHistory]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ClassNamespaceIterator(java.util.Iterator[ghidra.program.model.listing.GhidraClass]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, handle: db.DBHandle, addrMap: ghidra.program.database.map.AddressMap, openMode: ghidra.framework.data.OpenMode, errHandler: db.util.ErrorHandler, lock: ghidra.util.Lock, monitor: ghidra.util.task.TaskMonitor):
        """
        Creates a new Symbol manager.
        
        :param db.DBHandle handle: the database handler
        :param ghidra.program.database.map.AddressMap addrMap: the address map.
        :param ghidra.framework.data.OpenMode openMode: the open mode.
        :param db.util.ErrorHandler errHandler: database error handler
        :param ghidra.util.Lock lock: the program synchronization lock
        :param ghidra.util.task.TaskMonitor monitor: the progress monitor used when upgrading.
        :raises CancelledException: if the user cancels the upgrade.
        :raises IOException: if a database io error occurs.
        :raises VersionException: if the database version doesn't match the current version.
        """

    def createCodeSymbol(self, addr: ghidra.program.model.address.Address, name: typing.Union[java.lang.String, str], namespace: ghidra.program.model.symbol.Namespace, source: ghidra.program.model.symbol.SourceType, stringData: typing.Union[java.lang.String, str]) -> ghidra.program.model.symbol.Symbol:
        """
        Internal method for creating label symbols.
         
        
        If identical memory symbol already exists it will be returned.
        
        :param ghidra.program.model.address.Address addr: the address for the new symbol (memory or external)
        :param java.lang.String or str name: the name of the new symbol
        :param ghidra.program.model.symbol.Namespace namespace: the namespace for the new symbol (null may be specified for global
                    namespace)
        :param ghidra.program.model.symbol.SourceType source: the SourceType of the new symbol
        :param java.lang.String or str stringData: special use depending on the symbol type and whether or not it is external
        :return: the new symbol
        :rtype: ghidra.program.model.symbol.Symbol
        :raises InvalidInputException: if name contains white space, is zero length, or is null for
                    non-default source. Also thrown if invalid parent namespace is specified.
        :raises IllegalArgumentException: if :obj:`SourceType.DEFAULT` is improperly specified, or 
                    an invalid address, or if the given parent namespace is from a different 
                    program than that of this symbol table.
        """

    def createFunctionSymbol(self, addr: ghidra.program.model.address.Address, name: typing.Union[java.lang.String, str], namespace: ghidra.program.model.symbol.Namespace, source: ghidra.program.model.symbol.SourceType, stringData: typing.Union[java.lang.String, str]) -> ghidra.program.model.symbol.Symbol:
        """
        Internal method for creating function symbols
        
        :param ghidra.program.model.address.Address addr: the address for the new symbol
        :param java.lang.String or str name: the name of the new symbol
        :param ghidra.program.model.symbol.Namespace namespace: the namespace for the new symbol (null may be specified for global
                    namespace)
        :param ghidra.program.model.symbol.SourceType source: the SourceType of the new symbol
        :param java.lang.String or str stringData: special use depending on the symbol type and whether or not it is external.
        :return: the new symbol
        :rtype: ghidra.program.model.symbol.Symbol
        :raises InvalidInputException: if the name contains illegal characters (i.e. space)
        """

    def createLibrarySymbol(self, name: typing.Union[java.lang.String, str], pathname: typing.Union[java.lang.String, str], source: ghidra.program.model.symbol.SourceType) -> SymbolDB:
        """
        Create a Library symbol with the specified name and optional pathname
        
        :param java.lang.String or str name: library name
        :param java.lang.String or str pathname: project file path (may be null)
        :param ghidra.program.model.symbol.SourceType source: symbol source
        :return: library symbol
        :rtype: SymbolDB
        :raises DuplicateNameException: if library name conflicts with another symbol
        :raises InvalidInputException: if name contains white space, is zero length, or is null for
                    non-default source. Also thrown if invalid parent namespace is specified.
        :raises IllegalArgumentException: if :obj:`SourceType.DEFAULT` is improperly specified, or 
                    or if the given parent namespace is from a different program than that of this 
                    symbol table.
        """

    def createVariableSymbol(self, name: typing.Union[java.lang.String, str], function: ghidra.program.database.function.FunctionDB, type: ghidra.program.model.symbol.SymbolType, firstUseOffsetOrOrdinal: typing.Union[jpype.JInt, int], storage: ghidra.program.model.listing.VariableStorage, source: ghidra.program.model.symbol.SourceType) -> VariableSymbolDB:
        """
        Creates variable symbols.
         
        
        Note this is not a method defined in the Symbol Table interface. It is intended to be used by
        Ghidra program internals.
        
        :param java.lang.String or str name: the name of the variable
        :param ghidra.program.database.function.FunctionDB function: the function that contains the variable.
        :param ghidra.program.model.symbol.SymbolType type: the type of the variable (can only be PARAMETER or LOCAL_VAR)
        :param jpype.JInt or int firstUseOffsetOrOrdinal: the offset in the function where the variable is first used.
        :param ghidra.program.model.listing.VariableStorage storage: the VariableStorage (stack, registers, etc.)
        :param ghidra.program.model.symbol.SourceType source: the symbol source type (user defined, analysis, etc.)
        :return: the new VariableSymbol that was created.
        :rtype: VariableSymbolDB
        :raises DuplicateNameException: if there is another variable in this function with that name.
        :raises InvalidInputException: if the name contains illegal characters (space for example)
        """

    def findVariableStorageAddress(self, storage: ghidra.program.model.listing.VariableStorage) -> ghidra.program.model.address.Address:
        """
        Find previously defined variable storage address
        
        :param ghidra.program.model.listing.VariableStorage storage: variable storage
        :return: previously defined variable storage address or null if not found
        :rtype: ghidra.program.model.address.Address
        :raises IOException: if there is database exception
        """

    def getMaxSymbolAddress(self, space: ghidra.program.model.address.AddressSpace) -> ghidra.program.model.address.Address:
        """
        Returns the maximum symbol address within the specified address space.
        
        :param ghidra.program.model.address.AddressSpace space: address space
        :return: maximum symbol address within space or null if none are found.
        :rtype: ghidra.program.model.address.Address
        """

    def getNextExternalSymbolAddress(self) -> ghidra.program.model.address.Address:
        """
        Returns the next available external symbol address
        
        :return: the address
        :rtype: ghidra.program.model.address.Address
        """

    def getVariableStorageManager(self) -> VariableStorageManager:
        """
        Get the variable storage manager used by this symbol table
        
        :return: varable storage manager
        :rtype: VariableStorageManager
        """

    def imageBaseChanged(self, oldBase: ghidra.program.model.address.Address, newBase: ghidra.program.model.address.Address):
        ...

    def migrateFromOldVariableStorageManager(self, monitor: ghidra.util.task.TaskMonitor):
        """
        No more sharing the same variable address for multiple variable symbols.
         
        
        Must split these up. Only reference to variable addresses should be the symbol address -
        reference refer to physical/stack addresses, and symbolIDs.
        
        :param ghidra.util.task.TaskMonitor monitor: the task monitor
        :raises CancelledException: if the operation is cancelled
        """

    def moveSymbolsAt(self, oldAddr: ghidra.program.model.address.Address, newAddr: ghidra.program.model.address.Address):
        """
        Move symbol.
         
        
        Only symbol address is changed. References must be moved separately.
        
        :param ghidra.program.model.address.Address oldAddr: the old symbol memory address
        :param ghidra.program.model.address.Address newAddr: the new symbol memory address
        """

    def namespaceRemoved(self, namespaceID: typing.Union[jpype.JLong, int]):
        """
        Called by the NamespaceManager when a namespace is removed; remove all symbols that have the
        given namespace ID.
        
        :param jpype.JLong or int namespaceID: ID of namespace being removed
        """

    def replaceDataTypes(self, dataTypeReplacementMap: collections.abc.Mapping):
        ...

    def setLanguage(self, translator: ghidra.program.util.LanguageTranslator, monitor: ghidra.util.task.TaskMonitor):
        ...

    @property
    def variableStorageManager(self) -> VariableStorageManager:
        ...

    @property
    def maxSymbolAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def nextExternalSymbolAddress(self) -> ghidra.program.model.address.Address:
        ...


@typing.type_check_only
class SymbolDatabaseAdapterV0(SymbolDatabaseAdapter):
    """
    ``SymbolDatabaseAdapterV0`` handles symbol tables which were created 
    prior to the addition of Namespace support and Function symbols.  Function symbols 
    are synthesized for those functions whose entry point currently has a 
    label symbol.  The ID of these synthesized function symbols is the max ID plus 
    the function ID.  The function Namespace ID is the same as the Function ID.
    The upgrade of this version may also add additional Function symbols for which there
    is no corresponding label symbol.
    """

    @typing.type_check_only
    class V0ConvertedRecordIterator(db.RecordIterator):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]


class VariableStorageDBAdapterV2(VariableStorageDBAdapter):

    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def upgrade(dbHandle: db.DBHandle, oldAdapter: VariableStorageDBAdapter, monitor: ghidra.util.task.TaskMonitor) -> VariableStorageDBAdapter:
        ...


@typing.type_check_only
class EquateRefDBAdapterV0(EquateRefDBAdapter):
    """
    Implementation for Version 0 of the equate references table.
    """

    @typing.type_check_only
    class MyRecordConversionIterator(db.ConvertedRecordIterator):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class SymbolDatabaseAdapterV2(SymbolDatabaseAdapter):
    """
    SymbolDatabaseAdapter for version 2
    """

    @typing.type_check_only
    class AnchoredSymbolRecordFilter(ghidra.program.database.util.RecordFilter):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class V2ConvertedRecordIterator(db.ConvertedRecordIterator):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]


class VariableSymbolDB(SymbolDB):
    """
    Symbol class for function variables.
    
    Symbol Data Usage:
        String stringData - variable comment
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, symbolMgr: SymbolManager, cache: ghidra.program.database.DBObjectCache[SymbolDB], type: ghidra.program.model.symbol.SymbolType, variableMgr: VariableStorageManagerDB, address: ghidra.program.model.address.Address, record: db.DBRecord):
        """
        Constructs a new VariableSymbol
        
        :param SymbolManager symbolMgr: the symbol manager
        :param ghidra.program.database.DBObjectCache[SymbolDB] cache: symbol object cache
        :param ghidra.program.model.symbol.SymbolType type: the symbol type.
        :param VariableStorageManagerDB variableMgr: variable storage manager
        :param ghidra.program.model.address.Address address: the address of the symbol (stack address)
        :param db.DBRecord record: the record for the symbol
        """

    def getDataType(self) -> ghidra.program.model.data.DataType:
        ...

    def getFirstUseOffset(self) -> int:
        ...

    def getFunction(self) -> ghidra.program.database.function.FunctionDB:
        ...

    def getOrdinal(self) -> int:
        ...

    def getVariableStorage(self) -> ghidra.program.model.listing.VariableStorage:
        ...

    def setFirstUseOffset(self, firstUseOffset: typing.Union[jpype.JInt, int]):
        ...

    def setOrdinal(self, ordinal: typing.Union[jpype.JInt, int]):
        ...

    def setStorageAndDataType(self, newStorage: ghidra.program.model.listing.VariableStorage, dt: ghidra.program.model.data.DataType):
        """
        Change the storage address and data-type associated with this variable symbol.
        
        :param ghidra.program.model.listing.VariableStorage newStorage: the new storage
        :param ghidra.program.model.data.DataType dt: data-type
        """

    @property
    def firstUseOffset(self) -> jpype.JInt:
        ...

    @firstUseOffset.setter
    def firstUseOffset(self, value: jpype.JInt):
        ...

    @property
    def function(self) -> ghidra.program.database.function.FunctionDB:
        ...

    @property
    def dataType(self) -> ghidra.program.model.data.DataType:
        ...

    @property
    def variableStorage(self) -> ghidra.program.model.listing.VariableStorage:
        ...

    @property
    def ordinal(self) -> jpype.JInt:
        ...

    @ordinal.setter
    def ordinal(self, value: jpype.JInt):
        ...


class VariableStorageDBAdapterNoTable(VariableStorageDBAdapter):
    ...
    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class AddressSetFilteredSymbolIterator(ghidra.program.model.symbol.SymbolIterator):
    """
    Iterator (in address order) over all symbols that match the given query in an address set.
    """

    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class EquateRefDB(ghidra.program.database.DatabaseObject, ghidra.program.model.symbol.EquateReference):
    """
    Database object for the equate references.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getAddress(self) -> ghidra.program.model.address.Address:
        ...

    def getDynamicHashValue(self) -> int:
        ...

    def getOpIndex(self) -> int:
        ...

    @property
    def address(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def opIndex(self) -> jpype.JShort:
        ...

    @property
    def dynamicHashValue(self) -> jpype.JLong:
        ...


@typing.type_check_only
class VariableStorageDBAdapter(java.lang.Object):
    ...
    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class EquateDBAdapter(java.lang.Object):
    """
    Adpapter to access records in the Equate table.
    """

    class_: typing.ClassVar[java.lang.Class]


class OldVariableStorageManagerDB(java.lang.Object):

    @typing.type_check_only
    class OldVariableStorage(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, handle: db.DBHandle, addrMap: ghidra.program.database.map.AddressMap, monitor: ghidra.util.task.TaskMonitor):
        """
        Construct a read-only variable storage manager for the old record format
        utilized by the VariableStorage table (NOTE: old table name does not have
        a space in the name).  This adapter is intended for use during upgrades
        only.
        
        :param db.DBHandle handle: the database handle.
        :param ghidra.program.database.map.AddressMap addrMap: the address map
        :param ghidra.util.task.TaskMonitor monitor: the task monitor.
        :raises IOException: if a database error occurs.
        :raises CancelledException: if the user cancels the upgrade.
        """

    def getStorageAddress(self, variableAddr: ghidra.program.model.address.Address) -> ghidra.program.model.address.Address:
        ...

    @property
    def storageAddress(self) -> ghidra.program.model.address.Address:
        ...


@typing.type_check_only
class SymbolDatabaseAdapter(java.lang.Object):
    """
    Adapter to access records in the symbol table.
    """

    class_: typing.ClassVar[java.lang.Class]


class GlobalVariableSymbolDB(VariableSymbolDB):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, symbolMgr: SymbolManager, cache: ghidra.program.database.DBObjectCache[SymbolDB], variableMgr: VariableStorageManagerDB, address: ghidra.program.model.address.Address, record: db.DBRecord):
        """
        Constructs a new GlobalVariableSymbolDB which are restricted to the global namespace
        
        :param SymbolManager symbolMgr: the symbol manager
        :param ghidra.program.database.DBObjectCache[SymbolDB] cache: symbol object cache
        :param VariableStorageManagerDB variableMgr: variable storage manager
        :param ghidra.program.model.address.Address address: the address of the symbol (stack address)
        :param db.DBRecord record: the record for the symbol
        """


@typing.type_check_only
class LibraryDB(ghidra.program.model.listing.Library):
    """
    Object to represent an external library.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getBody(self) -> ghidra.program.model.address.AddressSetView:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.model.symbol.Namespace.getBody()`
        """

    def getID(self) -> int:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.model.symbol.Namespace.getID()`
        """

    @typing.overload
    def getName(self) -> str:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.model.symbol.Namespace.getName()`
        """

    @typing.overload
    def getName(self, includeNamespacePath: typing.Union[jpype.JBoolean, bool]) -> str:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.model.symbol.Namespace.getName(boolean)`
        """

    def getParentNamespace(self) -> ghidra.program.model.symbol.Namespace:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.model.symbol.Namespace.getParentNamespace()`
        """

    def getSymbol(self) -> ghidra.program.model.symbol.Symbol:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.model.symbol.Namespace.getSymbol()`
        """

    def setParentNamespace(self, parentNamespace: ghidra.program.model.symbol.Namespace):
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.model.symbol.Namespace.setParentNamespace(ghidra.program.model.symbol.Namespace)`
        """

    @property
    def symbol(self) -> ghidra.program.model.symbol.Symbol:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def parentNamespace(self) -> ghidra.program.model.symbol.Namespace:
        ...

    @parentNamespace.setter
    def parentNamespace(self, value: ghidra.program.model.symbol.Namespace):
        ...

    @property
    def iD(self) -> jpype.JLong:
        ...

    @property
    def body(self) -> ghidra.program.model.address.AddressSetView:
        ...


@typing.type_check_only
class GhidraClassDB(ghidra.program.model.listing.GhidraClass):
    """
    Object to represent a "Class"
    """

    class_: typing.ClassVar[java.lang.Class]

    def setName(self, name: typing.Union[java.lang.String, str], source: ghidra.program.model.symbol.SourceType, checkForDuplicates: typing.Union[jpype.JBoolean, bool]):
        ...


@typing.type_check_only
class EquateRefDBAdapter(java.lang.Object):
    """
    Adapter to access records in the equate references table.
    """

    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class EquateDBAdapterV0(EquateDBAdapter):
    """
    Implementation for Version 0 of the adapter that accesses the 
    equate record that has the equate name and value.
    """

    class_: typing.ClassVar[java.lang.Class]


class LibrarySymbol(SymbolDB):
    """
    Class for library symbols.
     
    Symbol data usage:
    String stringData - associated program project file path
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, symbolMgr: SymbolManager, cache: ghidra.program.database.DBObjectCache[SymbolDB], address: ghidra.program.model.address.Address, record: db.DBRecord):
        """
        Constructs a new Library Symbol
        
        :param SymbolManager symbolMgr: the symbol manager
        :param ghidra.program.database.DBObjectCache[SymbolDB] cache: symbol object cache
        :param ghidra.program.model.address.Address address: the address for this symbol
        :param db.DBRecord record: the record for this symbol
        """


class EquateDB(ghidra.program.database.DatabaseObject, ghidra.program.model.symbol.Equate):
    """
    Database object for an Equate.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, equateMgr: EquateManager, cache: ghidra.program.database.DBObjectCache[EquateDB], record: db.DBRecord):
        """
        Constructor
        
        :param EquateManager equateMgr: the equate manager
        :param ghidra.program.database.DBObjectCache[EquateDB] cache: EquateDB cache
        :param db.DBRecord record: the record for this equate.
        """


@typing.type_check_only
class LabelHistoryAdapterV0(LabelHistoryAdapter):
    """
    Version 0 of the Label History adapter.
    """

    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class LabelHistoryAdapterNoTable(LabelHistoryAdapter):
    """
    Adapter needed when a Program is being opened read only and the label
    history table does not exist in the Program.
    """

    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class LabelHistoryAdapter(java.lang.Object):
    """
    Adapter for the Label History table.
    """

    class_: typing.ClassVar[java.lang.Class]


class NamespaceManager(ghidra.program.database.ManagerDB):
    """
    Class to manage namespaces.
    """

    @typing.type_check_only
    class NamespaceHolder(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, handle: db.DBHandle, errHandler: db.util.ErrorHandler, addrMap: ghidra.program.database.map.AddressMap, openMode: ghidra.framework.data.OpenMode, lock: ghidra.util.Lock, monitor: ghidra.util.task.TaskMonitor):
        """
        Construct a new namespace manager.
        
        :param db.DBHandle handle: the database handle.
        :param db.util.ErrorHandler errHandler: the error handler.
        :param ghidra.program.database.map.AddressMap addrMap: the address map
        :param ghidra.framework.data.OpenMode openMode: the open mode
        :param ghidra.util.Lock lock: the program synchronization lock
        :param ghidra.util.task.TaskMonitor monitor: the task monitor.
        :raises VersionException: if the table version is different from this adapter.
        """

    def getAddressSet(self, namespace: ghidra.program.model.symbol.Namespace) -> ghidra.program.model.address.AddressSetView:
        """
        Gets the body for the given namespace.
        
        :param ghidra.program.model.symbol.Namespace namespace: the namespace for which to get its body.
        :return: body for the given namespace
        :rtype: ghidra.program.model.address.AddressSetView
        """

    def getGlobalNamespace(self) -> ghidra.program.model.symbol.Namespace:
        """
        Get the global namespace.
        
        :return: global namespace
        :rtype: ghidra.program.model.symbol.Namespace
        """

    def getNamespaceContaining(self, addr: ghidra.program.model.address.Address) -> ghidra.program.model.symbol.Namespace:
        """
        Get the Namespace containing the given address. If the address is not
        in a defined namespace (e.g., Function), the global namespace is
        returned.
        
        :param ghidra.program.model.address.Address addr: the address for which to find a namespace.
        :return: namespace which contains address or the 
        :meth:`global namespace <.getGlobalNamespace>` if a specific namespace not found.
        :rtype: ghidra.program.model.symbol.Namespace
        """

    def getNamespacesOverlapping(self, set: ghidra.program.model.address.AddressSetView) -> java.util.Iterator[ghidra.program.model.symbol.Namespace]:
        """
        Get all Namespaces whose body overlaps the specified address set.
        
        :param ghidra.program.model.address.AddressSetView set: the address for which to find namespace's that intersect it.
        :return: a LongField function key iterator.
        :rtype: java.util.Iterator[ghidra.program.model.symbol.Namespace]
        """

    def overlapsNamespace(self, set: ghidra.program.model.address.AddressSetView) -> ghidra.program.model.address.AddressRange:
        """
        Checks if an existing namespace's address set intersects with
        the given set. If so, return the first overlapping range.
        
        :param ghidra.program.model.address.AddressSetView set: address set to check for intersection
        :return: null if no overlaps, or an address range of the first overlap
        :rtype: ghidra.program.model.address.AddressRange
        """

    def removeBody(self, namespace: ghidra.program.model.symbol.Namespace) -> ghidra.program.model.address.AddressSetView:
        """
        Removes any associated body with the given namespace.
        
        :param ghidra.program.model.symbol.Namespace namespace: the namespace whose body is to be cleared.
        :return: old body
        :rtype: ghidra.program.model.address.AddressSetView
        """

    def setBody(self, namespace: ghidra.program.model.symbol.Namespace, set: ghidra.program.model.address.AddressSetView):
        """
        Sets the body of a namespace.
        
        :param ghidra.program.model.symbol.Namespace namespace: the namespace whose body is to be modified.
        :param ghidra.program.model.address.AddressSetView set: the address set for the new body.
        :raises OverlappingNamespaceException: if specified set overlaps another namespace
        """

    @property
    def addressSet(self) -> ghidra.program.model.address.AddressSetView:
        ...

    @property
    def namespacesOverlapping(self) -> java.util.Iterator[ghidra.program.model.symbol.Namespace]:
        ...

    @property
    def globalNamespace(self) -> ghidra.program.model.symbol.Namespace:
        ...

    @property
    def namespaceContaining(self) -> ghidra.program.model.symbol.Namespace:
        ...


class NamespaceSymbol(SymbolDB):
    """
    Symbol class for namespaces.
    """

    class_: typing.ClassVar[java.lang.Class]


class VariableStorageManagerDB(VariableStorageManager):

    @typing.type_check_only
    class MyVariableStorage(ghidra.program.database.DatabaseObject):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, handle: db.DBHandle, addrMap: ghidra.program.database.map.AddressMap, openMode: ghidra.framework.data.OpenMode, errorHandler: db.util.ErrorHandler, lock: ghidra.util.Lock, monitor: ghidra.util.task.TaskMonitor):
        """
        Construct a new variable manager.
        
        :param db.DBHandle handle: the database handle.
        :param ghidra.program.database.map.AddressMap addrMap: the address map (required for legacy adpter use only)
        :param ghidra.framework.data.OpenMode openMode: the open mode
        :param db.util.ErrorHandler errorHandler: database error handler
        :param ghidra.util.Lock lock: the program synchronization lock
        :param ghidra.util.task.TaskMonitor monitor: the task monitor.
        :raises IOException: if a database error occurs.
        :raises VersionException: if the table version is different from this adapter.
        :raises IOException: if an IO error occurs
        :raises CancelledException: if the user cancels the upgrade.
        """

    @staticmethod
    def delete(dbHandle: db.DBHandle):
        """
        Delete the DB table which correspnds to this variable storage implementation
        
        :param db.DBHandle dbHandle: database handle
        :raises IOException: if an IO error occurs
        """

    @staticmethod
    def exists(dbHandle: db.DBHandle) -> bool:
        """
        Determine if the variable storage manager table already exists
        
        :param db.DBHandle dbHandle: database handle
        :return: true if storage table exists
        :rtype: bool
        """

    def getVariableStorageAddress(self, storage: ghidra.program.model.listing.VariableStorage, create: typing.Union[jpype.JBoolean, bool]) -> ghidra.program.model.address.Address:
        """
        Get a variable address for the given storage specification.
        NOTE: The program architecture and error handler must be set appropriately prior to 
        invocation of this method (see :meth:`setProgramArchitecture(ProgramArchitecture) <.setProgramArchitecture>`.
        
        :param ghidra.program.model.listing.VariableStorage storage: variable storage specification
        :param jpype.JBoolean or bool create: if true a new variable address will be allocated if needed
        :return: variable address which corresponds to the storage specification or null if not found
        and create is false.
        :rtype: ghidra.program.model.address.Address
        :raises IOException: if an IO error occurs
        """

    def setLanguage(self, translator: ghidra.program.util.LanguageTranslator, monitor: ghidra.util.task.TaskMonitor):
        """
        Perform language translation.
        Following the invocation of this method it is important to ensure that the program 
        architecure is adjusted if neccessary.
        Update variable storage specifications to reflect address space and register mappings
        
        :param ghidra.program.util.LanguageTranslator translator: language translator to be used for mapping storage varnodes to new
        architecture.
        :param ghidra.util.task.TaskMonitor monitor: task monitor
        :raises CancelledException: if task is cancelled
        """

    def setProgramArchitecture(self, arch: ghidra.program.model.lang.ProgramArchitecture):
        """
        Set program architecture.
        
        :param ghidra.program.model.lang.ProgramArchitecture arch: program architecture
        """


class TypeFilteredSymbolIterator(ghidra.program.model.symbol.SymbolIterator):
    """
    Filters a symbol iterator to only return a specific symbol type
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, it: ghidra.program.model.symbol.SymbolIterator, type: ghidra.program.model.symbol.SymbolType):
        """
        Construct a new TypeFilteredSymbolIterator
        
        :param ghidra.program.model.symbol.SymbolIterator it: the symbol iterator to filter
        :param ghidra.program.model.symbol.SymbolType type: the symbol type to filter on.
        """

    def hasNext(self) -> bool:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.model.symbol.SymbolIterator.hasNext()`
        """

    def next(self) -> ghidra.program.model.symbol.Symbol:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.model.symbol.SymbolIterator.next()`
        """

    def remove(self):
        ...



__all__ = ["SymbolDB", "EquateManager", "ClassSymbol", "FunctionSymbol", "SymbolDatabaseAdapterV3", "EquateRefDBAdapterV1", "NamespaceDB", "CodeSymbol", "SymbolDatabaseAdapterV1", "VariableStorageManager", "OverlappingNamespaceException", "OldVariableStorageDBAdapterV0V1", "SymbolManager", "SymbolDatabaseAdapterV0", "VariableStorageDBAdapterV2", "EquateRefDBAdapterV0", "SymbolDatabaseAdapterV2", "VariableSymbolDB", "VariableStorageDBAdapterNoTable", "AddressSetFilteredSymbolIterator", "EquateRefDB", "VariableStorageDBAdapter", "EquateDBAdapter", "OldVariableStorageManagerDB", "SymbolDatabaseAdapter", "GlobalVariableSymbolDB", "LibraryDB", "GhidraClassDB", "EquateRefDBAdapter", "EquateDBAdapterV0", "LibrarySymbol", "EquateDB", "LabelHistoryAdapterV0", "LabelHistoryAdapterNoTable", "LabelHistoryAdapter", "NamespaceManager", "NamespaceSymbol", "VariableStorageManagerDB", "TypeFilteredSymbolIterator"]
