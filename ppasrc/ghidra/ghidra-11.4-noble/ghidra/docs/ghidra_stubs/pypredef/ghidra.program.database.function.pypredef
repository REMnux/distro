from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import db
import db.util
import generic
import ghidra.framework.data
import ghidra.program.database
import ghidra.program.database.map
import ghidra.program.database.symbol
import ghidra.program.model.address
import ghidra.program.model.listing
import ghidra.program.model.symbol
import ghidra.program.util
import ghidra.util
import ghidra.util.task
import java.lang # type: ignore
import java.util # type: ignore


class FunctionDB(ghidra.program.database.DatabaseObject, ghidra.program.model.listing.Function):
    """
    Database implementation of a Function.
    """

    @typing.type_check_only
    class ThunkVariableFilter(ghidra.program.model.listing.VariableFilter):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def doDeleteVariable(self, symbol: ghidra.program.database.symbol.VariableSymbolDB):
        """
        Callback to remove variable just prior to removal
        of the underlying symbol.
        
        :param ghidra.program.database.symbol.VariableSymbolDB symbol: variable symbol which is about to be deleted.
        """

    def getVariable(self, symbol: ghidra.program.database.symbol.VariableSymbolDB) -> ghidra.program.model.listing.Variable:
        """
        Return the Variable for the given symbol.
        
        :param ghidra.program.database.symbol.VariableSymbolDB symbol: variable symbol
        :return: Variable which corresponds to specified symbol
        :rtype: ghidra.program.model.listing.Variable
        """

    def setValidationEnabled(self, state: typing.Union[jpype.JBoolean, bool]):
        ...

    @property
    def variable(self) -> ghidra.program.model.listing.Variable:
        ...


@typing.type_check_only
class FunctionAdapter(java.lang.Object):
    """
    Database adapter for functions.
    """

    @typing.type_check_only
    class TranslatedRecordIterator(db.RecordIterator):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class ThunkFunctionAdapter(java.lang.Object):
    ...
    class_: typing.ClassVar[java.lang.Class]


class FunctionManagerDB(ghidra.program.model.listing.FunctionManager):
    """
    Class that manages all functions within the program; there are some
    convenience methods on Listing to create and access functions, but
    all function related calls are routed to this class.
    """

    @typing.type_check_only
    class FunctionFilteredIterator(generic.FilteredIterator[ghidra.program.model.listing.Function], ghidra.program.model.listing.FunctionIterator):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, it: java.util.Iterator[ghidra.program.model.listing.Function]):
            ...


    @typing.type_check_only
    class FunctionIteratorDB(ghidra.program.model.listing.FunctionIterator):
        """
        Function iterator class.
        """

        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, dbHandle: db.DBHandle, addrMap: ghidra.program.database.map.AddressMap, openMode: ghidra.framework.data.OpenMode, lock: ghidra.util.Lock, monitor: ghidra.util.task.TaskMonitor):
        """
        Construct a new FunctionManager
        
        :param db.DBHandle dbHandle: data base handle
        :param ghidra.program.database.map.AddressMap addrMap: address map for the program
        :param ghidra.framework.data.OpenMode openMode: CREATE, UPDATE, READ_ONLY, or UPGRADE
        :param ghidra.util.Lock lock: the program synchronization lock
        :param ghidra.util.task.TaskMonitor monitor: 
        :raises VersionException: if function manager's version does not match
        its expected version
        :raises CancelledException: if the function table is being upgraded
        and the user canceled the upgrade process
        :raises IOException: if there was a problem accessing the database
        """

    def createExternalFunction(self, extSpaceAddr: ghidra.program.model.address.Address, name: typing.Union[java.lang.String, str], nameSpace: ghidra.program.model.symbol.Namespace, extData: typing.Union[java.lang.String, str], source: ghidra.program.model.symbol.SourceType) -> ghidra.program.model.listing.Function:
        """
        Transform an existing external symbol into an external function.
        This method should only be invoked by an ExternalSymbol
        
        :param ghidra.program.model.address.Address extSpaceAddr: the external space address to use when creating this external.  Any 
        other symbol using this address must first be deleted.  Results are unpredictable if this is 
        not done.
        :param java.lang.String or str name: the external function name
        :param ghidra.program.model.symbol.Namespace nameSpace: the external function namespace
        :param java.lang.String or str extData: the external data string to store additional info (see :obj:`ExternalLocationDB`)
        :param ghidra.program.model.symbol.SourceType source: the source of this external.
        :return: external function
        :rtype: ghidra.program.model.listing.Function
        :raises InvalidInputException: if the name is invalid
        """

    def doRemoveFunction(self, key: typing.Union[jpype.JLong, int]) -> bool:
        ...

    def functionNamespaceChanged(self, key: typing.Union[jpype.JLong, int]):
        ...

    def functionTagsChanged(self):
        ...

    def getFunction(self, key: typing.Union[jpype.JLong, int]) -> ghidra.program.model.listing.Function:
        """
        Get the function with the given key.
        
        :param jpype.JLong or int key: ID of the function; ID is obtained by calling
        Function.getID()
        :return: null if there is no function with the given key
        :rtype: ghidra.program.model.listing.Function
        """

    def getThunkFunctionIds(self, referencedFunctionId: typing.Union[jpype.JLong, int]) -> java.util.List[java.lang.Long]:
        """
        Returns list of thunk function keys which reference the specified referencedFunctionKey
        
        :param jpype.JLong or int referencedFunctionId: 
        :return: list of thunk function IDs or null
        :rtype: java.util.List[java.lang.Long]
        """

    def getThunkedFunctionId(self, functionId: typing.Union[jpype.JLong, int]) -> int:
        ...

    def initSignatureSource(self, monitor: ghidra.util.task.TaskMonitor):
        """
        Initialize function signature source when it was first introduced and attempt to
        disable custom storage if possible.
        NOTE: This method intended to be called by ProgramDB only during appropriate upgrade.
        
        :param ghidra.util.task.TaskMonitor monitor: 
        :raises CancelledException: 
        :raises IOException:
        """

    def isThunk(self, key: typing.Union[jpype.JLong, int]) -> bool:
        ...

    def removeExplicitThisParameters(self, monitor: ghidra.util.task.TaskMonitor):
        """
        Remove parameter symbols which correspond to the 'this' parameter for all
        __thiscall functions using dynamic storage.
        NOTE: This method intended to be called by ProgramDB only during appropriate upgrade.
        
        :param ghidra.util.task.TaskMonitor monitor: 
        :raises CancelledException: 
        :raises IOException:
        """

    def replaceDataTypes(self, dataTypeReplacementMap: collections.abc.Mapping):
        ...

    def setLanguage(self, translator: ghidra.program.util.LanguageTranslator, monitor: ghidra.util.task.TaskMonitor):
        """
        Perform language translation.
        Update function return storage specifications to reflect address space and register mappings
        
        :param ghidra.program.util.LanguageTranslator translator: 
        :param ghidra.util.task.TaskMonitor monitor: 
        :raises CancelledException:
        """

    @property
    def thunkedFunctionId(self) -> jpype.JLong:
        ...

    @property
    def function(self) -> ghidra.program.model.listing.Function:
        ...

    @property
    def thunkFunctionIds(self) -> java.util.List[java.lang.Long]:
        ...

    @property
    def thunk(self) -> jpype.JBoolean:
        ...


class OverlappingFunctionException(java.lang.Exception):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, entryPoint: ghidra.program.model.address.Address, e: ghidra.program.database.symbol.OverlappingNamespaceException):
        ...

    @typing.overload
    def __init__(self, entryPoint: ghidra.program.model.address.Address):
        ...

    @typing.overload
    def __init__(self, msg: typing.Union[java.lang.String, str]):
        ...


class FunctionTagDB(ghidra.program.database.DatabaseObject, ghidra.program.model.listing.FunctionTag):
    """
    Database object for :obj:`FunctionTagAdapter` objects.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, mgr: FunctionTagManagerDB, cache: ghidra.program.database.DBObjectCache[FunctionTagDB], record: db.DBRecord):
        ...


@typing.type_check_only
class FunctionTagMappingAdapter(java.lang.Object):
    """
    Database adapter that maps function tags to individual functions. This table 
    consists of two columns, each of which is an index into the :obj:`FunctionTagAdapter`
    and :obj:`SymbolTable` respectively.
    """

    class_: typing.ClassVar[java.lang.Class]


class ThunkFunctionAdapterV0(ThunkFunctionAdapter):
    ...
    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class FunctionTagAdapterV0(FunctionTagAdapter, db.DBListener):
    """
    Initial version of the :obj:`FunctionTagAdapter`.
    """

    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class FunctionTagMappingAdapterV0(FunctionTagMappingAdapter, db.DBListener):
    """
    Initial version of the :obj:`FunctionTagMappingAdapter`.
    """

    class_: typing.ClassVar[java.lang.Class]
    V0_FUNCTION_ID_COL: typing.Final = 0
    V0_TAG_ID_COL: typing.Final = 1


@typing.type_check_only
class FunctionStackFrame(ghidra.program.model.listing.StackFrame):

    class_: typing.ClassVar[java.lang.Class]

    def equals(self, obj: java.lang.Object) -> bool:
        """
        Returns whether some other stack frame is "equivalent to" this one.
        The stack frame is considered equal to another even if they are each
        part of a different function.
        """

    def isParameterOffset(self, offset: typing.Union[jpype.JInt, int]) -> bool:
        """
        Returns true if specified offset could correspond to a parameter
        
        :param jpype.JInt or int offset:
        """

    @property
    def parameterOffset(self) -> jpype.JBoolean:
        ...


@typing.type_check_only
class ParameterDB(VariableDB, ghidra.program.model.listing.Parameter):
    ...
    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class FunctionTagMappingAdapterNoTable(FunctionTagMappingAdapter):
    """
    Adapter for the read-only version of the function tag mapping adapter that cannot
    be upgraded.
    """

    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class FunctionAdapterV0(FunctionAdapter):
    ...
    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class FunctionAdapterV2(FunctionAdapter):
    ...
    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class FunctionTagAdapter(java.lang.Object):
    """
    This represents a table that stores all possible function tags available for use.
    The table consists of two columns: one for the tag name, and one indicating
    whether this tag is modifiable.
     
    Non-modifiable tags cannot be deleted or edited by any user. These are typically
    tags that have been pre-loaded via some external mechanism and need to be 
    preserved as originally defined.
    """

    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class FunctionAdapterV3(FunctionAdapter):
    ...
    class_: typing.ClassVar[java.lang.Class]


class ReturnParameterDB(ParameterDB):
    ...
    class_: typing.ClassVar[java.lang.Class]


class FunctionTagManagerDB(ghidra.program.model.listing.FunctionTagManager, db.util.ErrorHandler):

    class_: typing.ClassVar[java.lang.Class]

    def getTagRecord(self, id: typing.Union[jpype.JLong, int]) -> db.DBRecord:
        ...

    def setProgram(self, program: ghidra.program.model.listing.Program):
        ...

    @property
    def tagRecord(self) -> db.DBRecord:
        ...


class LocalVariableDB(VariableDB, ghidra.program.model.listing.LocalVariable):
    ...
    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class FunctionAdapterV1(FunctionAdapter):
    ...
    class_: typing.ClassVar[java.lang.Class]


class VariableDB(ghidra.program.model.listing.Variable):
    """
    Database implementation of a Variable.
    """

    class_: typing.ClassVar[java.lang.Class]



__all__ = ["FunctionDB", "FunctionAdapter", "ThunkFunctionAdapter", "FunctionManagerDB", "OverlappingFunctionException", "FunctionTagDB", "FunctionTagMappingAdapter", "ThunkFunctionAdapterV0", "FunctionTagAdapterV0", "FunctionTagMappingAdapterV0", "FunctionStackFrame", "ParameterDB", "FunctionTagMappingAdapterNoTable", "FunctionAdapterV0", "FunctionAdapterV2", "FunctionTagAdapter", "FunctionAdapterV3", "ReturnParameterDB", "FunctionTagManagerDB", "LocalVariableDB", "FunctionAdapterV1", "VariableDB"]
