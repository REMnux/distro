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
import ghidra.program.database.map
import ghidra.program.model.address
import ghidra.program.model.listing
import ghidra.program.model.symbol
import ghidra.util
import ghidra.util.task
import java.lang # type: ignore


@typing.type_check_only
class ExternalReferenceDB(ReferenceDB, ghidra.program.model.symbol.ExternalReference):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, program: ghidra.program.model.listing.Program, fromAddr: ghidra.program.model.address.Address, toAddr: ghidra.program.model.address.Address, refType: ghidra.program.model.symbol.RefType, opIndex: typing.Union[jpype.JInt, int], sourceType: ghidra.program.model.symbol.SourceType):
        ...


@typing.type_check_only
class EmptyMemReferenceIterator(ghidra.program.model.symbol.ReferenceIterator):
    ...
    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class FromAdapterV0(FromAdapter):
    ...
    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class BigRefListV0(RefList):
    """
    To change the template for this generated type comment go to
    Window>Preferences>Java>Code Generation>Code and Comments
    """

    @typing.type_check_only
    class RefIterator(ghidra.program.model.symbol.ReferenceIterator):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class RefListV0(RefList):
    """
    To change the template for this generated type comment go to
    Window>Preferences>Java>Code Generation>Code and Comments
    """

    @typing.type_check_only
    class RefIterator(ghidra.program.model.symbol.ReferenceIterator):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def getLong(data: jpype.JArray[jpype.JByte], offset: typing.Union[jpype.JInt, int]) -> int:
        ...

    @staticmethod
    def putLong(data: jpype.JArray[jpype.JByte], offset: typing.Union[jpype.JInt, int], v: typing.Union[jpype.JLong, int]) -> int:
        ...


class ReferenceDBManager(ghidra.program.model.symbol.ReferenceManager, ghidra.program.database.ManagerDB, db.util.ErrorHandler):
    """
    Reference manager implementation for the database.
    """

    @typing.type_check_only
    class FromRefIterator(ghidra.program.model.symbol.ReferenceIterator):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ExtEntryAddressIterator(ghidra.program.model.address.AddressIterator):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ExternalReferenceIterator(ghidra.program.model.symbol.ReferenceIterator):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class FunctionVariableReferenceCacher(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class Scope(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, dbHandle: db.DBHandle, addrMap: ghidra.program.database.map.AddressMap, openMode: ghidra.framework.data.OpenMode, lock: ghidra.util.Lock, monitor: ghidra.util.task.TaskMonitor):
        """
        Construct a new reference manager.
        
        :param db.DBHandle dbHandle: handle to the database
        :param ghidra.program.database.map.AddressMap addrMap: map to convert addresses to longs and longs to addresses
        :param ghidra.framework.data.OpenMode openMode: one of ProgramDB.CREATE, UPDATE, UPGRADE, or READ_ONLY
        :param ghidra.util.Lock lock: the program synchronization lock
        :param ghidra.util.task.TaskMonitor monitor: Task monitor for upgrading
        :raises CancelledException: if the user cancels the loading of this db
        :raises IOException: if a database io error occurs.
        :raises VersionException: if the database version is different from the expected version
        """

    def addExternalEntryPointRef(self, toAddr: ghidra.program.model.address.Address):
        """
        Create a memory reference to the given address to mark it as
        an external entry point.
        
        :param ghidra.program.model.address.Address toAddr: the address at which to make an external entry point
        :raises java.lang.IllegalArgumentException: if a non-memory address is specified
        """

    def getExternalEntryIterator(self) -> ghidra.program.model.address.AddressIterator:
        ...

    def getReferenceLevel(self, toAddr: ghidra.program.model.address.Address) -> int:
        """
        Returns the reference level for the references to the given address
        
        :param ghidra.program.model.address.Address toAddr: the address at which to find the highest reference level
        """

    def getReferencedVariable(self, reference: ghidra.program.model.symbol.Reference) -> ghidra.program.model.listing.Variable:
        """
        Attempts to determine which if any of the local functions variables are referenced by the specified
        reference.  In utilizing the firstUseOffset scoping model, negative offsets (relative to the functions
        entry) are shifted beyond the maximum positive offset within the function.  While this does not account for the
        actual instruction flow, it is hopefully accurate enough for most situations.
        
        
        .. seealso::
        
            | :obj:`ghidra.program.model.symbol.ReferenceManager.getReferencedVariable(ghidra.program.model.symbol.Reference)`
        """

    def getReferencesTo(self, var: ghidra.program.model.listing.Variable) -> jpype.JArray[ghidra.program.model.symbol.Reference]:
        """
        Attempts to determine the set of references which refer to the specified variable.
        In utilizing the firstUseOffset scoping model, negative offsets (relative to the functions
        entry) are shifted beyond the maximum positive offset within the function.  While this does not account for the
        actual instruction flow, it is hopefully accurate enough for most situations.
        
        
        .. seealso::
        
            | :obj:`ghidra.program.model.symbol.ReferenceManager.getReferencesTo(ghidra.program.model.listing.Variable)`
        """

    def isExternalEntryPoint(self, toAddr: ghidra.program.model.address.Address) -> bool:
        """
        Return whether the address is an external entry point
        
        :param ghidra.program.model.address.Address toAddr: the address to test for external entry point
        :return: true if the address is an external entry point
        :rtype: bool
        """

    def moveReferencesTo(self, oldToAddr: ghidra.program.model.address.Address, newToAddr: ghidra.program.model.address.Address, monitor: ghidra.util.task.TaskMonitor) -> int:
        """
        Move all references to the specified oldAddr.  Any symbol binding will be discarded since
        these are intended for memory label references only.
        This method is intended specifically to support upgrading of certain references
        (i.e., Stack, Register and External addresses).
        NOTE! After ProgramDB version 12, this method will no longer be useful for
        upgrading stack and register references since they will not exist
        within the ReferenceTo-list.
        
        :param ghidra.program.model.address.Address oldToAddr: old reference to address
        :param ghidra.program.model.address.Address newToAddr: new reference to address
        :param ghidra.util.task.TaskMonitor monitor: the monitor
        :return: number of references updated
        :rtype: int
        :raises CancelledException: if the task is cancelled
        :raises IOException: if a database exception occurs
        """

    def removeExternalEntryPoint(self, addr: ghidra.program.model.address.Address):
        """
        Removes the external entry point at the given address
        
        :param ghidra.program.model.address.Address addr: that address at which to remove the external entry point attribute.
        """

    def symbolAdded(self, sym: ghidra.program.model.symbol.Symbol):
        """
        Symbol has been added
        
        :param ghidra.program.model.symbol.Symbol sym: new symbol
        """

    def symbolRemoved(self, symbol: ghidra.program.model.symbol.Symbol):
        """
        Symbol is about to be removed
        
        :param ghidra.program.model.symbol.Symbol symbol: the symbol that will be removed
        """

    @property
    def externalEntryPoint(self) -> jpype.JBoolean:
        ...

    @property
    def referenceLevel(self) -> jpype.JByte:
        ...

    @property
    def externalEntryIterator(self) -> ghidra.program.model.address.AddressIterator:
        ...

    @property
    def referencesTo(self) -> jpype.JArray[ghidra.program.model.symbol.Reference]:
        ...

    @property
    def referencedVariable(self) -> ghidra.program.model.listing.Variable:
        ...


@typing.type_check_only
class ToAdapterSharedTable(ToAdapter):
    ...
    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class MemReferenceDB(ReferenceDB):

    class_: typing.ClassVar[java.lang.Class]

    def getOffsetOrShift(self) -> int:
        ...

    def isOffset(self) -> bool:
        ...

    def isShifted(self) -> bool:
        ...

    @property
    def offset(self) -> jpype.JBoolean:
        ...

    @property
    def offsetOrShift(self) -> jpype.JLong:
        ...

    @property
    def shifted(self) -> jpype.JBoolean:
        ...


@typing.type_check_only
class ReferenceDB(ghidra.program.model.symbol.Reference):

    class_: typing.ClassVar[java.lang.Class]

    def getFromAddress(self) -> ghidra.program.model.address.Address:
        """
        Get the address of the codeunit that is making the reference.
        """

    def getOperandIndex(self) -> int:
        """
        Get the operand index of where this reference was placed.
        
        :return: op index or ReferenceManager.MNEMONIC
        :rtype: int
        """

    def getReferenceType(self) -> ghidra.program.model.symbol.RefType:
        """
        Get the type of reference being made.
        """

    def isMnemonicReference(self) -> bool:
        """
        Return true if this reference is on the mnemonic (versus an operand)
        """

    def isOperandReference(self) -> bool:
        """
        Return true if this reference is on an operand.
        """

    def toString(self) -> str:
        """
        Return a string that represents this references, for debugging purposes.
        """

    @property
    def referenceType(self) -> ghidra.program.model.symbol.RefType:
        ...

    @property
    def fromAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def operandReference(self) -> jpype.JBoolean:
        ...

    @property
    def operandIndex(self) -> jpype.JInt:
        ...

    @property
    def mnemonicReference(self) -> jpype.JBoolean:
        ...


@typing.type_check_only
class StackReferenceDB(MemReferenceDB, ghidra.program.model.symbol.StackReference):

    class_: typing.ClassVar[java.lang.Class]

    def getStackOffset(self) -> int:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.model.symbol.StackReference.getStackOffset()`
        """

    @property
    def stackOffset(self) -> jpype.JInt:
        ...


@typing.type_check_only
class RecordAdapter(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def createRecord(self, key: typing.Union[jpype.JLong, int], numRefs: typing.Union[jpype.JInt, int], refLevel: typing.Union[jpype.JByte, int], refData: jpype.JArray[jpype.JByte]) -> db.DBRecord:
        ...

    def getRecord(self, key: typing.Union[jpype.JLong, int]) -> db.DBRecord:
        ...

    def putRecord(self, record: db.DBRecord):
        """
        
        
        :param key: :param refData:
        """

    def removeRecord(self, key: typing.Union[jpype.JLong, int]):
        """
        
        
        :param jpype.JLong or int key:
        """

    @property
    def record(self) -> db.DBRecord:
        ...


@typing.type_check_only
class RefList(ghidra.program.database.DatabaseObject):

    class_: typing.ClassVar[java.lang.Class]

    def checkRefListSize(self, cache: ghidra.program.database.DBObjectCache[RefList], newSpaceRequired: typing.Union[jpype.JInt, int]) -> RefList:
        """
        Check to see if RefList should be transitioned to a BigRefList.
        A replacement RefList will be returned and the corresponding adapter record
        updated if a transition is performed, otherwise the original
        RefList is returned.
        
        :param ghidra.program.database.DBObjectCache[RefList] cache: RefList object cache
        :param jpype.JInt or int newSpaceRequired: number of references to be added.
        :return: original or replacement RefList
        :rtype: RefList
        :raises IOException:
        """


@typing.type_check_only
class FromAdapterSharedTable(FromAdapter):
    ...
    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class EntryPointReferenceDB(ReferenceDB):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, fromAddr: ghidra.program.model.address.Address, toAddr: ghidra.program.model.address.Address, refType: ghidra.program.model.symbol.RefType, opIndex: typing.Union[jpype.JInt, int], sourceType: ghidra.program.model.symbol.SourceType, isPrimary: typing.Union[jpype.JBoolean, bool], symbolID: typing.Union[jpype.JLong, int]):
        ...


@typing.type_check_only
class ToAdapterV1(ToAdapter):
    """
    Version
    """

    @typing.type_check_only
    class MyAddressKeyAddressIterator(ghidra.program.model.address.AddressIterator):
        """
        Converts an DBLongIterator into an AddressIterator
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, keyIter: db.DBLongIterator):
            ...


    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class OffsetReferenceDB(MemReferenceDB, ghidra.program.model.symbol.OffsetReference):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, program: ghidra.program.model.listing.Program, from_: ghidra.program.model.address.Address, to: ghidra.program.model.address.Address, refType: ghidra.program.model.symbol.RefType, opIndex: typing.Union[jpype.JByte, int], sourceType: ghidra.program.model.symbol.SourceType, isPrimary: typing.Union[jpype.JBoolean, bool], symbolID: typing.Union[jpype.JLong, int], offset: typing.Union[jpype.JLong, int]):
        ...


@typing.type_check_only
class FromAdapter(RecordAdapter):
    ...
    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class ShiftedReferenceDB(MemReferenceDB, ghidra.program.model.symbol.ShiftedReference):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, program: ghidra.program.model.listing.Program, from_: ghidra.program.model.address.Address, to: ghidra.program.model.address.Address, refType: ghidra.program.model.symbol.RefType, opIndex: typing.Union[jpype.JByte, int], sourceType: ghidra.program.model.symbol.SourceType, isPrimary: typing.Union[jpype.JBoolean, bool], symbolID: typing.Union[jpype.JLong, int], shift: typing.Union[jpype.JInt, int]):
        ...

    def getShift(self) -> int:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.model.symbol.ShiftedReference.getShift()`
        """

    def getValue(self) -> int:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.model.symbol.ShiftedReference.getValue()`
        """

    @property
    def shift(self) -> jpype.JInt:
        ...

    @property
    def value(self) -> jpype.JLong:
        ...


@typing.type_check_only
class OldStackRefDBAdpater(java.lang.Object):
    """
    Adapter for the stack references table in the database.
    """

    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class RefListFlagsV0(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, isPrimary: typing.Union[jpype.JBoolean, bool], isOffsetRef: typing.Union[jpype.JBoolean, bool], hasSymbolID: typing.Union[jpype.JBoolean, bool], isShiftRef: typing.Union[jpype.JBoolean, bool], source: ghidra.program.model.symbol.SourceType):
        ...

    def hasSymbolID(self) -> bool:
        ...

    def isOffsetRef(self) -> bool:
        ...

    def isPrimary(self) -> bool:
        ...

    def isShiftRef(self) -> bool:
        ...

    def setHasSymbolID(self, hasSymbolID: typing.Union[jpype.JBoolean, bool]):
        ...

    def setPrimary(self, isPrimary: typing.Union[jpype.JBoolean, bool]):
        ...

    @property
    def offsetRef(self) -> jpype.JBoolean:
        ...

    @property
    def shiftRef(self) -> jpype.JBoolean:
        ...

    @property
    def primary(self) -> jpype.JBoolean:
        ...

    @primary.setter
    def primary(self, value: jpype.JBoolean):
        ...


@typing.type_check_only
class ToAdapter(RecordAdapter):

    class_: typing.ClassVar[java.lang.Class]

    def putRecord(self, key: typing.Union[jpype.JLong, int], numRefs: typing.Union[jpype.JInt, int], refData: jpype.JArray[jpype.JByte]):
        ...


@typing.type_check_only
class ToAdapterV0(ToAdapter):
    """
    To change the template for this generated type comment go to
    Window>Preferences>Java>Code Generation>Code and Comments
    """

    @typing.type_check_only
    class TranslatedRecordIterator(db.RecordIterator):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]



__all__ = ["ExternalReferenceDB", "EmptyMemReferenceIterator", "FromAdapterV0", "BigRefListV0", "RefListV0", "ReferenceDBManager", "ToAdapterSharedTable", "MemReferenceDB", "ReferenceDB", "StackReferenceDB", "RecordAdapter", "RefList", "FromAdapterSharedTable", "EntryPointReferenceDB", "ToAdapterV1", "OffsetReferenceDB", "FromAdapter", "ShiftedReferenceDB", "OldStackRefDBAdpater", "RefListFlagsV0", "ToAdapter", "ToAdapterV0"]
