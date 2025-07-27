from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import db
import ghidra.framework.data
import ghidra.program.database
import ghidra.program.database.map
import ghidra.program.database.symbol
import ghidra.program.model.address
import ghidra.program.model.symbol
import ghidra.program.util
import ghidra.util
import ghidra.util.task
import java.lang # type: ignore


class ExternalLocationDB(ghidra.program.model.symbol.ExternalLocation):

    @typing.type_check_only
    class ExternalData(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        def getAddressString(self) -> str:
            ...

        @property
        def addressString(self) -> java.lang.String:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def saveOriginalNameIfNeeded(self, oldNamespace: ghidra.program.model.symbol.Namespace, oldName: typing.Union[java.lang.String, str], oldSource: ghidra.program.model.symbol.SourceType):
        ...


@typing.type_check_only
class OldExtNameAdapter(java.lang.Object):
    ...
    class_: typing.ClassVar[java.lang.Class]


class ExternalManagerDB(ghidra.program.database.ManagerDB, ghidra.program.model.symbol.ExternalManager):
    """
    Manages the database for external references.
    """

    @typing.type_check_only
    class ExternalLocationDBIterator(ghidra.program.model.symbol.ExternalLocationIterator):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, handle: db.DBHandle, addrMap: ghidra.program.database.map.AddressMap, openMode: ghidra.framework.data.OpenMode, lock: ghidra.util.Lock, monitor: ghidra.util.task.TaskMonitor):
        """
        Constructs a new ExternalManagerDB
        
        :param db.DBHandle handle: the open database handle
        :param ghidra.program.database.map.AddressMap addrMap: the address map
        :param ghidra.framework.data.OpenMode openMode: the program open mode.
        :param ghidra.util.Lock lock: the program synchronization lock
        :param ghidra.util.task.TaskMonitor monitor: the progress monitor used when upgrading
        :raises CancelledException: if the user cancelled while an upgrade was occurring
        :raises IOException: if a database io error occurs.
        :raises VersionException: if the database version does not match the expected version
        """

    @staticmethod
    def getDefaultExternalName(sym: ghidra.program.database.symbol.SymbolDB) -> str:
        """
        Get the default name for an external function or code symbol
        
        :param ghidra.program.database.symbol.SymbolDB sym: 
        :return: default name
        :rtype: str
        """

    def getExtLocation(self, externalAddr: ghidra.program.model.address.Address) -> ghidra.program.model.symbol.ExternalLocation:
        """
        Returns the external location associated with the given external address
        
        :param ghidra.program.model.address.Address externalAddr: the external address.
        """

    def removeExternalLocation(self, externalAddr: ghidra.program.model.address.Address) -> bool:
        """
        Removes the external location at the given external address
        
        :param ghidra.program.model.address.Address externalAddr: the address at which to remove the external location.
        """

    def setLanguage(self, translator: ghidra.program.util.LanguageTranslator, monitor: ghidra.util.task.TaskMonitor):
        ...

    def updateExternalLibraryName(self, oldName: typing.Union[java.lang.String, str], newName: typing.Union[java.lang.String, str], source: ghidra.program.model.symbol.SourceType):
        """
        Update the external program for all references.
        
        :param java.lang.String or str oldName: old external program name
        :param java.lang.String or str newName: new external program name
        :param ghidra.program.model.symbol.SourceType source: the source of this external library:
        Symbol.DEFAULT, Symbol.ANALYSIS, Symbol.IMPORTED, or Symbol.USER_DEFINED
        :raises DuplicateNameException: 
        :raises InvalidInputException:
        """

    @property
    def extLocation(self) -> ghidra.program.model.symbol.ExternalLocation:
        ...


@typing.type_check_only
class OldExtRefAdapter(java.lang.Object):
    ...
    class_: typing.ClassVar[java.lang.Class]



__all__ = ["ExternalLocationDB", "OldExtNameAdapter", "ExternalManagerDB", "OldExtRefAdapter"]
