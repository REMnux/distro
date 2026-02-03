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
import ghidra.util
import ghidra.util.task
import java.lang # type: ignore


class ExternalLocationDB(ghidra.program.model.symbol.ExternalLocation):

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
        :return: the default name for an external function or code symbol
        :rtype: str
        
        
        :param ghidra.program.database.symbol.SymbolDB sym: external label or function symbol
        :raises IllegalArgumentException: if external label or function symbol not specified or 
        external symbol does not have an external program address.
        """

    def getExtLocation(self, externalAddr: ghidra.program.model.address.Address) -> ghidra.program.model.symbol.ExternalLocation:
        """
        :return: the external location associated with the given external address or null
        :rtype: ghidra.program.model.symbol.ExternalLocation
        
        
        :param ghidra.program.model.address.Address externalAddr: the external address.
        :raises IllegalArgumentException: if address is not external
        """

    def removeExternalLocation(self, externalAddr: ghidra.program.model.address.Address) -> bool:
        """
        Removes the external location at the given external address
        
        :param ghidra.program.model.address.Address externalAddr: the address at which to remove the external location.
        :return: true if external location was successfully removed else false
        :rtype: bool
        """

    @property
    def extLocation(self) -> ghidra.program.model.symbol.ExternalLocation:
        ...


@typing.type_check_only
class OldExtRefAdapter(java.lang.Object):
    ...
    class_: typing.ClassVar[java.lang.Class]



__all__ = ["ExternalLocationDB", "OldExtNameAdapter", "ExternalManagerDB", "OldExtRefAdapter"]
