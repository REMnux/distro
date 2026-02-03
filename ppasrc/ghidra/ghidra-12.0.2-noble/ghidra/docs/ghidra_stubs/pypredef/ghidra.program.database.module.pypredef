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
import ghidra.util
import ghidra.util.task
import java.lang # type: ignore
import java.util # type: ignore


@typing.type_check_only
class ModuleDBAdapter(java.lang.Object):
    ...
    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class ProgramTreeDBAdapter(java.lang.Object):
    ...
    class_: typing.ClassVar[java.lang.Class]


class ParentChildDBAdapterV0(ParentChildDBAdapter):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, handle: db.DBHandle, create: typing.Union[jpype.JBoolean, bool], treeID: typing.Union[jpype.JLong, int]):
        """
        Gets a version 0 adapter for the program tree parent/child database table.
        
        :param db.DBHandle handle: handle to the database containing the table.
        :param jpype.JBoolean or bool create: true if this constructor should create the table.
        :param jpype.JLong or int treeID: associated program tree ID
        :raises VersionException: if the table's version does not match the expected version
        for this adapter.
        :raises IOException: if database IO error occurs
        """


@typing.type_check_only
class FragmentDBAdapter(java.lang.Object):
    ...
    class_: typing.ClassVar[java.lang.Class]


class ProgramTreeDBAdapterV0(ProgramTreeDBAdapter):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, handle: db.DBHandle, create: typing.Union[jpype.JBoolean, bool]):
        """
        Gets a version 0 adapter for the program tree database table.
        
        :param db.DBHandle handle: handle to the database containing the table.
        :param jpype.JBoolean or bool create: true if this constructor should create the table.
        :raises VersionException: if the table's version does not match the expected version
        for this adapter.
        :raises IOException: if database IO error occurs
        """


@typing.type_check_only
class ModuleDB(ghidra.program.database.DatabaseObject, ghidra.program.model.listing.ProgramModule):
    """
    Database implementation for Module.
    """

    @typing.type_check_only
    class ParentChildRecordComparator(java.util.Comparator[db.DBRecord]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class ModuleManager(java.lang.Object):
    """
    Manages the tables for modules and fragments in a tree view.
    """

    @typing.type_check_only
    class FragmentHolder(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class FragmentDB(ghidra.program.database.DatabaseObject, ghidra.program.model.listing.ProgramFragment):
    """
    Database implementation for Fragment.
    """

    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class ModuleDBAdapterV0(ModuleDBAdapter, db.RecordTranslator):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, handle: db.DBHandle, treeID: typing.Union[jpype.JLong, int], parentChildAdapter: ParentChildDBAdapter):
        """
        Gets a version 0 adapter for the program tree module database table (read-only).
        
        :param db.DBHandle handle: handle to the database containing the table.
        :param jpype.JLong or int treeID: associated program tree ID
        :param ParentChildDBAdapter parentChildAdapter: parent/child database adapter
        :raises VersionException: if the table's version does not match the expected version
        for this adapter.
        :raises IOException: if database IO error occurs
        """


@typing.type_check_only
class FragmentDBAdapterV0(FragmentDBAdapter):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, handle: db.DBHandle, create: typing.Union[jpype.JBoolean, bool], treeID: typing.Union[jpype.JLong, int]):
        """
        Gets a version 0 adapter for the program tree fragment database table.
        
        :param db.DBHandle handle: handle to the database containing the table.
        :param jpype.JBoolean or bool create: true if this constructor should create the table.
        :param jpype.JLong or int treeID: associated program tree ID
        :raises VersionException: if the table's version does not match the expected version
        for this adapter.
        :raises IOException: if database IO error occurs
        """


class TreeManager(ghidra.program.database.ManagerDB):
    """
    Manage the set of trees in the program.
    """

    class_: typing.ClassVar[java.lang.Class]
    DEFAULT_TREE_NAME: typing.Final = "Program Tree"
    """
    The name of the default tree that is created when a program is created.
    """


    def __init__(self, handle: db.DBHandle, errHandler: db.util.ErrorHandler, addrMap: ghidra.program.database.map.AddressMap, openMode: ghidra.framework.data.OpenMode, lock: ghidra.util.Lock, monitor: ghidra.util.task.TaskMonitor):
        """
        Construct a new TreeManager.
        
        :param db.DBHandle handle: database handle
        :param db.util.ErrorHandler errHandler: error handler
        :param ghidra.program.database.map.AddressMap addrMap: map to convert addresses to longs and longs to addresses
        :param ghidra.framework.data.OpenMode openMode: the open mode for the program.
        :param ghidra.util.Lock lock: the program synchronization lock
        :param ghidra.util.task.TaskMonitor monitor: Task monitor for upgrading
        :raises IOException: if a database io error occurs.
        :raises VersionException: if the database version is different from the expected version
        :raises CancelledException: if instantiation has been cancelled
        """

    def addMemoryBlock(self, name: typing.Union[java.lang.String, str], range: ghidra.program.model.address.AddressRange):
        """
        Add a memory block with the given range.
        
        :param java.lang.String or str name: memory block name (name of new fragment)
        :param ghidra.program.model.address.AddressRange range: memory block address range
        """

    def createRootModule(self, treeName: typing.Union[java.lang.String, str]) -> ghidra.program.model.listing.ProgramModule:
        """
        Create a new tree with given name.
        
        :param java.lang.String or str treeName: name of the tree (not the root module)
        :return: root module for the new tree
        :rtype: ghidra.program.model.listing.ProgramModule
        :raises DuplicateNameException: if there is already tree named
        treeName
        """

    def getDefaultRootModule(self) -> ghidra.program.model.listing.ProgramModule:
        """
        Returns the root module for the default program tree. The default tree is the oldest tree.
        
        :return: the root module for the default program tree. The default tree is the oldest tree.
        :rtype: ghidra.program.model.listing.ProgramModule
        """

    @typing.overload
    def getFragment(self, treeName: typing.Union[java.lang.String, str], name: typing.Union[java.lang.String, str]) -> ghidra.program.model.listing.ProgramFragment:
        """
        Get the fragment with the given name that is in the tree identified
        by the treeName.
        
        :param java.lang.String or str treeName: name of the tree
        :param java.lang.String or str name: name of fragment to look for
        :return: null if there is no fragment with the given name in the tree
        :rtype: ghidra.program.model.listing.ProgramFragment
        """

    @typing.overload
    def getFragment(self, treeName: typing.Union[java.lang.String, str], addr: ghidra.program.model.address.Address) -> ghidra.program.model.listing.ProgramFragment:
        """
        Get the fragment that contains the given address within the tree
        identified by the treeName.
        
        :param java.lang.String or str treeName: name of the tree
        :param ghidra.program.model.address.Address addr: address contained within some fragment
        :return: fragment containing addr, or null if addr does not
        exist in memory
        :rtype: ghidra.program.model.listing.ProgramFragment
        """

    def getModule(self, treeName: typing.Union[java.lang.String, str], name: typing.Union[java.lang.String, str]) -> ghidra.program.model.listing.ProgramModule:
        """
        Get the module with the given name that is in the tree identified
        by the treeName.
        
        :param java.lang.String or str treeName: name of the tree
        :param java.lang.String or str name: module name to look for
        :return: null if there is no module with the given name in the tree
        :rtype: ghidra.program.model.listing.ProgramModule
        """

    @typing.overload
    def getRootModule(self, treeName: typing.Union[java.lang.String, str]) -> ghidra.program.model.listing.ProgramModule:
        """
        Get the root module of the tree with the given name.
        
        :param java.lang.String or str treeName: tree name
        :return: root module, or null if there is no tree with the
        given name
        :rtype: ghidra.program.model.listing.ProgramModule
        """

    @typing.overload
    def getRootModule(self, treeID: typing.Union[jpype.JLong, int]) -> ghidra.program.model.listing.ProgramModule:
        """
        Get the root module for the tree that has the given ID.
        
        :param jpype.JLong or int treeID: ID of the tree
        :return: root module
        :rtype: ghidra.program.model.listing.ProgramModule
        """

    def getTreeNames(self) -> jpype.JArray[java.lang.String]:
        """
        Get the names of all the trees in the program.
        
        :return: sorted array of tree names
        :rtype: jpype.JArray[java.lang.String]
        """

    def imageBaseChanged(self, commit: typing.Union[jpype.JBoolean, bool]):
        ...

    def removeTree(self, treeName: typing.Union[java.lang.String, str]) -> bool:
        """
        Remove the tree with the given name.
        
        :param java.lang.String or str treeName: tree name
        :return: true if the tree was removed
        :rtype: bool
        """

    def renameTree(self, oldName: typing.Union[java.lang.String, str], newName: typing.Union[java.lang.String, str]):
        """
        Rename the tree to the new name. This method has no effect on the
        name of the root module.
        
        :param java.lang.String or str oldName: old name of root module
        :param java.lang.String or str newName: new name for root module
        :raises DuplicateNameException: if newName exists as the name
        for another root
        """

    def setProgramName(self, oldName: typing.Union[java.lang.String, str], newName: typing.Union[java.lang.String, str]):
        ...

    @property
    def defaultRootModule(self) -> ghidra.program.model.listing.ProgramModule:
        ...

    @property
    def rootModule(self) -> ghidra.program.model.listing.ProgramModule:
        ...

    @property
    def treeNames(self) -> jpype.JArray[java.lang.String]:
        ...


@typing.type_check_only
class ModuleDBAdapterV1(ModuleDBAdapter):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, handle: db.DBHandle, create: typing.Union[jpype.JBoolean, bool], treeID: typing.Union[jpype.JLong, int]):
        """
        Gets a version 0 adapter for the program tree module database table.
        
        :param db.DBHandle handle: handle to the database containing the table.
        :param jpype.JBoolean or bool create: true if this constructor should create the table.
        :param jpype.JLong or int treeID: associated program tree ID
        :raises VersionException: if the table's version does not match the expected version
        for this adapter.
        :raises IOException: if database IO error occurs
        """


@typing.type_check_only
class ParentChildDBAdapter(java.lang.Object):
    ...
    class_: typing.ClassVar[java.lang.Class]



__all__ = ["ModuleDBAdapter", "ProgramTreeDBAdapter", "ParentChildDBAdapterV0", "FragmentDBAdapter", "ProgramTreeDBAdapterV0", "ModuleDB", "ModuleManager", "FragmentDB", "ModuleDBAdapterV0", "FragmentDBAdapterV0", "TreeManager", "ModuleDBAdapterV1", "ParentChildDBAdapter"]
