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
import ghidra.program.model.util
import ghidra.program.util
import ghidra.util
import ghidra.util.task
import java.lang # type: ignore


T = typing.TypeVar("T")


class ObjectPropertyMapDB(PropertyMapDB[T], ghidra.program.model.util.ObjectPropertyMap[T], typing.Generic[T]):
    """
    Property manager that deals with properties that are of
    a :obj:`Saveable` Object type and store within a database table.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, dbHandle: db.DBHandle, openMode: ghidra.framework.data.OpenMode, errHandler: db.util.ErrorHandler, changeMgr: ghidra.program.util.ChangeManager, addrMap: ghidra.program.database.map.AddressMap, name: typing.Union[java.lang.String, str], saveableObjectClass: java.lang.Class[T], monitor: ghidra.util.task.TaskMonitor, supportsPrivate: typing.Union[jpype.JBoolean, bool]):
        """
        Construct an Saveable object property map.
        
        :param db.DBHandle dbHandle: database handle.
        :param ghidra.framework.data.OpenMode openMode: the mode that the program was openned in or null if instantiated during
        cache invalidate.  Used to detect versioning error only.
        :param db.util.ErrorHandler errHandler: database error handler.
        :param ghidra.program.util.ChangeManager changeMgr: change manager for event notification
        :param ghidra.program.database.map.AddressMap addrMap: address map.
        :param java.lang.String or str name: property name.
        :param java.lang.Class[T] saveableObjectClass: saveable implementation class
        :param ghidra.util.task.TaskMonitor monitor: progress monitor that is only used when upgrading
        :param jpype.JBoolean or bool supportsPrivate: if private saveable changes should not be broadcast
        :raises CancelledException: if the user cancels the upgrade operation.
        :raises IOException: if a database io error occurs.
        :raises VersionException: the map version is incompatible with
        the current Saveable object class version.  This will never be thrown
        if upgrade is true.
        """

    @staticmethod
    def getSaveableClassForName(classPath: typing.Union[java.lang.String, str]) -> java.lang.Class[ghidra.util.Saveable]:
        """
        Returns the class for the indicated class path name.
        If the class can't be determined,
        the GenericSaveable class is returned.
        
        :param java.lang.String or str classPath: the class path name of the desired class.
        :return: the class or a GenericSaveable.
        :rtype: java.lang.Class[ghidra.util.Saveable]
        """


class VoidPropertyMapDB(PropertyMapDB[java.lang.Boolean], ghidra.program.model.util.VoidPropertyMap):
    """
    Property manager that deals with properties that are of
    "void" type, which is a marker for whether a property exists.
    Records contain only a address key are stored within the underlying database table.
    Object values returned are either :obj:`Boolean.TRUE` or null.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, dbHandle: db.DBHandle, openMode: ghidra.framework.data.OpenMode, errHandler: db.util.ErrorHandler, changeMgr: ghidra.program.util.ChangeManager, addrMap: ghidra.program.database.map.AddressMap, name: typing.Union[java.lang.String, str], monitor: ghidra.util.task.TaskMonitor):
        """
        Construct an void object property map.
        
        :param db.DBHandle dbHandle: database handle.
        :param ghidra.framework.data.OpenMode openMode: the mode that the program was openned in or null if instantiated during
        cache invalidate.  Used to detect versioning error only.
        :param db.util.ErrorHandler errHandler: database error handler.
        :param ghidra.program.util.ChangeManager changeMgr: change manager for event notification
        :param ghidra.program.database.map.AddressMap addrMap: address map.
        :param java.lang.String or str name: property name.
        :param ghidra.util.task.TaskMonitor monitor: progress monitor that is only used when upgrading
        :raises VersionException: if the database version is not the expected version.
        :raises CancelledException: if the user cancels the upgrade operation.
        :raises IOException: if a database io error occurs.
        """


class PropertyMapDB(ghidra.program.database.DatabaseObject, ghidra.program.model.util.PropertyMap[T], typing.Generic[T]):
    """
    Abstract class which defines a map containing properties over a set of addresses.
    The map is stored within a database table.
    """

    class_: typing.ClassVar[java.lang.Class]

    def delete(self):
        """
        Delete this property map and all underlying tables.
        This method should be overidden if any table other than the 
        default propertyTable is used.
        
        :raises IOException: if IO error occurs
        """

    @typing.overload
    def getAddressKeyIterator(self, set: ghidra.program.model.address.AddressSetView, atStart: typing.Union[jpype.JBoolean, bool]) -> ghidra.program.database.map.AddressKeyIterator:
        """
        Get an iterator over the long address keys which contain a property value.
        
        :param ghidra.program.model.address.AddressSetView set: addresses over which to iterate (null indicates all defined memory regions)
        :param jpype.JBoolean or bool atStart: true if the iterator should be positioned at the start
        of the range
        :return: long address iterator.
        :rtype: ghidra.program.database.map.AddressKeyIterator
        :raises IOException: if IO error occurs
        """

    @typing.overload
    def getAddressKeyIterator(self, start: ghidra.program.model.address.Address, before: typing.Union[jpype.JBoolean, bool]) -> ghidra.program.database.map.AddressKeyIterator:
        """
        Get an iterator over the long address keys which contain a property value.
        
        :param ghidra.program.model.address.Address start: iterator starting position
        :param jpype.JBoolean or bool before: true if the iterator should be positioned before the start address
        :return: long address iterator.
        :rtype: ghidra.program.database.map.AddressKeyIterator
        :raises IOException: if IO error occurs
        """

    @typing.overload
    def getAddressKeyIterator(self, start: ghidra.program.model.address.Address, end: ghidra.program.model.address.Address, atStart: typing.Union[jpype.JBoolean, bool]) -> ghidra.program.database.map.AddressKeyIterator:
        """
        Get an iterator over the long address keys which contain a property value.
        
        :param ghidra.program.model.address.Address start: start of iterator address range
        :param ghidra.program.model.address.Address end: end of iterator address range
        :param jpype.JBoolean or bool atStart: true if the iterator should be positioned at the start
        of the range
        :return: long address iterator.
        :rtype: ghidra.program.database.map.AddressKeyIterator
        :raises IOException: if IO error occurs
        """

    @staticmethod
    def getTableName(propertyName: typing.Union[java.lang.String, str]) -> str:
        ...

    def invalidate(self):
        """
        Invalidates the cache.
        """

    def setCacheSize(self, size: typing.Union[jpype.JInt, int]):
        """
        Adjust the size of the underlying read cache.
        
        :param jpype.JInt or int size: the size of the cache.
        """


class DBPropertyMapManager(ghidra.program.model.util.PropertyMapManager, ghidra.program.database.ManagerDB):
    """
    Manages generic address keyed properties.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, handle: db.DBHandle, changeMgr: ghidra.program.util.ChangeManager, addrMap: ghidra.program.database.map.AddressMap, openMode: ghidra.framework.data.OpenMode, lock: ghidra.util.Lock, monitor: ghidra.util.task.TaskMonitor):
        """
        Constructs a new DBPropertyMapManager
        
        :param db.DBHandle handle: the database handle
        :param ghidra.program.util.ChangeManager changeMgr: the change manager
        :param ghidra.program.database.map.AddressMap addrMap: the address map
        :param ghidra.framework.data.OpenMode openMode: the program open mode.
        :param ghidra.util.Lock lock: the program synchronization lock
        :param ghidra.util.task.TaskMonitor monitor: the task monitor
        :raises IOException: if an IO error occurs
        :raises VersionException: if a version error occurs
        :raises CancelledException: if task is cancelled
        """

    def createIntPropertyMap(self, propertyName: typing.Union[java.lang.String, str]) -> ghidra.program.model.util.IntPropertyMap:
        """
        Creates a new IntPropertyMap with the given name.
        
        :param java.lang.String or str propertyName: the name of the property to create.
        :raises DuplicateNameException: thrown if a PropertyMap already
        exists with that name.
        """

    def createLongPropertyMap(self, propertyName: typing.Union[java.lang.String, str]) -> ghidra.program.model.util.LongPropertyMap:
        """
        Creates a new LongPropertyMap with the given name.
        
        :param java.lang.String or str propertyName: the name of the property to create.
        :raises DuplicateNameException: thrown if a PropertyMap already
        exists with that name.
        """

    def createStringPropertyMap(self, propertyName: typing.Union[java.lang.String, str]) -> ghidra.program.model.util.StringPropertyMap:
        """
        Creates a new StringPropertyMap with the given name.
        
        :param java.lang.String or str propertyName: the name of the property to create.
        :raises DuplicateNameException: thrown if a PropertyMap already
        exists with that name.
        """

    def createVoidPropertyMap(self, propertyName: typing.Union[java.lang.String, str]) -> ghidra.program.model.util.VoidPropertyMap:
        """
        Creates a new VoidPropertyMap with the given name.
        
        :param java.lang.String or str propertyName: the name of the property to create.
        :raises DuplicateNameException: thrown if a PropertyMap already
        exists with that name.
        """

    def getIntPropertyMap(self, propertyName: typing.Union[java.lang.String, str]) -> ghidra.program.model.util.IntPropertyMap:
        """
        Returns the IntPropertyMap associated with the given name.
        
        :param java.lang.String or str propertyName: the name of the property to retrieve.
        :raises TypeMismatchException: if a propertyMap named propertyName
        exists but is not an IntPropertyMap.
        """

    def getLongPropertyMap(self, propertyName: typing.Union[java.lang.String, str]) -> ghidra.program.model.util.LongPropertyMap:
        """
        Returns the LongPropertyMap associated with the given name.
        
        :param java.lang.String or str propertyName: the name of the property to retrieve.
        :raises TypeMismatchException: if a propertyMap named propertyName
        exists but is not an LongPropertyMap.
        """

    def getObjectPropertyMap(self, propertyName: typing.Union[java.lang.String, str]) -> ghidra.program.model.util.ObjectPropertyMap[typing.Any]:
        """
        Returns the ObjectPropertyMap associated with the given name.
        
        :param java.lang.String or str propertyName: the name of the property to retrieve.
        :raises TypeMismatchException: if a propertyMap named propertyName
        exists but is not an ObjectPropertyMap.
        """

    def getPropertyMap(self, propertyName: typing.Union[java.lang.String, str]) -> ghidra.program.model.util.PropertyMap[typing.Any]:
        """
        Returns the PropertyMap with the given name or null if no PropertyMap
        exists with that name.
        
        :param java.lang.String or str propertyName: the name of the property to retrieve.
        """

    def getStringPropertyMap(self, propertyName: typing.Union[java.lang.String, str]) -> ghidra.program.model.util.StringPropertyMap:
        """
        Returns the StringPropertyMap associated with the given name.
        
        :param java.lang.String or str propertyName: the name of the property to retrieve.
        :raises TypeMismatchException: if a propertyMap named propertyName
        exists but is not a StringPropertyMap.
        """

    def getVoidPropertyMap(self, propertyName: typing.Union[java.lang.String, str]) -> ghidra.program.model.util.VoidPropertyMap:
        """
        Returns the VoidPropertyMap associated with the given name.
        
        :param java.lang.String or str propertyName: the name of the property to retrieve.
        :raises TypeMismatchException: if a propertyMap named propertyName
        exists but is not a VoidPropertyMap.
        """

    @property
    def intPropertyMap(self) -> ghidra.program.model.util.IntPropertyMap:
        ...

    @property
    def voidPropertyMap(self) -> ghidra.program.model.util.VoidPropertyMap:
        ...

    @property
    def stringPropertyMap(self) -> ghidra.program.model.util.StringPropertyMap:
        ...

    @property
    def propertyMap(self) -> ghidra.program.model.util.PropertyMap[typing.Any]:
        ...

    @property
    def longPropertyMap(self) -> ghidra.program.model.util.LongPropertyMap:
        ...

    @property
    def objectPropertyMap(self) -> ghidra.program.model.util.ObjectPropertyMap[typing.Any]:
        ...


class GenericSaveable(ghidra.util.Saveable):
    """
    ``GenericSaveable`` is used by the ``DBPropertyMapManager``
    when the class can not be found and loaded for the class path name of a 
    property in the database. This allows the properties for that class to be 
    accessed in a generic way so that the manager can copy or remove the property 
    at a particular address. This allows the Diff and MultiUser Merge to compare 
    and manipulate the property as needed.
    """

    class_: typing.ClassVar[java.lang.Class]


class StringPropertyMapDB(PropertyMapDB[java.lang.String], ghidra.program.model.util.StringPropertyMap):
    """
    Property manager that deals with properties that are of
    String type and stored with a database table.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, dbHandle: db.DBHandle, openMode: ghidra.framework.data.OpenMode, errHandler: db.util.ErrorHandler, changeMgr: ghidra.program.util.ChangeManager, addrMap: ghidra.program.database.map.AddressMap, name: typing.Union[java.lang.String, str], monitor: ghidra.util.task.TaskMonitor):
        """
        Construct an String property map.
        
        :param db.DBHandle dbHandle: database handle.
        :param ghidra.framework.data.OpenMode openMode: the mode that the program was openned in or null if instantiated during
        cache invalidate.  Used to detect versioning error only.
        :param db.util.ErrorHandler errHandler: database error handler.
        :param ghidra.program.util.ChangeManager changeMgr: change manager for event notification
        :param ghidra.program.database.map.AddressMap addrMap: address map.
        :param java.lang.String or str name: property name.
        :param ghidra.util.task.TaskMonitor monitor: progress monitor that is only used when upgrading
        :raises VersionException: if the database version is not the expected version.
        :raises CancelledException: if the user cancels the upgrade operation.
        :raises IOException: if a database io error occurs.
        """


class LongPropertyMapDB(PropertyMapDB[java.lang.Long], ghidra.program.model.util.LongPropertyMap):
    """
    Property manager that deals with properties that are of
    long type and stored with a database table.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, dbHandle: db.DBHandle, openMode: ghidra.framework.data.OpenMode, errHandler: db.util.ErrorHandler, changeMgr: ghidra.program.util.ChangeManager, addrMap: ghidra.program.database.map.AddressMap, name: typing.Union[java.lang.String, str], monitor: ghidra.util.task.TaskMonitor):
        """
        Construct a long property map.
        
        :param db.DBHandle dbHandle: database handle.
        :param ghidra.framework.data.OpenMode openMode: the mode that the program was openned in or null if instantiated during
        cache invalidate.  Used to detect versioning error only.
        :param db.util.ErrorHandler errHandler: database error handler.
        :param ghidra.program.util.ChangeManager changeMgr: change manager for event notification
        :param ghidra.program.database.map.AddressMap addrMap: address map.
        :param java.lang.String or str name: property name.
        :param ghidra.util.task.TaskMonitor monitor: progress monitor that is only used when upgrading
        :raises VersionException: if the database version is not the expected version.
        :raises CancelledException: if the user cancels the upgrade operation.
        :raises IOException: if a database io error occurs.
        """


class UnsupportedMapDB(PropertyMapDB[java.lang.Object]):
    """
    This class provides a dummy map for an unsupported map.
    """

    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class PropertiesDBAdapterV0(PropertiesDBAdapter):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, dbHandle: db.DBHandle):
        """
        Construct property map DB adapter
        
        :param db.DBHandle dbHandle: database handle
        :raises VersionException: if version error occurs
        """


@typing.type_check_only
class PropertiesDBAdapter(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def getRecords(self) -> db.RecordIterator:
        """
        Iterate over the records contained within the Properties table.
        
        :return: RecordIterator record iterator
        :rtype: db.RecordIterator
        :raises IOException: if an IO error occurs
        """

    def putRecord(self, propertyName: typing.Union[java.lang.String, str], type: typing.Union[jpype.JByte, int], objClassName: typing.Union[java.lang.String, str]):
        """
        Create a new property map definition record.
        
        :param java.lang.String or str propertyName: unique property name.
        :param jpype.JByte or int type: property map type
        :param java.lang.String or str objClassName: full class name for Saveable objects when
        type is OBJECT_PROPERTY_TYPE, else value should be null.
        :raises IOException: if an IO error occurs
        """

    def removeRecord(self, propertyName: typing.Union[java.lang.String, str]):
        """
        Remove a specific property map definition record.
        
        :param java.lang.String or str propertyName: property map name
        :raises IOException: if an IO error occurs
        """

    @property
    def records(self) -> db.RecordIterator:
        ...


class IntPropertyMapDB(PropertyMapDB[java.lang.Integer], ghidra.program.model.util.IntPropertyMap):
    """
    Property manager that deals with properties that are of
    int type and stored with a database table.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, dbHandle: db.DBHandle, openMode: ghidra.framework.data.OpenMode, errHandler: db.util.ErrorHandler, changeMgr: ghidra.program.util.ChangeManager, addrMap: ghidra.program.database.map.AddressMap, name: typing.Union[java.lang.String, str], monitor: ghidra.util.task.TaskMonitor):
        """
        Construct a integer property map.
        
        :param db.DBHandle dbHandle: database handle.
        :param ghidra.framework.data.OpenMode openMode: the mode that the program was openned in or null if instantiated during
        cache invalidate.  Used to detect versioning error only.
        :param db.util.ErrorHandler errHandler: database error handler.
        :param ghidra.program.util.ChangeManager changeMgr: change manager for event notification
        :param ghidra.program.database.map.AddressMap addrMap: address map.
        :param java.lang.String or str name: property name.
        :param ghidra.util.task.TaskMonitor monitor: progress monitor that is only used when upgrading
        :raises VersionException: if the database version is not the expected version.
        :raises CancelledException: if the user cancels the upgrade operation.
        :raises IOException: if a database io error occurs.
        """



__all__ = ["ObjectPropertyMapDB", "VoidPropertyMapDB", "PropertyMapDB", "DBPropertyMapManager", "GenericSaveable", "StringPropertyMapDB", "LongPropertyMapDB", "UnsupportedMapDB", "PropertiesDBAdapterV0", "PropertiesDBAdapter", "IntPropertyMapDB"]
