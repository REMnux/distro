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
class BookmarkDBAdapterV2(BookmarkDBAdapterV1):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, dbHandle: db.DBHandle, addrMap: ghidra.program.database.map.AddressMap):
        """
        Constructor (Version 2 Schema)
        """


@typing.type_check_only
class BookmarkDBAdapterV0(BookmarkDBAdapter):
    ...
    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class OldBookmarkManager(java.lang.Object):
    """
    Interface to manage bookmarks on a program.
    """

    class_: typing.ClassVar[java.lang.Class]
    OLD_BOOKMARK_PROPERTY: typing.Final = "Bookmarks"

    def getTypeRecords(self) -> jpype.JArray[db.DBRecord]:
        """
        Returns array of bookmark type records
        """

    @property
    def typeRecords(self) -> jpype.JArray[db.DBRecord]:
        ...


@typing.type_check_only
class EmptyAddressIterator(ghidra.program.model.address.AddressIterator):

    class_: typing.ClassVar[java.lang.Class]

    def hasPrevious(self) -> bool:
        ...

    def previous(self) -> ghidra.program.model.address.Address:
        ...


class BookmarkTypeDBAdapterV0(BookmarkTypeDBAdapter):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, dbHandle: db.DBHandle, create: typing.Union[jpype.JBoolean, bool]):
        ...


class BookmarkDBManager(ghidra.program.model.listing.BookmarkManager, db.util.ErrorHandler, ghidra.program.database.ManagerDB):

    @typing.type_check_only
    class BookmarkRecordIterator(java.util.Iterator[ghidra.program.model.listing.Bookmark]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class TotalIterator(java.util.Iterator[ghidra.program.model.listing.Bookmark]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, handle: db.DBHandle, addrMap: ghidra.program.database.map.AddressMap, openMode: ghidra.framework.data.OpenMode, lock: ghidra.util.Lock, monitor: ghidra.util.task.TaskMonitor):
        """
        Constructs a new CodeManager for a program.
        
        :param db.DBHandle handle: handle to database
        :param ghidra.program.database.map.AddressMap addrMap: addressMap to convert between addresses and long values.
        :param ghidra.framework.data.OpenMode openMode: either READ_ONLY, UPDATE, or UPGRADE
        :param ghidra.util.Lock lock: the program synchronization lock
        :param ghidra.util.task.TaskMonitor monitor: the task monitor use while upgrading.
        :raises VersionException: if the database is incompatible with the current
        schema
        :raises IOException: if there is a problem accessing the database.
        """

    def invalidateCache(self, all: typing.Union[jpype.JBoolean, bool]):
        """
        Invalidate cached objects held by this manager.
        """


@typing.type_check_only
class BookmarkDBAdapterV1(BookmarkDBAdapter):

    @typing.type_check_only
    class BatchRecordIterator(db.RecordIterator):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class V1ConvertedRecordIterator(db.ConvertedRecordIterator):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]


class BookmarkTypeDB(ghidra.program.model.listing.BookmarkType):
    ...
    class_: typing.ClassVar[java.lang.Class]


class BookmarkDBAdapterV3(BookmarkDBAdapter):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, handle: db.DBHandle, create: typing.Union[jpype.JBoolean, bool], typeIDs: jpype.JArray[jpype.JInt], addrMap: ghidra.program.database.map.AddressMap):
        ...


class OldBookmark(ghidra.util.Saveable):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, type: typing.Union[java.lang.String, str], category: typing.Union[java.lang.String, str], comment: typing.Union[java.lang.String, str], addr: ghidra.program.model.address.Address):
        """
        Constructs a Bookmark.
        
        :param java.lang.String or str type: 
        :param java.lang.String or str category: 
        :param java.lang.String or str comment: 
        :param ghidra.program.model.address.Address addr:
        """

    @typing.overload
    def __init__(self):
        """
        Constructs a Note Bookmark (required for Saveable property objects).
        Contains no address.
        """

    def equals(self, obj: java.lang.Object) -> bool:
        """
        Return true if this object is the same as obj.
        """

    def getAddress(self) -> ghidra.program.model.address.Address:
        """
        Get the address of this bookmark info.
        
        :return: Address
        :rtype: ghidra.program.model.address.Address
        """

    def getCategory(self) -> str:
        ...

    def getComment(self) -> str:
        ...

    def getType(self) -> str:
        ...

    def setCategory(self, category: typing.Union[java.lang.String, str]):
        ...

    def setComment(self, comment: typing.Union[java.lang.String, str]):
        ...

    @property
    def address(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def comment(self) -> java.lang.String:
        ...

    @comment.setter
    def comment(self, value: java.lang.String):
        ...

    @property
    def type(self) -> java.lang.String:
        ...

    @property
    def category(self) -> java.lang.String:
        ...

    @category.setter
    def category(self, value: java.lang.String):
        ...


@typing.type_check_only
class BookmarkTypeDBAdapter(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def getTypeIds(self) -> jpype.JArray[jpype.JInt]:
        ...

    @property
    def typeIds(self) -> jpype.JArray[jpype.JInt]:
        ...


class BookmarkDB(ghidra.program.database.DatabaseObject, ghidra.program.model.listing.Bookmark):

    class_: typing.ClassVar[java.lang.Class]

    def getType(self) -> ghidra.program.model.listing.BookmarkType:
        """
        Returns bookmark type or null if type has been removed.
        """

    def setComment(self, comment: typing.Union[java.lang.String, str]):
        ...

    @property
    def type(self) -> ghidra.program.model.listing.BookmarkType:
        ...


class BookmarkTypeDBAdapterNoTable(BookmarkTypeDBAdapter):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, dbHandle: db.DBHandle):
        """
        
        
        :param db.DBHandle dbHandle: the database handle
        """

    def setOldBookmarkManager(self, oldMgr: OldBookmarkManager):
        """
        Set the old bookmark manager which handles read-only access
        to bookmarks stored within property maps.
        The old bookmark manager must be set prior to invoking any other method;
        
        :param OldBookmarkManager oldMgr: old bookmark manager
        """


@typing.type_check_only
class BookmarkDBAdapter(java.lang.Object):
    ...
    class_: typing.ClassVar[java.lang.Class]



__all__ = ["BookmarkDBAdapterV2", "BookmarkDBAdapterV0", "OldBookmarkManager", "EmptyAddressIterator", "BookmarkTypeDBAdapterV0", "BookmarkDBManager", "BookmarkDBAdapterV1", "BookmarkTypeDB", "BookmarkDBAdapterV3", "OldBookmark", "BookmarkTypeDBAdapter", "BookmarkDB", "BookmarkTypeDBAdapterNoTable", "BookmarkDBAdapter"]
