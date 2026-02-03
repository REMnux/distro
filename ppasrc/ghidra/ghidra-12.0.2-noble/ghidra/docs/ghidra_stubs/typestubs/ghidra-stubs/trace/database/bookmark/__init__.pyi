from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import db
import ghidra.framework.data
import ghidra.program.model.address
import ghidra.program.model.lang
import ghidra.trace.database
import ghidra.trace.database.map
import ghidra.trace.database.space
import ghidra.trace.database.thread
import ghidra.trace.model.bookmark
import ghidra.util.database
import ghidra.util.task
import java.awt # type: ignore
import java.lang # type: ignore
import java.util # type: ignore
import java.util.concurrent.locks # type: ignore
import javax.swing # type: ignore


class DBTraceBookmarkManager(ghidra.trace.database.space.AbstractDBTraceSpaceBasedManager[DBTraceBookmarkSpace], ghidra.trace.model.bookmark.TraceBookmarkManager, ghidra.trace.database.space.DBTraceDelegatingManager[DBTraceBookmarkSpace]):

    class_: typing.ClassVar[java.lang.Class]
    NAME: typing.Final = "Bookmark"

    def __init__(self, dbh: db.DBHandle, openMode: ghidra.framework.data.OpenMode, lock: java.util.concurrent.locks.ReadWriteLock, monitor: ghidra.util.task.TaskMonitor, baseLanguage: ghidra.program.model.lang.Language, trace: ghidra.trace.database.DBTrace, threadManager: ghidra.trace.database.thread.DBTraceThreadManager):
        ...

    def getBookmarksByType(self, typeName: typing.Union[java.lang.String, str]) -> java.util.Collection[DBTraceBookmark]:
        ...

    def getOrDefineBookmarkType(self, typeName: typing.Union[java.lang.String, str]) -> DBTraceBookmarkType:
        ...

    def isDefinedType(self, type: typing.Union[java.lang.String, str]) -> bool:
        ...

    @property
    def orDefineBookmarkType(self) -> DBTraceBookmarkType:
        ...

    @property
    def definedType(self) -> jpype.JBoolean:
        ...

    @property
    def bookmarksByType(self) -> java.util.Collection[DBTraceBookmark]:
        ...


class DBTraceBookmarkSpace(ghidra.trace.model.bookmark.TraceBookmarkSpace, ghidra.trace.database.space.DBTraceSpaceBased):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, manager: DBTraceBookmarkManager, space: ghidra.program.model.address.AddressSpace):
        ...

    def getBookmarksByType(self, typeName: typing.Union[java.lang.String, str]) -> java.util.Collection[DBTraceBookmark]:
        ...

    @property
    def bookmarksByType(self) -> java.util.Collection[DBTraceBookmark]:
        ...


class DBTraceBookmark(ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMapTree.AbstractDBTraceAddressSnapRangePropertyMapData[DBTraceBookmark], ghidra.trace.model.bookmark.TraceBookmark):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, space: DBTraceBookmarkSpace, tree: ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMapTree[DBTraceBookmark, typing.Any], store: ghidra.util.database.DBCachedObjectStore[typing.Any], record: db.DBRecord):
        ...


class DBTraceBookmarkType(ghidra.trace.model.bookmark.TraceBookmarkType):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, manager: DBTraceBookmarkManager, name: typing.Union[java.lang.String, str], icon: javax.swing.Icon, color: java.awt.Color, priority: typing.Union[jpype.JInt, int]):
        ...

    @typing.overload
    def __init__(self, manager: DBTraceBookmarkManager, name: typing.Union[java.lang.String, str]):
        ...



__all__ = ["DBTraceBookmarkManager", "DBTraceBookmarkSpace", "DBTraceBookmark", "DBTraceBookmarkType"]
