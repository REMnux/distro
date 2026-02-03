from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.program.model.address
import ghidra.program.model.lang
import ghidra.program.model.listing
import ghidra.trace.model
import ghidra.trace.model.stack
import ghidra.trace.model.thread
import java.awt # type: ignore
import java.lang # type: ignore
import java.util # type: ignore
import javax.swing # type: ignore


class TraceBookmarkOperations(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def addBookmark(self, lifespan: ghidra.trace.model.Lifespan, address: ghidra.program.model.address.Address, type: TraceBookmarkType, category: typing.Union[java.lang.String, str], comment: typing.Union[java.lang.String, str]) -> TraceBookmark:
        """
        Add a bookmark at the given location.
         
        The category need not be created explicitly beforehand. It will be created implicitly if it
        does not already exist.
        
        :param ghidra.trace.model.Lifespan lifespan: the span of snaps to bookmark
        :param ghidra.program.model.address.Address address: the address to bookmark
        :param TraceBookmarkType type: the type of the bookmark
        :param java.lang.String or str category: a category for the bookmark
        :param java.lang.String or str comment: a comment to add to the bookmark
        :return: the new bookmark
        :rtype: TraceBookmark
        """

    def getAllBookmarks(self) -> java.util.Collection[TraceBookmark]:
        ...

    def getBookmarksAt(self, snap: typing.Union[jpype.JLong, int], address: ghidra.program.model.address.Address) -> java.lang.Iterable[TraceBookmark]:
        ...

    def getBookmarksEnclosed(self, lifespan: ghidra.trace.model.Lifespan, range: ghidra.program.model.address.AddressRange) -> java.lang.Iterable[TraceBookmark]:
        ...

    def getBookmarksIntersecting(self, lifespan: ghidra.trace.model.Lifespan, range: ghidra.program.model.address.AddressRange) -> java.lang.Iterable[TraceBookmark]:
        ...

    def getCategoriesForType(self, type: TraceBookmarkType) -> java.util.Set[java.lang.String]:
        """
        Get all the categories used for a given type
        
        :param TraceBookmarkType type: the bookmark type
        :return: the set of categories
        :rtype: java.util.Set[java.lang.String]
        """

    @property
    def allBookmarks(self) -> java.util.Collection[TraceBookmark]:
        ...

    @property
    def categoriesForType(self) -> java.util.Set[java.lang.String]:
        ...


class TraceBookmarkType(ghidra.program.model.listing.BookmarkType):

    class_: typing.ClassVar[java.lang.Class]

    def countBookmarks(self) -> int:
        ...

    def getBookmarks(self) -> java.util.Collection[TraceBookmark]:
        ...

    def getCategories(self) -> java.util.Collection[java.lang.String]:
        ...

    def setIcon(self, icon: javax.swing.ImageIcon):
        ...

    def setMarkerColor(self, color: java.awt.Color):
        ...

    def setMarkerPriority(self, priority: typing.Union[jpype.JInt, int]):
        ...

    @property
    def bookmarks(self) -> java.util.Collection[TraceBookmark]:
        ...

    @property
    def categories(self) -> java.util.Collection[java.lang.String]:
        ...


class TraceBookmarkSpace(TraceBookmarkOperations):

    class_: typing.ClassVar[java.lang.Class]

    def addBookmark(self, lifespan: ghidra.trace.model.Lifespan, register: ghidra.program.model.lang.Register, type: TraceBookmarkType, category: typing.Union[java.lang.String, str], comment: typing.Union[java.lang.String, str]) -> TraceBookmark:
        ...

    def getAddressSpace(self) -> ghidra.program.model.address.AddressSpace:
        ...

    def getBookmarksEnclosed(self, lifespan: ghidra.trace.model.Lifespan, register: ghidra.program.model.lang.Register) -> java.lang.Iterable[TraceBookmark]:
        ...

    def getBookmarksIntersecting(self, lifespan: ghidra.trace.model.Lifespan, register: ghidra.program.model.lang.Register) -> java.lang.Iterable[TraceBookmark]:
        ...

    def getTrace(self) -> ghidra.trace.model.Trace:
        ...

    @property
    def trace(self) -> ghidra.trace.model.Trace:
        ...

    @property
    def addressSpace(self) -> ghidra.program.model.address.AddressSpace:
        ...


class TraceBookmark(ghidra.program.model.listing.Bookmark):

    class_: typing.ClassVar[java.lang.Class]

    def delete(self):
        ...

    def getLifespan(self) -> ghidra.trace.model.Lifespan:
        ...

    def getThread(self) -> ghidra.trace.model.thread.TraceThread:
        """
        If this bookmark is in a register space, identifies the containing thread
        
        :return: the thread, or null if this bookmark is not in register space
        :rtype: ghidra.trace.model.thread.TraceThread
        """

    def getTrace(self) -> ghidra.trace.model.Trace:
        ...

    def setLifespan(self, lifespan: ghidra.trace.model.Lifespan):
        ...

    @property
    def trace(self) -> ghidra.trace.model.Trace:
        ...

    @property
    def lifespan(self) -> ghidra.trace.model.Lifespan:
        ...

    @lifespan.setter
    def lifespan(self, value: ghidra.trace.model.Lifespan):
        ...

    @property
    def thread(self) -> ghidra.trace.model.thread.TraceThread:
        ...


class TraceBookmarkManager(TraceBookmarkOperations):

    class_: typing.ClassVar[java.lang.Class]

    def defineBookmarkType(self, name: typing.Union[java.lang.String, str], icon: javax.swing.Icon, color: java.awt.Color, priority: typing.Union[jpype.JInt, int]) -> TraceBookmarkType:
        """
        Define (or redefine) a bookmark type.
         
        Bookmark type metadata are not stored in the database. To customize these things, a plugin
        must call this method for every opened program
        
        :param java.lang.String or str name: a name to uniquely identify the type
        :param javax.swing.Icon icon: an icon for displaying the mark (usually in the listing margin)
        :param java.awt.Color color: a color for displaying the mark (usually in the listing background)
        :param jpype.JInt or int priority: a priority to determine which mark is displayed when multiple are present at
                    the same location
        :return: the newly-defined type
        :rtype: TraceBookmarkType
        """

    def getBookmark(self, id: typing.Union[jpype.JLong, int]) -> TraceBookmark:
        ...

    @typing.overload
    def getBookmarkRegisterSpace(self, thread: ghidra.trace.model.thread.TraceThread, createIfAbsent: typing.Union[jpype.JBoolean, bool]) -> TraceBookmarkSpace:
        ...

    @typing.overload
    def getBookmarkRegisterSpace(self, frame: ghidra.trace.model.stack.TraceStackFrame, createIfAbsent: typing.Union[jpype.JBoolean, bool]) -> TraceBookmarkSpace:
        ...

    def getBookmarkSpace(self, space: ghidra.program.model.address.AddressSpace, createIfAbsent: typing.Union[jpype.JBoolean, bool]) -> TraceBookmarkSpace:
        ...

    def getBookmarkType(self, name: typing.Union[java.lang.String, str]) -> TraceBookmarkType:
        ...

    def getBookmarksAdded(self, from_: typing.Union[jpype.JLong, int], to: typing.Union[jpype.JLong, int]) -> java.util.Collection[TraceBookmark]:
        ...

    def getBookmarksRemoved(self, from_: typing.Union[jpype.JLong, int], to: typing.Union[jpype.JLong, int]) -> java.util.Collection[TraceBookmark]:
        ...

    def getDefinedBookmarkTypes(self) -> java.util.Collection[TraceBookmarkType]:
        """
        Get the defined bookmark types.
        
        :return: the types
        :rtype: java.util.Collection[TraceBookmarkType]
        """

    @property
    def bookmark(self) -> TraceBookmark:
        ...

    @property
    def definedBookmarkTypes(self) -> java.util.Collection[TraceBookmarkType]:
        ...

    @property
    def bookmarkType(self) -> TraceBookmarkType:
        ...



__all__ = ["TraceBookmarkOperations", "TraceBookmarkType", "TraceBookmarkSpace", "TraceBookmark", "TraceBookmarkManager"]
