from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking
import docking.action
import docking.actions
import ghidra.app.plugin
import ghidra.app.services
import ghidra.framework.cmd
import ghidra.framework.model
import ghidra.framework.options
import ghidra.framework.plugintool
import ghidra.program.model.address
import ghidra.program.model.listing
import ghidra.util
import ghidra.util.table
import ghidra.util.table.field
import ghidra.util.task
import java.lang # type: ignore
import java.util # type: ignore
import javax.swing # type: ignore


class BookmarkPlugin(ghidra.app.plugin.ProgramPlugin, docking.actions.PopupActionProvider, ghidra.app.services.BookmarkService):
    """
    Plugin to for adding/deleting/editing bookmarks.
    """

    @typing.type_check_only
    class NavUpdater(java.lang.Runnable):
        """
        Runner used in thread to update bookmark display in the marker margins.
        """

        class_: typing.ClassVar[java.lang.Class]

        def addType(self, type: typing.Union[java.lang.String, str]):
            ...


    class_: typing.ClassVar[java.lang.Class]
    MIN_TIMEOUT: typing.Final = 1000
    MAX_TIMEOUT: typing.Final = 1200000

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...

    def dispose(self):
        """
        Get rid of any resources this plugin is using before the plugin is destroyed.
        """

    def filterBookmarks(self):
        """
        Display a dialog to set up a filter on the displayed bookmarks.
        """

    def reload(self):
        ...

    def setNote(self, addr: ghidra.program.model.address.Address, category: typing.Union[java.lang.String, str], comment: typing.Union[java.lang.String, str]):
        """
        Called when a new bookmark is to be added; called from the add bookmark dialog
        
        :param ghidra.program.model.address.Address addr: bookmark address. If null a Note bookmark will set at the start address of each
                    range in the current selection
        :param java.lang.String or str category: bookmark category
        :param java.lang.String or str comment: comment text
        """


@typing.type_check_only
class AddBookmarkAction(docking.action.DockingAction):
    """
    ``AddBookmarkAction`` allows the user to add a Note bookmark at the current location.
    """

    class_: typing.ClassVar[java.lang.Class]

    def actionPerformed(self, context: docking.ActionContext):
        """
        Method called when the action is invoked.
        
        :param ActionEvent: details regarding the invocation of this action
        """


@typing.type_check_only
class FilterState(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def getBookmarkTypes(self) -> java.util.Set[java.lang.String]:
        ...

    @property
    def bookmarkTypes(self) -> java.util.Set[java.lang.String]:
        ...


class BookmarkEditCmd(ghidra.framework.cmd.Command[ghidra.program.model.listing.Program]):
    """
    Command to set a Bookmark(s) at a location or range of locations.
    The location to create the bookmark(s) can be set by:
        1) by address set where the bookmark is placed at the first address
            in each range in the address set
        2) at a given address
        3) by the information contained in a Bookmark
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, set: ghidra.program.model.address.AddressSetView, type: typing.Union[java.lang.String, str], category: typing.Union[java.lang.String, str], comment: typing.Union[java.lang.String, str]):
        """
        Edit a Bookmark. When editing a bookmark, all fields are used except the address
        which is determined by the first address within each range of the set.
        
        :param ghidra.program.model.address.AddressSetView set: list of bookmark addresses.
        :param java.lang.String or str type: the bookmark type.
        :param java.lang.String or str category: the bookmark category.
        :param java.lang.String or str comment: the bookmark comment.
        """

    @typing.overload
    def __init__(self, addr: ghidra.program.model.address.Address, type: typing.Union[java.lang.String, str], category: typing.Union[java.lang.String, str], comment: typing.Union[java.lang.String, str]):
        """
        Edit a Bookmark. When editing a bookmark, all fields are used except the address
        which is provided by the addrs parameter.
        
        :param ghidra.program.model.address.Address addr: the bookmark address.
        :param java.lang.String or str type: the bookmark type.
        :param java.lang.String or str category: the bookmark category.
        :param java.lang.String or str comment: the bookmark comment.
        """

    @typing.overload
    def __init__(self, bookmark: ghidra.program.model.listing.Bookmark, category: typing.Union[java.lang.String, str], comment: typing.Union[java.lang.String, str]):
        ...

    def getPresentationName(self) -> str:
        """
        The name of the edit action.
        """

    @property
    def presentationName(self) -> java.lang.String:
        ...


@typing.type_check_only
class DeleteBookmarkAction(docking.action.DockingAction):
    """
    ``DeleteFunctionAction`` allows the user to delete a function at
    the entry point of the function.
    """

    class_: typing.ClassVar[java.lang.Class]

    def actionPerformed(self, context: docking.ActionContext):
        """
        Method called when the action is invoked.
        
        :param ActionEvent: details regarding the invocation of this action
        """


class BookmarkDeleteCmd(ghidra.framework.cmd.Command[ghidra.program.model.listing.Program]):
    """
    Command to delete some number of bookmarks.
    The bookmarks to delete can be specified by:
        an array of bookmarks
        an address set to delete all bookmarks within
        by type of bookmark
        by category of bookmark
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, bookmark: ghidra.program.model.listing.Bookmark):
        """
        Delete a Bookmark.
        
        :param ghidra.program.model.listing.Bookmark bookmark: the bookmark to be deleted
        """

    @typing.overload
    def __init__(self, bookmarks: java.util.List[ghidra.program.model.listing.Bookmark]):
        """
        Delete an array of Bookmarks.
        
        :param java.util.List[ghidra.program.model.listing.Bookmark] bookmarks: the array of bookmarks to be deleted.
        """

    @typing.overload
    def __init__(self, addr: ghidra.program.model.address.Address):
        """
        Deletes all bookmarks at the given address
        
        :param ghidra.program.model.address.Address addr: that address at which to delete all bookmarks
        """

    @typing.overload
    def __init__(self, addr: ghidra.program.model.address.Address, type: typing.Union[java.lang.String, str]):
        """
        Deletes all bookmarks at the given address with the given type
        
        :param ghidra.program.model.address.Address addr: the address at which to delete bookmarks of the given type.
        :param java.lang.String or str type: the type of bookmark to delete at the given address
        """

    @typing.overload
    def __init__(self, addr: ghidra.program.model.address.Address, type: typing.Union[java.lang.String, str], category: typing.Union[java.lang.String, str]):
        """
        Deletes all bookmarks at the given address with the given type and category
        
        :param ghidra.program.model.address.Address addr: the address at which to delete bookmarks of the given type and category
        :param java.lang.String or str type: the type of bookmark to delete at the given address
        :param java.lang.String or str category: the category of the bookmark to delete at the given address
        """

    @typing.overload
    def __init__(self, set: ghidra.program.model.address.AddressSetView):
        """
        Deletes all bookmarks in the given address set
        
        :param ghidra.program.model.address.AddressSetView set: set of addresses at which to delete all bookmarks
        """

    @typing.overload
    def __init__(self, set: ghidra.program.model.address.AddressSetView, type: typing.Union[java.lang.String, str]):
        """
        Deletes all bookmarks in the given address set that have the given type
        
        :param ghidra.program.model.address.AddressSetView set: set of addresses at which to delete all bookmarks
        :param java.lang.String or str type: the type of bookmark to delete at the given address
        """

    @typing.overload
    def __init__(self, set: ghidra.program.model.address.AddressSetView, type: typing.Union[java.lang.String, str], category: typing.Union[java.lang.String, str]):
        """
        Deletes all bookmarks at the given address that have the given type and category
        
        :param ghidra.program.model.address.AddressSetView set: set of addresses at which to delete all bookmarks
        :param java.lang.String or str type: the type of bookmark to delete at the given address
        :param java.lang.String or str category: the category of the bookmark to delete at the given address
        """

    @typing.overload
    def __init__(self, type: typing.Union[java.lang.String, str]):
        """
        Deletes all bookmarks of the given type.
        
        :param java.lang.String or str type: the type of bookmarks to delete
        """

    @typing.overload
    def __init__(self, type: typing.Union[java.lang.String, str], category: typing.Union[java.lang.String, str]):
        """
        Deletes all bookmarks of the given type and category.
        
        :param java.lang.String or str type: the type of bookmarks to delete
        :param java.lang.String or str category: the category of bookmarks to delete.
        """

    def getPresentationName(self) -> str:
        """
        The name of the edit action.
        """

    @property
    def presentationName(self) -> java.lang.String:
        ...


class BookmarkNavigator(java.lang.Object):
    """
    Handles navigation/display of bookmarks in the browser marker margins.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, markerService: ghidra.app.services.MarkerService, bookmarkManager: ghidra.program.model.listing.BookmarkManager, bmt: ghidra.program.model.listing.BookmarkType):
        ...

    def add(self, addr: ghidra.program.model.address.Address):
        """
        Add bookmark marker at specified address.
        
        :param ghidra.program.model.address.Address addr: the address
        """

    def clear(self, addr: ghidra.program.model.address.Address):
        """
        Clear bookmark marker at specified address.
        
        :param ghidra.program.model.address.Address addr: the address
        """

    @staticmethod
    def defineBookmarkTypes(program: ghidra.program.model.listing.Program):
        """
        Define the bookmark types, as this information is not maintained in the program
        
        :param ghidra.program.model.listing.Program program: the program
        """

    def dispose(self):
        """
        Get rid of any local resource connections before this object is disposed of.
        """

    def intersects(self, start: ghidra.program.model.address.Address, end: ghidra.program.model.address.Address) -> bool:
        """
        Return whether the marker set intersections with the given range.
        
        :param ghidra.program.model.address.Address start: start of the range
        :param ghidra.program.model.address.Address end: end of the range
        :return: true if intersects
        :rtype: bool
        """

    def updateBookmarkers(self, set: ghidra.program.model.address.AddressSet):
        """
        Refresh bookmark markers
        
        :param ghidra.program.model.address.AddressSet set: the addresses
        """


class CreateBookmarkDialog(docking.DialogComponentProvider):
    ...
    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class BookmarkTableModel(ghidra.util.table.AddressBasedTableModel[BookmarkRowObject]):

    @typing.type_check_only
    class BookmarkKeyIterator(ghidra.util.LongIterator):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class TypeTableColumn(ghidra.util.table.field.AbstractProgramBasedDynamicTableColumn[BookmarkRowObject, java.lang.String]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class CategoryTableColumn(ghidra.util.table.field.AbstractProgramBasedDynamicTableColumn[BookmarkRowObject, java.lang.String]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class DescriptionTableColumn(ghidra.util.table.field.AbstractProgramBasedDynamicTableColumn[BookmarkRowObject, java.lang.String]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def typeAdded(self):
        ...


@typing.type_check_only
class FilterDialog(docking.DialogComponentProvider):
    ...
    class_: typing.ClassVar[java.lang.Class]


class BookmarkRowObjectToProgramLocationTableRowMapper(ghidra.util.table.ProgramLocationTableRowMapper[BookmarkRowObject, ghidra.program.util.ProgramLocation]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class BookmarkRowObjectToAddressTableRowMapper(ghidra.util.table.ProgramLocationTableRowMapper[BookmarkRowObject, ghidra.program.model.address.Address]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class BookmarkDeleteBackgroundCmd(ghidra.framework.cmd.BackgroundCommand[ghidra.program.model.listing.Program]):
    """
    Command to delete a number of bookmarks.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, bookmarks: jpype.JArray[ghidra.program.model.listing.Bookmark]):
        """
        Delete an array of Bookmarks.
        
        :param jpype.JArray[ghidra.program.model.listing.Bookmark] bookmarks: the array of bookmarks to be deleted.
        """


@typing.type_check_only
class BookmarkRowObject(java.lang.Comparable[BookmarkRowObject]):
    ...
    class_: typing.ClassVar[java.lang.Class]


class BookmarkProvider(ghidra.framework.plugintool.ComponentProviderAdapter):

    @typing.type_check_only
    class CategoryCellEditor(javax.swing.DefaultCellEditor):
        """
        Class for the Category combo box editor component.
        Category list model is refreshed each time cell editor is used.
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class CategoryComboBoxModel(javax.swing.DefaultComboBoxModel[java.lang.String]):
        """
        Class for the combo box model to hold list of categories.
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class BookmarkRowObjectDeleteCommand(ghidra.framework.cmd.BackgroundCommand[ghidra.program.model.listing.Program]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, bookmarkList: java.util.List[BookmarkRowObject]):
            ...

        def doApplyTo(self, obj: ghidra.framework.model.DomainObject, monitor: ghidra.util.task.TaskMonitor) -> bool:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def readConfigState(self, saveState: ghidra.framework.options.SaveState):
        ...

    def repaint(self):
        ...

    def typeAdded(self, type: typing.Union[java.lang.String, str]):
        ...

    def writeConfigState(self, saveState: ghidra.framework.options.SaveState):
        ...



__all__ = ["BookmarkPlugin", "AddBookmarkAction", "FilterState", "BookmarkEditCmd", "DeleteBookmarkAction", "BookmarkDeleteCmd", "BookmarkNavigator", "CreateBookmarkDialog", "BookmarkTableModel", "FilterDialog", "BookmarkRowObjectToProgramLocationTableRowMapper", "BookmarkRowObjectToAddressTableRowMapper", "BookmarkDeleteBackgroundCmd", "BookmarkRowObject", "BookmarkProvider"]
