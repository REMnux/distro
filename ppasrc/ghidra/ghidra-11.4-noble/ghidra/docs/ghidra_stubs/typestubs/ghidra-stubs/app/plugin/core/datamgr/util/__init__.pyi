from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking
import docking.widgets.tree
import generic.jar
import ghidra.app.plugin.core.datamgr
import ghidra.app.plugin.core.datamgr.archive
import ghidra.app.plugin.core.datamgr.tree
import ghidra.app.services
import ghidra.app.util
import ghidra.program.model.address
import ghidra.program.model.data
import ghidra.program.model.listing
import ghidra.util.task
import java.awt # type: ignore
import java.awt.datatransfer # type: ignore
import java.awt.dnd # type: ignore
import java.lang # type: ignore
import java.util # type: ignore
import javax.swing # type: ignore
import javax.swing.tree # type: ignore


@typing.type_check_only
class HighlightIcon(javax.swing.Icon):
    ...
    class_: typing.ClassVar[java.lang.Class]


class DataTypeUtils(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def binarySearchWithDuplicates(data: java.util.List[ghidra.program.model.data.DataType], searchItem: typing.Union[java.lang.String, str], comparator: java.util.Comparator[java.lang.Object]) -> int:
        ...

    @staticmethod
    def copyToNamedBaseDataType(dataType: ghidra.program.model.data.DataType, dtm: ghidra.program.model.data.DataTypeManager) -> ghidra.program.model.data.DataType:
        """
        Create a copy of the chain of data types that eventually lead to a named
        data type.
         
        
        Returns a :meth:`copy() <DataType.copy>` of the first named data type found
        in the pointer / array type chain, and returns an identical chain of pointer / arrays up to
        the copied named type.
        
        :param ghidra.program.model.data.DataType dataType: data type to be copied
        :param ghidra.program.model.data.DataTypeManager dtm: data type manager
        :return: deep copy of dataType
        :rtype: ghidra.program.model.data.DataType
        """

    @staticmethod
    def getBaseDataType(dt: ghidra.program.model.data.DataType) -> ghidra.program.model.data.DataType:
        """
        Get the base data type for the specified data type.
        
         
        For example, the base data type for Word*[5] is Word.  For a pointer, the base data type
        is the type being pointed to or the pointer itself if it is pointing at nothing.
        
         
        If "INT" is a typedef on a "dword" then INT[7][3] would have a base data type of dword.
        If you wanted to get the INT from INT[7][3] you should call getNamedBasedDataType(DataType)
        instead.
        
        :param ghidra.program.model.data.DataType dt: the data type whose base data type is to be determined.
        :return: the base data type.
        :rtype: ghidra.program.model.data.DataType
        """

    @staticmethod
    def getBuiltInIcon(disabled: typing.Union[jpype.JBoolean, bool]) -> javax.swing.Icon:
        """
        Returns the BuiltIn icon.
        
        :param jpype.JBoolean or bool disabled: True returns a disabled icon; false returns the normal icon.
        :return: the BuiltIn icon.
        :rtype: javax.swing.Icon
        """

    @staticmethod
    def getClosedArchiveFolder(isLocked: typing.Union[jpype.JBoolean, bool]) -> javax.swing.Icon:
        """
        Returns the closed folder icon.
        
        :param jpype.JBoolean or bool isLocked: True means to return the checked-out closed folder icon
        :return: the closed folder icon.
        :rtype: javax.swing.Icon
        """

    @staticmethod
    def getClosedFolderIcon(disabled: typing.Union[jpype.JBoolean, bool]) -> javax.swing.Icon:
        """
        Returns the closed folder icon.
        
        :param jpype.JBoolean or bool disabled: True returns a disabled icon; false returns the normal icon.
        :return: the closed folder icon.
        :rtype: javax.swing.Icon
        """

    @staticmethod
    def getDataTypeComponent(program: ghidra.program.model.listing.Program, address: ghidra.program.model.address.Address, componentPath: jpype.JArray[jpype.JInt]) -> ghidra.program.model.data.DataTypeComponent:
        """
        Finds the DataTypeComponent at an address and component path in a program.
        
        :param ghidra.program.model.listing.Program program: the program to look for a datatype component
        :param ghidra.program.model.address.Address address: the address to look for a datatype component
        :param jpype.JArray[jpype.JInt] componentPath: the component path (an array of indexes into hierarchy of nested
        datatypes)
        :return: The datatype component at that address and component path or null if there is
        none at that location.
        :rtype: ghidra.program.model.data.DataTypeComponent
        """

    @staticmethod
    def getExactMatchingDataTypes(searchString: typing.Union[java.lang.String, str], dataService: ghidra.app.services.DataTypeQueryService) -> java.util.List[ghidra.program.model.data.DataType]:
        """
        Returns a sorted list of :obj:`DataType`s that have names which match the given search
        string.  The list is sorted according to :obj:`.DATA_TYPE_LOOKUP_COMPARATOR`.
        
        :param java.lang.String or str searchString: The name of the DataTypes to match.
        :param ghidra.app.services.DataTypeQueryService dataService: The service from which the data types will be taken.
        :return: A sorted list of :obj:`DataType`s that have names which match the given search
                string.
        :rtype: java.util.List[ghidra.program.model.data.DataType]
        """

    @staticmethod
    def getFavoriteIcon(disabled: typing.Union[jpype.JBoolean, bool]) -> javax.swing.Icon:
        """
        Returns the favorites icon.
        
        :param jpype.JBoolean or bool disabled: True returns a disabled icon; false returns the normal icon.
        :return: the favorites icon.
        :rtype: javax.swing.Icon
        """

    @staticmethod
    def getHighlightIcon(baseIcon: javax.swing.Icon) -> javax.swing.Icon:
        """
        Returns an icon that adds highlighting to the provided icon.
        
        :param javax.swing.Icon baseIcon: The icon to highlight.
        :return: the highlighted icon.
        :rtype: javax.swing.Icon
        """

    @staticmethod
    def getIconForDataType(dataType: ghidra.program.model.data.DataType, disabled: typing.Union[jpype.JBoolean, bool]) -> javax.swing.Icon:
        """
        Finds the icon associated with the provided data type.
        
        :param ghidra.program.model.data.DataType dataType: The data type for which to find an icon.
        :param jpype.JBoolean or bool disabled: True returns a disabled icon; false returns the normal icon.
        :return: the icon associated with the provided data type.
        :rtype: javax.swing.Icon
        """

    @staticmethod
    def getNamedBaseDataType(dt: ghidra.program.model.data.DataType) -> ghidra.program.model.data.DataType:
        """
        Get the named base data type for the specified data type.  This method intentionally does
        not drill down into typedefs.
        
         
        For example, the named base data type for Word*[5] is Word.  For a pointer, the named
        base data type is the type being pointed to or the pointer itself if it is pointing at
        nothing.
        
         
        If "INT" is a typedef on a "dword", then INT[7][3] would have a named base data type of
        INT.  If you wanted to get the dword from INT[7][3] you should call
        getBasedDataType(DataType) instead.
        
        :param ghidra.program.model.data.DataType dt: the data type whose named base data type is to be determined.
        :return: the base data type.
        :rtype: ghidra.program.model.data.DataType
        """

    @staticmethod
    def getOpenArchiveFolder(isLocked: typing.Union[jpype.JBoolean, bool]) -> javax.swing.Icon:
        """
        Returns the open archive folder icon.
        
        :param jpype.JBoolean or bool isLocked: True means to return the checked-out open archive folder icon
        :return: the open archive folder icon.
        :rtype: javax.swing.Icon
        """

    @staticmethod
    def getOpenFolderIcon(disabled: typing.Union[jpype.JBoolean, bool]) -> javax.swing.Icon:
        """
        Returns the open folder icon.
        
        :param jpype.JBoolean or bool disabled: True returns a disabled icon; false returns the normal icon.
        :return: the open folder icon.
        :rtype: javax.swing.Icon
        """

    @staticmethod
    def getRootIcon(expanded: typing.Union[jpype.JBoolean, bool]) -> javax.swing.Icon:
        """
        Returns the root folder icon.
        
        :param jpype.JBoolean or bool expanded: true to use the expanded icon; false to use the collapsed icon.
        :return: the root folder icon.
        :rtype: javax.swing.Icon
        """

    @staticmethod
    def getStartsWithMatchingDataTypes(searchString: typing.Union[java.lang.String, str], dataService: ghidra.app.services.DataTypeQueryService) -> java.util.List[ghidra.program.model.data.DataType]:
        """
        Returns a sorted list of :obj:`DataType`s that have names which start with the given search
        string.   The list is sorted according to :obj:`.DATA_TYPE_LOOKUP_COMPARATOR`.
        
        :param java.lang.String or str searchString: The name of the DataTypes to match.
        :param ghidra.app.services.DataTypeQueryService dataService: The service from which the data types will be taken.
        :return: A sorted list of :obj:`DataType`s that have names which start with the given search
                string.
        :rtype: java.util.List[ghidra.program.model.data.DataType]
        """

    @staticmethod
    def prepareSearchText(searchText: typing.Union[java.lang.String, str]) -> str:
        """
        Changes the given text to prepare it for use in searching for data types.  Clients should
        call this method to make sure that the given text is suitable for use when searching the
        data type values returned by
        :meth:`getExactMatchingDataTypes(String, DataTypeQueryService) <.getExactMatchingDataTypes>` and
        :meth:`getStartsWithMatchingDataTypes(String, DataTypeQueryService) <.getStartsWithMatchingDataTypes>`.
        
        :param java.lang.String or str searchText: the search text
        :return: the updated text
        :rtype: str
        """

    @staticmethod
    def showUnmodifiableArchiveErrorMessage(parent: java.awt.Component, title: typing.Union[java.lang.String, str], dtm: ghidra.program.model.data.DataTypeManager):
        ...


@typing.type_check_only
class DataTypeIconWrapper(java.lang.Object):
    ...
    class_: typing.ClassVar[java.lang.Class]


class DataTypeArchiveUtility(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    GHIDRA_ARCHIVES: typing.Final[java.util.Map[java.lang.String, generic.jar.ResourceFile]]

    @staticmethod
    def findArchiveFile(archiveName: typing.Union[java.lang.String, str]) -> generic.jar.ResourceFile:
        """
        Find an archive file within the Ghidra installation.
        If archive has been replaced between Ghidra releases,
        it may be re-mapped to a newer resource file.
        
        :param java.lang.String or str archiveName: archive file name
        :return: existing resource file or null if not found
        :rtype: generic.jar.ResourceFile
        """

    @staticmethod
    def getArchiveList(program: ghidra.program.model.listing.Program) -> java.util.List[java.lang.String]:
        """
        get a list of known applicable .GDT archives for the given program.
        
        :param ghidra.program.model.listing.Program program: - program to lookup archives for
        :return: list of archives that could apply to this program
        :rtype: java.util.List[java.lang.String]
        """

    @staticmethod
    def getRemappedArchiveName(archiveName: typing.Union[java.lang.String, str]) -> str:
        ...


class DataTypeTreeCopyMoveTask(ghidra.util.task.Task):
    """
    Task for copying and moving data type nodes within the Data Types tree.
    """

    class ActionType(java.lang.Enum[DataTypeTreeCopyMoveTask.ActionType]):

        class_: typing.ClassVar[java.lang.Class]
        COPY: typing.Final[DataTypeTreeCopyMoveTask.ActionType]
        MOVE: typing.Final[DataTypeTreeCopyMoveTask.ActionType]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> DataTypeTreeCopyMoveTask.ActionType:
            ...

        @staticmethod
        def values() -> jpype.JArray[DataTypeTreeCopyMoveTask.ActionType]:
            ...


    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, destinationNode: ghidra.app.plugin.core.datamgr.tree.CategoryNode, droppedNodeList: java.util.List[docking.widgets.tree.GTreeNode], actionType: DataTypeTreeCopyMoveTask.ActionType, gTree: ghidra.app.plugin.core.datamgr.tree.DataTypeArchiveGTree, conflictHandler: ghidra.program.model.data.DataTypeConflictHandler):
        ...

    @typing.overload
    def __init__(self, destinationArchive: ghidra.app.plugin.core.datamgr.archive.Archive, destinationCategory: ghidra.program.model.data.Category, droppedNodeList: java.util.List[docking.widgets.tree.GTreeNode], actionType: DataTypeTreeCopyMoveTask.ActionType, gTree: ghidra.app.plugin.core.datamgr.tree.DataTypeArchiveGTree, conflictHandler: ghidra.program.model.data.DataTypeConflictHandler):
        ...

    def setPromptToAssociateTypes(self, prompt: typing.Union[jpype.JBoolean, bool]):
        """
        Any types being newly copied/moved to a suitable archive are eligible for 'association',
        which means changes between the two archives will be tracked.  True, the default, signals to
        prompt before associating types; false signals not to prompt the user, but to always
        associate types.
        
        :param jpype.JBoolean or bool prompt: true to prompt; false to not prompt
        """


class DataTypeChooserDialog(docking.DialogComponentProvider):
    """
    A dialog that allows the user to choose from a tree of similarly named data types.  This class
    is meant to be used by the :obj:`DataTypeManagerPlugin`.  For API needs, clients should use the 
    :obj:`DataTypeSelectionDialog` utility widget.
    """

    @typing.type_check_only
    class SelectFirstNodeTask(docking.widgets.tree.GTreeTask):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin):
        ...

    def getSelectedDataType(self) -> ghidra.program.model.data.DataType:
        ...

    def getTreeFilterProvider(self) -> docking.widgets.tree.GTreeFilterProvider:
        """
        Returns the filter provider currently in use by the tree in this dialog
        
        :return: the filter provider
        :rtype: docking.widgets.tree.GTreeFilterProvider
        """

    def setFilterFieldEditable(self, editable: typing.Union[jpype.JBoolean, bool]):
        """
        Sets the enabled state of the filter field.  This method can be used to prevent the user 
        from changing the nodes displayed by the tree.  By default, the filter is enabled.
        
        :param jpype.JBoolean or bool editable: true if the field should be editable; false to disable the field
        """

    def setFilterText(self, filterText: typing.Union[java.lang.String, str]):
        """
        Sets the filter text of the tree
        
        :param java.lang.String or str filterText: the filter text
        """

    def setFirstNodeSelected(self):
        """
        Selects the first child node of the root node.  Use this method to force the tree to have
        focus when the dialog is shown, which allows for keyboard navigation.
        """

    def setSelectedPath(self, selectedPath: javax.swing.tree.TreePath):
        """
        Selects the given tree path in the tree
        
        :param javax.swing.tree.TreePath selectedPath: the path
        """

    def setTreeFilterProvider(self, provider: docking.widgets.tree.GTreeFilterProvider):
        """
        Sets the filter provider on the tree used by this dialog
        
        :param docking.widgets.tree.GTreeFilterProvider provider: the filter provider
        """

    def showPrepopulatedDialog(self, tool: docking.Tool, dataTypeText: typing.Union[java.lang.String, str]):
        """
        A convenience method to show this dialog with the following configuration:
         
        * the tree will be filtered using the given filter text
        * the filter field will be disabled so the user cannot change the nodes available in the 
        tree
        * the first child node of the root node in the tree will be selected
        
        
        :param docking.Tool tool: the tool to which this dialog will be parented; cannot be null
        :param java.lang.String or str dataTypeText: the filter text; cannot be null
        :raises IllegalArgumentException: if the given filter text is null or empty
        """

    @property
    def treeFilterProvider(self) -> docking.widgets.tree.GTreeFilterProvider:
        ...

    @treeFilterProvider.setter
    def treeFilterProvider(self, value: docking.widgets.tree.GTreeFilterProvider):
        ...

    @property
    def selectedDataType(self) -> ghidra.program.model.data.DataType:
        ...


@typing.type_check_only
class CaseInsensitveDataTypeLookupComparator(java.util.Comparator[java.lang.Object]):
    ...
    class_: typing.ClassVar[java.lang.Class]


class DataDropOnBrowserHandler(ghidra.app.util.ProgramDropProvider):
    """
    Handles datatype drops in the codebrowser.  Installed by the dataTypeManagerPlugin
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin):
        ...

    def add(self, contextObj: java.lang.Object, data: java.lang.Object, flavor: java.awt.datatransfer.DataFlavor):
        ...

    def getDataFlavors(self) -> jpype.JArray[java.awt.datatransfer.DataFlavor]:
        ...

    def getPriority(self) -> int:
        ...

    def isDropOk(self, contextObj: java.lang.Object, evt: java.awt.dnd.DropTargetDragEvent) -> bool:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.app.util.ProgramDropProvider.isDropOk(java.lang.Object, java.awt.dnd.DropTargetDragEvent)`
        """

    @property
    def dataFlavors(self) -> jpype.JArray[java.awt.datatransfer.DataFlavor]:
        ...

    @property
    def priority(self) -> jpype.JInt:
        ...


class DataTypeTreeDeleteTask(ghidra.util.task.Task):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin, nodes: java.util.List[docking.widgets.tree.GTreeNode]):
        ...



__all__ = ["HighlightIcon", "DataTypeUtils", "DataTypeIconWrapper", "DataTypeArchiveUtility", "DataTypeTreeCopyMoveTask", "DataTypeChooserDialog", "CaseInsensitveDataTypeLookupComparator", "DataDropOnBrowserHandler", "DataTypeTreeDeleteTask"]
