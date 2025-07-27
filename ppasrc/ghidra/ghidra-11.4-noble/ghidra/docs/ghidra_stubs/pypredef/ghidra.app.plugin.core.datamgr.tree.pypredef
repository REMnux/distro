from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking
import docking.widgets.tree
import docking.widgets.tree.internal
import docking.widgets.tree.support
import ghidra.app.plugin.core.datamgr
import ghidra.app.plugin.core.datamgr.archive
import ghidra.framework.model
import ghidra.framework.options
import ghidra.program.model.data
import ghidra.program.model.listing
import java.awt # type: ignore
import java.lang # type: ignore
import java.util # type: ignore
import javax.swing # type: ignore
import javax.swing.event # type: ignore


class BuiltInArchiveNode(ArchiveNode):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, archive: ghidra.app.plugin.core.datamgr.archive.BuiltInArchive, filterState: DtFilterState):
        ...


class DataTypeDragNDropHandler(docking.widgets.tree.support.GTreeDragNDropHandler):

    class_: typing.ClassVar[java.lang.Class]
    allSupportedFlavors: typing.ClassVar[jpype.JArray[java.awt.datatransfer.DataFlavor]]
    builtinFlavors: typing.ClassVar[jpype.JArray[java.awt.datatransfer.DataFlavor]]
    restrictedFlavors: typing.ClassVar[jpype.JArray[java.awt.datatransfer.DataFlavor]]

    def __init__(self, plugin: ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin, tree: docking.widgets.tree.GTree):
        ...

    def isValidDataTypeDestination(self, destinationNode: docking.widgets.tree.GTreeNode, flavors: jpype.JArray[java.awt.datatransfer.DataFlavor], dropAction: typing.Union[jpype.JInt, int]) -> bool:
        """
        Verifies the given destination node can accept the given drop/copy/paste action and content
        flavors.
        
        :param docking.widgets.tree.GTreeNode destinationNode: the node accepting the action
        :param jpype.JArray[java.awt.datatransfer.DataFlavor] flavors: the supported flavors of the action
        :param jpype.JInt or int dropAction: the actual action see :obj:`DnDConstants`
        :return: true if valid
        :rtype: bool
        """


class DtFilterState(java.lang.Object):
    """
    A simple object to store various filter settings for the data type provider.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def copy(self) -> DtFilterState:
        ...

    def getArraysFilter(self) -> DtTypeFilter:
        ...

    def getEnumsFilter(self) -> DtTypeFilter:
        ...

    def getFunctionsFilter(self) -> DtTypeFilter:
        ...

    def getPointersFilter(self) -> DtTypeFilter:
        ...

    def getStructuresFilter(self) -> DtTypeFilter:
        ...

    def getUnionsFilter(self) -> DtTypeFilter:
        ...

    def isShowArrays(self) -> bool:
        ...

    def isShowEnums(self) -> bool:
        ...

    def isShowFunctions(self) -> bool:
        ...

    def isShowPointers(self) -> bool:
        ...

    def isShowStructures(self) -> bool:
        ...

    def isShowUnions(self) -> bool:
        ...

    def passesFilters(self, dt: ghidra.program.model.data.DataType) -> bool:
        ...

    def restore(self, parentSaveState: ghidra.framework.options.SaveState):
        ...

    def save(self, parentSaveState: ghidra.framework.options.SaveState):
        ...

    def setArraysFilter(self, filter: DtTypeFilter):
        ...

    def setEnumsFilter(self, filter: DtTypeFilter):
        ...

    def setFunctionsFilter(self, filter: DtTypeFilter):
        ...

    def setPointersFilter(self, filter: DtTypeFilter):
        ...

    def setStructuresFilter(self, filter: DtTypeFilter):
        ...

    def setUnionsFilter(self, filter: DtTypeFilter):
        ...

    @property
    def unionsFilter(self) -> DtTypeFilter:
        ...

    @unionsFilter.setter
    def unionsFilter(self, value: DtTypeFilter):
        ...

    @property
    def enumsFilter(self) -> DtTypeFilter:
        ...

    @enumsFilter.setter
    def enumsFilter(self, value: DtTypeFilter):
        ...

    @property
    def arraysFilter(self) -> DtTypeFilter:
        ...

    @arraysFilter.setter
    def arraysFilter(self, value: DtTypeFilter):
        ...

    @property
    def showStructures(self) -> jpype.JBoolean:
        ...

    @property
    def functionsFilter(self) -> DtTypeFilter:
        ...

    @functionsFilter.setter
    def functionsFilter(self, value: DtTypeFilter):
        ...

    @property
    def showPointers(self) -> jpype.JBoolean:
        ...

    @property
    def showEnums(self) -> jpype.JBoolean:
        ...

    @property
    def showFunctions(self) -> jpype.JBoolean:
        ...

    @property
    def showArrays(self) -> jpype.JBoolean:
        ...

    @property
    def showUnions(self) -> jpype.JBoolean:
        ...

    @property
    def structuresFilter(self) -> DtTypeFilter:
        ...

    @structuresFilter.setter
    def structuresFilter(self, value: DtTypeFilter):
        ...

    @property
    def pointersFilter(self) -> DtTypeFilter:
        ...

    @pointersFilter.setter
    def pointersFilter(self, value: DtTypeFilter):
        ...


class ProjectArchiveNode(DomainFileArchiveNode):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, archive: ghidra.app.plugin.core.datamgr.archive.ProjectArchive, filterState: DtFilterState):
        ...

    def equals(self, o: java.lang.Object) -> bool:
        """
        Overridden to avoid path conflicts that arise in CategoryNode.equals()
        
        
        .. seealso::
        
            | :obj:`java.lang.Object.equals(java.lang.Object)`
        """

    def hasWriteLock(self) -> bool:
        ...


class DtTypeFilter(java.lang.Object):
    """
    A class that holds enabled state for a type and related typedefs.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getName(self) -> str:
        ...

    def isTypeActive(self) -> bool:
        ...

    def isTypeDefActive(self) -> bool:
        ...

    def setTypeActive(self, b: typing.Union[jpype.JBoolean, bool]):
        ...

    def setTypeDefActive(self, b: typing.Union[jpype.JBoolean, bool]):
        ...

    @property
    def typeDefActive(self) -> jpype.JBoolean:
        ...

    @typeDefActive.setter
    def typeDefActive(self, value: jpype.JBoolean):
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def typeActive(self) -> jpype.JBoolean:
        ...

    @typeActive.setter
    def typeActive(self, value: jpype.JBoolean):
        ...


class CenterVerticalIcon(javax.swing.Icon):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, icon: javax.swing.Icon, height: typing.Union[jpype.JInt, int]):
        ...

    def getIconHeight(self) -> int:
        ...

    def getIconWidth(self) -> int:
        ...

    def paintIcon(self, c: java.awt.Component, g: java.awt.Graphics, x: typing.Union[jpype.JInt, int], y: typing.Union[jpype.JInt, int]):
        ...

    @property
    def iconHeight(self) -> jpype.JInt:
        ...

    @property
    def iconWidth(self) -> jpype.JInt:
        ...


class DataTypeArchiveGTree(docking.widgets.tree.GTree):

    @typing.type_check_only
    class DefaultDtTreeDataTransformer(docking.widgets.tree.internal.DefaultGTreeDataTransformer):
        """
        Only filters on name or display name, not dt contents
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class DataTypeTransformer(DataTypeArchiveGTree.DefaultDtTreeDataTransformer):
        """
        Filters on dt contents
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class DataTypeTreeExpansionListener(javax.swing.event.TreeExpansionListener):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class DataTypeTreeRenderer(docking.widgets.tree.support.GTreeRenderer):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class MyFolderListener(ghidra.framework.model.DomainFolderListenerAdapter):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, dataTypeManagerPlugin: ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin):
        ...

    def getProgram(self) -> ghidra.program.model.listing.Program:
        ...

    def setFilterState(self, filterState: DtFilterState):
        ...

    def updateDataTransformer(self, provider: ghidra.app.plugin.core.datamgr.DataTypesProvider):
        ...

    def updateFilterForChoosingDataType(self):
        """
        Signals to this tree that it should configure itself for use inside of a widget that allows
        the user to choose a data type.
        """

    @property
    def program(self) -> ghidra.program.model.listing.Program:
        ...


class DataTypeTreeNode(docking.widgets.tree.GTreeLazyNode):
    """
    A single interface for unifying the handling of nodes that can be manipulated during
    cut/copy/paste operations.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def canCut(self) -> bool:
        """
        Returns true if this node can be cut and moved to a different location.
        
        :return: true if this node can be cut and moved to a different location.
        :rtype: bool
        """

    def canDelete(self) -> bool:
        """
        Returns true if this node can be deleted
        
        :return: true if this node can be deleted
        :rtype: bool
        """

    def canPaste(self, pastedNodes: java.util.List[docking.widgets.tree.GTreeNode]) -> bool:
        """
        Returns true if this nodes handles paste operations
        
        :param java.util.List[docking.widgets.tree.GTreeNode] pastedNodes: the nodes to be pasted
        :return: true if this nodes handles paste operations
        :rtype: bool
        """

    def getArchiveNode(self) -> ArchiveNode:
        """
        Returns the ArchiveNode for this tree node.
        
        :return: the ArchiveNode for this tree node.
        :rtype: ArchiveNode
        """

    def isCut(self) -> bool:
        """
        Return true if the node has been cut.
        
        :return: true if the node has been cut.
        :rtype: bool
        """

    def isModifiable(self) -> bool:
        """
        Returns true if this node is from an archive that can be modified.
        
        :return: true if this node is from an archive that can be modified.
        :rtype: bool
        """

    def setNodeCut(self, isCut: typing.Union[jpype.JBoolean, bool]):
        """
        Signals to this node that it has been cut during a cut operation, for example, like during
        a cut/paste operation.
        
        :param jpype.JBoolean or bool isCut: true signals that the node has been cut; false that it is not cut.
        """

    @property
    def cut(self) -> jpype.JBoolean:
        ...

    @property
    def modifiable(self) -> jpype.JBoolean:
        ...

    @property
    def archiveNode(self) -> ArchiveNode:
        ...


class DomainFileArchiveNode(ArchiveNode):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, archive: ghidra.app.plugin.core.datamgr.archive.DomainFileArchive, filterState: DtFilterState):
        ...

    def getDomainFile(self) -> ghidra.framework.model.DomainFile:
        ...

    @property
    def domainFile(self) -> ghidra.framework.model.DomainFile:
        ...


class FileArchiveNode(ArchiveNode):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, archive: ghidra.app.plugin.core.datamgr.archive.FileArchive, filterState: DtFilterState):
        ...

    def hasWriteLock(self) -> bool:
        ...


class ArchiveRootNode(DataTypeTreeNode):

    @typing.type_check_only
    class RootNodeListener(ghidra.app.plugin.core.datamgr.archive.ArchiveManagerListener):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def findCategoryNode(self, category: ghidra.program.model.data.Category) -> CategoryNode:
        ...

    def getArchiveHandler(self) -> ghidra.app.plugin.core.datamgr.archive.DataTypeManagerHandler:
        ...

    def getArchiveNode(self) -> ArchiveNode:
        """
        This implementation returns null, since this class is the root of the hierarchy and does
        not have an archive.
        
        
        .. seealso::
        
            | :obj:`ghidra.app.plugin.core.datamgr.tree.DataTypeTreeNode.getArchiveNode()`
        """

    def getModificationCount(self) -> int:
        """
        Returns the modification count for any changes to any category or datatype in any
        open archive including the program.
        
        :return: the modification count
        :rtype: int
        """

    def getNodeForManager(self, dtm: ghidra.program.model.data.DataTypeManager) -> ArchiveNode:
        ...

    def setFilterState(self, dtFilterState: DtFilterState):
        ...

    @property
    def nodeForManager(self) -> ArchiveNode:
        ...

    @property
    def modificationCount(self) -> jpype.JLong:
        ...

    @property
    def archiveHandler(self) -> ghidra.app.plugin.core.datamgr.archive.DataTypeManagerHandler:
        ...

    @property
    def archiveNode(self) -> ArchiveNode:
        ...


class DataTypeNode(DataTypeTreeNode):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, dataType: ghidra.program.model.data.DataType):
        ...

    def dataTypeChanged(self):
        ...

    def dataTypeStatusChanged(self):
        ...

    def getDataType(self) -> ghidra.program.model.data.DataType:
        ...

    def hasCustomEditor(self) -> bool:
        """
        Returns true if this dataType node uses and editor that is different than Java's default
        editor.
        
        :return: true if this dataType node has a custom editor.
        :rtype: bool
        """

    def isFavorite(self) -> bool:
        ...

    @property
    def dataType(self) -> ghidra.program.model.data.DataType:
        ...

    @property
    def favorite(self) -> jpype.JBoolean:
        ...


class DtBackgroundIcon(javax.swing.Icon):
    """
    An icon used by the data types tree to uniformly space all icons.  Clients of versioned objects
    can signal that this icon can paint a custom background.
    """

    class_: typing.ClassVar[java.lang.Class]


class ArchiveNode(CategoryNode):

    @typing.type_check_only
    class ArchiveNodeCategoryChangeListener(ghidra.program.model.data.DataTypeManagerChangeListener):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, archive: ghidra.app.plugin.core.datamgr.archive.Archive, filterState: DtFilterState):
        ...

    @typing.overload
    def findCategoryNode(self, localCategory: ghidra.program.model.data.Category) -> CategoryNode:
        """
        Finds the node that represents the given category.
         
         
        
        Children **will not** be loaded when searching for the node. This allows clients to search
        for data types of interest, only updating the tree when the nodes are loaded.
        
        :param ghidra.program.model.data.Category localCategory: the category of interest
        :return: the node if loaded; null if not loaded
        :rtype: CategoryNode
        """

    @typing.overload
    def findCategoryNode(self, localCategory: ghidra.program.model.data.Category, loadChildren: typing.Union[jpype.JBoolean, bool]) -> CategoryNode:
        """
        Finds the node that represents the given category.
        
        :param ghidra.program.model.data.Category localCategory: the category of interest
        :param jpype.JBoolean or bool loadChildren: true will load child nodes when searching; false will not load children
        :return: the node
        :rtype: CategoryNode
        """

    def getArchive(self) -> ghidra.app.plugin.core.datamgr.archive.Archive:
        ...

    def hashCode(self) -> int:
        """
        The hashcode must not be based on the name since it can change based upon the underlying
        archive. This must be consistent with the equals method implementation.
        """

    def nodeChanged(self):
        ...

    def structureChanged(self):
        ...

    @property
    def archive(self) -> ghidra.app.plugin.core.datamgr.archive.Archive:
        ...


class DtFilterDialog(docking.DialogComponentProvider):
    """
    Data Types provider dialog to allow users to change the types that are filtered.
    """

    @typing.type_check_only
    class TypeComponent(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, filterState: DtFilterState):
        ...

    def getFilterState(self) -> DtFilterState:
        ...

    def isCancelled(self) -> bool:
        ...

    @property
    def filterState(self) -> DtFilterState:
        ...

    @property
    def cancelled(self) -> jpype.JBoolean:
        ...


class InvalidArchiveNode(ArchiveNode):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, archive: ghidra.app.plugin.core.datamgr.archive.InvalidFileArchive):
        ...


class ProgramArchiveNode(DomainFileArchiveNode):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, archive: ghidra.app.plugin.core.datamgr.archive.ProgramArchive, filterState: DtFilterState):
        ...


class CategoryNode(DataTypeTreeNode):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, category: ghidra.program.model.data.Category, filterState: DtFilterState):
        ...

    def canRename(self) -> bool:
        ...

    def categoryAdded(self, newCategory: ghidra.program.model.data.Category):
        ...

    def categoryRemoved(self, categoryName: typing.Union[java.lang.String, str]):
        ...

    def dataTypeAdded(self, dataType: ghidra.program.model.data.DataType):
        ...

    def dataTypeChanged(self, dataType: ghidra.program.model.data.DataType):
        ...

    def dataTypeRemoved(self, dataTypeName: typing.Union[java.lang.String, str]):
        ...

    def getCategory(self) -> ghidra.program.model.data.Category:
        ...

    def getNode(self, dataType: ghidra.program.model.data.DataType) -> DataTypeNode:
        ...

    def isEnabled(self) -> bool:
        """
        This method is handy to signal whether this node is can be used to perform actions. Returning
        false from this method is essentially a way to disable the actions that can be performed upon
        this node.
        
        :return: true if this node is enabled.
        :rtype: bool
        """

    def setNodeCut(self, isCut: typing.Union[jpype.JBoolean, bool]):
        """
        Signals to this node that it has been cut during a cut operation, for example, like during a
        cut/paste operation.
         
        
        This implementation will throw a runtime exception if this method is called and
        :meth:`canCut() <.canCut>` returns false.
        
        :param jpype.JBoolean or bool isCut: true signals that the node has been cut; false that it is not cut.
        """

    @property
    def node(self) -> DataTypeNode:
        ...

    @property
    def category(self) -> ghidra.program.model.data.Category:
        ...

    @property
    def enabled(self) -> jpype.JBoolean:
        ...



__all__ = ["BuiltInArchiveNode", "DataTypeDragNDropHandler", "DtFilterState", "ProjectArchiveNode", "DtTypeFilter", "CenterVerticalIcon", "DataTypeArchiveGTree", "DataTypeTreeNode", "DomainFileArchiveNode", "FileArchiveNode", "ArchiveRootNode", "DataTypeNode", "DtBackgroundIcon", "ArchiveNode", "DtFilterDialog", "InvalidArchiveNode", "ProgramArchiveNode", "CategoryNode"]
