from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking.widgets.table
import docking.widgets.table.threaded
import docking.widgets.textfield
import ghidra.app.context
import ghidra.app.plugin
import ghidra.framework.model
import ghidra.framework.plugintool
import ghidra.program.model.listing
import ghidra.program.util
import ghidra.util.table
import ghidra.util.task
import java.lang # type: ignore
import java.util # type: ignore
import javax.swing # type: ignore
import javax.swing.table # type: ignore


class FunctionTagTableModel(docking.widgets.table.threaded.ThreadedTableModel[FunctionTagRowObject, ghidra.program.model.listing.Program]):
    """
    Model that backs a :obj:`FunctionTagTable`
    """

    @typing.type_check_only
    class FunctionTagCountColumn(docking.widgets.table.AbstractDynamicTableColumnStub[FunctionTagRowObject, java.lang.Integer]):
        """
        Table column that displays a count of the number of times a function tag has been
        applied to a function (in the selected program)
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class FunctionTagNameColumn(docking.widgets.table.AbstractDynamicTableColumnStub[FunctionTagRowObject, java.lang.String]):
        """
        Table column that displays the name of a function tag
        """

        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def clear(self):
        """
        Removes all function tags from the model
        """

    def containsTag(self, name: typing.Union[java.lang.String, str]) -> bool:
        """
        Returns true if a function tag with a given name is in the model
        
        :param java.lang.String or str name: the tag name
        :return: true if the tag exists in the model
        :rtype: bool
        """

    def getRowObject(self, name: typing.Union[java.lang.String, str]) -> FunctionTagRowObject:
        """
        Returns the row object that matches the given tag name
        
        :param java.lang.String or str name: the tag name
        :return: the row object
        :rtype: FunctionTagRowObject
        """

    def setProgram(self, program: ghidra.program.model.listing.Program):
        ...

    @property
    def rowObject(self) -> FunctionTagRowObject:
        ...


class FunctionTagTable(ghidra.util.table.GhidraTable):
    """
    Table that displays function tags and a count of the number of times
    each tag has been used
    """

    @typing.type_check_only
    class TagRenderer(ghidra.util.table.GhidraTableCellRenderer):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, model: FunctionTagTableModel):
        """
        Constructor
        
        :param FunctionTagTableModel model: the table model
        """

    def getCellRenderer(self, row: typing.Union[jpype.JInt, int], col: typing.Union[jpype.JInt, int]) -> javax.swing.table.TableCellRenderer:
        """
        We need to override the renderer for the following cases:
         
        * italicize tags that cannot be edited
        * disable rows in the source table that have already been added to the selected function
        """

    def setFunction(self, function: ghidra.program.model.listing.Function):
        ...


@typing.type_check_only
class InMemoryFunctionTag(ghidra.program.model.listing.FunctionTag):
    """
    This class provides an implementation of the :obj:`FunctionTag` interface for
    tags that are not yet ready to be inserted into the database. This was created
    to allow tags to be imported from an external file and made available to the user
    through the :obj:`FunctionTagProvider` UI without needing to formally
    add them to the ``FunctionTagAdapter`` table.
    """

    class_: typing.ClassVar[java.lang.Class]


class FunctionTagPlugin(ghidra.app.plugin.ProgramPlugin):
    """
    Plugin for managing function tags. This works with the associated
    :obj:`FunctionTagProvider` to allow users to view and
    edit function tags both globally and for individual functions.
    """

    class_: typing.ClassVar[java.lang.Class]
    FUNCTION_TAG_MENU_SUBGROUP: typing.Final = "TagFunction"

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...

    def getProvider(self) -> FunctionTagProvider:
        """
        Returns the component provider for this plugin
        
        :return: the component provider
        :rtype: FunctionTagProvider
        """

    @property
    def provider(self) -> FunctionTagProvider:
        ...


class FunctionTagProvider(ghidra.framework.plugintool.ComponentProviderAdapter, ghidra.framework.model.DomainObjectListener):
    """
    Displays all the function tags in the database and identifies which ones have
    been assigned to the currently selected function. Through this display users can:
     
    
     
    * Create new tags
    * Edit tags (both name and comment)
    * Delete tags
    * Assign tags to the currently selected function
    * Remove tags from the currently selected function
    
    This provider can be shown by right-clicking on a function and selecting the
    "Edit Tags" option, or by selecting the "Edit Function Tags" option from the
    "Window" menu.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: FunctionTagPlugin, program: ghidra.program.model.listing.Program):
        """
        Constructor
        
        :param FunctionTagPlugin plugin: the function tag plugin
        :param ghidra.program.model.listing.Program program: the current program
        """

    def getAllFunctionsPanel(self) -> AllFunctionsPanel:
        ...

    def getButtonPanel(self) -> FunctionTagButtonPanel:
        ...

    def getInputPanel(self) -> javax.swing.JPanel:
        ...

    def getSourcePanel(self) -> SourceTagsPanel:
        ...

    def getTagInputField(self) -> docking.widgets.textfield.HintTextField:
        ...

    def getTargetPanel(self) -> TargetTagsPanel:
        ...

    def locationChanged(self, loc: ghidra.program.util.ProgramLocation):
        """
        Invoked when a new location has been detected in the listing. When
        this happens we need to update the tag list to show what tags are assigned
        at the current location.
        
        :param ghidra.program.util.ProgramLocation loc: the address selected in the listing
        """

    def programActivated(self, activatedProgram: ghidra.program.model.listing.Program):
        ...

    def programDeactivated(self, deactivatedProgram: ghidra.program.model.listing.Program):
        ...

    def selectionChanged(self, panel: TagListPanel):
        """
        Updates the button panel depending on the selection state of the
        tag lists. Also updates the :obj:`AllFunctionsPanel` so it can update
        its list.
        
        :param TagListPanel panel: the panel that generated the selection event
        """

    @property
    def targetPanel(self) -> TargetTagsPanel:
        ...

    @property
    def sourcePanel(self) -> SourceTagsPanel:
        ...

    @property
    def inputPanel(self) -> javax.swing.JPanel:
        ...

    @property
    def allFunctionsPanel(self) -> AllFunctionsPanel:
        ...

    @property
    def buttonPanel(self) -> FunctionTagButtonPanel:
        ...

    @property
    def tagInputField(self) -> docking.widgets.textfield.HintTextField:
        ...


class FunctionTagButtonPanel(javax.swing.JPanel):
    """
    Provides buttons to be used with the :obj:`FunctionTagProvider`.
    These buttons allow users to add or remove tags from functions, or delete
    tags altogether. 
     
    
    This panel has knowledge of the two tag lists it manages, called "source" and
    "target". The former contains all tags in the database, minus those already
    assigned to the current function. The latter contains only those tags
    assigned to the current function.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, sourcePanel: SourceTagsPanel, targetPanel: TargetTagsPanel):
        """
        Constructor.
        
        :param SourceTagsPanel sourcePanel: the panel displaying tags not yet assigned to the current function
        :param TargetTagsPanel targetPanel: the panel displaying tags assigned to the current function
        """

    def sourcePanelSelectionChanged(self, validFunction: typing.Union[jpype.JBoolean, bool]):
        """
        Invoked when the user has selected an item in the source panel.
        
        :param jpype.JBoolean or bool validFunction: true if a function is selected in the listing
        """

    def targetPanelSelectionChanged(self, validFunction: typing.Union[jpype.JBoolean, bool]):
        """
        Invoked when the user has selected an item in the target panel.
        
        :param jpype.JBoolean or bool validFunction: true if a function is selected in the listing
        """


class SourceTagsPanel(TagListPanel):
    """
    List for displaying all tags in the programs
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, provider: FunctionTagProvider, tool: ghidra.framework.plugintool.PluginTool):
        """
        Constructor
        
        :param FunctionTagProvider provider: the component provider
        :param ghidra.framework.plugintool.PluginTool tool: the plugin tool
        """

    def addSelectedTags(self):
        """
        Adds any selected tags to the function currently selected in the listing
        """

    def isSelectionEnabled(self) -> bool:
        """
        Returns true if all tags in the selection are enabled; false otherwise
        
        :return: true if all tags in the selection are enabled; false otherwise
        :rtype: bool
        """

    @property
    def selectionEnabled(self) -> jpype.JBoolean:
        ...


@typing.type_check_only
class FunctionTableModel(ghidra.util.table.AddressBasedTableModel[ghidra.program.model.listing.Function]):
    """
    The data model that backs the :obj:`AllFunctionsPanel`. This displays a list
    of functions that have function tags matching a provided set. Note that
    a function will be displayed as long as it has AT LEAST ONE of the tags
    in the set.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, title: typing.Union[java.lang.String, str], serviceProvider: ghidra.framework.plugintool.ServiceProvider, program: ghidra.program.model.listing.Program, monitor: ghidra.util.task.TaskMonitor):
        """
        Constructor
        
        :param java.lang.String or str title: the title of the model
        :param ghidra.framework.plugintool.ServiceProvider serviceProvider: the service provider
        :param ghidra.program.model.listing.Program program: the current program
        :param ghidra.util.task.TaskMonitor monitor: the task monitor
        """

    def getFunctions(self) -> java.util.List[ghidra.program.model.listing.Function]:
        """
        Returns the list of functions in the table
        
        :return: the contents of the table
        :rtype: java.util.List[ghidra.program.model.listing.Function]
        """

    def getTags(self) -> java.util.Set[ghidra.program.model.listing.FunctionTag]:
        """
        Returns the tags being used by this model
        
        :return: the tags
        :rtype: java.util.Set[ghidra.program.model.listing.FunctionTag]
        """

    def setTags(self, tags: java.util.Set[ghidra.program.model.listing.FunctionTag]):
        """
        Sets the tags associated with this model. This causes a reload of
        the function table
        
        :param java.util.Set[ghidra.program.model.listing.FunctionTag] tags: the selected tags
        """

    @property
    def functions(self) -> java.util.List[ghidra.program.model.listing.Function]:
        ...

    @property
    def tags(self) -> java.util.Set[ghidra.program.model.listing.FunctionTag]:
        ...

    @tags.setter
    def tags(self, value: java.util.Set[ghidra.program.model.listing.FunctionTag]):
        ...


@typing.type_check_only
class FunctionTagRowObject(java.lang.Object):
    ...
    class_: typing.ClassVar[java.lang.Class]


class AllFunctionsPanel(javax.swing.JPanel):
    """
    Displays all functions that are associated with the selected tag in the
    :obj:`SourceTagsPanel`
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, program: ghidra.program.model.listing.Program, provider: ghidra.framework.plugintool.ComponentProviderAdapter):
        """
        Constructor
        
        :param ghidra.program.model.listing.Program program: the current program
        :param ghidra.framework.plugintool.ComponentProviderAdapter provider: the component provider
        """

    def getFunctions(self) -> java.util.List[ghidra.program.model.listing.Function]:
        """
        Returns the list of functions in the panel
         
        
        This is only used for testing!
        
        :return: the list of functions
        :rtype: java.util.List[ghidra.program.model.listing.Function]
        """

    def getTable(self) -> ghidra.util.table.GhidraTable:
        """
        Returns the underlying table.
        
        :return: table
        :rtype: ghidra.util.table.GhidraTable
        """

    def getTableModel(self) -> FunctionTableModel:
        """
        Returns the functions table model
        
        :return: the functions table model
        :rtype: FunctionTableModel
        """

    @typing.overload
    def refresh(self):
        """
        Updates the table with whatever is in the :obj:`.model`
        """

    @typing.overload
    def refresh(self, selectedTags: java.util.Set[ghidra.program.model.listing.FunctionTag]):
        """
        Updates the table with functions containing the selected tags given
        
        :param java.util.Set[ghidra.program.model.listing.FunctionTag] selectedTags: the selected function tags
        """

    def setProgram(self, program: ghidra.program.model.listing.Program):
        """
        Stores the current program
        
        :param ghidra.program.model.listing.Program program: the current program
        """

    def setSelectedTags(self, tags: java.util.Set[ghidra.program.model.listing.FunctionTag]):
        """
        Updates the panel with the set of tags selected by the user. This
        will update the panel title and the contents of the function table.
        
        :param java.util.Set[ghidra.program.model.listing.FunctionTag] tags: the selected tags
        """

    @property
    def functions(self) -> java.util.List[ghidra.program.model.listing.Function]:
        ...

    @property
    def tableModel(self) -> FunctionTableModel:
        ...

    @property
    def table(self) -> ghidra.util.table.GhidraTable:
        ...


class TargetTagsPanel(TagListPanel):
    """
    Displays a list of tags that have been assigned to the current function
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, provider: FunctionTagProvider, tool: ghidra.framework.plugintool.PluginTool):
        """
        Constructor
        
        :param FunctionTagProvider provider: the component provider
        :param ghidra.framework.plugintool.PluginTool tool: the plugin tool
        """

    def refresh(self, newFunction: ghidra.program.model.listing.Function):
        """
        PUBLIC METHODS
        """

    def removeSelectedTags(self):
        """
        Removes selected tags from the currently-selected function.
        """


class EditFunctionTagsAction(ghidra.app.context.ListingContextAction):
    """
    Presents the user with a :obj:`ComponentProvider` showing all function tags available,along with
    all those currently assigned to the selected function.
     
    
    Users may select, deselect, edit or delete tags.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, name: typing.Union[java.lang.String, str], plugin: FunctionTagPlugin):
        """
        Constructor.
        
        :param java.lang.String or str name: the name for this action.
        :param FunctionTagPlugin plugin: the plugin this action is associated with.
        """


class FunctionTagLoader(java.lang.Object):
    """
    Reads function tags from  @see ghidra.framework.Application#getModuleDataFile(java.lang.String)
    or a File on the filesystem.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class TagListPanel(javax.swing.JPanel):
    """
    Base panel for displaying tags in the function tag window.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, provider: FunctionTagProvider, tool: ghidra.framework.plugintool.PluginTool, name: typing.Union[java.lang.String, str]):
        """
        Constructor
        
        :param FunctionTagProvider provider: the display provider
        :param ghidra.framework.plugintool.PluginTool tool: the plugin tool
        :param java.lang.String or str name: the name of the panel
        """

    def clearSelection(self):
        ...

    def getTable(self) -> FunctionTagTable:
        ...

    def refresh(self, newFunction: ghidra.program.model.listing.Function):
        """
        Clears the list and re-populates it with a new data set. Clients should override this
        to retrieve data for the given function.
        
        :param ghidra.program.model.listing.Function newFunction: the currently selected function in the listing
        """

    def setProgram(self, program: ghidra.program.model.listing.Program):
        ...

    def setTitle(self, title: typing.Union[java.lang.String, str]):
        ...

    def tagExists(self, name: typing.Union[java.lang.String, str]) -> bool:
        """
        Returns true if the tag already exists in the model.
        
        :param java.lang.String or str name: the name of the tag
        :return: true if the tag exists
        :rtype: bool
        """

    @property
    def table(self) -> FunctionTagTable:
        ...



__all__ = ["FunctionTagTableModel", "FunctionTagTable", "InMemoryFunctionTag", "FunctionTagPlugin", "FunctionTagProvider", "FunctionTagButtonPanel", "SourceTagsPanel", "FunctionTableModel", "FunctionTagRowObject", "AllFunctionsPanel", "TargetTagsPanel", "EditFunctionTagsAction", "FunctionTagLoader", "TagListPanel"]
