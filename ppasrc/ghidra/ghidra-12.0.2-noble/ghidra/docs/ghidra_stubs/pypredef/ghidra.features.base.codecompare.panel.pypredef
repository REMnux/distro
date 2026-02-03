from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking
import docking.action
import ghidra.features.base.codecompare.listing
import ghidra.framework.options
import ghidra.framework.plugintool
import ghidra.program.model.address
import ghidra.program.model.listing
import ghidra.program.util
import ghidra.util.classfinder
import java.awt # type: ignore
import java.awt.event # type: ignore
import java.lang # type: ignore
import java.util # type: ignore
import javax.swing # type: ignore
import javax.swing.event # type: ignore
import utility.function


class FunctionComparisonState(java.lang.Object):
    """
    An object to share config state between providers and all views within those providers.
     
    
    When a comparison provider updates its save state object, it should call 
    :meth:`PluginTool.setConfigChanged(boolean) <PluginTool.setConfigChanged>` so that tool knows there are settings to be saved.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...

    def addUpdateCallback(self, callback: utility.function.Callback):
        """
        Adds a callback to this state that is notified when this state changes.
        
        :param utility.function.Callback callback: the callback
        """

    def getPanelState(self) -> ghidra.framework.options.SaveState:
        """
        Returns the state object for the provider
        
        :return: the state object for the provider
        :rtype: ghidra.framework.options.SaveState
        """

    def getViewState(self) -> CodeComparisonViewState:
        """
        Returns the save state object for the views that live inside a provider
        
        :return: the state
        :rtype: CodeComparisonViewState
        """

    def readConfigState(self, saveState: ghidra.framework.options.SaveState):
        ...

    def setChanged(self):
        """
        Signals to the tool that there are changes to the config state that can be saved.
        """

    def writeConfigState(self, saveState: ghidra.framework.options.SaveState):
        ...

    @property
    def panelState(self) -> ghidra.framework.options.SaveState:
        ...

    @property
    def viewState(self) -> CodeComparisonViewState:
        ...


class CodeComparisonViewState(java.lang.Object):
    """
    A state object to save settings each type of comparison view known by the system.  This class
    is meant to be used to allow user settings to be applied to each new comparison widget that is 
    created.   Also, the class allows the tool to save those settings when the tool is saved.
     
    
    When a comparison provider updates its save state object, it should call 
    :meth:`PluginTool.setConfigChanged(boolean) <PluginTool.setConfigChanged>` so that tool knows there are settings to be saved.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def getSaveState(self, clazz: java.lang.Class[CodeComparisonView]) -> ghidra.framework.options.SaveState:
        ...

    def readConfigState(self, saveState: ghidra.framework.options.SaveState):
        """
        Called by the tool to load saved state for the comparison providers
        
        :param ghidra.framework.options.SaveState saveState: the tool's state
        """

    def writeConfigState(self, saveState: ghidra.framework.options.SaveState):
        """
        Called by the tool to write the panels' saved states into the tools save state
        
        :param ghidra.framework.options.SaveState saveState: the tool's save state
        """

    @property
    def saveState(self) -> ghidra.framework.options.SaveState:
        ...


class FunctionComparisonPanel(javax.swing.JPanel, javax.swing.event.ChangeListener):
    """
    A panel for displaying :obj:`functions <Function>` side-by-side for comparison purposes
    """

    @typing.type_check_only
    class ToggleScrollLockAction(docking.action.ToggleDockingAction):
        """
        Action that sets the scrolling state of the comparison panels
        """

        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool, owner: typing.Union[java.lang.String, str], state: FunctionComparisonState):
        """
        Constructor
        
        :param ghidra.framework.plugintool.PluginTool tool: the tool
        :param java.lang.String or str owner: the owner's name
        :param FunctionComparisonState state: the comparison save state
        """

    def clear(self):
        """
        Clear both sides of this panel
        """

    def dispose(self):
        """
        Remove all views in the tabbed pane
        """

    def getActionContext(self, event: java.awt.event.MouseEvent, componentProvider: docking.ComponentProvider) -> docking.ActionContext:
        """
        Returns the action context for a given mouse event and provider
        
        :param java.awt.event.MouseEvent event: the mouse event
        :param docking.ComponentProvider componentProvider: the component provider
        :return: the action context
        :rtype: docking.ActionContext
        """

    def getActions(self) -> jpype.JArray[docking.action.DockingAction]:
        """
        Get the actions for this FunctionComparisonPanel
        
        :return: an array containing the actions
        :rtype: jpype.JArray[docking.action.DockingAction]
        """

    def getCodeComparisonActions(self) -> jpype.JArray[docking.action.DockingAction]:
        ...

    def getCodeComparisonView(self, name: typing.Union[java.lang.String, str]) -> CodeComparisonView:
        ...

    def getComparisonView(self) -> java.util.List[CodeComparisonView]:
        ...

    def getCurrentComponentName(self) -> str:
        """
        Get the name of the current comparison panel being viewed
        
        :return: the tab name, or null if there is nothing selected
        :rtype: str
        """

    def getCurrentView(self) -> CodeComparisonView:
        """
        Get the current code comparison view being viewed
        
        :return: null if there is no code comparison view
        :rtype: CodeComparisonView
        """

    def getDescription(self) -> str:
        """
        Gets a description to help distinguish this comparison panel from others
        
        :return: the description
        :rtype: str
        """

    def getDisplayedView(self) -> CodeComparisonView:
        """
        Gets the currently displayed :obj:`CodeComparisonView`
        
        :return: the current panel or null.
        :rtype: CodeComparisonView
        """

    def getDualListingView(self) -> ghidra.features.base.codecompare.listing.ListingCodeComparisonView:
        """
        Gets the ListingCodeComparisonView being displayed by this panel
        if one exists
        
        :return: the comparison panel or null
        :rtype: ghidra.features.base.codecompare.listing.ListingCodeComparisonView
        """

    def isEmpty(self) -> bool:
        """
        Returns true if the comparison window has no information to display in
        either the left or right panel
        
        :return: true if the comparison window has no information to display
        :rtype: bool
        """

    def isScrollingSynced(self) -> bool:
        """
        Determines if the layouts of the views are synchronized with respect
        to scrolling and location
        
        :return: true if scrolling is synchronized between the two views
        :rtype: bool
        """

    def loadAddresses(self, leftProgram: ghidra.program.model.listing.Program, rightProgram: ghidra.program.model.listing.Program, leftAddresses: ghidra.program.model.address.AddressSetView, rightAddresses: ghidra.program.model.address.AddressSetView):
        """
        Load the given addresses of the indicated programs into the views of
        this panel
        
        :param ghidra.program.model.listing.Program leftProgram: the program for the left side of the panel
        :param ghidra.program.model.listing.Program rightProgram: the program for the right side of the panel
        :param ghidra.program.model.address.AddressSetView leftAddresses: addresses for the info to display in the left side
        of the panel
        :param ghidra.program.model.address.AddressSetView rightAddresses: addresses for the info to display in the right
        side of the panel
        """

    def loadComparisons(self, left: ComparisonData, right: ComparisonData):
        ...

    def loadData(self, leftData: ghidra.program.model.listing.Data, rightData: ghidra.program.model.listing.Data):
        """
        Load the given data into the views of this panel
        
        :param ghidra.program.model.listing.Data leftData: The data for the left side of the panel
        :param ghidra.program.model.listing.Data rightData: The data for the right side of the panel
        """

    def loadFunctions(self, leftFunction: ghidra.program.model.listing.Function, rightFunction: ghidra.program.model.listing.Function):
        """
        Load the given functions into the views of this panel
        
        :param ghidra.program.model.listing.Function leftFunction: The function for the left side of the panel
        :param ghidra.program.model.listing.Function rightFunction: The function for the right side of the panel
        """

    def programClosed(self, program: ghidra.program.model.listing.Program):
        ...

    def selectComparisonView(self, name: typing.Union[java.lang.String, str]):
        ...

    def setCurrentTabbedComponent(self, name: typing.Union[java.lang.String, str]) -> bool:
        """
        Set the current tabbed panel to be the component with the given name
        
        :param java.lang.String or str name: name of view to set as the current tab
        :return: true if the named view was found in the view map
        :rtype: bool
        """

    def setScrollingSyncState(self, syncScrolling: typing.Union[jpype.JBoolean, bool]):
        """
        Sets whether or not scrolling is synchronized
        
        :param jpype.JBoolean or bool syncScrolling: true means synchronize scrolling and location
        between the two views
        """

    def setTitlePrefixes(self, leftTitlePrefix: typing.Union[java.lang.String, str], rightTitlePrefix: typing.Union[java.lang.String, str]):
        """
        Sets the prefixes that are to be prepended to the title displayed for each side of
        each :obj:`CodeComparisonView`
        
        :param java.lang.String or str leftTitlePrefix: the prefix to prepend to the left titles
        :param java.lang.String or str rightTitlePrefix: the prefix to prepend to the right titles
        """

    def updateActionEnablement(self):
        """
        Updates the enablement for all actions provided by each view
        """

    @property
    def scrollingSynced(self) -> jpype.JBoolean:
        ...

    @property
    def dualListingView(self) -> ghidra.features.base.codecompare.listing.ListingCodeComparisonView:
        ...

    @property
    def comparisonView(self) -> java.util.List[CodeComparisonView]:
        ...

    @property
    def displayedView(self) -> CodeComparisonView:
        ...

    @property
    def description(self) -> java.lang.String:
        ...

    @property
    def currentView(self) -> CodeComparisonView:
        ...

    @property
    def currentComponentName(self) -> java.lang.String:
        ...

    @property
    def codeComparisonView(self) -> CodeComparisonView:
        ...

    @property
    def codeComparisonActions(self) -> jpype.JArray[docking.action.DockingAction]:
        ...

    @property
    def actions(self) -> jpype.JArray[docking.action.DockingAction]:
        ...

    @property
    def empty(self) -> jpype.JBoolean:
        ...


class CodeComparisonViewActionContext(java.lang.Object):
    """
    Action context for a :obj:`CodeComparisonView`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getCodeComparisonView(self) -> CodeComparisonView:
        """
        Gets the view associated with this context.
        
        :return: the code comparison provider.
        :rtype: CodeComparisonView
        """

    @property
    def codeComparisonView(self) -> CodeComparisonView:
        ...


class CodeComparisonView(javax.swing.JPanel, ghidra.util.classfinder.ExtensionPoint):
    """
    The :obj:`CodeComparisonView` class should be extended by any class that is to be 
    discovered by the :obj:`FunctionComparisonPanel` class and included as a 
    form of comparing two sections of code within the same or different programs
     
    
    NOTE: ALL CodeComparisonView CLASSES MUST END IN
    ``CodeComparisonView`` so they are discoverable by the :obj:`ClassSearcher`
    """

    @typing.type_check_only
    class ToggleOrientationAction(docking.action.ToggleDockingAction):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]
    HELP_TOPIC: typing.Final = "FunctionComparison"

    def clearComparisons(self):
        """
        Clears out the current comparisonDatas
        """

    def dispose(self):
        """
        Cleans up resources when this panel is no longer needed
        """

    def getActionContext(self, componentProvider: docking.ComponentProvider, event: java.awt.event.MouseEvent) -> docking.ActionContext:
        """
        Returns the context object which corresponds to the area of focus within this view's 
        component. Null is returned when there is no context.
        
        :param docking.ComponentProvider componentProvider: the provider that includes this code comparison component.
        :param java.awt.event.MouseEvent event: mouse event which corresponds to this request.
        May be null for key-stroke or other non-mouse event.
        :return: the action context for the area of focus in this component.
        :rtype: docking.ActionContext
        """

    def getActions(self) -> java.util.List[docking.action.DockingAction]:
        """
        Returns the actions for this panel
        
        :return: an array of docking actions
        :rtype: java.util.List[docking.action.DockingAction]
        """

    def getActiveSide(self) -> ghidra.util.datastruct.Duo.Side:
        """
        Returns the :obj:`Side` that is currently active
        
        :return: the :obj:`Side` that is currently active
        :rtype: ghidra.util.datastruct.Duo.Side
        """

    def getAddresses(self, side: ghidra.util.datastruct.Duo.Side) -> ghidra.program.model.address.AddressSetView:
        """
        Returns the addresses being shown in the given side.
        
        :param ghidra.util.datastruct.Duo.Side side: the :obj:`Side` to get the program for
        :return: the address set for the given side
        :rtype: ghidra.program.model.address.AddressSetView
        """

    def getComparisonComponent(self, side: ghidra.util.datastruct.Duo.Side) -> javax.swing.JComponent:
        """
        Returns the Component for the given :obj:`Side`
        
        :param ghidra.util.datastruct.Duo.Side side: the Side to its component
        :return: the Component for the given :obj:`Side`
        :rtype: javax.swing.JComponent
        """

    def getFunction(self, side: ghidra.util.datastruct.Duo.Side) -> ghidra.program.model.listing.Function:
        """
        Returns the function being shown in the given side.
        
        :param ghidra.util.datastruct.Duo.Side side: the :obj:`Side` to get the function for
        :return: the function for the given side.
        :rtype: ghidra.program.model.listing.Function
        """

    def getName(self) -> str:
        """
        Force subclasses to supply a descriptive name.
        
        :return: a descriptive name for this panel type
        :rtype: str
        """

    def getProgram(self, side: ghidra.util.datastruct.Duo.Side) -> ghidra.program.model.listing.Program:
        """
        Returns the program being shown in the given side.
        
        :param ghidra.util.datastruct.Duo.Side side: the :obj:`Side` to get the program for
        :return: the program for the given side.
        :rtype: ghidra.program.model.listing.Program
        """

    def getTool(self) -> ghidra.framework.plugintool.PluginTool:
        ...

    def isSideBySide(self) -> bool:
        """
        Returns true if dual panels are displayed horizontally, false if displayed vertically.
        
        :return: true if dual panels are displayed horizontally, false if displayed vertically
        :rtype: bool
        """

    def loadComparisons(self, left: ComparisonData, right: ComparisonData):
        """
        Displays a comparison of two ComparisonData objects
        
        :param ComparisonData left: the comparisonData for the left side
        :param ComparisonData right: the comparisonData for the right side
        """

    def programClosed(self, program: ghidra.program.model.listing.Program):
        """
        Called when a program is closed.
        
        :param ghidra.program.model.listing.Program program: the closed program
        """

    def programRestored(self, program: ghidra.program.model.listing.Program):
        """
        Called when the indicated program has been restored because of an Undo/Redo.
        This method allows this CodeComparisonPanel to take an appropriate action (such as
        refreshing itself) to respond to the program changing.
        
        :param ghidra.program.model.listing.Program program: the program that was restored.
        """

    def setOrientationChangedCallback(self, callback: utility.function.Callback):
        ...

    def setSaveState(self, saveState: ghidra.framework.options.SaveState):
        ...

    def setShowDataTitles(self, showTitles: typing.Union[jpype.JBoolean, bool]):
        """
        Toggles whether or not to display data titles for each side.
        
        :param jpype.JBoolean or bool showTitles: true to show data titles
        """

    def setSideBySide(self, b: typing.Union[jpype.JBoolean, bool]):
        """
        Sets the orientation for the dual panels.
        
        :param jpype.JBoolean or bool b: if true, panels will be display horizontally, otherwise vertically
        """

    def setSynchronizedScrolling(self, b: typing.Union[jpype.JBoolean, bool]):
        """
        Sets whether or not scrolling is synchronized.
        
        :param jpype.JBoolean or bool b: true means synchronize scrolling between the two views.
        """

    def setTitlePrefixes(self, leftTitlePrefix: typing.Union[java.lang.String, str], rightTitlePrefix: typing.Union[java.lang.String, str]):
        """
        A CodeComparisonPanel should provide a title based on what the code comparison panel
        is displaying. This method sets a prefix string that should be prepended to each
        of the code comparison panel's titles.
        
        :param java.lang.String or str leftTitlePrefix: the prefix string to prepend to the left panel's title.
        :param java.lang.String or str rightTitlePrefix: the prefix string to prepend to the right panel's title.
        """

    def setTopComponent(self, component: javax.swing.JComponent):
        """
        Sets the component displayed in the top of this panel.
        
        :param javax.swing.JComponent component: the component.
        """

    def updateActionEnablement(self):
        """
        Updates the enablement for any actions created by this code comparison panel.
        """

    @property
    def comparisonComponent(self) -> javax.swing.JComponent:
        ...

    @property
    def addresses(self) -> ghidra.program.model.address.AddressSetView:
        ...

    @property
    def program(self) -> ghidra.program.model.listing.Program:
        ...

    @property
    def tool(self) -> ghidra.framework.plugintool.PluginTool:
        ...

    @property
    def activeSide(self) -> ghidra.util.datastruct.Duo.Side:
        ...

    @property
    def sideBySide(self) -> jpype.JBoolean:
        ...

    @sideBySide.setter
    def sideBySide(self, value: jpype.JBoolean):
        ...

    @property
    def function(self) -> ghidra.program.model.listing.Function:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def actions(self) -> java.util.List[docking.action.DockingAction]:
        ...


class DataComparisonData(ComparisonData):
    """
    ComparisonData for a Data object
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, data: ghidra.program.model.listing.Data, otherLength: typing.Union[jpype.JInt, int]):
        ...


class EmptyComparisonData(ComparisonData):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class AddressSetComparisonData(ComparisonData):
    """
    ComparisonData for a generic set of addresses.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, program: ghidra.program.model.listing.Program, addresses: ghidra.program.model.address.AddressSetView):
        ...


class ComparisonData(java.lang.Object):
    """
    ComparisonData is an abstraction of items that can be compared in a :obj:`CodeComparisonView`. 
    Not all comparison panels can handle all types of comparison data. For example, the decompiler
    comparison only works when the comparison data is a function.
    """

    class_: typing.ClassVar[java.lang.Class]
    FG_COLOR_TITLE: typing.Final[java.awt.Color]
    EMPTY: typing.Final[ComparisonData]

    def getAddressSet(self) -> ghidra.program.model.address.AddressSetView:
        """
        Returns the set of addresses being compared. Currently, all comparisons are address based,
        so this should never be null.
        
        :return: the set of addresses being compared
        :rtype: ghidra.program.model.address.AddressSetView
        """

    def getDescription(self) -> str:
        """
        Returns a description of the data being compared.
        
        :return: a description of the data being compared.
        :rtype: str
        """

    def getFunction(self) -> ghidra.program.model.listing.Function:
        """
        Returns the function being compared or null if this comparison data is not function based.
        
        :return: the function being compared or null if this comparison data is not function based
        :rtype: ghidra.program.model.listing.Function
        """

    def getInitialLocation(self) -> ghidra.program.util.ProgramLocation:
        """
        Returns the initial program location to put the cursor when the panel is first displayed
        
        :return: the location
        :rtype: ghidra.program.util.ProgramLocation
        """

    def getProgram(self) -> ghidra.program.model.listing.Program:
        """
        Returns the program containing the data being compared.
        
        :return: the program containing the data being compared.
        :rtype: ghidra.program.model.listing.Program
        """

    def getShortDescription(self) -> str:
        """
        Returns a short description (useful for tab name)
        
        :return: a short description
        :rtype: str
        """

    def isEmpty(self) -> bool:
        """
        Returns true if this comparison has no addresses to compare
        
        :return: true if this comparison has no addresses to compare
        :rtype: bool
        """

    @property
    def addressSet(self) -> ghidra.program.model.address.AddressSetView:
        ...

    @property
    def function(self) -> ghidra.program.model.listing.Function:
        ...

    @property
    def initialLocation(self) -> ghidra.program.util.ProgramLocation:
        ...

    @property
    def description(self) -> java.lang.String:
        ...

    @property
    def shortDescription(self) -> java.lang.String:
        ...

    @property
    def program(self) -> ghidra.program.model.listing.Program:
        ...

    @property
    def empty(self) -> jpype.JBoolean:
        ...


class FunctionComparisonData(ComparisonData):
    """
    ComparisonData for a function
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, function: ghidra.program.model.listing.Function):
        ...


class CodeComparisonActionContext(docking.DefaultActionContext, CodeComparisonViewActionContext):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, provider: docking.ComponentProvider, comparisonProvider: CodeComparisonView, component: java.awt.Component):
        """
        Constructor
        
        :param docking.ComponentProvider provider: the ComponentProvider containing the code comparison panel
        :param CodeComparisonView comparisonProvider: the provider that generated this context
        :param java.awt.Component component: the focusable component for associated with the comparison panel
        """

    def getSourceFunction(self) -> ghidra.program.model.listing.Function:
        """
        Returns the function that is the source of the info being applied. This will be whichever
        side of the function diff window that isn't active.
        
        :return: the function to get information from
        :rtype: ghidra.program.model.listing.Function
        """

    def getTargetFunction(self) -> ghidra.program.model.listing.Function:
        """
        Returns the function that is the target of the info being applied. This will be whichever
        side of the function diff window that is active.
        
        :return: the function to apply information to
        :rtype: ghidra.program.model.listing.Function
        """

    @property
    def targetFunction(self) -> ghidra.program.model.listing.Function:
        ...

    @property
    def sourceFunction(self) -> ghidra.program.model.listing.Function:
        ...



__all__ = ["FunctionComparisonState", "CodeComparisonViewState", "FunctionComparisonPanel", "CodeComparisonViewActionContext", "CodeComparisonView", "DataComparisonData", "EmptyComparisonData", "AddressSetComparisonData", "ComparisonData", "FunctionComparisonData", "CodeComparisonActionContext"]
