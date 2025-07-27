from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking
import docking.action
import docking.widgets.fieldpanel
import docking.widgets.fieldpanel.support
import ghidra.app.nav
import ghidra.app.plugin.core.codebrowser.hover
import ghidra.app.plugin.core.marker
import ghidra.app.services
import ghidra.app.util
import ghidra.app.util.viewer.format
import ghidra.app.util.viewer.listingpanel
import ghidra.features.base.codecompare.panel
import ghidra.framework.options
import ghidra.framework.plugintool
import ghidra.program.model.address
import ghidra.program.model.listing
import ghidra.program.util
import ghidra.util.datastruct
import java.awt # type: ignore
import java.awt.event # type: ignore
import java.lang # type: ignore
import java.util # type: ignore


class LinearAddressCorrelation(ghidra.program.util.ListingAddressCorrelation):
    """
    Creates an address correlation with a simplistic correlation where each address correlates based
    on an offset from the address set's minimum address.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, comparisonData: ghidra.util.datastruct.Duo[ghidra.features.base.codecompare.panel.ComparisonData]):
        ...


class ListingDiffChangeListener(java.lang.Object):
    """
    Interface defining a listener that gets notified when the ListingDiff's set of differences 
    and unmatched addresses has changed.
    """

    class_: typing.ClassVar[java.lang.Class]

    def listingDiffChanged(self):
        """
        Called when the ListingDiff's set of differences and unmatched addresses has changed.
        """


class ListingCodeComparisonPanel(ghidra.features.base.codecompare.panel.CodeComparisonPanel, ghidra.app.util.viewer.format.FormatModelListener, ghidra.framework.options.OptionsChangeListener):
    """
    Panel that displays two listings for comparison.
    """

    @typing.type_check_only
    class NavigateType(java.lang.Enum[ListingCodeComparisonPanel.NavigateType]):

        class_: typing.ClassVar[java.lang.Class]
        ALL: typing.Final[ListingCodeComparisonPanel.NavigateType]
        UNMATCHED: typing.Final[ListingCodeComparisonPanel.NavigateType]
        DIFF: typing.Final[ListingCodeComparisonPanel.NavigateType]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> ListingCodeComparisonPanel.NavigateType:
            ...

        @staticmethod
        def values() -> jpype.JArray[ListingCodeComparisonPanel.NavigateType]:
            ...


    class_: typing.ClassVar[java.lang.Class]
    NAME: typing.Final = "Listing View"

    def __init__(self, owner: typing.Union[java.lang.String, str], tool: ghidra.framework.plugintool.PluginTool):
        """
        Creates a comparison panel with two listings.
        
        :param java.lang.String or str owner: the owner of this panel
        :param ghidra.framework.plugintool.PluginTool tool: the tool displaying this panel
        """

    def addHighlightProviders(self, leftHighlightProvider: ghidra.app.util.ListingHighlightProvider, rightHighlightProvider: ghidra.app.util.ListingHighlightProvider):
        """
        Adds the indicated highlight providers for the left and right listing panels.
        
        :param ghidra.app.util.ListingHighlightProvider leftHighlightProvider: the highlight provider for the left side's listing.
        :param ghidra.app.util.ListingHighlightProvider rightHighlightProvider: the highlight provider for the right side's listing.
        """

    def getActiveListingPanel(self) -> ghidra.app.util.viewer.listingpanel.ListingPanel:
        ...

    def getContextObjectForMarginPanels(self, panel: ghidra.app.util.viewer.listingpanel.ListingPanel, event: java.awt.event.MouseEvent) -> java.lang.Object:
        """
        Gets a marker margin or overview margin context object if the mouse event occurred on one of
        the GUI components for the indicated listing panel's marker margin (left edge of listing) or
        overview margin (right edge of listing).
        
        :param ghidra.app.util.viewer.listingpanel.ListingPanel panel: The listing panel to check
        :param java.awt.event.MouseEvent event: the mouse event
        :return: a marker margin context object if the event was on a margin.
        :rtype: java.lang.Object
        """

    @typing.overload
    def getListingPanel(self, side: ghidra.util.datastruct.Duo.Side) -> ghidra.app.util.viewer.listingpanel.ListingPanel:
        ...

    @typing.overload
    def getListingPanel(self, fieldPanel: docking.widgets.fieldpanel.FieldPanel) -> ghidra.app.util.viewer.listingpanel.ListingPanel:
        """
        Gets the left or right listing panel that contains the indicated field panel.
        
        :param docking.widgets.fieldpanel.FieldPanel fieldPanel: the field panel
        :return: the listing panel or null.
        :rtype: ghidra.app.util.viewer.listingpanel.ListingPanel
        """

    def removeHighlightProviders(self, leftHighlightProvider: ghidra.app.util.ListingHighlightProvider, rightHighlightProvider: ghidra.app.util.ListingHighlightProvider):
        """
        Removes the indicated highlight providers from the left and right listing panels.
        
        :param ghidra.app.util.ListingHighlightProvider leftHighlightProvider: the highlight provider for the left side's listing.
        :param ghidra.app.util.ListingHighlightProvider rightHighlightProvider: the highlight provider for the right side's listing.
        """

    def setLocation(self, side: ghidra.util.datastruct.Duo.Side, program: ghidra.program.model.listing.Program, location: ghidra.program.util.ProgramLocation):
        """
        Sets the cursor for the side to the given location
        
        :param ghidra.util.datastruct.Duo.Side side: The side to goto
        :param ghidra.program.model.listing.Program program: the side's program
        :param ghidra.program.util.ProgramLocation location: the location
        """

    def setStatusInfo(self, text: typing.Union[java.lang.String, str]):
        """
        Displays the indicated text int the tool's status area.
        
        :param java.lang.String or str text: the message to display
        """

    def updateActionEnablement(self):
        """
        Updates the enablement for all actions provided by this panel.
        """

    def updateListings(self):
        """
        Repaints both the left and right listing panels if they are visible.
        """

    @property
    def listingPanel(self) -> ghidra.app.util.viewer.listingpanel.ListingPanel:
        ...

    @property
    def activeListingPanel(self) -> ghidra.app.util.viewer.listingpanel.ListingPanel:
        ...


class ListingDiffHighlightProvider(ghidra.app.util.ListingHighlightProvider):

    @typing.type_check_only
    class Range(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, listingDiff: ghidra.program.util.ListingDiff, side: ghidra.util.datastruct.Duo.Side, comparisonOptions: ListingCodeComparisonOptions):
        """
        Constructor for this highlight provider.
        
        :param ghidra.program.util.ListingDiff listingDiff: the ListingDiff to use to determine where there are differences that 
        need highlighting.
        :param ghidra.util.datastruct.Duo.Side side: LEFT or RIGHT
        false means the highlights are for the second listing.
        :param ListingCodeComparisonOptions comparisonOptions: the tool options that indicate the current 
        background colors for the Listing code comparison panel.
        """


@typing.type_check_only
class ListingDisplayGoToService(ghidra.app.services.GoToService):
    """
    This is a GoToService for a listing code compare panel. It allows the goTo to occur relative to
    the left or right listing panel of a dual listing panel, since the left and right sides can be
    displaying totally different addresses.
    """

    class_: typing.ClassVar[java.lang.Class]


class ListingComparisonActionContext(ghidra.features.base.codecompare.panel.CodeComparisonActionContext):
    """
    Action context for a ListingCodeComparisonPanel.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, provider: docking.ComponentProvider, panel: ListingCodeComparisonPanel):
        """
        Constructor for a dual listing's action context.
        
        :param docking.ComponentProvider provider: the provider that uses this action context.
        :param ListingCodeComparisonPanel panel: the ListingCodeComparisonPanel that generated this context
        """

    def getCodeComparisonPanel(self) -> ListingCodeComparisonPanel:
        """
        Returns the :obj:`ListingCodeComparisonPanel` that generated this context
        
        :return: the listing comparison panel that generated this context
        :rtype: ListingCodeComparisonPanel
        """

    @property
    def codeComparisonPanel(self) -> ListingCodeComparisonPanel:
        ...


class ListingCodeComparisonOptions(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    OPTIONS_CATEGORY_NAME: typing.Final = "Listing Code Comparison"
    HELP_TOPIC: typing.Final = "FunctionComparison"

    def __init__(self):
        ...

    def getByteDiffsBackgroundColor(self) -> java.awt.Color:
        ...

    def getDefaultByteDiffsBackgroundColor(self) -> java.awt.Color:
        ...

    def getDefaultDiffCodeUnitsBackgroundColor(self) -> java.awt.Color:
        ...

    def getDefaultMnemonicDiffsBackgroundColor(self) -> java.awt.Color:
        ...

    def getDefaultOperandDiffsBackgroundColor(self) -> java.awt.Color:
        ...

    def getDefaultUnmatchedCodeUnitsBackgroundColor(self) -> java.awt.Color:
        ...

    def getDiffCodeUnitsBackgroundColor(self) -> java.awt.Color:
        ...

    def getMnemonicDiffsBackgroundColor(self) -> java.awt.Color:
        ...

    def getOperandDiffsBackgroundColor(self) -> java.awt.Color:
        ...

    def getUnmatchedCodeUnitsBackgroundColor(self) -> java.awt.Color:
        ...

    def initializeOptions(self, options: ghidra.framework.options.ToolOptions):
        ...

    def loadOptions(self, options: ghidra.framework.options.ToolOptions):
        ...

    @property
    def defaultUnmatchedCodeUnitsBackgroundColor(self) -> java.awt.Color:
        ...

    @property
    def defaultMnemonicDiffsBackgroundColor(self) -> java.awt.Color:
        ...

    @property
    def defaultDiffCodeUnitsBackgroundColor(self) -> java.awt.Color:
        ...

    @property
    def byteDiffsBackgroundColor(self) -> java.awt.Color:
        ...

    @property
    def diffCodeUnitsBackgroundColor(self) -> java.awt.Color:
        ...

    @property
    def mnemonicDiffsBackgroundColor(self) -> java.awt.Color:
        ...

    @property
    def unmatchedCodeUnitsBackgroundColor(self) -> java.awt.Color:
        ...

    @property
    def operandDiffsBackgroundColor(self) -> java.awt.Color:
        ...

    @property
    def defaultOperandDiffsBackgroundColor(self) -> java.awt.Color:
        ...

    @property
    def defaultByteDiffsBackgroundColor(self) -> java.awt.Color:
        ...


class ListingDisplay(ListingDiffChangeListener):
    """
    Represents one side of a dual listing compare window. It holds the listing panel and
    related state information for one side.
    """

    @typing.type_check_only
    class ListingDisplayMarkerManager(ghidra.app.plugin.core.marker.MarkerManager):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ListingDisplayServiceProvider(ghidra.framework.plugintool.ServiceProviderStub):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool, owner: typing.Union[java.lang.String, str], listingDiff: ghidra.program.util.ListingDiff, comparsionOptions: ListingCodeComparisonOptions, side: ghidra.util.datastruct.Duo.Side):
        ...

    def addHighlightProvider(self, highlightProvider: ghidra.app.util.ListingHighlightProvider):
        ...

    def addHoverService(self, service: ghidra.app.plugin.core.codebrowser.hover.ListingHoverService):
        ...

    def getFormatManager(self) -> ghidra.app.util.viewer.format.FormatManager:
        ...

    def getListingPanel(self) -> ghidra.app.util.viewer.listingpanel.ListingPanel:
        ...

    def getProgramLocation(self) -> ghidra.program.util.ProgramLocation:
        ...

    def getViewerPosition(self) -> docking.widgets.fieldpanel.support.ViewerPosition:
        ...

    def goTo(self, location: ghidra.program.util.ProgramLocation):
        ...

    def isHeaderShowing(self) -> bool:
        ...

    def removeHighlightProvider(self, highlightProvider: ghidra.app.util.ListingHighlightProvider):
        ...

    def repaint(self):
        ...

    def setDiffHighlightProvider(self, newDiffHighlights: ListingDiffHighlightProvider):
        ...

    def setHoverMode(self, enabled: typing.Union[jpype.JBoolean, bool]):
        ...

    def setMouseNavigationEnabled(self, enabled: typing.Union[jpype.JBoolean, bool]):
        ...

    def setProgramView(self, program: ghidra.program.model.listing.Program, view: ghidra.program.model.address.AddressSetView, name: typing.Union[java.lang.String, str]):
        ...

    def setView(self, view: ghidra.program.model.address.AddressSetView):
        ...

    def setViewerPosition(self, position: docking.widgets.fieldpanel.support.ViewerPosition):
        ...

    def showHeader(self, show: typing.Union[jpype.JBoolean, bool]):
        ...

    def updateCursorMarkers(self, location: ghidra.program.util.ProgramLocation):
        ...

    @property
    def listingPanel(self) -> ghidra.app.util.viewer.listingpanel.ListingPanel:
        ...

    @property
    def viewerPosition(self) -> docking.widgets.fieldpanel.support.ViewerPosition:
        ...

    @viewerPosition.setter
    def viewerPosition(self, value: docking.widgets.fieldpanel.support.ViewerPosition):
        ...

    @property
    def formatManager(self) -> ghidra.app.util.viewer.format.FormatManager:
        ...

    @property
    def headerShowing(self) -> jpype.JBoolean:
        ...

    @property
    def programLocation(self) -> ghidra.program.util.ProgramLocation:
        ...


class ListingCoordinator(java.lang.Object):
    """
    Keeps two listing panels synchronized, both the view and cursor location
    """

    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class ListingDisplayNavigator(ghidra.app.nav.Navigatable):
    """
    Navigator for the listings contained in a ListingCodeComparisonPanel.
    """

    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class ListingDisplayToggleAction(docking.action.ToggleDockingAction):
    """
    Class that listing display toggle actions should extend.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], owner: typing.Union[java.lang.String, str], supportsKeyBindings: typing.Union[jpype.JBoolean, bool]):
        """
        Constructor that creates a toggle action for a dual listing.
        
        :param java.lang.String or str name: the name for this action
        :param java.lang.String or str owner: the owner of this action
        :param jpype.JBoolean or bool supportsKeyBindings: true if this action's key binding should be managed
        """

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], owner: typing.Union[java.lang.String, str]):
        """
        Constructor that creates a toggle action for a dual listing.
        
        :param java.lang.String or str name: the name for this action
        :param java.lang.String or str owner: the owner of this action
        """


class ListingDiffActionManager(java.lang.Object):
    """
    Manages the actions that control a ListingDiff.
    """

    @typing.type_check_only
    class ToggleIgnoreByteDiffsAction(ListingDisplayToggleAction):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ToggleIgnoreConstantsAction(ListingDisplayToggleAction):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ToggleIgnoreRegisterNamesAction(ListingDisplayToggleAction):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, listingDiff: ghidra.program.util.ListingDiff):
        """
        Constructor for the action manager for a ListingDiff.
        
        :param ghidra.program.util.ListingDiff listingDiff: the ListingDiff that is controlled by this manager's docking actions.
        """

    def getActions(self) -> java.util.List[docking.action.DockingAction]:
        """
        Gets the actions.
        
        :return: the docking actions.
        :rtype: java.util.List[docking.action.DockingAction]
        """

    def updateActionEnablement(self, isShowing: typing.Union[jpype.JBoolean, bool]):
        """
        Update the enablement of the actions created by this manager.
        
        :param jpype.JBoolean or bool isShowing: true indicates that the dual listing diff is currently visible on screen.
        """

    @property
    def actions(self) -> java.util.List[docking.action.DockingAction]:
        ...



__all__ = ["LinearAddressCorrelation", "ListingDiffChangeListener", "ListingCodeComparisonPanel", "ListingDiffHighlightProvider", "ListingDisplayGoToService", "ListingComparisonActionContext", "ListingCodeComparisonOptions", "ListingDisplay", "ListingCoordinator", "ListingDisplayNavigator", "ListingDisplayToggleAction", "ListingDiffActionManager"]
