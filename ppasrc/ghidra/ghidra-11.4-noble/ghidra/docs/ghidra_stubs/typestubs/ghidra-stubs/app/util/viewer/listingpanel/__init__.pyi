from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking.action
import docking.widgets
import docking.widgets.fieldpanel
import docking.widgets.fieldpanel.field
import docking.widgets.fieldpanel.listener
import docking.widgets.fieldpanel.support
import ghidra.app.nav
import ghidra.app.plugin.core.codebrowser.hover
import ghidra.app.plugin.core.hover
import ghidra.app.services
import ghidra.app.util
import ghidra.app.util.viewer.format
import ghidra.app.util.viewer.util
import ghidra.framework.model
import ghidra.framework.options
import ghidra.program.model.address
import ghidra.program.model.listing
import ghidra.program.util
import ghidra.util.task
import java.awt # type: ignore
import java.lang # type: ignore
import java.util # type: ignore
import javax.swing # type: ignore
import javax.swing.event # type: ignore


class ListingModel(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    FUNCTION_POINTER_OPTION_GROUP_NAME: typing.Final = "Function Pointers"
    DISPLAY_EXTERNAL_FUNCTION_POINTER_OPTION_NAME: typing.Final = "Function Pointers.Display External Function Pointer Header"
    DISPLAY_NONEXTERNAL_FUNCTION_POINTER_OPTION_NAME: typing.Final = "Function Pointers.Display Non-External Function Pointer Header"

    def addListener(self, listener: ListingModelListener):
        ...

    def adjustAddressSetToCodeUnitBoundaries(self, addressSet: ghidra.program.model.address.AddressSet) -> ghidra.program.model.address.AddressSet:
        ...

    @typing.overload
    def closeAllData(self, data: ghidra.program.model.listing.Data, monitor: ghidra.util.task.TaskMonitor):
        """
        Recursively close the given data and its sub-components.
        
        :param ghidra.program.model.listing.Data data: the data to close
        :param ghidra.util.task.TaskMonitor monitor: the task monitor
        """

    @typing.overload
    def closeAllData(self, addresses: ghidra.program.model.address.AddressSetView, monitor: ghidra.util.task.TaskMonitor):
        """
        Closes all data found within the given addresses.  Each data is fully closed.
        
        :param ghidra.program.model.address.AddressSetView addresses: the range of addresses to search for data
        :param ghidra.util.task.TaskMonitor monitor: the task monitor
        """

    def closeData(self, data: ghidra.program.model.listing.Data):
        """
        Closes the given data, but not any sub-components.
        
        :param ghidra.program.model.listing.Data data: the data to close
        """

    def copy(self) -> ListingModel:
        """
        Makes a copy of this model.
        
        :return: a copy of this model.
        :rtype: ListingModel
        """

    def dispose(self):
        ...

    def getAddressAfter(self, address: ghidra.program.model.address.Address) -> ghidra.program.model.address.Address:
        ...

    def getAddressBefore(self, address: ghidra.program.model.address.Address) -> ghidra.program.model.address.Address:
        ...

    def getAddressSet(self) -> ghidra.program.model.address.AddressSetView:
        ...

    def getLayout(self, address: ghidra.program.model.address.Address, isGapAddress: typing.Union[jpype.JBoolean, bool]) -> docking.widgets.fieldpanel.Layout:
        ...

    def getMaxWidth(self) -> int:
        ...

    def getProgram(self) -> ghidra.program.model.listing.Program:
        ...

    def isClosed(self) -> bool:
        ...

    def isOpen(self, data: ghidra.program.model.listing.Data) -> bool:
        """
        Returns true if the data is open
        
        :param ghidra.program.model.listing.Data data: the data to check
        :return: true if the data is open
        :rtype: bool
        """

    @typing.overload
    def openAllData(self, data: ghidra.program.model.listing.Data, monitor: ghidra.util.task.TaskMonitor):
        """
        Recursively open the given data and its sub-components.
        
        :param ghidra.program.model.listing.Data data: the data to open
        :param ghidra.util.task.TaskMonitor monitor: the task monitor
        """

    @typing.overload
    def openAllData(self, addresses: ghidra.program.model.address.AddressSetView, monitor: ghidra.util.task.TaskMonitor):
        """
        Opens all data found within the given addresses.  Each data is fully opened.
        
        :param ghidra.program.model.address.AddressSetView addresses: the range of addresses to search for data
        :param ghidra.util.task.TaskMonitor monitor: the task monitor
        """

    def openData(self, data: ghidra.program.model.listing.Data) -> bool:
        """
        Opens the given data, but not any sub-components.
        
        :param ghidra.program.model.listing.Data data: the data to open
        :return: true if the data was opened (will return false if the data is already open or has no children)
        :rtype: bool
        """

    def removeListener(self, listener: ListingModelListener):
        ...

    def setFormatManager(self, formatManager: ghidra.app.util.viewer.format.FormatManager):
        ...

    def toggleOpen(self, data: ghidra.program.model.listing.Data):
        """
        Changes the open state of the given data (open -> closes; closed-> open).
        
        :param ghidra.program.model.listing.Data data: the data to open
        """

    @property
    def addressSet(self) -> ghidra.program.model.address.AddressSetView:
        ...

    @property
    def addressBefore(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def closed(self) -> jpype.JBoolean:
        ...

    @property
    def program(self) -> ghidra.program.model.listing.Program:
        ...

    @property
    def addressAfter(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def open(self) -> jpype.JBoolean:
        ...

    @property
    def maxWidth(self) -> jpype.JInt:
        ...


class VerticalPixelAddressMap(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def findLayoutAt(self, y: typing.Union[jpype.JInt, int]) -> int:
        """
        Finds the layout containing the given point.
        
        :param jpype.JInt or int y: the y coordinate of layout to be found.
        :return: the layout index
        :rtype: int
        """

    def getAddressSet(self) -> ghidra.program.model.address.AddressSetView:
        """
        Gets the address set of this address map.
        
        :return: the address set of this address map
        :rtype: ghidra.program.model.address.AddressSetView
        """

    def getBeginPosition(self, i: typing.Union[jpype.JInt, int]) -> int:
        """
        Returns the y position of the top of the i'th layout.
        
        :param jpype.JInt or int i: the index of the layout.
        :return: the position
        :rtype: int
        """

    def getEndAddress(self) -> ghidra.program.model.address.Address:
        """
        Returns the index of the last layout in this map.
        
        :return: the address
        :rtype: ghidra.program.model.address.Address
        """

    def getEndPosition(self, i: typing.Union[jpype.JInt, int]) -> int:
        """
        Returns the y position of the bottom of the i'th layout.
        
        :param jpype.JInt or int i: the index of the layout.
        :return: the position
        :rtype: int
        """

    def getLayoutAddress(self, i: typing.Union[jpype.JInt, int]) -> ghidra.program.model.address.Address:
        """
        Returns the address of the i'th layout in this map.
        
        :param jpype.JInt or int i: the index into the local array of layouts
        :return: the address of the i'th layout in this map.
        :rtype: ghidra.program.model.address.Address
        """

    def getLayoutEndAddress(self, i: typing.Union[jpype.JInt, int]) -> ghidra.program.model.address.Address:
        """
        Returns the address of the bottom of the i'th layout.  
         
         
        Note: this will return null if at the end of an overlay block.
        
        :param jpype.JInt or int i: the index of the layout
        :return: the address of the bottom of the i'th layout
        :rtype: ghidra.program.model.address.Address
        """

    def getMarkPosition(self, i: typing.Union[jpype.JInt, int]) -> int:
        """
        Returns pixel location to draw marker icon.
        
        :param jpype.JInt or int i: the index of the layout to be marked with an icon.
        :return: the vertical pixel location at which to draw the icon.
        :rtype: int
        """

    def getNumLayouts(self) -> int:
        """
        Returns the number of layouts in this map.
        
        :return: the number of layouts
        :rtype: int
        """

    def getStartAddress(self) -> ghidra.program.model.address.Address:
        """
        Returns the Address of the first layout in this map
        
        :return: the address
        :rtype: ghidra.program.model.address.Address
        """

    def hasPrimaryField(self, i: typing.Union[jpype.JInt, int]) -> bool:
        """
        Determines if the given layout index contains the primary field
        
        :param jpype.JInt or int i: the layout index to test.
        :return: true if the layout contains the primary field.
        :rtype: bool
        """

    @property
    def markPosition(self) -> jpype.JInt:
        ...

    @property
    def addressSet(self) -> ghidra.program.model.address.AddressSetView:
        ...

    @property
    def numLayouts(self) -> jpype.JInt:
        ...

    @property
    def beginPosition(self) -> jpype.JInt:
        ...

    @property
    def endPosition(self) -> jpype.JInt:
        ...

    @property
    def startAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def layoutEndAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def layoutAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def endAddress(self) -> ghidra.program.model.address.Address:
        ...


class ListingBackgroundColorModel(docking.widgets.fieldpanel.support.BackgroundColorModel):
    """
    This interface extends the  :obj:`BackgroundColorModel`  exclusively for BackgroundColorModels used by
    the ListingPanel.  The :obj:`BackgroundColorModel` is a general contract for dealing with
    background colors in a :obj:`FieldPanel`.  ListingBackgroundColorModels require additional
    information such as the :obj:`AddressIndexMap` and the program so that it translate the indexes
    to specific addresses and look up information in the program.
    """

    class_: typing.ClassVar[java.lang.Class]

    def modelDataChanged(self, listingPanel: ListingPanel):
        """
        Called when the :obj:`AddressIndexMap` or the :obj:`Program` changes.
        
        :param ListingPanel listingPanel: the :obj:`ListingPanel` that changed and where the new :obj:`AddressIndexMap`
        and :obj:`Program` can be retrieved.
        """


class PropertyBasedBackgroundColorModel(ListingBackgroundColorModel, ghidra.framework.model.DomainObjectListener):
    """
    Default :obj:`BackgroundColorModel` for the ListingPanel where the color returned
    for an index is based on that corresponding address having a color set in the
    program's database. (You can "paint" colors over address ranges).
    """

    class_: typing.ClassVar[java.lang.Class]
    COLOR_PROPERTY_NAME: typing.Final = "LISTING_COLOR"

    def __init__(self):
        ...

    def setEnabled(self, b: typing.Union[jpype.JBoolean, bool]):
        ...


class ProgramBigListingModel(ListingModel, ghidra.app.util.viewer.format.FormatModelListener, ghidra.framework.model.DomainObjectListener, javax.swing.event.ChangeListener, ghidra.framework.options.OptionsChangeListener):

    @typing.type_check_only
    class LayoutCache(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, program: ghidra.program.model.listing.Program, formatMgr: ghidra.app.util.viewer.format.FormatManager):
        ...

    def isOpenData(self, cu: ghidra.program.model.listing.CodeUnit) -> bool:
        ...

    @property
    def openData(self) -> jpype.JBoolean:
        ...


class OverviewProvider(java.lang.Object):
    """
    Interface implemented by classes that provide overview components to the right side of the
    listing.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getComponent(self) -> javax.swing.JComponent:
        """
        Returns the component to display in the right margin of the listing.
        
        :return: the component
        :rtype: javax.swing.JComponent
        """

    def setNavigatable(self, navigatable: ghidra.app.nav.Navigatable):
        """
        Set the component provider that this overview navigates
        
        :param ghidra.app.nav.Navigatable navigatable: the navigatable provider
        """

    def setProgram(self, program: ghidra.program.model.listing.Program, map: ghidra.app.util.viewer.util.AddressIndexMap):
        """
        Sets the current program and associated address-index map
        
        :param ghidra.program.model.listing.Program program: the program to use.
        :param ghidra.app.util.viewer.util.AddressIndexMap map: the address-index map to use.
        """

    @property
    def component(self) -> javax.swing.JComponent:
        ...


class MarkerClickedListener(java.lang.Object):
    """
    Interface for notifications when the user double-clicks in the marker margin
    """

    class_: typing.ClassVar[java.lang.Class]

    def markerDoubleClicked(self, location: ghidra.program.util.MarkerLocation):
        """
        Notification that the user double-clicked in the marker margin
        
        :param ghidra.program.util.MarkerLocation location: the MarkerLocation where the user double-clicked
        """


class ListingPanel(javax.swing.JPanel, docking.widgets.fieldpanel.listener.FieldMouseListener, docking.widgets.fieldpanel.listener.FieldLocationListener, docking.widgets.fieldpanel.listener.FieldSelectionListener, docking.widgets.fieldpanel.listener.LayoutListener):

    class_: typing.ClassVar[java.lang.Class]
    DEFAULT_DIVIDER_LOCATION: typing.Final = 70

    @typing.overload
    def __init__(self, manager: ghidra.app.util.viewer.format.FormatManager):
        """
        Constructs a new ListingPanel using the given FormatManager
        
        :param ghidra.app.util.viewer.format.FormatManager manager: the FormatManager to use.
        """

    @typing.overload
    def __init__(self, mgr: ghidra.app.util.viewer.format.FormatManager, program: ghidra.program.model.listing.Program):
        """
        Constructs a new ListingPanel for the given program.
        
        :param ghidra.app.util.viewer.format.FormatManager mgr: the FormatManager to use.
        :param ghidra.program.model.listing.Program program: the program for which to create a new ListingPanel
        """

    @typing.overload
    def __init__(self, mgr: ghidra.app.util.viewer.format.FormatManager, model: ListingModel):
        """
        Constructs a new ListingPanel with the given FormatManager and ListingModel
        
        :param ghidra.app.util.viewer.format.FormatManager mgr: the FormatManager to use
        :param ListingModel model: the ListingModel to use.
        """

    def addButtonPressedListener(self, listener: ghidra.app.services.ButtonPressedListener):
        """
        Adds a ButtonPressedListener to be notified when the user presses the mouse button while over
        this panel
        
        :param ghidra.app.services.ButtonPressedListener listener: the ButtonPressedListener to add.
        """

    def addDisplayListener(self, listener: AddressSetDisplayListener):
        ...

    def addHighlightProvider(self, highlightProvider: ghidra.app.util.ListingHighlightProvider):
        """
        Adds a :obj:`ListingHighlightProvider` to this listing.
         
        
        This highlight provider will be used with any other registered providers to paint all the
        highlights for this listing.
        
        :param ghidra.app.util.ListingHighlightProvider highlightProvider: The provider to add
        """

    def addHoverService(self, hoverService: ghidra.app.plugin.core.codebrowser.hover.ListingHoverService):
        ...

    def addIndexMapChangeListener(self, listener: javax.swing.event.ChangeListener):
        """
        Add a change listener to be notified whenever the indexMap changes.
        
        :param javax.swing.event.ChangeListener listener: the listener to be added.
        """

    def addMarginProvider(self, provider: MarginProvider):
        """
        Adds the MarginProvider to this panel
        
        :param MarginProvider provider: the MarginProvider that will provide components to display in this panel's
                    left margin area.
        """

    def addOverviewProvider(self, provider: OverviewProvider):
        """
        Adds the given OverviewProvider with will be displayed in this panels right margin area.
        
        :param OverviewProvider provider: the OverviewProvider to display.
        """

    def center(self, location: ghidra.program.util.ProgramLocation):
        """
        Center the view of the listing around the given location.
        
        :param ghidra.program.util.ProgramLocation location: the location
        """

    def dispose(self):
        ...

    def enablePropertyBasedColorModel(self, b: typing.Union[jpype.JBoolean, bool]):
        ...

    def getAddressIndexMap(self) -> ghidra.app.util.viewer.util.AddressIndexMap:
        """
        Returns the AddressIndexMap currently used by this listing panel.
        
        :return: the map
        :rtype: ghidra.app.util.viewer.util.AddressIndexMap
        """

    def getCursorBounds(self) -> java.awt.Rectangle:
        ...

    def getCursorLocation(self) -> ghidra.program.util.ProgramLocation:
        ...

    def getCursorPoint(self) -> java.awt.Point:
        ...

    def getDividerLocation(self) -> int:
        """
        Returns the divider location between the left margin areas and the main display.
        
        :return: the location
        :rtype: int
        """

    def getFieldHeader(self) -> ghidra.app.util.viewer.format.FieldHeader:
        ...

    def getFieldPanel(self) -> docking.widgets.fieldpanel.FieldPanel:
        """
        Returns the FieldPanel used by this ListingPanel.
        
        :return: the field panel
        :rtype: docking.widgets.fieldpanel.FieldPanel
        """

    def getFormatManager(self) -> ghidra.app.util.viewer.format.FormatManager:
        """
        Returns the FormatManager used by this listing panel.
        
        :return: the format manager
        :rtype: ghidra.app.util.viewer.format.FormatManager
        """

    def getHeaderActions(self, ownerName: typing.Union[java.lang.String, str]) -> java.util.List[docking.action.DockingActionIf]:
        ...

    def getLayout(self, addr: ghidra.program.model.address.Address) -> docking.widgets.fieldpanel.Layout:
        ...

    def getListingModel(self) -> ListingModel:
        """
        Returns the current ListingModel used by this panel.
        
        :return: the model
        :rtype: ListingModel
        """

    def getMarginProviders(self) -> java.util.List[MarginProvider]:
        """
        Get the margin providers in this ListingPanel.
        
        :return: the providers
        :rtype: java.util.List[MarginProvider]
        """

    def getOverviewProviders(self) -> java.util.List[OverviewProvider]:
        """
        Get the overview providers in this ListingPanel.
        
        :return: the providers
        :rtype: java.util.List[OverviewProvider]
        """

    def getProgram(self) -> ghidra.program.model.listing.Program:
        ...

    def getProgramHighlight(self) -> ghidra.program.util.ProgramSelection:
        ...

    @typing.overload
    def getProgramLocation(self) -> ghidra.program.util.ProgramLocation:
        """
        Returns the current program location of the cursor.
        
        :return: the location
        :rtype: ghidra.program.util.ProgramLocation
        """

    @typing.overload
    def getProgramLocation(self, point: java.awt.Point) -> ghidra.program.util.ProgramLocation:
        """
        Get a program location for the given point.
        
        :param java.awt.Point point: the point
        :return: program location, or null if point does not correspond to a program location
        :rtype: ghidra.program.util.ProgramLocation
        """

    @typing.overload
    def getProgramSelection(self) -> ghidra.program.util.ProgramSelection:
        """
        Returns the current program selection.
        
        :return: the selection
        :rtype: ghidra.program.util.ProgramSelection
        """

    @typing.overload
    def getProgramSelection(self, fieldSelection: docking.widgets.fieldpanel.support.FieldSelection) -> ghidra.program.util.ProgramSelection:
        ...

    def getTextBackgroundColor(self) -> java.awt.Color:
        ...

    def getTextSelection(self) -> str:
        """
        Returns the currently selected text.
         
        
        The value will only be non-null for selections within a single field.
        
        :return: the selected text or null
        :rtype: str
        """

    def getVerticalScrollBar(self) -> javax.swing.JScrollBar:
        """
        Returns the vertical scrollbar used by this panel.
        
        :return: the scroll bar
        :rtype: javax.swing.JScrollBar
        """

    def getView(self) -> ghidra.program.model.address.AddressSetView:
        """
        Gets the view of this listing panel (meant to be used in conjunction with
        :meth:`setView(AddressSetView) <.setView>`.
        
        :return: the addresses
        :rtype: ghidra.program.model.address.AddressSetView
        """

    @typing.overload
    def goTo(self, loc: ghidra.program.util.ProgramLocation) -> bool:
        """
        Moves the cursor to the given program location and repositions the scrollbar to show that
        location in the screen.
        
        :param ghidra.program.util.ProgramLocation loc: the location to move to.
        :return: true if successful
        :rtype: bool
        """

    @typing.overload
    def goTo(self, loc: ghidra.program.util.ProgramLocation, centerWhenNotVisible: typing.Union[jpype.JBoolean, bool]) -> bool:
        """
        Moves the cursor to the given program location.
         
        
        Also, repositions the scrollbar to show that location, if the location is not on the screen.
        
        :param ghidra.program.util.ProgramLocation loc: the location to move to.
        :param jpype.JBoolean or bool centerWhenNotVisible: this variable only has an effect if the given location is not on
                    the screen. In that case, when this parameter is true, then the given location
                    will be placed in the center of the screen; when the parameter is false, then the
                    screen will be scrolled only enough to show the cursor.
        :return: true if successful
        :rtype: bool
        """

    @typing.overload
    def goTo(self, addr: ghidra.program.model.address.Address) -> bool:
        """
        Positions the ListingPanel to the given address.
        
        :param ghidra.program.model.address.Address addr: the address at which to position the listing.
        :return: true if successful
        :rtype: bool
        """

    @typing.overload
    def goTo(self, currentAddress: ghidra.program.model.address.Address, gotoAddress: ghidra.program.model.address.Address) -> bool:
        """
        Positions the ListingPanel to the given address.
        
        :param ghidra.program.model.address.Address currentAddress: used to determine which symbol to goto if the goto address has more
                    than one
        :param ghidra.program.model.address.Address gotoAddress: the address at which to position to listing.
        :return: true if the address exists
        :rtype: bool
        """

    def isActive(self) -> bool:
        """
        Returns true if this component has focus.
        
        :return: true if this component has focus.
        :rtype: bool
        """

    def isHeaderShowing(self) -> bool:
        """
        Returns true if the field header component is showing.
        
        :return: true if showing
        :rtype: bool
        """

    def isHoverShowing(self) -> bool:
        ...

    def isStartDragOk(self) -> bool:
        """
        Returns true if the mouse is at a location that can be dragged.
        
        :return: true if the mouse is at a location that can be dragged.
        :rtype: bool
        """

    def removeButtonPressedListener(self, listener: ghidra.app.services.ButtonPressedListener):
        """
        Removes the given ButtonPressedListener.
        
        :param ghidra.app.services.ButtonPressedListener listener: the ButtonPressedListener to remove.
        """

    def removeDisplayListener(self, listener: AddressSetDisplayListener):
        ...

    def removeHighlightProvider(self, highlightProvider: ghidra.app.util.ListingHighlightProvider):
        """
        Removes the given :obj:`ListingHighlightProvider` from this listing.
        
        :param ghidra.app.util.ListingHighlightProvider highlightProvider: The provider to remove.
        
        .. seealso::
        
            | :obj:`.addHighlightProvider(ListingHighlightProvider)`
        """

    def removeHoverService(self, hoverService: ghidra.app.plugin.core.codebrowser.hover.ListingHoverService):
        ...

    def removeIndexMapChangeListener(self, listener: javax.swing.event.ChangeListener):
        """
        Removes the change listener to be notified when the indexMap changes.
        
        :param javax.swing.event.ChangeListener listener: the listener to be removed.
        """

    def removeMarginProvider(self, provider: MarginProvider):
        """
        Removes the given margin provider from this panel
        
        :param MarginProvider provider: the MarginProvider to remove.
        """

    def removeOverviewProvider(self, provider: OverviewProvider):
        """
        Removes the given OverviewProvider from this panel
        
        :param OverviewProvider provider: the OverviewProvider to remove.
        """

    def scrollTo(self, location: ghidra.program.util.ProgramLocation):
        """
        Scroll the view of the listing to the given location.
         
         
        
        If the given location is not displayed, this has no effect.
        
        :param ghidra.program.util.ProgramLocation location: the location
        """

    def selectAll(self):
        """
        Sets the selection to the entire listing view.
        """

    def selectComplement(self) -> ghidra.program.model.address.AddressSet:
        """
        Sets the selection to the complement of the current selection in the listing view.
        
        :return: the addresses
        :rtype: ghidra.program.model.address.AddressSet
        """

    def setBackgroundColorModel(self, colorModel: ListingBackgroundColorModel):
        """
        Sets the externally supplied :obj:`ListingBackgroundColorModel` to be blended with its own
        :obj:`PropertyBasedBackgroundColorModel`.
        
        :param ListingBackgroundColorModel colorModel: the :obj:`ListingBackgroundColorModel` to use in conjunction with the
                    built-in :obj:`PropertyBasedBackgroundColorModel`
        """

    @typing.overload
    def setCursorPosition(self, loc: ghidra.program.util.ProgramLocation):
        """
        Sets the cursor to the given program location.
        
        :param ghidra.program.util.ProgramLocation loc: the location at which to move the cursor.
        """

    @typing.overload
    def setCursorPosition(self, loc: ghidra.program.util.ProgramLocation, trigger: docking.widgets.EventTrigger):
        """
        Sets the cursor to the given program location with a given trigger
         
        
        This method should only be used in automated testing to programmatically simulate a user
        navigating within the listing panel.
        
        :param ghidra.program.util.ProgramLocation loc: the location at which to move the cursor.
        :param docking.widgets.EventTrigger trigger: the event trigger
        """

    def setDividerLocation(self, dividerLocation: typing.Union[jpype.JInt, int]):
        """
        Sets the divider location between the left margin areas and the main display.
        
        :param jpype.JInt or int dividerLocation: the location to set on the divider.
        """

    def setFormatManager(self, formatManager: ghidra.app.util.viewer.format.FormatManager):
        ...

    def setHighlight(self, highlight: ghidra.program.util.ProgramSelection):
        """
        Sets the highlight.
        
        :param ghidra.program.util.ProgramSelection highlight: the new highlight.
        """

    def setHoverMode(self, enabled: typing.Union[jpype.JBoolean, bool]):
        ...

    def setListingHoverHandler(self, handler: ListingHoverProvider):
        ...

    def setListingModel(self, newModel: ListingModel):
        """
        Sets the ListingModel to use.
        
        :param ListingModel newModel: the model to use.
        """

    def setLiveProgramSelectionListener(self, listener: ProgramSelectionListener):
        """
        Sets the ProgramSelectionListener for selection changes while dragging.
         
        
        Only one listener is supported
        
        :param ProgramSelectionListener listener: the ProgramSelectionListener to use.
        """

    def setNeverSroll(self):
        """
        Sets listing panel to never show scroll bars.
         
        
        This is useful when you want this listing's parent to always be as big as this listing.
        """

    def setProgram(self, program: ghidra.program.model.listing.Program):
        """
        Sets the program to be displayed by this listing panel
        
        :param ghidra.program.model.listing.Program program: the program to display.
        """

    def setProgramLocationListener(self, listener: ProgramLocationListener):
        """
        Sets the ProgramLocationListener.
         
        
        Only one listener is supported
        
        :param ProgramLocationListener listener: the ProgramLocationListener to use.
        """

    def setProgramSelectionListener(self, listener: ProgramSelectionListener):
        """
        Sets the ProgramSelectionListener.
         
        
        Only one listener is supported
        
        :param ProgramSelectionListener listener: the ProgramSelectionListener to use.
        """

    @typing.overload
    def setSelection(self, sel: ghidra.program.util.ProgramSelection):
        """
        Sets the selection.
        
        :param ghidra.program.util.ProgramSelection sel: the new selection
        """

    @typing.overload
    def setSelection(self, sel: ghidra.program.util.ProgramSelection, trigger: docking.widgets.EventTrigger):
        """
        Sets the selection.
        
        :param ghidra.program.util.ProgramSelection sel: the new selection
        :param docking.widgets.EventTrigger trigger: the cause of the change
        """

    def setStringSelectionListener(self, listener: StringSelectionListener):
        ...

    def setTextBackgroundColor(self, c: java.awt.Color):
        """
        Sets the background color for the listing panel.
         
        
        This will set the background for the main listing display.
        
        :param java.awt.Color c: the color
        """

    def setView(self, view: ghidra.program.model.address.AddressSetView):
        """
        Restricts the program's view to the given address set
        
        :param ghidra.program.model.address.AddressSetView view: the set of address to include in the view.
        """

    def showHeader(self, show: typing.Union[jpype.JBoolean, bool]):
        """
        Sets whether or not the field header component is visible at the top of the listing panel
        
        :param jpype.JBoolean or bool show: if true, the header component will be show, otherwise it will be hidden.
        """

    def updateDisplay(self, updateImmediately: typing.Union[jpype.JBoolean, bool]):
        ...

    @property
    def cursorPoint(self) -> java.awt.Point:
        ...

    @property
    def textSelection(self) -> java.lang.String:
        ...

    @property
    def verticalScrollBar(self) -> javax.swing.JScrollBar:
        ...

    @property
    def program(self) -> ghidra.program.model.listing.Program:
        ...

    @program.setter
    def program(self, value: ghidra.program.model.listing.Program):
        ...

    @property
    def hoverShowing(self) -> jpype.JBoolean:
        ...

    @property
    def overviewProviders(self) -> java.util.List[OverviewProvider]:
        ...

    @property
    def dividerLocation(self) -> jpype.JInt:
        ...

    @dividerLocation.setter
    def dividerLocation(self, value: jpype.JInt):
        ...

    @property
    def cursorLocation(self) -> ghidra.program.util.ProgramLocation:
        ...

    @property
    def view(self) -> ghidra.program.model.address.AddressSetView:
        ...

    @view.setter
    def view(self, value: ghidra.program.model.address.AddressSetView):
        ...

    @property
    def headerActions(self) -> java.util.List[docking.action.DockingActionIf]:
        ...

    @property
    def programHighlight(self) -> ghidra.program.util.ProgramSelection:
        ...

    @property
    def programLocation(self) -> ghidra.program.util.ProgramLocation:
        ...

    @property
    def fieldHeader(self) -> ghidra.app.util.viewer.format.FieldHeader:
        ...

    @property
    def marginProviders(self) -> java.util.List[MarginProvider]:
        ...

    @property
    def formatManager(self) -> ghidra.app.util.viewer.format.FormatManager:
        ...

    @formatManager.setter
    def formatManager(self, value: ghidra.app.util.viewer.format.FormatManager):
        ...

    @property
    def headerShowing(self) -> jpype.JBoolean:
        ...

    @property
    def active(self) -> jpype.JBoolean:
        ...

    @property
    def addressIndexMap(self) -> ghidra.app.util.viewer.util.AddressIndexMap:
        ...

    @property
    def fieldPanel(self) -> docking.widgets.fieldpanel.FieldPanel:
        ...

    @property
    def textBackgroundColor(self) -> java.awt.Color:
        ...

    @textBackgroundColor.setter
    def textBackgroundColor(self, value: java.awt.Color):
        ...

    @property
    def cursorBounds(self) -> java.awt.Rectangle:
        ...

    @property
    def layout(self) -> docking.widgets.fieldpanel.Layout:
        ...

    @property
    def programSelection(self) -> ghidra.program.util.ProgramSelection:
        ...

    @property
    def listingModel(self) -> ListingModel:
        ...

    @listingModel.setter
    def listingModel(self, value: ListingModel):
        ...

    @property
    def startDragOk(self) -> jpype.JBoolean:
        ...


class StringSelectionListener(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def setStringSelection(self, string: typing.Union[java.lang.String, str]):
        ...


class EmptyListingModel(ListingModel):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class ProgramLocationTranslator(java.lang.Object):
    """
    Class for converting a program location from one program to another
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, correlator: ghidra.program.util.ListingAddressCorrelation):
        """
        Constructor given a correlator for translating addresses
        
        :param ghidra.program.util.ListingAddressCorrelation correlator: converts address from one program to another
        """

    def getProgramLocation(self, side: ghidra.util.datastruct.Duo.Side, otherSideLocation: ghidra.program.util.ProgramLocation) -> ghidra.program.util.ProgramLocation:
        """
        Converts a program location from the other side to the given side.
        
        :param ghidra.util.datastruct.Duo.Side side: the side to get a location for
        :param ghidra.program.util.ProgramLocation otherSideLocation: the location from the other side
        :return: a program location for the given side that matches the other given location
        :rtype: ghidra.program.util.ProgramLocation
        """


class ProgramSelectionListener(java.lang.Object):
    """
    Listener that is notified when the program selection changes
    """

    class_: typing.ClassVar[java.lang.Class]

    def programSelectionChanged(self, selection: ghidra.program.util.ProgramSelection, trigger: docking.widgets.EventTrigger):
        """
        Called whenever the program selection changes.
        
        :param ghidra.program.util.ProgramSelection selection: the new program selection.
        :param docking.widgets.EventTrigger trigger: the cause of the change
        """


class ProgramLocationListener(java.lang.Object):
    """
    Listener that is notified when the program location changes.
    """

    class_: typing.ClassVar[java.lang.Class]

    def programLocationChanged(self, loc: ghidra.program.util.ProgramLocation, trigger: docking.widgets.EventTrigger):
        """
        Called whenever the program location changes.
        
        :param ghidra.program.util.ProgramLocation loc: the new program location.
        :param docking.widgets.EventTrigger trigger: the cause of the change
        """


class MarginProvider(java.lang.Object):
    """
    Interface for objects that want to add a component to the listing's left margin.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getComponent(self) -> javax.swing.JComponent:
        """
        Get the component to show the margin markers.
        
        :return: the component
        :rtype: javax.swing.JComponent
        """

    def getMarkerLocation(self, x: typing.Union[jpype.JInt, int], y: typing.Union[jpype.JInt, int]) -> ghidra.program.util.MarkerLocation:
        """
        Get the marker location for the given x, y point.
        
        :param jpype.JInt or int x: the horizontal coordinate.
        :param jpype.JInt or int y: the vertical coordinate.
        :return: the location
        :rtype: ghidra.program.util.MarkerLocation
        """

    def isResizeable(self) -> bool:
        """
        Return true if can be resized.
        
        :return: true if can be resized.
        :rtype: bool
        """

    def setProgram(self, program: ghidra.program.model.listing.Program, addressIndexMap: ghidra.app.util.viewer.util.AddressIndexMap, pixelMap: VerticalPixelAddressMap):
        """
        Set the program and associated maps.
        
        :param ghidra.program.model.listing.Program program: the program to use.
        :param ghidra.app.util.viewer.util.AddressIndexMap addressIndexMap: the address-index map to use.
        :param VerticalPixelAddressMap pixelMap: the vertical pixel map to use.
        """

    @property
    def component(self) -> javax.swing.JComponent:
        ...

    @property
    def resizeable(self) -> jpype.JBoolean:
        ...


class ListingModelAdapter(docking.widgets.fieldpanel.LayoutModel, ListingModelListener):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, bigListingModel: ListingModel):
        ...

    def dispose(self):
        ...

    def getAddressIndexMap(self) -> ghidra.app.util.viewer.util.AddressIndexMap:
        ...

    def getAllProgramSelection(self) -> ghidra.program.util.ProgramSelection:
        ...

    def getFieldLocation(self, location: ghidra.program.util.ProgramLocation) -> docking.widgets.fieldpanel.support.FieldLocation:
        """
        Translates the given ProgramLocation into a FieldLocation.  Attempts to find a
        field that can exactly find a match for the program location.  Otherwise, it
        will return a fieldLocation to the default field or beginning of the line.
        
        :param ghidra.program.util.ProgramLocation location: the ProgramLocation to translate.
        :return: a FieldLocation for the ProgramLocation or null if none can be found.
        :rtype: docking.widgets.fieldpanel.support.FieldLocation
        """

    def getFieldSelection(self, selection: ghidra.program.util.ProgramSelection) -> docking.widgets.fieldpanel.support.FieldSelection:
        ...

    def getLayout(self, addr: ghidra.program.model.address.Address) -> docking.widgets.fieldpanel.Layout:
        ...

    @typing.overload
    def getProgramLocation(self, floc: docking.widgets.fieldpanel.support.FieldLocation) -> ghidra.program.util.ProgramLocation:
        ...

    @typing.overload
    def getProgramLocation(self, location: docking.widgets.fieldpanel.support.FieldLocation, field: docking.widgets.fieldpanel.field.Field) -> ghidra.program.util.ProgramLocation:
        ...

    def getProgramSelection(self, selection: docking.widgets.fieldpanel.support.FieldSelection) -> ghidra.program.util.ProgramSelection:
        ...

    def setAddressSet(self, view: ghidra.program.model.address.AddressSetView):
        """
        Sets the addresses displayed by this model's listing.
        
        :param ghidra.program.model.address.AddressSetView view: the addresses. These must already be compatible with the program
        associated with this model.
        """

    def viewUpdated(self):
        ...

    @property
    def layout(self) -> docking.widgets.fieldpanel.Layout:
        ...

    @property
    def fieldLocation(self) -> docking.widgets.fieldpanel.support.FieldLocation:
        ...

    @property
    def programSelection(self) -> ghidra.program.util.ProgramSelection:
        ...

    @property
    def fieldSelection(self) -> docking.widgets.fieldpanel.support.FieldSelection:
        ...

    @property
    def allProgramSelection(self) -> ghidra.program.util.ProgramSelection:
        ...

    @property
    def addressIndexMap(self) -> ghidra.app.util.viewer.util.AddressIndexMap:
        ...

    @property
    def programLocation(self) -> ghidra.program.util.ProgramLocation:
        ...


class ListingHoverProvider(ghidra.app.plugin.core.hover.AbstractHoverProvider):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def addHoverService(self, hoverService: ghidra.app.plugin.core.codebrowser.hover.ListingHoverService):
        ...

    def removeHoverService(self, hoverService: ghidra.app.plugin.core.codebrowser.hover.ListingHoverService):
        ...


class ListingModelListener(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def dataChanged(self, updateImmediately: typing.Union[jpype.JBoolean, bool]):
        """
        Called when the data at an index or range of indexes changes.
        
        :param jpype.JBoolean or bool updateImmediately: true to immediately update the listing upon change.
        """

    def modelSizeChanged(self):
        """
        Called whenever the number of indexes changed
        """


class AddressSetDisplayListener(java.lang.Object):
    """
    Interface for being notified whenever the set of visible addresses change in the listing.
    """

    class_: typing.ClassVar[java.lang.Class]

    def visibleAddressesChanged(self, visibleAddresses: ghidra.program.model.address.AddressSetView):
        """
        Callback whenever the set of visible addresses change in the listing.
        
        :param ghidra.program.model.address.AddressSetView visibleAddresses: the current set of visible addresses in the listing.  If no
        visible addresses are in the listing view, then an empty AddressSetView will be passed.
        """



__all__ = ["ListingModel", "VerticalPixelAddressMap", "ListingBackgroundColorModel", "PropertyBasedBackgroundColorModel", "ProgramBigListingModel", "OverviewProvider", "MarkerClickedListener", "ListingPanel", "StringSelectionListener", "EmptyListingModel", "ProgramLocationTranslator", "ProgramSelectionListener", "ProgramLocationListener", "MarginProvider", "ListingModelAdapter", "ListingHoverProvider", "ListingModelListener", "AddressSetDisplayListener"]
