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
import docking.dnd
import docking.widgets.fieldpanel.support
import docking.widgets.table
import ghidra.app.context
import ghidra.app.nav
import ghidra.app.services
import ghidra.app.util
import ghidra.app.util.viewer.format
import ghidra.app.util.viewer.listingpanel
import ghidra.app.util.viewer.util
import ghidra.framework.model
import ghidra.framework.options
import ghidra.framework.plugintool
import ghidra.program.model.address
import ghidra.program.model.listing
import ghidra.program.util
import ghidra.util.table
import java.awt # type: ignore
import java.awt.event # type: ignore
import java.lang # type: ignore
import javax.swing # type: ignore
import javax.swing.event # type: ignore


P = typing.TypeVar("P")


class AddressRangeInfo(java.lang.Record):
    """
    A record for information about an :obj:`AddressRange`, used when creating
    address range tables
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, min: ghidra.program.model.address.Address, max: ghidra.program.model.address.Address, size: typing.Union[jpype.JLong, int], isSameByte: typing.Union[jpype.JBoolean, bool], numRefsTo: typing.Union[jpype.JInt, int], numRefsFrom: typing.Union[jpype.JInt, int]):
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def isSameByte(self) -> bool:
        ...

    @staticmethod
    def isSameByteValue(min: ghidra.program.model.address.Address, max: ghidra.program.model.address.Address, program: ghidra.program.model.listing.Program) -> bool:
        """
        Returns true precisely when all of the addresses between min and max (inclusive)
        have the same byte value OR all addresses are without values
        
        :param ghidra.program.model.address.Address min: minimum address
        :param ghidra.program.model.address.Address max: maximum address
        :param ghidra.program.model.listing.Program program: program
        :return: true if all addresses have same value
        :rtype: bool
        """

    def max(self) -> ghidra.program.model.address.Address:
        ...

    def min(self) -> ghidra.program.model.address.Address:
        ...

    def numRefsFrom(self) -> int:
        ...

    def numRefsTo(self) -> int:
        ...

    def size(self) -> int:
        ...

    def toString(self) -> str:
        ...

    @property
    def sameByte(self) -> jpype.JBoolean:
        ...


class AddressRangeBytesTableColumn(docking.widgets.table.AbstractDynamicTableColumn[AddressRangeInfo, jpype.JArray[java.lang.Byte], ghidra.program.model.listing.Program]):
    """
    A column for displaying a small window of bytes around the endpoints of an :obj:`AddressRange`
    in an address range table
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        """
        Default constructor
        """


class MarkAndSelectionAction(docking.action.ToggleDockingAction):
    """
    Actions for creating a selection using two distinct steps. The first time the action is invoked,
    it records the current location as the start of a selection. The second time the action is
    invoked it creates a selection from the recorded location to the current location.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, owner: typing.Union[java.lang.String, str], group: typing.Union[java.lang.String, str], subGroup: typing.Union[java.lang.String, str]):
        ...


class CodeBrowserPlugin(AbstractCodeBrowserPlugin[CodeViewerProvider]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...


class ListingMiddleMouseHighlightProvider(ghidra.app.services.ButtonPressedListener, ghidra.framework.options.OptionsChangeListener, ghidra.app.util.ListingHighlightProvider):

    @typing.type_check_only
    class WriteChecker(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        def hasWrite(self, instr: ghidra.program.model.listing.Instruction) -> bool:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool, repaintComponent: java.awt.Component):
        ...


class AddressRangeTableModel(ghidra.util.table.GhidraProgramTableModel[AddressRangeInfo]):
    """
    A :obj:`GhidraProgramTableModel` for displaying tables in which one row corresponds
    to an :obj:`AddressRange`
    """

    @typing.type_check_only
    class MinAddressTableColumn(docking.widgets.table.AbstractDynamicTableColumn[AddressRangeInfo, ghidra.program.model.address.Address, java.lang.Object]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class MaxAddressTableColumn(docking.widgets.table.AbstractDynamicTableColumn[AddressRangeInfo, ghidra.program.model.address.Address, java.lang.Object]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class LengthTableColumn(docking.widgets.table.AbstractDynamicTableColumn[AddressRangeInfo, java.lang.Long, java.lang.Object]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class IdenticalBytesTableColumn(docking.widgets.table.AbstractDynamicTableColumn[AddressRangeInfo, java.lang.Boolean, java.lang.Object]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class BlockNameTableColumn(docking.widgets.table.AbstractDynamicTableColumn[AddressRangeInfo, java.lang.String, java.lang.Object]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class NumRefsToTableColumn(docking.widgets.table.AbstractDynamicTableColumn[AddressRangeInfo, java.lang.Integer, java.lang.Object]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class NumRefsFromTableColumn(docking.widgets.table.AbstractDynamicTableColumn[AddressRangeInfo, java.lang.Integer, java.lang.Object]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]


class CodeViewerProvider(ghidra.framework.plugintool.NavigatableComponentProviderAdapter, ghidra.app.util.viewer.listingpanel.ProgramLocationListener, ghidra.app.util.viewer.listingpanel.ProgramSelectionListener, docking.dnd.Draggable, docking.dnd.Droppable, javax.swing.event.ChangeListener, ghidra.app.util.viewer.listingpanel.StringSelectionListener, docking.actions.PopupActionProvider):

    @typing.type_check_only
    class ToggleHeaderAction(docking.action.ToggleDockingAction):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ToggleHoverAction(docking.action.ToggleDockingAction):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ProgramHighlighterProvider(ghidra.app.util.ListingHighlightProvider):
        """
        A class that allows clients to install transient highlighters while keeping the middle-mouse
        highlighting on at the same time.
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class FocusingMouseListener(java.awt.event.MouseAdapter):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: CodeBrowserPluginInterface, formatMgr: ghidra.app.util.viewer.format.FormatManager, isConnected: typing.Union[jpype.JBoolean, bool]):
        ...

    def addDisplayListener(self, listener: ghidra.app.util.viewer.listingpanel.AddressSetDisplayListener):
        """
        Add the :obj:`AddressSetDisplayListener` to the listing panel
        
        :param ghidra.app.util.viewer.listingpanel.AddressSetDisplayListener listener: the listener to add
        """

    def addMarginProvider(self, marginProvider: ghidra.app.util.viewer.listingpanel.MarginProvider):
        ...

    def addOverviewProvider(self, overviewProvider: ghidra.app.util.viewer.listingpanel.OverviewProvider):
        ...

    def clearPanel(self):
        ...

    def cloneWindow(self):
        ...

    def getListingPanel(self) -> ghidra.app.util.viewer.listingpanel.ListingPanel:
        ...

    def getOtherPanel(self) -> ghidra.app.util.viewer.listingpanel.ListingPanel:
        ...

    def getStringSelection(self) -> str:
        ...

    def isReadOnly(self) -> bool:
        """
        TODO: Remove or rename this to something that accommodates redirecting writes, e.g., to a
        debug target process, particularly for assembly, which may involve code unit modification
        after a successful write, reported asynchronously :/ .
        
        :return: true if this listing represents a read-only view
        :rtype: bool
        """

    def removeDisplayListener(self, listener: ghidra.app.util.viewer.listingpanel.AddressSetDisplayListener):
        """
        Remove the :obj:`AddressSetDisplayListener` from the listing panel
        
        :param ghidra.app.util.viewer.listingpanel.AddressSetDisplayListener listener: the listener to remove
        """

    def removeMarginProvider(self, marginProvider: ghidra.app.util.viewer.listingpanel.MarginProvider):
        ...

    def removeOverviewProvider(self, overviewProvider: ghidra.app.util.viewer.listingpanel.OverviewProvider):
        ...

    def selectAll(self):
        ...

    def selectComplement(self):
        ...

    def setClipboardService(self, service: ghidra.app.services.ClipboardService):
        ...

    def setCoordinatedListingPanelListener(self, listener: ghidra.app.services.CoordinatedListingPanelListener):
        ...

    def setNorthComponent(self, comp: javax.swing.JComponent):
        ...

    def setOtherPanel(self, lp: ghidra.app.util.viewer.listingpanel.ListingPanel):
        ...

    def updateHighlightProvider(self):
        ...

    @property
    def listingPanel(self) -> ghidra.app.util.viewer.listingpanel.ListingPanel:
        ...

    @property
    def otherPanel(self) -> ghidra.app.util.viewer.listingpanel.ListingPanel:
        ...

    @otherPanel.setter
    def otherPanel(self, value: ghidra.app.util.viewer.listingpanel.ListingPanel):
        ...

    @property
    def readOnly(self) -> jpype.JBoolean:
        ...

    @property
    def stringSelection(self) -> java.lang.String:
        ...


class OtherPanelContext(ghidra.app.context.ProgramActionContext):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, provider: docking.ComponentProvider, program: ghidra.program.model.listing.Program):
        ...


class LayeredColorModel(ghidra.app.util.viewer.listingpanel.ListingBackgroundColorModel):
    """
    Class for blending two :obj:`ListingBackgroundColorModel`s.  If neither model has a color
    different from its default, then the primary's color is returned.  If only one model
    has a color different from its default, then that color is returned.  If they both have
    colors different, the color returned is a blend of the two colors.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, primary: ghidra.app.util.viewer.listingpanel.ListingBackgroundColorModel, secondary: ghidra.app.util.viewer.listingpanel.ListingBackgroundColorModel):
        ...


class CodeBrowserPluginInterface(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def createNewDisconnectedProvider(self) -> CodeViewerProvider:
        ...

    def getName(self) -> str:
        ...

    def getTool(self) -> ghidra.framework.plugintool.PluginTool:
        ...

    def getViewManager(self, codeViewerProvider: CodeViewerProvider) -> ghidra.app.services.ViewManagerService:
        ...

    def highlightChanged(self, codeViewerProvider: CodeViewerProvider, highlight: ghidra.program.util.ProgramSelection):
        ...

    def isDisposed(self) -> bool:
        ...

    def locationChanged(self, codeViewerProvider: CodeViewerProvider, loc: ghidra.program.util.ProgramLocation):
        ...

    def providerClosed(self, codeViewerProvider: CodeViewerProvider):
        ...

    def selectionChanged(self, codeViewerProvider: CodeViewerProvider, currentSelection: ghidra.program.util.ProgramSelection):
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def disposed(self) -> jpype.JBoolean:
        ...

    @property
    def tool(self) -> ghidra.framework.plugintool.PluginTool:
        ...

    @property
    def viewManager(self) -> ghidra.app.services.ViewManagerService:
        ...


class CodeViewerActionContext(ghidra.app.context.ListingActionContext):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, provider: CodeViewerProvider):
        ...

    @typing.overload
    def __init__(self, provider: CodeViewerProvider, location: ghidra.program.util.ProgramLocation):
        ...


class SelectEndpointsAction(docking.action.DockingAction):
    """
    An action for creating a :obj:`ProgramSelection` from rows of an :obj:`AddressRangeTableModel`
    using either the min addresses or the max addresses
    """

    @typing.type_check_only
    class RangeEndpoint(java.lang.Enum[SelectEndpointsAction.RangeEndpoint]):

        class_: typing.ClassVar[java.lang.Class]
        MIN: typing.Final[SelectEndpointsAction.RangeEndpoint]
        MAX: typing.Final[SelectEndpointsAction.RangeEndpoint]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> SelectEndpointsAction.RangeEndpoint:
            ...

        @staticmethod
        def values() -> jpype.JArray[SelectEndpointsAction.RangeEndpoint]:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ghidra.framework.plugintool.Plugin, program: ghidra.program.model.listing.Program, model: AddressRangeTableModel, endpoint: SelectEndpointsAction.RangeEndpoint):
        """
        Creates an action which selects the endpoint of a range based on ``RangeEndpoint``
        
        :param ghidra.framework.plugintool.Plugin plugin: plugin
        :param ghidra.program.model.listing.Program program: program
        :param AddressRangeTableModel model: model
        :param SelectEndpointsAction.RangeEndpoint endpoint: left or right endpoint
        """


class CodeViewerLocationMemento(ghidra.app.nav.LocationMemento):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, location: ghidra.program.util.ProgramLocation, cursorOffset: typing.Union[jpype.JInt, int]):
        ...

    @typing.overload
    def __init__(self, saveState: ghidra.framework.options.SaveState, programs: jpype.JArray[ghidra.program.model.listing.Program]):
        ...

    def getCursorOffset(self) -> int:
        ...

    @property
    def cursorOffset(self) -> jpype.JInt:
        ...


class AbstractCodeBrowserPlugin(ghidra.framework.plugintool.Plugin, ghidra.app.services.CodeViewerService, ghidra.app.services.CodeFormatService, ghidra.framework.options.OptionsChangeListener, ghidra.app.util.viewer.format.FormatModelListener, ghidra.framework.model.DomainObjectListener, CodeBrowserPluginInterface, typing.Generic[P]):

    @typing.type_check_only
    class MarkerChangeListener(javax.swing.event.ChangeListener):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...

    def getCurrentAddress(self) -> ghidra.program.model.address.Address:
        ...

    def getCurrentFieldLoction(self) -> docking.widgets.fieldpanel.support.FieldLocation:
        ...

    def getCurrentFieldText(self) -> str:
        ...

    def getProvider(self) -> CodeViewerProvider:
        ...

    def goTo(self, location: ghidra.program.util.ProgramLocation) -> bool:
        ...

    @typing.overload
    def goToField(self, address: ghidra.program.model.address.Address, fieldName: typing.Union[java.lang.String, str], row: typing.Union[jpype.JInt, int], col: typing.Union[jpype.JInt, int]) -> bool:
        """
        Positions the cursor to the given location
        
        :param ghidra.program.model.address.Address address: the address to goto
        :param java.lang.String or str fieldName: the name of the field to
        :param jpype.JInt or int row: the row within the given field
        :param jpype.JInt or int col: the col within the given row
        :return: true if the specified location was found, false otherwise
        :rtype: bool
        """

    @typing.overload
    def goToField(self, addr: ghidra.program.model.address.Address, fieldName: typing.Union[java.lang.String, str], occurrence: typing.Union[jpype.JInt, int], row: typing.Union[jpype.JInt, int], col: typing.Union[jpype.JInt, int]) -> bool:
        """
        Positions the cursor to the given location
        
        :param ghidra.program.model.address.Address addr: the address to goto
        :param java.lang.String or str fieldName: the name of the field to
        :param jpype.JInt or int occurrence: specifies the which occurrence for multiple fields of same type
        :param jpype.JInt or int row: the row within the given field
        :param jpype.JInt or int col: the col within the given row
        :return: true if the specified location was found, false otherwise
        :rtype: bool
        """

    @typing.overload
    def goToField(self, a: ghidra.program.model.address.Address, fieldName: typing.Union[java.lang.String, str], occurrence: typing.Union[jpype.JInt, int], row: typing.Union[jpype.JInt, int], col: typing.Union[jpype.JInt, int], scroll: typing.Union[jpype.JBoolean, bool]) -> bool:
        """
        Positions the cursor to the given location
        
        :param ghidra.program.model.address.Address a: the address to goto
        :param java.lang.String or str fieldName: the name of the field to
        :param jpype.JInt or int occurrence: specifies the which occurrence for multiple fields of same type
        :param jpype.JInt or int row: the row within the given field
        :param jpype.JInt or int col: the col within the given row
        :param jpype.JBoolean or bool scroll: specifies if the field panel to scroll the position to the center of the screen
        :return: true if the specified location was found, false otherwise
        :rtype: bool
        """

    def toggleOpen(self, data: ghidra.program.model.listing.Data):
        ...

    def updateNow(self):
        ...

    @property
    def currentFieldLoction(self) -> docking.widgets.fieldpanel.support.FieldLocation:
        ...

    @property
    def currentFieldText(self) -> java.lang.String:
        ...

    @property
    def provider(self) -> CodeViewerProvider:
        ...

    @property
    def currentAddress(self) -> ghidra.program.model.address.Address:
        ...


class AddressRangeCodeUnitTableColumn(docking.widgets.table.AbstractDynamicTableColumn[AddressRangeInfo, ghidra.util.table.field.CodeUnitTableCellData, ghidra.program.model.listing.Program]):
    """
    A column for displaying a small window of :obj:`CodeUnit`s around a selected endpoint
    of an :obj:`AddressRange` in an address range table
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        """
        Default constructor
        """


class MarkerServiceBackgroundColorModel(ghidra.app.util.viewer.listingpanel.ListingBackgroundColorModel):
    """
    :obj:`BackgroundColorModel` for coloring the Listing based on the :obj:`MarkerService`
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, markerService: ghidra.app.services.MarkerService, program: ghidra.program.model.listing.Program, indexMap: ghidra.app.util.viewer.util.AddressIndexMap):
        ...

    @typing.overload
    def __init__(self, markerService: ghidra.app.services.MarkerService, indexMap: ghidra.app.util.viewer.util.AddressIndexMap):
        ...


class CodeBrowserSelectionPlugin(ghidra.framework.plugintool.Plugin):
    """
    Plugin for adding some basic selection actions for Code Browser Listings.
    """

    @typing.type_check_only
    class CodeUnitFromSelectionTableModelLoader(ghidra.util.table.TableModelLoader[ghidra.program.model.address.Address]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...



__all__ = ["AddressRangeInfo", "AddressRangeBytesTableColumn", "MarkAndSelectionAction", "CodeBrowserPlugin", "ListingMiddleMouseHighlightProvider", "AddressRangeTableModel", "CodeViewerProvider", "OtherPanelContext", "LayeredColorModel", "CodeBrowserPluginInterface", "CodeViewerActionContext", "SelectEndpointsAction", "CodeViewerLocationMemento", "AbstractCodeBrowserPlugin", "AddressRangeCodeUnitTableColumn", "MarkerServiceBackgroundColorModel", "CodeBrowserSelectionPlugin"]
