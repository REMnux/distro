from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking.action
import ghidra.app.services
import ghidra.app.util.viewer.listingpanel
import ghidra.app.util.viewer.util
import ghidra.framework.options
import ghidra.framework.plugintool
import ghidra.program.model.address
import ghidra.program.model.listing
import ghidra.program.util
import ghidra.util.datastruct
import java.awt # type: ignore
import java.lang # type: ignore
import javax.swing # type: ignore


class MarkerPanel(javax.swing.JPanel):
    """
    Panel to display markers. Normally placed to the left hand side of the scrolled
    :obj:`FieldPanel`.
    """

    class_: typing.ClassVar[java.lang.Class]


class MarkerManager(ghidra.app.services.MarkerService):
    """
    Manages markers on the marker panel (left side) and the overview panel (right side).
    """

    @typing.type_check_only
    class AddressColorCache(ghidra.util.datastruct.FixedSizeHashMap[ghidra.program.model.address.Address, java.awt.Color]):
        """
        A LRU map that maintains *insertion-order* iteration over the elements. As new items are
        added, the older items will be removed from this map the given plugin.
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class MarkerSetCache(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        def clear(self):
            ...


    @typing.type_check_only
    class MarkerSetCacheEntry(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, cache: MarkerManager.MarkerSetCache, program: ghidra.program.model.listing.Program):
            ...


    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, plugin: ghidra.framework.plugintool.Plugin):
        ...

    @typing.overload
    def __init__(self, owner: typing.Union[java.lang.String, str], tool: ghidra.framework.plugintool.PluginTool):
        ...

    def clearAll(self):
        ...

    def dispose(self):
        ...

    def getGoToService(self) -> ghidra.app.services.GoToService:
        ...

    def getMarginProvider(self) -> MarkerMarginProvider:
        ...

    def getMarkerClickedListener(self) -> ghidra.app.util.viewer.listingpanel.MarkerClickedListener:
        ...

    def getOverviewProvider(self) -> ghidra.app.util.viewer.listingpanel.OverviewProvider:
        ...

    def setGoToService(self, goToService: ghidra.app.services.GoToService):
        ...

    @property
    def marginProvider(self) -> MarkerMarginProvider:
        ...

    @property
    def markerClickedListener(self) -> ghidra.app.util.viewer.listingpanel.MarkerClickedListener:
        ...

    @property
    def overviewProvider(self) -> ghidra.app.util.viewer.listingpanel.OverviewProvider:
        ...

    @property
    def goToService(self) -> ghidra.app.services.GoToService:
        ...

    @goToService.setter
    def goToService(self, value: ghidra.app.services.GoToService):
        ...


class MarkerOverviewProvider(ghidra.app.util.viewer.listingpanel.OverviewProvider):
    """
    The provider which renders the overview margin, usually placed outside the scrollbar to the right
    of lisitng :obj:`FieldPanel`s.
     
     
    
    These are managed by a :obj:`MarkerManager`. Obtain one via
    :meth:`MarkerService.createOverviewProvider() <MarkerService.createOverviewProvider>`.
    """

    @typing.type_check_only
    class MarkerActionList(ghidra.framework.options.OptionsChangeListener):
        """
        Marker Option Menu - controls the visibility of the various markers.
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ActivateMarkerAction(docking.action.ToggleDockingAction):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ActivateMarkerGroupAction(docking.action.ToggleDockingAction):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def repaintPanel(self):
        ...


@typing.type_check_only
class AreaMarkerSet(MarkerSetImpl):
    ...
    class_: typing.ClassVar[java.lang.Class]


class NavigationPanel(javax.swing.JPanel):
    """
    Panel to display an overview of all markers placed within a scrolled :obj:`FieldPanel`. Normally
    placed to the right of the scrolled panel.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getViewHeight(self) -> int:
        ...

    @property
    def viewHeight(self) -> jpype.JInt:
        ...


class MarkerMarginProvider(ghidra.app.util.viewer.listingpanel.MarginProvider):
    """
    The provider which renders the marker margin, usually placed to the left of listing
    :obj:`FieldPanel`s.
     
     
    
    These are managed by a :obj:`MarkerManager`. Obtain one via
    :meth:`MarkerService.createMarginProvider() <MarkerService.createMarginProvider>`.
    """

    class_: typing.ClassVar[java.lang.Class]


class ModifiableAddressSetCollection(ghidra.program.model.address.AddressSet, ghidra.program.model.address.AddressSetCollection):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


@typing.type_check_only
class MarkerSetImpl(ghidra.app.services.MarkerSet):

    class_: typing.ClassVar[java.lang.Class]

    def getDescription(self) -> str:
        ...

    def getNavIcon(self) -> javax.swing.ImageIcon:
        """
        Returns the Navigator Icon for this marker set
        
        :return: the Navigator Icon for this marker set
        :rtype: javax.swing.ImageIcon
        """

    def getProgramLocation(self, y: typing.Union[jpype.JInt, int], height: typing.Union[jpype.JInt, int], map: ghidra.app.util.viewer.util.AddressIndexMap, x: typing.Union[jpype.JInt, int]) -> ghidra.program.util.ProgramLocation:
        ...

    def getTooltip(self, addr: ghidra.program.model.address.Address, x: typing.Union[jpype.JInt, int], y: typing.Union[jpype.JInt, int]) -> str:
        """
        Get the tooltip for the marker at the specified index and address
        
        :param ghidra.program.model.address.Address addr: address of item to navigate to
        :param jpype.JInt or int x: x location of cursor
        :param jpype.JInt or int y: y location of cursor
        :return: tool tip string, null if no tool tip
        :rtype: str
        """

    def paintMarkers(self, g: java.awt.Graphics, index: typing.Union[jpype.JInt, int], pixmap: ghidra.app.util.viewer.listingpanel.VerticalPixelAddressMap, map: ghidra.app.util.viewer.util.AddressIndexMap):
        ...

    def paintNavigation(self, g: java.awt.Graphics, height: typing.Union[jpype.JInt, int], width: typing.Union[jpype.JInt, int], map: ghidra.app.util.viewer.util.AddressIndexMap):
        ...

    @property
    def navIcon(self) -> javax.swing.ImageIcon:
        ...

    @property
    def description(self) -> java.lang.String:
        ...


@typing.type_check_only
class PointMarkerSet(MarkerSetImpl):
    ...
    class_: typing.ClassVar[java.lang.Class]


class MarginProviderSupplier(java.lang.Object):
    """
    Supplies :obj:`MarkerMarginProvider`s.
    """

    class_: typing.ClassVar[java.lang.Class]

    def createMarginProvider(self) -> MarkerMarginProvider:
        """
        Creates a new marker margin provider.
        
        :return: the provider.
        :rtype: MarkerMarginProvider
        """


class MarkerManagerPlugin(ghidra.framework.plugintool.Plugin):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...



__all__ = ["MarkerPanel", "MarkerManager", "MarkerOverviewProvider", "AreaMarkerSet", "NavigationPanel", "MarkerMarginProvider", "ModifiableAddressSetCollection", "MarkerSetImpl", "PointMarkerSet", "MarginProviderSupplier", "MarkerManagerPlugin"]
