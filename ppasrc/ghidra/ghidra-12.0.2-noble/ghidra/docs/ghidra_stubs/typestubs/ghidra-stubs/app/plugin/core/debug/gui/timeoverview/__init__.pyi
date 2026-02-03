from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking.action
import ghidra.app.plugin.core.debug
import ghidra.app.plugin.core.debug.gui.timeoverview.timetype
import ghidra.app.util.viewer.listingpanel
import ghidra.debug.api.tracemgr
import ghidra.framework.plugintool
import ghidra.trace.model
import ghidra.util
import ghidra.util.classfinder
import java.awt # type: ignore
import java.lang # type: ignore
import java.util # type: ignore
import javax.swing # type: ignore
import org.apache.commons.lang3.tuple # type: ignore


class TimeOverviewColorService(ghidra.util.classfinder.ExtensionPoint):
    """
    Interface for services that know how to associate colors with any snap in a program. Instances
    of these services are discovered and presented as options on the Listing's right margin area.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getActions(self) -> java.util.List[docking.action.DockingActionIf]:
        """
        Returns a list of popup actions to be shown when the user right-clicks on the
        :obj:`TimeOverviewColorComponent` associated with this service.
        
        :return: the list of popup actions.
        :rtype: java.util.List[docking.action.DockingActionIf]
        """

    def getBounds(self) -> ghidra.trace.model.Lifespan:
        """
        Get the display bounds
        
        :return: bounds time-range to display
        :rtype: ghidra.trace.model.Lifespan
        """

    def getColor(self, snap: typing.Union[java.lang.Long, int]) -> java.awt.Color:
        """
        Returns the color that this service associates with the given snap.
        
        :param java.lang.Long or int snap: the snap to convert to a color.
        :return: the color that this service associates with the given snap.
        :rtype: java.awt.Color
        """

    def getHelpLocation(self) -> ghidra.util.HelpLocation:
        """
        Returns the :obj:`HelpLocation` for this service
        
        :return: the :obj:`HelpLocation` for this service
        :rtype: ghidra.util.HelpLocation
        """

    def getName(self) -> str:
        """
        Returns the name of this color service.
        
        :return: the name of this color service.
        :rtype: str
        """

    def getSnap(self, pixel: typing.Union[jpype.JInt, int]) -> int:
        """
        Get the snap for a given pixel's time coordinate
        
        :param jpype.JInt or int pixel: location in the display
        :return: snap
        :rtype: int
        """

    def getToolTipText(self, snap: typing.Union[java.lang.Long, int]) -> str:
        """
        Returns the tool tip that the :obj:`TimeOverviewColorComponent` should display when the
        mouse is hovering on the pixel that maps to the given snap.
        
        :param java.lang.Long or int snap: the snap for which to get a tooltip.
        :return: the tooltip text for the given snap.
        :rtype: str
        """

    def getTrace(self) -> ghidra.trace.model.Trace:
        """
        Returns the current trace used by the service.
        
        :return: the current trace used by the service.
        :rtype: ghidra.trace.model.Trace
        """

    def initialize(self, tool: ghidra.framework.plugintool.PluginTool):
        """
        Initialize the service which typically is used to read options for the service.
        
        :param ghidra.framework.plugintool.PluginTool tool: the :obj:`PluginTool` using this service.
        """

    def setBounds(self, bounds: ghidra.trace.model.Lifespan):
        """
        Set the display bounds
        
        :param ghidra.trace.model.Lifespan bounds: time-range to display
        """

    def setIndices(self, set: java.util.TreeSet[java.lang.Long]):
        """
        Set the indices for mapping pixels->indices->snaps (and vice-versa)
        
        :param java.util.TreeSet[java.lang.Long] set: tree-set of snaps
        """

    def setOverviewComponent(self, component: TimeOverviewColorComponent):
        """
        Sets the component that will be displaying the colors for this
        service.
        
        :param TimeOverviewColorComponent component: the :obj:`TimeOverviewColorComponent` that will be displaying the colors
                    for this service.
        """

    def setPlugin(self, plugin: TimeOverviewColorPlugin):
        """
        Set the plugin
        
        :param TimeOverviewColorPlugin plugin: overview plugin
        """

    def setTrace(self, trace: ghidra.trace.model.Trace):
        """
        Sets the trace that this service will provide snap colors for.
        
        :param ghidra.trace.model.Trace trace: the program that this service will provide snap colors for.
        """

    @property
    def trace(self) -> ghidra.trace.model.Trace:
        ...

    @trace.setter
    def trace(self, value: ghidra.trace.model.Trace):
        ...

    @property
    def color(self) -> java.awt.Color:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def bounds(self) -> ghidra.trace.model.Lifespan:
        ...

    @bounds.setter
    def bounds(self, value: ghidra.trace.model.Lifespan):
        ...

    @property
    def helpLocation(self) -> ghidra.util.HelpLocation:
        ...

    @property
    def actions(self) -> java.util.List[docking.action.DockingActionIf]:
        ...

    @property
    def toolTipText(self) -> java.lang.String:
        ...

    @property
    def snap(self) -> jpype.JLong:
        ...


class TimeOverviewEventListener(ghidra.trace.model.TraceDomainObjectListener):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: TimeOverviewColorPlugin):
        ...

    def coordinatesActivated(self, coordinates: ghidra.debug.api.tracemgr.DebuggerCoordinates):
        ...

    def setCoordinates(self, coordinates: ghidra.debug.api.tracemgr.DebuggerCoordinates):
        ...


class TimeOverviewColorPlugin(ghidra.app.plugin.core.debug.AbstractDebuggerPlugin):
    """
    Plugin to manage :obj:`TimeOverviewColorService`s. It creates actions for each service and
    installs and removes :obj:`TimeOverviewColorComponent` as indicated by the action.
    """

    @typing.type_check_only
    class OverviewToggleAction(docking.action.ToggleDockingAction):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, owner: typing.Union[java.lang.String, str], service: TimeOverviewColorService):
            ...


    class_: typing.ClassVar[java.lang.Class]
    HELP_TOPIC: typing.Final = "OverviewPlugin"

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...

    def getTypes(self, offset: typing.Union[java.lang.Long, int]) -> java.util.Set[org.apache.commons.lang3.tuple.Pair[ghidra.app.plugin.core.debug.gui.timeoverview.timetype.TimeType, java.lang.String]]:
        """
        Determines the :obj:`TimeType` for the given offset
        
        :param java.lang.Long or int offset: the offset for which to get an LifespanType.
        :return: the :obj:`TimeType` for the given offset.
        :rtype: java.util.Set[org.apache.commons.lang3.tuple.Pair[ghidra.app.plugin.core.debug.gui.timeoverview.timetype.TimeType, java.lang.String]]
        """

    def gotoSnap(self, offset: typing.Union[java.lang.Long, int]):
        ...

    def installOverview(self, overviewColorService: TimeOverviewColorService):
        """
        Installs the given :obj:`TimeOverviewColorService` into the Listing margin bars. This is
        public only for testing and screenshot purposes.
        
        :param TimeOverviewColorService overviewColorService: the service to display colors in the Listing's margin bars.
        """

    def setLifespan(self, span: ghidra.trace.model.Lifespan):
        ...

    @property
    def types(self) -> java.util.Set[org.apache.commons.lang3.tuple.Pair[ghidra.app.plugin.core.debug.gui.timeoverview.timetype.TimeType, java.lang.String]]:
        ...


class TimeOverviewColorComponent(javax.swing.JPanel, ghidra.app.util.viewer.listingpanel.OverviewProvider):
    """
    Overview bar component. Uses color to indicate various snap-based properties for a program.
    Uses an :obj:`TimeOverviewColorService` to get the appropriate color for a snaps.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool, overviewColorService: TimeOverviewColorService):
        """
        Constructor
        
        :param ghidra.framework.plugintool.PluginTool tool: the PluginTool
        :param TimeOverviewColorService overviewColorService: the :obj:`TimeOverviewColorService` that provides colors for
                    various snaps.
        """

    def getLifespan(self) -> ghidra.trace.model.Lifespan:
        ...

    def getOverviewPixelCount(self) -> int:
        ...

    def getTool(self) -> ghidra.framework.plugintool.PluginTool:
        """
        Returns the PluginTool
        
        :return: the PluginTool
        :rtype: ghidra.framework.plugintool.PluginTool
        """

    def installActions(self):
        """
        Installs actions for this component
        """

    def refreshAll(self):
        """
        Causes this component to completely compute the colors used to paint the overview bar.
        """

    def setLifeSet(self, set: java.util.TreeSet[java.lang.Long]):
        ...

    def setLifespan(self, bounds: ghidra.trace.model.Lifespan):
        ...

    def setPlugin(self, plugin: TimeOverviewColorPlugin):
        ...

    def uninstallActions(self):
        """
        Removes previous installed actions for this component.
        """

    @property
    def overviewPixelCount(self) -> jpype.JInt:
        ...

    @property
    def lifespan(self) -> ghidra.trace.model.Lifespan:
        ...

    @lifespan.setter
    def lifespan(self, value: ghidra.trace.model.Lifespan):
        ...

    @property
    def tool(self) -> ghidra.framework.plugintool.PluginTool:
        ...



__all__ = ["TimeOverviewColorService", "TimeOverviewEventListener", "TimeOverviewColorPlugin", "TimeOverviewColorComponent"]
