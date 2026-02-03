from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking
import docking.action
import ghidra.app.plugin
import ghidra.app.util.viewer.listingpanel
import ghidra.framework.plugintool
import ghidra.program.model.address
import ghidra.program.model.listing
import ghidra.util
import ghidra.util.classfinder
import java.awt # type: ignore
import java.lang # type: ignore
import java.util # type: ignore
import javax.swing # type: ignore


class OverviewColorComponent(javax.swing.JPanel, ghidra.app.util.viewer.listingpanel.OverviewProvider):
    """
    Overview bar component. Uses color to indicate various address based properties for a program.
    Uses an :obj:`OverviewColorService` to get the appropriate color for an address.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool, overviewColorService: OverviewColorService):
        """
        Constructor
        
        :param ghidra.framework.plugintool.PluginTool tool: the PluginTool
        :param OverviewColorService overviewColorService: the :obj:`OverviewColorService` that provides colors for various
                    addresses.
        """

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

    def refresh(self, start: ghidra.program.model.address.Address, end: ghidra.program.model.address.Address):
        """
        Causes the component to refresh any colors for the given address range.
        
        :param ghidra.program.model.address.Address start: the start of the address range to refresh.
        :param ghidra.program.model.address.Address end: the end of the address range to refresh.
        """

    def refreshAll(self):
        """
        Causes this component to completely compute the colors used to paint the overview bar.
        """

    def uninstallActions(self):
        """
        Removes previous installed actions for this component.
        """

    @property
    def tool(self) -> ghidra.framework.plugintool.PluginTool:
        ...


class OverviewColorService(ghidra.util.classfinder.ExtensionPoint):
    """
    Interface for services that know how to associate colors with any address in a program.
    Instances of these services are discovered and presented as options on the Listing's right
    margin area.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getActions(self) -> java.util.List[docking.action.DockingActionIf]:
        """
        Returns a list of popup actions to be shown when the user right-clicks on the :obj:`OverviewColorComponent`
        associated with this service.
        
        :return: the list of popup actions.
        :rtype: java.util.List[docking.action.DockingActionIf]
        """

    def getColor(self, address: ghidra.program.model.address.Address) -> java.awt.Color:
        """
        Returns the color that this service associates with the given address.
        
        :param ghidra.program.model.address.Address address: the address for with to get a color.
        :return: the color that this service associates with the given address.
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

    def getProgram(self) -> ghidra.program.model.listing.Program:
        """
        Returns the current program used by the service.
        
        :return: the current program used by the service.
        :rtype: ghidra.program.model.listing.Program
        """

    def getToolTipText(self, address: ghidra.program.model.address.Address) -> str:
        """
        Returns the tool tip that the :obj:`OverviewColorComponent` should display when the mouse
        is hovering on the pixel that maps to the given address.
        
        :param ghidra.program.model.address.Address address: the address for which to get a tooltip.
        :return: the tooltip text for the given address.
        :rtype: str
        """

    def initialize(self, tool: ghidra.framework.plugintool.PluginTool):
        """
        Initialize the service which typically is used to read options for the service.
        
        :param ghidra.framework.plugintool.PluginTool tool: the :obj:`PluginTool` using this service.
        """

    def setOverviewComponent(self, component: OverviewColorComponent):
        """
        Sets the :obj:`OverviewColorComponent` that will be displaying the colors for this service.
        
        :param OverviewColorComponent component: the :obj:`OverviewColorComponent` that will be displaying the colors for this service.
        """

    def setProgram(self, program: ghidra.program.model.listing.Program):
        """
        Sets the program that this service will provide address colors for.
        
        :param ghidra.program.model.listing.Program program: the program that this service will provide address colors for.
        """

    @property
    def color(self) -> java.awt.Color:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def helpLocation(self) -> ghidra.util.HelpLocation:
        ...

    @property
    def program(self) -> ghidra.program.model.listing.Program:
        ...

    @program.setter
    def program(self, value: ghidra.program.model.listing.Program):
        ...

    @property
    def actions(self) -> java.util.List[docking.action.DockingActionIf]:
        ...

    @property
    def toolTipText(self) -> java.lang.String:
        ...


class AbstractColorOverviewAction(docking.action.DockingAction):
    """
    Base class for popup overview bar actions
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, name: typing.Union[java.lang.String, str], owner: typing.Union[java.lang.String, str], component: java.awt.Component, help: ghidra.util.HelpLocation):
        """
        Constructor
        
        :param java.lang.String or str name: the name of the action
        :param java.lang.String or str owner: the name of the owner of the action.
        :param java.awt.Component component: the color bar component.
        :param ghidra.util.HelpLocation help: the help location for this action.
        """


class OverviewColorLegendDialog(docking.DialogComponentProvider):
    """
    Convenience dialog for showing a Legend for an :obj:`OverviewColorComponent`
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, title: typing.Union[java.lang.String, str], component: javax.swing.JComponent, help: ghidra.util.HelpLocation):
        """
        Constructs a new :obj:`DialogComponentProvider` to show the given component with a "Dismiss"
        button.
        
        :param java.lang.String or str title: the title of the dialog
        :param javax.swing.JComponent component: the component to show as the main area of the dialog.
        :param ghidra.util.HelpLocation help: the help location for the dialog.
        """

    def refresh(self):
        ...


class OverviewColorPlugin(ghidra.app.plugin.ProgramPlugin):
    """
    Plugin to manage :obj:`OverviewColorService`s.  It creates actions for each service and installs
    and removes :obj:`OverviewColorComponent` as indicated by the action.
    """

    @typing.type_check_only
    class OverviewToggleAction(docking.action.ToggleDockingAction):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, owner: typing.Union[java.lang.String, str], service: OverviewColorService):
            ...


    class_: typing.ClassVar[java.lang.Class]
    HELP_TOPIC: typing.Final = "OverviewPlugin"

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...

    def installOverview(self, overviewColorService: OverviewColorService):
        """
        Installs the given :obj:`OverviewColorService` into the Listing margin bars.
        This is public only for testing and screenshot purposes.
        
        :param OverviewColorService overviewColorService: the service to display colors in the Listing's margin bars.
        """



__all__ = ["OverviewColorComponent", "OverviewColorService", "AbstractColorOverviewAction", "OverviewColorLegendDialog", "OverviewColorPlugin"]
