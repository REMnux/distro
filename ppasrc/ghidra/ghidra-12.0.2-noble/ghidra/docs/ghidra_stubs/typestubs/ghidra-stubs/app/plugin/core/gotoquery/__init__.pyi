from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.nav
import ghidra.app.plugin
import ghidra.app.plugin.core.navigation
import ghidra.app.util.query
import ghidra.framework.options
import ghidra.framework.plugintool
import ghidra.program.model.address
import ghidra.program.model.listing
import ghidra.program.model.symbol
import ghidra.program.util
import ghidra.util.task
import java.lang # type: ignore
import java.util # type: ignore


class DefaultNavigatableLocationMemento(ghidra.app.nav.LocationMemento):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, location: ghidra.program.util.ProgramLocation, tool: ghidra.framework.plugintool.PluginTool):
        ...

    @typing.overload
    def __init__(self, saveState: ghidra.framework.options.SaveState, programs: jpype.JArray[ghidra.program.model.listing.Program]):
        ...

    def getFocusedNavigatable(self) -> ghidra.app.nav.Navigatable:
        ...

    def setMementos(self):
        ...

    @property
    def focusedNavigatable(self) -> ghidra.app.nav.Navigatable:
        ...


class GoToServicePlugin(ghidra.app.plugin.ProgramPlugin):

    @typing.type_check_only
    class DefaultNavigatable(ghidra.app.nav.Navigatable):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        """
        Creates a new instance of the ``GoToServicePlugin``
        
        :param ghidra.framework.plugintool.PluginTool tool: the tool
        """


class GoToHelper(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...

    def dispose(self):
        ...

    def getLocation(self, program: ghidra.program.model.listing.Program, currentAddress: ghidra.program.model.address.Address, gotoAddress: ghidra.program.model.address.Address) -> ghidra.program.util.ProgramLocation:
        ...

    def getOptions(self) -> ghidra.app.plugin.core.navigation.NavigationOptions:
        ...

    @staticmethod
    def getProgramLocationForAddress(goToAddress: ghidra.program.model.address.Address, program: ghidra.program.model.listing.Program) -> ghidra.program.util.ProgramLocation:
        ...

    def goTo(self, navigatable: ghidra.app.nav.Navigatable, loc: ghidra.program.util.ProgramLocation, program: ghidra.program.model.listing.Program) -> bool:
        ...

    def goToExternalLocation(self, nav: ghidra.app.nav.Navigatable, externalLocation: ghidra.program.model.symbol.ExternalLocation, checkNavigationOption: typing.Union[jpype.JBoolean, bool]) -> bool:
        """
        Navigate to either the external program location or address linkage location.
         
        
        This method will only navigate to the external program associated with the specified location
        if either checkNavigationOption is false, or the navigation option is set to Show External
        Program, or the current location is the same as the single linkage location. See
        :meth:`goToExternalLinkage(Navigatable, ExternalLocation, boolean) <.goToExternalLinkage>` method for external
        linkage navigation behavior.
         
        
        If navigation to an external program will be performed, the associated program will be
        identified and the location within that program found. Once this occurs, the external program
        will be opened within the current tool and navigation completed. If an external program
        association has not yet been established, the user will be prompted to make an association if
        they choose before completing the navigation.
        
        :param ghidra.app.nav.Navigatable nav: Navigatable
        :param ghidra.program.model.symbol.ExternalLocation externalLocation: external location
        :param jpype.JBoolean or bool checkNavigationOption: if true the
                    :obj:`NavigationOptions.isGotoExternalProgramEnabled` option will be used to
                    determine if navigation to the external program will be attempted, or if
                    navigation to the external linkage location within the current program will be
                    attempted. If false, only navigation to the external linkage will be attempted.
        :return: true if navigation to the external program was successful or navigation to a linkage
                location was performed.
        :rtype: bool
        """

    @property
    def options(self) -> ghidra.app.plugin.core.navigation.NavigationOptions:
        ...


class GoToQueryResultsTableModel(ghidra.app.util.query.ProgramLocationPreviewTableModel):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, prog: ghidra.program.model.listing.Program, serviceProvider: ghidra.framework.plugintool.ServiceProvider, locations: java.util.List[ghidra.program.util.ProgramLocation], monitor: ghidra.util.task.TaskMonitor):
        ...



__all__ = ["DefaultNavigatableLocationMemento", "GoToServicePlugin", "GoToHelper", "GoToQueryResultsTableModel"]
