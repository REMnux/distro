from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.plugin.core.debug.gui.tracermi.launcher
import ghidra.debug.api.tracermi
import ghidra.framework.options
import ghidra.program.model.listing
import ghidra.util.classfinder
import java.lang # type: ignore
import java.util # type: ignore


class TraceRmiLaunchOpinion(ghidra.util.classfinder.ExtensionPoint):
    """
    A factory of launch offers
     
     
    
    Each opinion is instantiated only once for the entire application, even when multiple tools are
    open.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getOffers(self, plugin: ghidra.app.plugin.core.debug.gui.tracermi.launcher.TraceRmiLauncherServicePlugin, program: ghidra.program.model.listing.Program) -> java.util.Collection[ghidra.debug.api.tracermi.TraceRmiLaunchOffer]:
        """
        Generate or retrieve a collection of offers based on the current program.
         
         
        
        Take care trying to "validate" a particular mechanism. For example, it is *not*
        appropriate to check that GDB exists, nor to execute it to derive its version.
         
         
        1. It's possible the user has dependencies installed in non-standard locations. I.e., the
        user needs a chance to configure thingsbefore the UI decides whether or not to
        display them.
        2. The menus are meant to display all possibilities installed in Ghidra, even if
        some dependencies are missing on the local system. Discovery of the feature is most
        important. Knowing a feature exists may motivate a user to obtain the required dependencies
        and try it out.
        3. An offer is only promoted to the quick-launch menu upon successful connection.
        I.e., the entries there are already validated; they've worked at least once before.
        
        
        :param ghidra.app.plugin.core.debug.gui.tracermi.launcher.TraceRmiLauncherServicePlugin plugin: the Trace RMI launcher service plugin. **NOTE:** to get access to the Trace
                    RMI (connection) service, use the :obj:`InternalTraceRmiService`, so that the
                    offers can register the connection's resources. See
                    :meth:`TraceRmiHandler.registerTerminals(Collection) <TraceRmiHandler.registerTerminals>`. Terminal registration is
                    required for the Disconnect button to completely terminate the back end.
        :param ghidra.program.model.listing.Program program: the current program. While this is not *always* used by the launcher,
                    it is implied that the user expects the debugger to do something with the current
                    program, even if it's just informing the back-end debugger of the target image.
        :return: the offers. The order is ignored, since items are displayed alphabetically.
        :rtype: java.util.Collection[ghidra.debug.api.tracermi.TraceRmiLaunchOffer]
        """

    def registerOptions(self, options: ghidra.framework.options.Options):
        """
        Register any options
        
        :param ghidra.framework.options.Options options: the tool options
        """

    def requiresRefresh(self, optionName: typing.Union[java.lang.String, str]) -> bool:
        """
        Check if a change in the given option requires a refresh of offers
        
        :param java.lang.String or str optionName: the name of the option that changed
        :return: true to refresh, false otherwise
        :rtype: bool
        """



__all__ = ["TraceRmiLaunchOpinion"]
