from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking.action.builder
import ghidra.app.context
import ghidra.app.plugin.core.clipboard
import ghidra.app.plugin.core.codebrowser
import ghidra.app.plugin.core.debug.gui
import ghidra.app.plugin.core.debug.gui.action
import ghidra.app.plugin.core.debug.gui.colors
import ghidra.app.services
import ghidra.app.util.viewer.format
import ghidra.app.util.viewer.listingpanel
import ghidra.debug.api.action
import ghidra.debug.api.modules
import ghidra.debug.api.tracemgr
import ghidra.framework.plugintool
import ghidra.program.model.listing
import ghidra.program.util
import ghidra.trace.model
import java.lang # type: ignore
import javax.swing.event # type: ignore


class DebuggerListingProvider(ghidra.app.plugin.core.codebrowser.CodeViewerProvider):

    @typing.type_check_only
    class AutoDisassembleAction(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "Auto-Disassembly"
        DESCRIPTION: typing.Final = "If the tracking spec follows the PC, disassemble automatically."
        HELP_ANCHOR: typing.Final = "auto_disassembly"

        @staticmethod
        def builder(owner: ghidra.framework.plugintool.Plugin) -> docking.action.builder.ToggleActionBuilder:
            ...


    @typing.type_check_only
    class MarkerSetChangeListener(javax.swing.event.ChangeListener):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ForStaticSyncMappingChangeListener(ghidra.debug.api.modules.DebuggerStaticMappingChangeListener):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ForListingGoToTrait(ghidra.app.plugin.core.debug.gui.action.DebuggerGoToTrait):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    @typing.type_check_only
    class ForListingTrackingTrait(ghidra.app.plugin.core.debug.gui.action.DebuggerTrackLocationTrait):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    @typing.type_check_only
    class ForListingReadsMemoryTrait(ghidra.app.plugin.core.debug.gui.action.DebuggerReadsMemoryTrait):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    @typing.type_check_only
    class ForListingClipboardProvider(ghidra.app.plugin.core.clipboard.CodeBrowserClipboardProvider):

        @typing.type_check_only
        class PasteIntoTargetCommand(ghidra.app.util.ByteCopier.PasteByteStringCommand, ghidra.app.plugin.core.debug.gui.PasteIntoTargetMixin):
            ...
            class_: typing.ClassVar[java.lang.Class]


        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: DebuggerListingPlugin, formatManager: ghidra.app.util.viewer.format.FormatManager, isConnected: typing.Union[jpype.JBoolean, bool]):
        ...

    def addTrackingSpecChangeListener(self, listener: ghidra.app.services.DebuggerListingService.LocationTrackingSpecChangeListener):
        ...

    def coordinatesActivated(self, coordinates: ghidra.debug.api.tracemgr.DebuggerCoordinates):
        ...

    def getAutoReadMemorySpec(self) -> ghidra.debug.api.action.AutoReadMemorySpec:
        ...

    def getTrackingSpec(self) -> ghidra.debug.api.action.LocationTrackingSpec:
        ...

    def goToCoordinates(self, coordinates: ghidra.debug.api.tracemgr.DebuggerCoordinates):
        ...

    def isAutoDisassemble(self) -> bool:
        ...

    def isFollowsCurrentThread(self) -> bool:
        ...

    def isMainListing(self) -> bool:
        """
        Check if this is the main dynamic listing.
         
         
        
        The method :meth:`isConnected() <.isConnected>` is not quite the same as this, although the concepts are a
        little conflated, since before the debugger, no one else presented a listing that could claim
        to be "main" except the "connected" one. Here, we treat "connected" to mean that the address
        is synchronized exactly with the other providers. "Main" on the other hand, does not
        necessarily have that property, but it is still *not* a clone. It is the main listing
        presented by this plugin, and so it has certain unique features. Calling
        :meth:`DebuggerListingPlugin.getProvider() <DebuggerListingPlugin.getProvider>` will return the main dynamic listing.
        
        :return: true if this is the main listing for the plugin.
        :rtype: bool
        """

    def programClosed(self, program: ghidra.program.model.listing.Program):
        ...

    def removeTrackingSpecChangeListener(self, listener: ghidra.app.services.DebuggerListingService.LocationTrackingSpecChangeListener):
        ...

    def setAutoDisassemble(self, auto: typing.Union[jpype.JBoolean, bool]):
        ...

    def setAutoReadMemorySpec(self, spec: ghidra.debug.api.action.AutoReadMemorySpec):
        ...

    def setFollowsCurrentThread(self, follows: typing.Union[jpype.JBoolean, bool]):
        ...

    def setTrackingSpec(self, spec: ghidra.debug.api.action.LocationTrackingSpec):
        ...

    def traceClosed(self, trace: ghidra.trace.model.Trace):
        ...

    @property
    def followsCurrentThread(self) -> jpype.JBoolean:
        ...

    @followsCurrentThread.setter
    def followsCurrentThread(self, value: jpype.JBoolean):
        ...

    @property
    def autoDisassemble(self) -> jpype.JBoolean:
        ...

    @autoDisassemble.setter
    def autoDisassemble(self, value: jpype.JBoolean):
        ...

    @property
    def mainListing(self) -> jpype.JBoolean:
        ...

    @property
    def trackingSpec(self) -> ghidra.debug.api.action.LocationTrackingSpec:
        ...

    @trackingSpec.setter
    def trackingSpec(self, value: ghidra.debug.api.action.LocationTrackingSpec):
        ...

    @property
    def autoReadMemorySpec(self) -> ghidra.debug.api.action.AutoReadMemorySpec:
        ...

    @autoReadMemorySpec.setter
    def autoReadMemorySpec(self, value: ghidra.debug.api.action.AutoReadMemorySpec):
        ...


class DebuggerTrackedRegisterListingBackgroundColorModel(ghidra.app.plugin.core.debug.gui.colors.DebuggerTrackedRegisterBackgroundColorModel, ghidra.app.util.viewer.listingpanel.ListingBackgroundColorModel):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, listingPanel: ghidra.app.util.viewer.listingpanel.ListingPanel):
        ...


class DebuggerListingActionContext(ghidra.app.context.ListingActionContext, ghidra.app.plugin.core.debug.gui.action.DebuggerProgramLocationActionContext):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, provider: DebuggerListingProvider):
        ...

    @typing.overload
    def __init__(self, provider: DebuggerListingProvider, location: ghidra.program.util.ProgramLocation):
        ...

    @typing.overload
    def __init__(self, provider: DebuggerListingProvider, location: ghidra.program.util.ProgramLocation, selection: ghidra.program.util.ProgramSelection, highlight: ghidra.program.util.ProgramSelection):
        ...


class MemoryStateListingBackgroundColorModel(ghidra.app.util.viewer.listingpanel.ListingBackgroundColorModel):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, listingPanel: ghidra.app.util.viewer.listingpanel.ListingPanel):
        ...


class DebuggerListingPlugin(ghidra.app.plugin.core.codebrowser.AbstractCodeBrowserPlugin[DebuggerListingProvider], ghidra.app.services.DebuggerListingService):

    @typing.type_check_only
    class NewListingAction(ghidra.app.plugin.core.debug.gui.DebuggerResources.AbstractNewListingAction):

        class_: typing.ClassVar[java.lang.Class]
        GROUP: typing.Final = "Dbg3a. Transient Views"

        def __init__(self):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...

    def createListingIfMissing(self, spec: ghidra.debug.api.action.LocationTrackingSpec, followsCurrentThread: typing.Union[jpype.JBoolean, bool]) -> DebuggerListingProvider:
        ...

    def setTraceManager(self, traceManager: ghidra.app.services.DebuggerTraceManagerService):
        ...


@typing.type_check_only
class CursorBackgroundColorModel(ghidra.app.util.viewer.listingpanel.ListingBackgroundColorModel):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ghidra.framework.plugintool.Plugin, listingPanel: ghidra.app.util.viewer.listingpanel.ListingPanel):
        ...



__all__ = ["DebuggerListingProvider", "DebuggerTrackedRegisterListingBackgroundColorModel", "DebuggerListingActionContext", "MemoryStateListingBackgroundColorModel", "DebuggerListingPlugin", "CursorBackgroundColorModel"]
