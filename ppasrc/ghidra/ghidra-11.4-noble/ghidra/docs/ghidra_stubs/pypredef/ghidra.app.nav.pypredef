from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.context
import ghidra.app.plugin.core.navigation
import ghidra.app.util
import ghidra.features.base.memsearch.bytesource
import ghidra.framework.options
import ghidra.framework.plugintool
import ghidra.program.model.address
import ghidra.program.model.listing
import ghidra.program.util
import java.lang # type: ignore
import java.util # type: ignore
import javax.swing # type: ignore


class NextRangeAction(ghidra.app.context.NavigatableContextAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool, name: typing.Union[java.lang.String, str], owner: typing.Union[java.lang.String, str], navOptions: ghidra.app.plugin.core.navigation.NavigationOptions):
        ...


class NavigatableRegistry(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def getNavigatable(navigationID: typing.Union[jpype.JLong, int]) -> Navigatable:
        ...

    @staticmethod
    def getRegisteredNavigatables(tool: ghidra.framework.plugintool.PluginTool) -> java.util.List[Navigatable]:
        ...

    @staticmethod
    def registerNavigatable(tool: ghidra.framework.plugintool.PluginTool, navigatable: Navigatable):
        ...

    @staticmethod
    def unregisterNavigatable(tool: ghidra.framework.plugintool.PluginTool, navigatable: Navigatable):
        ...


class DecoratorPanel(javax.swing.JPanel):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, component: javax.swing.JComponent, isConnected: typing.Union[jpype.JBoolean, bool]):
        ...

    def setConnected(self, isConnected: typing.Union[jpype.JBoolean, bool]):
        ...


class ListingPanelContainer(javax.swing.JPanel):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, leftListingPanel: javax.swing.JComponent, isConnected: typing.Union[jpype.JBoolean, bool]):
        ...

    @typing.overload
    def __init__(self, leftListingPanel: javax.swing.JComponent, rightListingPanel: javax.swing.JComponent, leftTitle: typing.Union[java.lang.String, str], rightTitle: typing.Union[java.lang.String, str]):
        ...

    def clearOtherPanel(self):
        ...

    def getNorthPanel(self) -> javax.swing.JComponent:
        ...

    def setConnnected(self, isConnected: typing.Union[jpype.JBoolean, bool]):
        ...

    def setNorthPanel(self, comp: javax.swing.JComponent):
        ...

    def setOrientation(self, isSideBySide: typing.Union[jpype.JBoolean, bool]):
        ...

    def setOtherPanel(self, rightListingPanel: javax.swing.JComponent, leftTitle: typing.Union[java.lang.String, str], rightTitle: typing.Union[java.lang.String, str]):
        ...

    def updateTitle(self, newTitle: typing.Union[java.lang.String, str]):
        ...

    @property
    def northPanel(self) -> javax.swing.JComponent:
        ...

    @northPanel.setter
    def northPanel(self, value: javax.swing.JComponent):
        ...


class LocationMemento(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, location: ghidra.program.util.ProgramLocation):
        ...

    @typing.overload
    def __init__(self, saveState: ghidra.framework.options.SaveState, programs: jpype.JArray[ghidra.program.model.listing.Program]):
        ...

    def getLocationDescription(self) -> str:
        ...

    @staticmethod
    def getLocationMemento(saveState: ghidra.framework.options.SaveState, programs: jpype.JArray[ghidra.program.model.listing.Program]) -> LocationMemento:
        ...

    def getProgram(self) -> ghidra.program.model.listing.Program:
        ...

    def getProgramLocation(self) -> ghidra.program.util.ProgramLocation:
        ...

    def isValid(self) -> bool:
        ...

    def saveState(self, saveState: ghidra.framework.options.SaveState):
        ...

    @property
    def valid(self) -> jpype.JBoolean:
        ...

    @property
    def locationDescription(self) -> java.lang.String:
        ...

    @property
    def program(self) -> ghidra.program.model.listing.Program:
        ...

    @property
    def programLocation(self) -> ghidra.program.util.ProgramLocation:
        ...


class NavigatableIconFactory(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def createSnapshotOverlayIcon(primaryIcon: javax.swing.Icon) -> javax.swing.ImageIcon:
        ...


class NavigatableRemovalListener(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def navigatableRemoved(self, navigatable: Navigatable):
        ...


class Navigatable(java.lang.Object):
    """
    Interface for ComponentProviders to implement if they support basic navigation and selection
    capabilities. Implementing this interface will provide the provider with navigation history and
    actions that require navigation or selection. (Search Text, Search Memory, Select bytes, Select
    instructions, etc.)
    """

    class_: typing.ClassVar[java.lang.Class]
    DEFAULT_NAVIGATABLE_ID: typing.Final = -1

    def addNavigatableListener(self, listener: NavigatableRemovalListener):
        """
        Adds a listener to be notified if this Navigatable is terminated
        
        :param NavigatableRemovalListener listener: the listener to be notified when this Navigatable is closed
        """

    def getByteSource(self) -> ghidra.features.base.memsearch.bytesource.AddressableByteSource:
        """
        Returns a source for providing byte values of the program associated with this navigatable.
         
        
        For a static program, this is just a wrapper for a program's memory. But dynamic programs
        require special handling for reading bytes.
        
        :return: a source of bytes for the navigatable's program
        :rtype: ghidra.features.base.memsearch.bytesource.AddressableByteSource
        """

    def getHighlight(self) -> ghidra.program.util.ProgramSelection:
        """
        Returns the current highlight of this Navigatable
        
        :return: the current highlight of this Navigatable
        :rtype: ghidra.program.util.ProgramSelection
        """

    def getInstanceID(self) -> int:
        ...

    def getLocation(self) -> ghidra.program.util.ProgramLocation:
        """
        Returns the current location of this Navigatable
        
        :return: the current location of this Navigatable
        :rtype: ghidra.program.util.ProgramLocation
        """

    def getMemento(self) -> LocationMemento:
        """
        Returns the view state for this navigatable
        
        :return: the view state for this navigatable
        :rtype: LocationMemento
        """

    def getNavigatableIcon(self) -> javax.swing.Icon:
        """
        Returns an icon that represents this Navigatable
        
        :return: the icon
        :rtype: javax.swing.Icon
        """

    def getProgram(self) -> ghidra.program.model.listing.Program:
        """
        Returns the current Program of this Navigatable
        
        :return: the current Program of this Navigatable
        :rtype: ghidra.program.model.listing.Program
        """

    def getSelection(self) -> ghidra.program.util.ProgramSelection:
        """
        Returns the current selection of this Navigatable
        
        :return: the current selection of this Navigatable
        :rtype: ghidra.program.util.ProgramSelection
        """

    def getTextSelection(self) -> str:
        """
        Returns the current text selection or null
        
        :return: the text selection
        :rtype: str
        """

    def goTo(self, program: ghidra.program.model.listing.Program, location: ghidra.program.util.ProgramLocation) -> bool:
        """
        Commands this navigatable to goto (display) the given program and location
        
        :param ghidra.program.model.listing.Program program: the program
        :param ghidra.program.util.ProgramLocation location: the location in that program to display
        :return: true if the goto was successful
        :rtype: bool
        """

    def isConnected(self) -> bool:
        """
        Returns true if this Navigatable is "connected".
         
        
        Navigatables are connected if they produce and consume location and selection events.
        
        :return: true if this Navigatable is "connected"
        :rtype: bool
        """

    def isDisposed(self) -> bool:
        """
        Returns true if this navigatable is no longer valid
        
        :return: true if this navigatable is no longer valid
        :rtype: bool
        """

    def isDynamic(self) -> bool:
        """
        Return true if this Navigatable is part of the "dynamic analysis" or "debugger" user
        interface.
        
        :return: true if this Navigatable is "dynamic"
        :rtype: bool
        """

    def isVisible(self) -> bool:
        """
        Returns true if this provider is visible
        
        :return: true if visible
        :rtype: bool
        """

    def removeHighlightProvider(self, highlightProvider: ghidra.app.util.ListingHighlightProvider, program: ghidra.program.model.listing.Program):
        """
        Removes the given highlight provider for the given program
        
        :param ghidra.app.util.ListingHighlightProvider highlightProvider: the provider
        :param ghidra.program.model.listing.Program program: the program
        """

    def removeNavigatableListener(self, listener: NavigatableRemovalListener):
        """
        Removes a listener to be notified if this Navigatable is terminated.
        
        :param NavigatableRemovalListener listener: the listener that no longer should be notified when this Navigatable is
                    closed.
        """

    def requestFocus(self):
        """
        Tells this provider to request focus.
        """

    def setHighlight(self, highlight: ghidra.program.util.ProgramSelection):
        """
        Tells this Navigatable to set its highlight to the given highlight
        
        :param ghidra.program.util.ProgramSelection highlight: the highlight to set.
        """

    def setHighlightProvider(self, highlightProvider: ghidra.app.util.ListingHighlightProvider, program: ghidra.program.model.listing.Program):
        """
        Set the highlight provider for the given program
        
        :param ghidra.app.util.ListingHighlightProvider highlightProvider: the provider
        :param ghidra.program.model.listing.Program program: the program
        """

    def setMemento(self, memento: LocationMemento):
        """
        Sets the view state for this navigatable. This is used later to restore the view state.
        
        :param LocationMemento memento: the state of this navigatable
        """

    def setSelection(self, selection: ghidra.program.util.ProgramSelection):
        """
        Tells this Navigatable to set its selection to the given selection
        
        :param ghidra.program.util.ProgramSelection selection: the selection to set.
        """

    def supportsHighlight(self) -> bool:
        """
        Returns true if this navigatable supports highlighting
        
        :return: true if this navigatable supports highlighting
        :rtype: bool
        """

    def supportsMarkers(self) -> bool:
        """
        Currently only the 'connected' windows support markers
        
        :return: true if this navigatable supports markers
        :rtype: bool
        """

    @property
    def visible(self) -> jpype.JBoolean:
        ...

    @property
    def textSelection(self) -> java.lang.String:
        ...

    @property
    def memento(self) -> LocationMemento:
        ...

    @memento.setter
    def memento(self, value: LocationMemento):
        ...

    @property
    def program(self) -> ghidra.program.model.listing.Program:
        ...

    @property
    def byteSource(self) -> ghidra.features.base.memsearch.bytesource.AddressableByteSource:
        ...

    @property
    def connected(self) -> jpype.JBoolean:
        ...

    @property
    def highlight(self) -> ghidra.program.util.ProgramSelection:
        ...

    @highlight.setter
    def highlight(self, value: ghidra.program.util.ProgramSelection):
        ...

    @property
    def instanceID(self) -> jpype.JLong:
        ...

    @property
    def selection(self) -> ghidra.program.util.ProgramSelection:
        ...

    @selection.setter
    def selection(self, value: ghidra.program.util.ProgramSelection):
        ...

    @property
    def navigatableIcon(self) -> javax.swing.Icon:
        ...

    @property
    def dynamic(self) -> jpype.JBoolean:
        ...

    @property
    def disposed(self) -> jpype.JBoolean:
        ...

    @property
    def location(self) -> ghidra.program.util.ProgramLocation:
        ...


class NavigationUtils(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def getActiveNavigatable() -> Navigatable:
        ...

    @staticmethod
    def getExternalLinkageAddresses(program: ghidra.program.model.listing.Program, externalAddr: ghidra.program.model.address.Address) -> jpype.JArray[ghidra.program.model.address.Address]:
        """
        Locate all possible linkage addresses which correspond to the specified external address.
        This will correspond to either a generic reference type (DATA or EXTERNAL_REF) on a pointer
        or a thunk to the external location.  Both pointers and thunk constructs are utilized to
        perform dynamic linking between programs and external libraries they reference.  These
        linkage locations facilitate the function calls into any dynamically
        linked external program (i.e., library).
        
        :param ghidra.program.model.listing.Program program: the program
        :param ghidra.program.model.address.Address externalAddr: external location address
        :return: array of possible linkage addresses found
        :rtype: jpype.JArray[ghidra.program.model.address.Address]
        """

    @staticmethod
    def setSelection(tool: ghidra.framework.plugintool.PluginTool, navigatable: Navigatable, selection: ghidra.program.util.ProgramSelection):
        ...


class PreviousRangeAction(ghidra.app.context.NavigatableContextAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool, name: typing.Union[java.lang.String, str], owner: typing.Union[java.lang.String, str], navOptions: ghidra.app.plugin.core.navigation.NavigationOptions):
        ...



__all__ = ["NextRangeAction", "NavigatableRegistry", "DecoratorPanel", "ListingPanelContainer", "LocationMemento", "NavigatableIconFactory", "NavigatableRemovalListener", "Navigatable", "NavigationUtils", "PreviousRangeAction"]
