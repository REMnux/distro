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
import ghidra.framework.cmd
import ghidra.framework.model
import ghidra.framework.plugintool
import ghidra.program.model.address
import java.awt # type: ignore
import java.lang # type: ignore
import java.util # type: ignore


class ColorizingService(java.lang.Object):
    """
    A service that allows the user to set the background color of the Listing at specific addresses.
     
    
    The colors set here will appear in the listing and other plugins that use Listing components.
    """

    class_: typing.ClassVar[java.lang.Class]

    def clearAllBackgroundColors(self):
        """
        Clears all background colors set on the current program.
        
        
        .. seealso::
        
            | :obj:`.setBackgroundColor(Address, Address, Color)`
        
            | :obj:`.clearBackgroundColor(Address, Address)`
        """

    @typing.overload
    def clearBackgroundColor(self, min: ghidra.program.model.address.Address, max: ghidra.program.model.address.Address):
        """
        Clears any applied colors over the given address range.
        
        :param ghidra.program.model.address.Address min: The start address of the given range to clear
        :param ghidra.program.model.address.Address max: The end address of the given range to clear
        
        .. seealso::
        
            | :obj:`.setBackgroundColor(Address, Address, Color)`
        """

    @typing.overload
    def clearBackgroundColor(self, set: ghidra.program.model.address.AddressSetView):
        """
        Clears any applied colors over the given address set.
        
        :param ghidra.program.model.address.AddressSetView set: The address set over which to clear any applied colors
        
        .. seealso::
        
            | :obj:`.setBackgroundColor(AddressSetView, Color)`
        """

    def getAllBackgroundColorAddresses(self) -> ghidra.program.model.address.AddressSetView:
        """
        Returns a set of addresses where colors are applied.
        
        :return: a set of addresses where colors are applied.
        :rtype: ghidra.program.model.address.AddressSetView
        """

    def getBackgroundColor(self, address: ghidra.program.model.address.Address) -> java.awt.Color:
        """
        Returns the color applied at the given address.
        
        :param ghidra.program.model.address.Address address: The address to check
        :return: The color applied at the given address; null if no color is set
        :rtype: java.awt.Color
        
        .. seealso::
        
            | :obj:`.setBackgroundColor(Address, Address, Color)`
        
            | :obj:`.clearBackgroundColor(Address, Address)`
        """

    def getBackgroundColorAddresses(self, color: java.awt.Color) -> ghidra.program.model.address.AddressSetView:
        """
        Returns all addresses that have the given color applied.
        
        :param java.awt.Color color: The applied color for which to check
        :return: all addresses that have the given color applied.
        :rtype: ghidra.program.model.address.AddressSetView
        """

    def getColorFromUser(self, suggestedColor: java.awt.Color) -> java.awt.Color:
        """
        Prompts the user to choose a color
        
        :param java.awt.Color suggestedColor: The initial color to select; may be null
        :return: the user chosen color or null if the user cancelled the operation
        :rtype: java.awt.Color
        """

    def getMostRecentColor(self) -> java.awt.Color:
        """
        Returns the most recently used color.   Returns null if the user has not chosen any colors
        by using this interface via :meth:`getColorFromUser(Color) <.getColorFromUser>`.
        
        :return: the most recently used color; null if not set
        :rtype: java.awt.Color
        """

    def getRecentColors(self) -> java.util.List[java.awt.Color]:
        """
        Gets the recently used colors.  These are the colors that users have picked in recent 
        sessions (up to a limit).  If not colors have been chosen via this interface, then the
        empty list is returned.
        
        :return: the recently used colors.
        :rtype: java.util.List[java.awt.Color]
        """

    @typing.overload
    def setBackgroundColor(self, min: ghidra.program.model.address.Address, max: ghidra.program.model.address.Address, color: java.awt.Color):
        """
        Sets the background color for the given address range.  This color data gets saved with
        the program.
        
        :param ghidra.program.model.address.Address min: The start address to color
        :param ghidra.program.model.address.Address max: The end address of the given range to color
        :param java.awt.Color color: The color to apply
        
        .. seealso::
        
            | :obj:`.clearBackgroundColor(Address, Address)`
        
            | :obj:`.getBackgroundColor(Address)`
        """

    @typing.overload
    def setBackgroundColor(self, set: ghidra.program.model.address.AddressSetView, color: java.awt.Color):
        """
        Sets the background color for the given address range for the current program.  
        This color data gets saved with the program.  This color data gets saved with
        the program.
        
        :param ghidra.program.model.address.AddressSetView set: The address at which the given color will be applied
        :param java.awt.Color color: The color to apply
        
        .. seealso::
        
            | :obj:`.clearBackgroundColor(AddressSetView)`
        
            | :obj:`.getBackgroundColor(Address)`
        """

    @property
    def allBackgroundColorAddresses(self) -> ghidra.program.model.address.AddressSetView:
        ...

    @property
    def colorFromUser(self) -> java.awt.Color:
        ...

    @property
    def backgroundColor(self) -> java.awt.Color:
        ...

    @property
    def backgroundColorAddresses(self) -> ghidra.program.model.address.AddressSetView:
        ...

    @property
    def mostRecentColor(self) -> java.awt.Color:
        ...

    @property
    def recentColors(self) -> java.util.List[java.awt.Color]:
        ...


class PreviousColorRangeAction(ghidra.app.nav.PreviousRangeAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ColorizingPlugin, tool: ghidra.framework.plugintool.PluginTool, navOptions: ghidra.app.plugin.core.navigation.NavigationOptions):
        ...


@typing.type_check_only
class ClearColorCommand(ghidra.framework.cmd.Command[ghidra.framework.model.DomainObject]):
    ...
    class_: typing.ClassVar[java.lang.Class]


class ColorizingPlugin(ghidra.app.plugin.ProgramPlugin, ghidra.framework.model.DomainObjectListener):
    """
    A plugin to provider actions for manipulating the colors of the :obj:`CodeViewerService`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...


@typing.type_check_only
class ColorizingServiceProvider(ColorizingService):
    ...
    class_: typing.ClassVar[java.lang.Class]


class NextColorRangeAction(ghidra.app.nav.NextRangeAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ColorizingPlugin, tool: ghidra.framework.plugintool.PluginTool, navOptions: ghidra.app.plugin.core.navigation.NavigationOptions):
        ...


@typing.type_check_only
class SetColorCommand(ghidra.framework.cmd.Command[ghidra.framework.model.DomainObject]):
    ...
    class_: typing.ClassVar[java.lang.Class]



__all__ = ["ColorizingService", "PreviousColorRangeAction", "ClearColorCommand", "ColorizingPlugin", "ColorizingServiceProvider", "NextColorRangeAction", "SetColorCommand"]
