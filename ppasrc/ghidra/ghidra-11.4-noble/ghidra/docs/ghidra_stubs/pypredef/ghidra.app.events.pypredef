from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.framework.plugintool
import ghidra.program.model.address
import ghidra.program.model.listing
import ghidra.program.model.symbol
import ghidra.program.util
import java.lang # type: ignore


class AbstractHighlightPluginEvent(ghidra.framework.plugintool.PluginEvent):
    """
    Plugin event generated when the highlight in a program changes.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, sourceName: typing.Union[java.lang.String, str], eventName: typing.Union[java.lang.String, str], highlight: ghidra.program.util.ProgramSelection, program: ghidra.program.model.listing.Program):
        """
        Construct a new event.
        
        :param java.lang.String or str sourceName: the name of the plugin that generated this event
        :param java.lang.String or str eventName: the name of the event type
        :param ghidra.program.util.ProgramSelection highlight: the program highlight
        :param ghidra.program.model.listing.Program program: the program associated with this event
        """

    def getHighlight(self) -> ghidra.program.util.ProgramSelection:
        """
        Get the program highlight contained in this event.
        
        :return: the program highlight in this event.
        :rtype: ghidra.program.util.ProgramSelection
        """

    def getProgram(self) -> ghidra.program.model.listing.Program:
        """
        Get the program that the highlight refers to.
        
        :return: the program
        :rtype: ghidra.program.model.listing.Program
        """

    @property
    def highlight(self) -> ghidra.program.util.ProgramSelection:
        ...

    @property
    def program(self) -> ghidra.program.model.listing.Program:
        ...


class ProgramOpenedPluginEvent(ghidra.framework.plugintool.PluginEvent):
    """
    Plugin event class for notification of programs being created, opened, or closed.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, source: typing.Union[java.lang.String, str], p: ghidra.program.model.listing.Program):
        """
        Construct a new plugin event.
        
        :param java.lang.String or str source: name of the plugin that created this event
        :param ghidra.program.model.listing.Program p: the program associated with this event
        """

    def getProgram(self) -> ghidra.program.model.listing.Program:
        """
        Returns the :obj:`Program` that has just been opened. This method
        can return null, but only if the program has been closed and is no longer in use which
        can't happen if the method is called during the original event notification.
        
        :return: the :obj:`Program` that has just been analyzed for the first time.
        :rtype: ghidra.program.model.listing.Program
        """

    @property
    def program(self) -> ghidra.program.model.listing.Program:
        ...


class ProgramClosedPluginEvent(ghidra.framework.plugintool.PluginEvent):
    """
    Plugin event class for notification of programs being created, opened, or closed.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, source: typing.Union[java.lang.String, str], p: ghidra.program.model.listing.Program):
        """
        Construct a new plugin event.
        
        :param java.lang.String or str source: name of the plugin that created this event
        :param ghidra.program.model.listing.Program p: the program associated with this event
        """

    def getProgram(self) -> ghidra.program.model.listing.Program:
        """
        Returns the :obj:`Program` that has just been opened. This method
        can return null, but only if the method is called some time after the original event
        notification.
        
        :return: the :obj:`Program` that has just been analyzed for the first time.
        :rtype: ghidra.program.model.listing.Program
        """

    @property
    def program(self) -> ghidra.program.model.listing.Program:
        ...


class ProgramVisibilityChangePluginEvent(ghidra.framework.plugintool.PluginEvent):
    """
    Event for telling a tool to open a program.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, source: typing.Union[java.lang.String, str], p: ghidra.program.model.listing.Program, isVisible: typing.Union[jpype.JBoolean, bool]):
        """
        Construct a new plugin event.
        
        :param java.lang.String or str source: name of the plugin that created this event
        :param ghidra.program.model.listing.Program p: the program associated with this event
        :param jpype.JBoolean or bool isVisible: true if visible
        """

    def getProgram(self) -> ghidra.program.model.listing.Program:
        """
        Return the program on this event.
        
        :return: null if the event if for a program closing.
        :rtype: ghidra.program.model.listing.Program
        """

    def isProgramVisible(self) -> bool:
        """
        Returns true if program is currently in a visible state.
        
        :return: true if program is currently in a visible state.
        :rtype: bool
        """

    @property
    def programVisible(self) -> jpype.JBoolean:
        ...

    @property
    def program(self) -> ghidra.program.model.listing.Program:
        ...


class AbstractSelectionPluginEvent(ghidra.framework.plugintool.PluginEvent):
    """
    Plugin event generated when the selection in a program changes.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, sourceName: typing.Union[java.lang.String, str], eventName: typing.Union[java.lang.String, str], selection: ghidra.program.util.ProgramSelection, program: ghidra.program.model.listing.Program):
        """
        Construct a new plugin event
        
        :param java.lang.String or str sourceName: the name of the plugin that generated this event
        :param java.lang.String or str eventName: the name of the event type
        :param ghidra.program.util.ProgramSelection selection: the program selection
        :param ghidra.program.model.listing.Program program: the program associated with this event
        """

    def getProgram(self) -> ghidra.program.model.listing.Program:
        """
        Get the program that the selection refers to.
        
        :return: the program
        :rtype: ghidra.program.model.listing.Program
        """

    def getSelection(self) -> ghidra.program.util.ProgramSelection:
        """
        Get the program selection contained in this event.
        
        :return: the program selection in this event.
        :rtype: ghidra.program.util.ProgramSelection
        """

    @property
    def selection(self) -> ghidra.program.util.ProgramSelection:
        ...

    @property
    def program(self) -> ghidra.program.model.listing.Program:
        ...


class ExternalReferencePluginEvent(ghidra.framework.plugintool.PluginEvent):
    """
    Plugin event used to navigate to a location in another program when following
    a external reference.
    """

    class_: typing.ClassVar[java.lang.Class]
    NAME: typing.Final = "ExternalReference"
    """
    The name of this plugin event.
    """


    def __init__(self, src: typing.Union[java.lang.String, str], extLoc: ghidra.program.model.symbol.ExternalLocation, programPath: typing.Union[java.lang.String, str]):
        """
        Construct a new plugin event.
        
        :param java.lang.String or str src: name of the source of this event
        :param ghidra.program.model.symbol.ExternalLocation extLoc: the external location to follow
        :param java.lang.String or str programPath: The ghidra path name of the program file to go to.
        """

    def getExternalLocation(self) -> ghidra.program.model.symbol.ExternalLocation:
        """
        Get the external location for this event.
        
        :return: the external location
        :rtype: ghidra.program.model.symbol.ExternalLocation
        """

    def getProgramPath(self) -> str:
        """
        Returns the program path name
        
        :return: String containing the program path name.
        :rtype: str
        """

    @property
    def programPath(self) -> java.lang.String:
        ...

    @property
    def externalLocation(self) -> ghidra.program.model.symbol.ExternalLocation:
        ...


class ProgramLocationPluginEvent(AbstractLocationPluginEvent):
    """
    This plugin event class provides program location information.
     
     
    
    The event is fired when a plugin's program location has changed. Typically, a plugin does not
    actually generate the event unless it is processing some user action, e.g., the user mouse clicks
    somewhere on a plugin component to cause the program location to change.
    """

    class_: typing.ClassVar[java.lang.Class]
    NAME: typing.Final = "ProgramLocationChange"
    """
    The name of this plugin event.
    """


    def __init__(self, src: typing.Union[java.lang.String, str], loc: ghidra.program.util.ProgramLocation, program: ghidra.program.model.listing.Program):
        """
        Construct a new ProgramLocationEvent.
        
        :param java.lang.String or str src: the name of the plugin that generated this event.
        :param ghidra.program.util.ProgramLocation loc: the ProgramLocation object that contains the new location.
        :param ghidra.program.model.listing.Program program: the Program for which the loc object refers.
        """


class ProgramActivatedPluginEvent(ghidra.framework.plugintool.PluginEvent):
    """
    Plugin event class for notification of programs being created, opened, or
    closed.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, source: typing.Union[java.lang.String, str], activeProgram: ghidra.program.model.listing.Program):
        """
        Construct a new plugin event.
        
        :param java.lang.String or str source: name of the plugin that created this event
        :param ghidra.program.model.listing.Program activeProgram: the program associated with this event
        """

    def getActiveProgram(self) -> ghidra.program.model.listing.Program:
        """
        Returns the :obj:`Program` that has is being activated. This method
        can return null, but it is unlikely. It will only return null if the program has been closed
        and is no longer in use.
        
        :return: the :obj:`Program` that has just been analyzed for the first time.
        :rtype: ghidra.program.model.listing.Program
        """

    @property
    def activeProgram(self) -> ghidra.program.model.listing.Program:
        ...


class ExternalProgramSelectionPluginEvent(ghidra.framework.plugintool.PluginEvent):
    """
    Plugin event generated when a tool receives an
    ProgramSelectionToolEvent; the selection in the external tool has
    changed.
    """

    class_: typing.ClassVar[java.lang.Class]
    NAME: typing.Final = "ExternalProgramSelection"
    """
    The name of this plugin event.
    """

    TOOL_EVENT_NAME: typing.Final = "Program Selection"

    def __init__(self, src: typing.Union[java.lang.String, str], sel: ghidra.program.util.ProgramSelection, program: ghidra.program.model.listing.Program):
        """
        Construct a new event.
        
        :param java.lang.String or str src: source of this event
        :param ghidra.program.util.ProgramSelection sel: selection
        :param ghidra.program.model.listing.Program program: program that is open
        """

    def getProgram(self) -> ghidra.program.model.listing.Program:
        """
        Returns the Program object that the selection refers to.
        """

    def getSelection(self) -> ghidra.program.util.ProgramSelection:
        """
        Get the selection for this event.
        """

    @property
    def selection(self) -> ghidra.program.util.ProgramSelection:
        ...

    @property
    def program(self) -> ghidra.program.model.listing.Program:
        ...


class ProgramPostActivatedPluginEvent(ghidra.framework.plugintool.PluginEvent):
    """
    Plugin event class for notification that plugin first pass processing of a newly activated 
    program is complete. More specifically, all plugins have received and had a chance
    to react to a :obj:`ProgramActivatedPluginEvent`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, source: typing.Union[java.lang.String, str], activeProgram: ghidra.program.model.listing.Program):
        """
        Constructor
        
        :param java.lang.String or str source: name of the plugin that created this event
        :param ghidra.program.model.listing.Program activeProgram: the program that has been activated
        """

    def getActiveProgram(self) -> ghidra.program.model.listing.Program:
        """
        Return the new activated program. May be null.
        
        :return: null if the event if for a program closing.
        :rtype: ghidra.program.model.listing.Program
        """

    @property
    def activeProgram(self) -> ghidra.program.model.listing.Program:
        ...


class CloseProgramPluginEvent(ghidra.framework.plugintool.PluginEvent):
    """
    Event for telling a tool to close a program
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, source: typing.Union[java.lang.String, str], p: ghidra.program.model.listing.Program, ignoreChanges: typing.Union[jpype.JBoolean, bool]):
        """
        Construct a new plugin event.
        
        :param java.lang.String or str source: name of the plugin that created this event
        :param ghidra.program.model.listing.Program p: the program associated with this event
        :param jpype.JBoolean or bool ignoreChanges: true to ignore changes
        """

    def getProgram(self) -> ghidra.program.model.listing.Program:
        """
        Return the program on this event.
        
        :return: null if the event if for a program closing.
        :rtype: ghidra.program.model.listing.Program
        """

    def ignoreChanges(self) -> bool:
        ...

    @property
    def program(self) -> ghidra.program.model.listing.Program:
        ...


class TreeSelectionPluginEvent(ghidra.framework.plugintool.PluginEvent):
    """
    Notification for a new Program Tree selection.
    """

    class_: typing.ClassVar[java.lang.Class]
    NAME: typing.Final = "ProgramTreeSelection"
    """
    Name of the event.
    """


    def __init__(self, source: typing.Union[java.lang.String, str], treeName: typing.Union[java.lang.String, str], groupPaths: jpype.JArray[ghidra.program.util.GroupPath]):
        """
        Constructor for TreeSelectionPluginEvent.
        
        :param java.lang.String or str source: name of the plugin that generated this event
        :param java.lang.String or str treeName: name of the tree in the program
        :param jpype.JArray[ghidra.program.util.GroupPath] groupPaths: group paths that are selected in a Program Tree; the
        group path uniquely identifies a Module (folder) or fragment in the
        tree
        """

    def getGroupPaths(self) -> jpype.JArray[ghidra.program.util.GroupPath]:
        """
        Get the group paths that are in the tree selection.
        """

    def getTreeName(self) -> str:
        """
        Get the tree name associated with this event.
        
        :return: String tree name
        :rtype: str
        """

    def toString(self) -> str:
        """
        String representation of this event for debugging purposes.
        
        
        .. seealso::
        
            | :obj:`java.lang.Object.toString()`
        """

    @property
    def treeName(self) -> java.lang.String:
        ...

    @property
    def groupPaths(self) -> jpype.JArray[ghidra.program.util.GroupPath]:
        ...


class FirstTimeAnalyzedPluginEvent(ghidra.framework.plugintool.PluginEvent):
    """
    Plugin event class for notification of when programs have completed being analyzed for the first 
    time.
    """

    class_: typing.ClassVar[java.lang.Class]
    EVENT_NAME: typing.Final = "FirstTimeAnalyzed"

    def __init__(self, sourceName: typing.Union[java.lang.String, str], program: ghidra.program.model.listing.Program):
        """
        Constructor
        
        :param java.lang.String or str sourceName: source name of the plugin that created this event
        :param ghidra.program.model.listing.Program program: the program that has been analyzed for the first time
        """

    def getProgram(self) -> ghidra.program.model.listing.Program:
        """
        Returns the :obj:`Program` that has just been analyzed for the first time. This method
        can return null, but only if the program has been closed and is no longer in use which
        can't happen if the method is called during the original event notification.
        
        :return: the :obj:`Program` that has just been analyzed for the first time.
        :rtype: ghidra.program.model.listing.Program
        """

    @property
    def program(self) -> ghidra.program.model.listing.Program:
        ...


class ExternalProgramLocationPluginEvent(ghidra.framework.plugintool.PluginEvent):
    """
    Plugin event that is generated when a tool receives an external
    ProgramLocationToolEvent.
    """

    class_: typing.ClassVar[java.lang.Class]
    NAME: typing.Final = "External Program Location Change"
    """
    The name of this plugin event.
    """

    TOOL_EVENT_NAME: typing.Final = "Program Location Change"

    def __init__(self, src: typing.Union[java.lang.String, str], loc: ghidra.program.util.ProgramLocation, program: ghidra.program.model.listing.Program):
        """
        Construct a new ProgramLocationEvent.
        
        :param java.lang.String or str src: the name of the plugin that generated this event.
        :param ghidra.program.util.ProgramLocation loc: the ProgramLocation object that contains the new location.
        :param ghidra.program.model.listing.Program program: the Program for which the loc object refers.
        """

    def getLocation(self) -> ghidra.program.util.ProgramLocation:
        """
        Returns the ProgramLocation stored in this event.
        """

    def getProgram(self) -> ghidra.program.model.listing.Program:
        """
        Returns the Program object that the location refers to.
        """

    @property
    def location(self) -> ghidra.program.util.ProgramLocation:
        ...

    @property
    def program(self) -> ghidra.program.model.listing.Program:
        ...


class ViewChangedPluginEvent(ghidra.framework.plugintool.PluginEvent):
    """
    Event for notifying plugins when the program view changes (what the
    Code Browser shows in the listing window).
    """

    class_: typing.ClassVar[java.lang.Class]
    NAME: typing.Final = "ViewChanged"
    """
    Name of the event.
    """


    def __init__(self, source: typing.Union[java.lang.String, str], treeName: typing.Union[java.lang.String, str], viewSet: ghidra.program.model.address.AddressSet):
        """
        Constructor for ViewChangedPluginEvent.
        
        :param java.lang.String or str source: name of the plugin that created this event
        :param java.lang.String or str treeName: name of the tree in the program
        :param ghidra.program.model.address.AddressSet viewSet: set of addresses in the view
        """

    def getTreeName(self) -> str:
        """
        Get the name of the tree where the view is from.
        """

    def getView(self) -> ghidra.program.model.address.AddressSet:
        """
        Get the address set in the view.
        """

    def toString(self) -> str:
        """
        Returns a string for debugging purposes.
        
        
        .. seealso::
        
            | :obj:`java.lang.Object.toString()`
        """

    @property
    def view(self) -> ghidra.program.model.address.AddressSet:
        ...

    @property
    def treeName(self) -> java.lang.String:
        ...


class OpenProgramPluginEvent(ghidra.framework.plugintool.PluginEvent):
    """
    Event for telling a tool to open a program
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, source: typing.Union[java.lang.String, str], p: ghidra.program.model.listing.Program):
        """
        Construct a new plugin event.
        
        :param java.lang.String or str source: name of the plugin that created this event
        :param ghidra.program.model.listing.Program p: the program associated with this event
        """

    def getProgram(self) -> ghidra.program.model.listing.Program:
        """
        Return the program on this event.
        
        :return: null if the event if for a program closing.
        :rtype: ghidra.program.model.listing.Program
        """

    @property
    def program(self) -> ghidra.program.model.listing.Program:
        ...


class ProgramSelectionPluginEvent(AbstractSelectionPluginEvent):
    """
    Plugin event generated when the selection in a program changes.
    """

    class_: typing.ClassVar[java.lang.Class]
    NAME: typing.Final = "ProgramSelection"
    """
    The name of this plugin event.
    """


    def __init__(self, src: typing.Union[java.lang.String, str], sel: ghidra.program.util.ProgramSelection, program: ghidra.program.model.listing.Program):
        """
        Construct a new plugin event
        
        :param java.lang.String or str src: the name of the plugin that generated this event
        :param ghidra.program.util.ProgramSelection sel: the program selection
        :param ghidra.program.model.listing.Program program: the program associated with this event
        """


class ProgramHighlightPluginEvent(AbstractHighlightPluginEvent):
    """
    Plugin event generated when the highlight in a program changes.
    """

    class_: typing.ClassVar[java.lang.Class]
    NAME: typing.Final = "ProgramHighlight"

    def __init__(self, src: typing.Union[java.lang.String, str], hl: ghidra.program.util.ProgramSelection, program: ghidra.program.model.listing.Program):
        """
        Construct a new event.
        
        :param java.lang.String or str src: name of the plugin that generated the event
        :param ghidra.program.util.ProgramSelection hl: Program selection containing the selected address set.
        :param ghidra.program.model.listing.Program program: program being highlighted
        """


class AbstractLocationPluginEvent(ghidra.framework.plugintool.PluginEvent):

    class_: typing.ClassVar[java.lang.Class]

    def getLocation(self) -> ghidra.program.util.ProgramLocation:
        """
        Get the location stored in this event.
        
        :return: the location
        :rtype: ghidra.program.util.ProgramLocation
        """

    def getProgram(self) -> ghidra.program.model.listing.Program:
        """
        Get the program that the location refers to.
        
        :return: the program
        :rtype: ghidra.program.model.listing.Program
        """

    @property
    def location(self) -> ghidra.program.util.ProgramLocation:
        ...

    @property
    def program(self) -> ghidra.program.model.listing.Program:
        ...



__all__ = ["AbstractHighlightPluginEvent", "ProgramOpenedPluginEvent", "ProgramClosedPluginEvent", "ProgramVisibilityChangePluginEvent", "AbstractSelectionPluginEvent", "ExternalReferencePluginEvent", "ProgramLocationPluginEvent", "ProgramActivatedPluginEvent", "ExternalProgramSelectionPluginEvent", "ProgramPostActivatedPluginEvent", "CloseProgramPluginEvent", "TreeSelectionPluginEvent", "FirstTimeAnalyzedPluginEvent", "ExternalProgramLocationPluginEvent", "ViewChangedPluginEvent", "OpenProgramPluginEvent", "ProgramSelectionPluginEvent", "ProgramHighlightPluginEvent", "AbstractLocationPluginEvent"]
