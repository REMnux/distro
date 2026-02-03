from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking
import docking.action
import docking.menu
import ghidra.app.services
import ghidra.framework.data
import ghidra.framework.model
import ghidra.framework.options
import ghidra.framework.plugintool
import ghidra.program.model.listing
import ghidra.util.task
import ghidra.util.timer
import java.awt # type: ignore
import java.lang # type: ignore
import java.net # type: ignore
import java.time # type: ignore
import java.util # type: ignore
import javax.swing # type: ignore


class ProgramManagerPlugin(ghidra.framework.plugintool.Plugin, ghidra.app.services.ProgramManager, ghidra.framework.options.OptionsChangeListener):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...

    def acceptData(self, data: jpype.JArray[ghidra.framework.model.DomainFile]) -> bool:
        """
        Method called if the plugin supports this domain file.
        
        :param jpype.JArray[ghidra.framework.model.DomainFile] data: the data to be used by the running tool
        :return: false if data is not a Program object.
        :rtype: bool
        """

    def isManaged(self, program: ghidra.program.model.listing.Program) -> bool:
        ...

    def openProgram(self, program: ghidra.program.model.listing.Program):
        """
        This method notifies listening plugins that a programs has been added to the program manager.
        This is not used for actually opening a program from the database and will act strangely if
        given a closed Program object.
        
        
        .. seealso::
        
            | :obj:`ghidra.app.services.ProgramManager.openProgram(ghidra.program.model.listing.Program)`
        """

    def openPrograms(self, filesToOpen: java.util.List[ghidra.framework.model.DomainFile]):
        ...

    def readDataState(self, saveState: ghidra.framework.options.SaveState):
        """
        Read in my data state.
        """

    def writeDataState(self, saveState: ghidra.framework.options.SaveState):
        """
        Write out my data state.
        """

    @property
    def managed(self) -> jpype.JBoolean:
        ...


class UndoAction(AbstractUndoRedoAction):
    """
    Action class for the "Undo" action
    """

    class_: typing.ClassVar[java.lang.Class]
    SUBGROUP: typing.Final = "1Undo"

    def __init__(self, plugin: ProgramManagerPlugin, tool: ghidra.framework.plugintool.PluginTool):
        ...


@typing.type_check_only
class TransactionMonitor(javax.swing.JComponent, ghidra.framework.model.TransactionListener):
    ...
    class_: typing.ClassVar[java.lang.Class]


class SaveAsProgramAction(AbstractProgramNameSwitchingAction):
    """
    Action class for the "Save As" action
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ProgramManagerPlugin, group: typing.Union[java.lang.String, str], subGroup: typing.Union[jpype.JInt, int]):
        ...


class CloseProgramAction(AbstractProgramNameSwitchingAction):
    """
    Action class for the "Close Program" action
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ProgramManagerPlugin, group: typing.Union[java.lang.String, str], subGroup: typing.Union[jpype.JInt, int]):
        ...


class ProgramLocator(java.lang.Object):
    """
    Programs locations can be specified from either a :obj:`DomainFile` or a ghidra :obj:`URL`.
    This class combines the two ways to specify the location of a program into a single object. The
    DomainFile or URL will be normalized, so that this ProgramLocator can be used as a key that 
    uniquely represents the program, even if the location is specified from different
    DomainFiles or URLs that represent the same program instance.
     
    
    The class must specify either a DomainFile or a URL, but not both.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, url: java.net.URL):
        """
        Creates a :obj:`URL` based ProgramLocator. The URL must be using the Ghidra protocol
        
        :param java.net.URL url: the URL to a Ghidra Program
        """

    @typing.overload
    def __init__(self, domainFile: ghidra.framework.model.DomainFile):
        """
        Creates a :obj:`DomainFile`-based ProgramLocator for the current version of a Program.
        
        :param ghidra.framework.model.DomainFile domainFile: the DomainFile for a program
        """

    @typing.overload
    def __init__(self, domainFile: ghidra.framework.model.DomainFile, version: typing.Union[jpype.JInt, int]):
        """
        Creates a :obj:`DomainFile`-based ProgramLocator for a specific Program version.
        
        :param ghidra.framework.model.DomainFile domainFile: the DomainFile for a program
        :param jpype.JInt or int version: the specific version of the program
        """

    def canReopen(self) -> bool:
        """
        Returns true if the information in this location can be used to reopen a program.
        
        :return: true if the information in this location can be used to reopen a program
        :rtype: bool
        """

    def getDomainFile(self) -> ghidra.framework.model.DomainFile:
        """
        Returns the DomainFile for this locator or null if this is a URL based locator
        
        :return: the DomainFile for this locator or null if this is a URL based locator
        :rtype: ghidra.framework.model.DomainFile
        """

    def getURL(self) -> java.net.URL:
        """
        Returns the URL for this locator or null if this is a DomainFile based locator
        
        :return: the URL for this locator or null if this is a DomainFile based locator
        :rtype: java.net.URL
        """

    def getVersion(self) -> int:
        """
        Returns the version of the program that this locator represents
        
        :return: the version of the program that this locator represents
        :rtype: int
        """

    def isDomainFile(self) -> bool:
        """
        Returns true if this is a DomainFile based program locator
        
        :return: true if this is a DomainFile based program locator
        :rtype: bool
        """

    def isURL(self) -> bool:
        """
        Returns true if this is a URL based program locator
        
        :return: true if this is a URL based program locator
        :rtype: bool
        """

    def isValid(self) -> bool:
        """
        Returns true if this ProgramLocator represents a valid program location
        
        :return: true if this ProgramLocator represents a valid program location
        :rtype: bool
        """

    @property
    def valid(self) -> jpype.JBoolean:
        ...

    @property
    def domainFile(self) -> ghidra.framework.model.DomainFile:
        ...

    @property
    def version(self) -> jpype.JInt:
        ...

    @property
    def uRL(self) -> java.net.URL:
        ...


@typing.type_check_only
class MultiProgramManager(ghidra.framework.model.TransactionListener):
    """
    Class for tracking open programs in the tool.
    """

    @typing.type_check_only
    class ProgramInfo(java.lang.Comparable[MultiProgramManager.ProgramInfo]):

        class_: typing.ClassVar[java.lang.Class]
        program: typing.Final[ghidra.program.model.listing.Program]
        programLocator: ProgramLocator

        def canReopen(self) -> bool:
            ...

        def setVisible(self, state: typing.Union[jpype.JBoolean, bool]):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def contains(self, p: ghidra.program.model.listing.Program) -> bool:
        ...

    def isEmpty(self) -> bool:
        ...

    @property
    def empty(self) -> jpype.JBoolean:
        ...


class ProgramOptionsAction(AbstractProgramNameSwitchingAction):
    """
    Action class for the "Edit Program Options" action
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ProgramManagerPlugin):
        ...


class MultiTabListener(java.lang.Object):
    """
    Listener notified when tabs are added, removed, or selected 
    in the MultiTabPanel.
    """

    class_: typing.ClassVar[java.lang.Class]

    def objectAdded(self, obj: java.lang.Object):
        """
        Notification that the given object was added.
        
        :param java.lang.Object obj: object that is represented as a tab in the MultiTabPanel
        """

    def objectSelected(self, obj: java.lang.Object):
        """
        Notification that the given object is selected.
        
        :param java.lang.Object obj: object that is represented as a tab in the MultiTabPanel
        """

    def removeObject(self, obj: java.lang.Object) -> bool:
        """
        Remove the object's tab if this method returns true.
        
        :param java.lang.Object obj: object that is represented as a tab in the MultiTabPanel
        :return: true if the object's tab should be removed
        :rtype: bool
        """


class SaveProgramAction(AbstractProgramNameSwitchingAction):
    """
    Action class for the "Save Program" action
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ProgramManagerPlugin, group: typing.Union[java.lang.String, str], subGroup: typing.Union[jpype.JInt, int]):
        ...


class RedoAction(AbstractUndoRedoAction):
    """
    Action class for the "redo" action
    """

    class_: typing.ClassVar[java.lang.Class]
    SUBGROUP: typing.Final = "2Redo"

    def __init__(self, plugin: ProgramManagerPlugin, tool: ghidra.framework.plugintool.PluginTool):
        ...


class AbstractProgramNameSwitchingAction(docking.action.DockingAction):
    """
    Abstract base class for program actions that change their menu name depending on the active
    program. Note that actions that derived from this class only work on programs that are
    globally managed by Ghidra and not opened and managed by individual plugins. If the action 
    context should happen to contain a non-global managed program, the tool's concept of the 
    current active program will be used as target of this action instead.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ProgramManagerPlugin, name: typing.Union[java.lang.String, str]):
        """
        Constructor
        
        :param ProgramManagerPlugin plugin: the ProgramManagerPlugin (i.e. the global Ghidra manager for programs)
        :param java.lang.String or str name: the name of the action
        programs
        """


class MultiTabPlugin(ghidra.framework.plugintool.Plugin, ghidra.framework.model.DomainObjectListener, ghidra.framework.options.OptionsChangeListener):
    """
    Plugin to show a "tab" for each open program; the selected tab is the activated program.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...


class ProgramTabActionContext(docking.DefaultActionContext):
    """
    Action context for program tabs
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, provider: docking.ComponentProvider, program: ghidra.program.model.listing.Program, source: java.awt.Component):
        ...

    def getProgram(self) -> ghidra.program.model.listing.Program:
        """
        Returns the program for the tab that was clicked on.
        
        :return: the program for the tab that was clicked on
        :rtype: ghidra.program.model.listing.Program
        """

    @property
    def program(self) -> ghidra.program.model.listing.Program:
        ...


class AbstractUndoRedoAction(docking.menu.MultiActionDockingAction):
    """
    Abstract base class for the undo and redo actions. These actions add a listener to the
    current context program in order to know when to update their enabled state and description.
    """

    @typing.type_check_only
    class RepeatedAction(docking.action.DockingAction):
        """
        Action for repeating the undo/redo action multiple times to effectively undo/redo to
        a transaction that is not at the top of the list of undo/redo items.
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, name: typing.Union[java.lang.String, str], repeatCount: typing.Union[jpype.JInt, int]):
            ...


    @typing.type_check_only
    class ContextProgramTransactionListener(ghidra.framework.model.TransactionListener):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool, plugin: ProgramManagerPlugin, name: typing.Union[java.lang.String, str], iconId: typing.Union[java.lang.String, str], keyBinding: typing.Union[java.lang.String, str], subGroup: typing.Union[java.lang.String, str]):
        ...


@typing.type_check_only
class ProgramCache(ghidra.util.timer.GTimerCache[ProgramLocator, ghidra.program.model.listing.Program]):
    """
    Class for doing time based Program caching. 
     
    
    Caching programs has some unique challenges because
    of the way they are shared using a consumer concept. 
    Program instances are shared even if unrelated clients open
    them. Each client using a program registers its use by giving it a 
    unique consumer object. When done with the program, the client removes its consumer. When the 
    last consumer is removed, the program instance is closed.
     
    
    When a program is put into the cache, the cache adds itself as a consumer on the program, 
    effectively keeping it open even if all clients release it. Further, when an entry expires
    the cache removes itself as a consumer. A race condition can occur when a client attempts to 
    retrieve a program from the cache and add itself as a consumer, while the entry's expiration is  
    being processed. Specifically, there may be a small window where there are no consumers on that 
    program, causing it to be closed. However, since accessing the program will renew its expiration
    time, it is very unlikely to happen, except for debugging scenarios.
     
    
    Also, because Program instances can change their association from one DomainFile to another
    (Save As), we need to add a listener to the program to detect this. If this occurs on
    a program in the cache, we simple remove it from the cache instead of trying to fix it.
    """

    @typing.type_check_only
    class ProgramFileListener(ghidra.framework.data.DomainObjectFileListener, ghidra.framework.model.DomainObjectListener):
        """
        DomainObjectFileListener for programs in the cache. If a program instance has its DomainFile 
        changed (e.g., 'Save As' action), then the cache mapping is incorrect as it sill has the
        program instance associated with its old DomainFile. So we need to add a listener to 
        recognize when this occurs. If it does, we simply remove the entry from the cache. Also,
        we need to remove any programs from the cache if changes are made to avoid questions about
        who is responsible for saving changed programs that only live in the cache.
        """

        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, duration: java.time.Duration, capacity: typing.Union[jpype.JInt, int]):
        """
        Constructs new ProgramCache with a duration for keeping programs open and a maximum
        number of programs to cache.
        
        :param java.time.Duration duration: the time that a program will remain in the cache without being
        accessed (accessing a cached program resets its time)
        :param jpype.JInt or int capacity: the maximum number of programs in the cache before least recently used
        programs are removed.
        """


@typing.type_check_only
class ProgramSaveManager(java.lang.Object):

    @typing.type_check_only
    class SaveFileTask(ghidra.util.task.Task):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class SaveAsTask(ghidra.util.task.Task):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def saveChangedPrograms(self):
        """
        Saves all programs that have changes
        """



__all__ = ["ProgramManagerPlugin", "UndoAction", "TransactionMonitor", "SaveAsProgramAction", "CloseProgramAction", "ProgramLocator", "MultiProgramManager", "ProgramOptionsAction", "MultiTabListener", "SaveProgramAction", "RedoAction", "AbstractProgramNameSwitchingAction", "MultiTabPlugin", "ProgramTabActionContext", "AbstractUndoRedoAction", "ProgramCache", "ProgramSaveManager"]
