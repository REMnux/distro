from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking
import docking.action
import docking.test
import generic.jar
import ghidra.app.plugin.core.codebrowser
import ghidra.base.project
import ghidra.framework.cmd
import ghidra.framework.main
import ghidra.framework.model
import ghidra.framework.plugintool
import ghidra.framework.project.tool
import ghidra.program.database
import ghidra.program.model.address
import ghidra.program.model.data
import ghidra.program.model.lang
import ghidra.program.model.listing
import ghidra.program.model.symbol
import ghidra.util.task
import java.awt # type: ignore
import java.io # type: ignore
import java.lang # type: ignore
import java.net # type: ignore
import java.util # type: ignore
import utility.function


E = typing.TypeVar("E")
R = typing.TypeVar("R")
T = typing.TypeVar("T")


class AbstractProgramBasedTest(AbstractGhidraHeadedIntegrationTest):
    """
    A convenience base class for creating tests that use the default tool and open a program.
    This class will create for you a tool, a :obj:`TestEnv` and will open the program
    specified by :meth:`getProgramName() <.getProgramName>`.
    
     
    To use this class, you must call :meth:`initialize() <.initialize>` from your test or ``setUp``
    method.
    
     
    Note: if you are loading a pre-existing program, then simply override
    :meth:`getProgramName() <.getProgramName>`.  Alternatively, if you are building a program, then override
    :meth:`getProgram() <.getProgram>` and return it there.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @typing.overload
    def addr(self, offset: typing.Union[jpype.JLong, int]) -> ghidra.program.model.address.Address:
        ...

    @typing.overload
    def addr(self, offset: typing.Union[java.lang.String, str]) -> ghidra.program.model.address.Address:
        ...

    @typing.overload
    def addr(self, p: ghidra.program.model.listing.Program, offset: typing.Union[jpype.JLong, int]) -> ghidra.program.model.address.Address:
        ...

    @typing.overload
    def addr(self, p: ghidra.program.model.listing.Program, offset: typing.Union[java.lang.String, str]) -> ghidra.program.model.address.Address:
        ...

    @typing.overload
    def addrs(self, *offsets: typing.Union[jpype.JLong, int]) -> java.util.List[ghidra.program.model.address.Address]:
        ...

    @typing.overload
    def addrs(self, *addrs: ghidra.program.model.address.Address) -> java.util.List[ghidra.program.model.address.Address]:
        ...

    def assertCurrentAddress(self, expected: ghidra.program.model.address.Address):
        ...

    def createInProgram(self, f: utility.function.ExceptionalFunction[ghidra.program.model.listing.Program, R, E]) -> R:
        """
        Provides a convenient method for modifying the current program, handling the transaction
        logic and returning a new item as a result.
        
        :param utility.function.ExceptionalFunction[ghidra.program.model.listing.Program, R, E] f: the function for modifying the program and creating the desired result
        :return: the result
        :rtype: R
        """

    def function(self, addr: ghidra.program.model.address.Address) -> ghidra.program.model.listing.Function:
        ...

    @typing.overload
    def goTo(self, offset: typing.Union[jpype.JLong, int]):
        ...

    @typing.overload
    def goTo(self, offset: typing.Union[java.lang.String, str]):
        ...

    @typing.overload
    def goTo(self, a: ghidra.program.model.address.Address):
        ...

    def modifyProgram(self, callback: utility.function.ExceptionalConsumer[ghidra.program.model.listing.Program, E]):
        """
        Provides a convenient method for modifying the current program, handling the transaction
        logic.
        
        :param utility.function.ExceptionalConsumer[ghidra.program.model.listing.Program, E] callback: the code to execute
        """

    def range(self, from_: typing.Union[jpype.JLong, int], to: typing.Union[jpype.JLong, int]) -> ghidra.program.model.address.AddressRange:
        ...

    def showProvider(self, name: typing.Union[java.lang.String, str]):
        ...

    def tearDown(self):
        ...

    def toAddressSet(self, *offsets: typing.Union[jpype.JLong, int]) -> ghidra.program.model.address.AddressSet:
        ...


class TestTool(ghidra.framework.project.tool.GhidraTool):

    class_: typing.ClassVar[java.lang.Class]
    NAME: typing.Final = "Test Tool"

    def __init__(self, project: ghidra.framework.model.Project):
        ...


class AbstractGhidraHeadedIntegrationTest(AbstractGhidraHeadlessIntegrationTest):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def addPlugin(tool: ghidra.framework.plugintool.PluginTool, c: java.lang.Class[T]) -> T:
        """
        Adds the given plugin to the tool and then returns the instance of the plugin that was
        added
        
        :param ghidra.framework.plugintool.PluginTool tool: the tool
        :param java.lang.Class[T] c: the class of the plugin to add
        :return: the newly added plugin
        :rtype: T
        :raises PluginException: if the plugin could not be constructed, or there was problem
                    executing its init() method, or if a plugin of this class already exists in the tool
        """

    @typing.overload
    def click(self, codeBrowser: ghidra.app.plugin.core.codebrowser.AbstractCodeBrowserPlugin[typing.Any], clickCount: typing.Union[jpype.JInt, int]):
        """
        Triggers a browser click at the current cursor location.  Thus, this method should be
        called only after the browser location is set to the desired field.
        
        :param ghidra.app.plugin.core.codebrowser.AbstractCodeBrowserPlugin[typing.Any] codeBrowser: the CodeBrowserPlugin
        :param jpype.JInt or int clickCount: the click count
        """

    @typing.overload
    def click(self, codeBrowser: ghidra.app.plugin.core.codebrowser.AbstractCodeBrowserPlugin[typing.Any], clickCount: typing.Union[jpype.JInt, int], wait: typing.Union[jpype.JBoolean, bool]):
        ...

    @staticmethod
    def getAction(plugin: ghidra.framework.plugintool.Plugin, actionName: typing.Union[java.lang.String, str]) -> docking.action.DockingActionIf:
        ...

    @staticmethod
    def getPluginByName(tool: ghidra.framework.plugintool.PluginTool, pluginName: typing.Union[java.lang.String, str]) -> ghidra.framework.plugintool.Plugin:
        ...

    @staticmethod
    def saveTool(project: ghidra.framework.model.Project, tool: ghidra.framework.plugintool.PluginTool) -> ghidra.framework.plugintool.PluginTool:
        """
        Save the given tool to the project tool chest.  If the tool already exists, then it will
        be overwritten with the given tool.
        
        :param ghidra.framework.model.Project project: The project which with the tool is associated.
        :param ghidra.framework.plugintool.PluginTool tool: The tool to be saved
        :return: the new tool
        :rtype: ghidra.framework.plugintool.PluginTool
        """

    @staticmethod
    def showDialogWithoutBlocking(tool: ghidra.framework.plugintool.PluginTool, provider: docking.DialogComponentProvider) -> docking.DialogComponentProvider:
        """
        Shows the given DialogComponentProvider using the given tool's
        :meth:`PluginTool.showDialog(DialogComponentProvider) <PluginTool.showDialog>` method.
        
        :param ghidra.framework.plugintool.PluginTool tool: The tool used to show the given provider.
        :param docking.DialogComponentProvider provider: The DialogComponentProvider to show.
        :return: The provider once it has been shown, or null if the provider is not shown within
                the given maximum wait time.
        :rtype: docking.DialogComponentProvider
        """

    @staticmethod
    def showTool(tool: ghidra.framework.plugintool.PluginTool) -> ghidra.framework.plugintool.PluginTool:
        ...

    @staticmethod
    def waitForBusyTool(tool: ghidra.framework.plugintool.PluginTool):
        """
        Waits for the tool to finish executing commands and tasks
        
        :param ghidra.framework.plugintool.PluginTool tool: the tool
        :raises AssertionFailedError: if the tool does not finish work within a reasonable limit
        """

    @staticmethod
    def waitForProgram(program: ghidra.program.model.listing.Program):
        """
        Flushes the given program's events before waiting for the swing update manager
        
        :param ghidra.program.model.listing.Program program: The program whose events will be flushed; may be null
        """


class TestProgramManager(java.lang.Object):
    """
    A class to handle locating, opening and caching (within a JVM) programs in the test
    environment.  (This code was formerly inside of TestEnv.)
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def add(self, p: ghidra.program.model.listing.Program):
        ...

    def addOpenProgram(self, program: ghidra.program.model.listing.Program):
        ...

    @typing.overload
    def addProgramToProject(self, project: ghidra.framework.model.Project, programName: typing.Union[java.lang.String, str]) -> ghidra.framework.model.DomainFile:
        """
        Copies the specified program zip file to the JUnit test project's root folder. **This
        means that the program will appear in the FrontEndTool as part of the project.**  That is
        the only reason to use this method vice openProgram().
        
        :param ghidra.framework.model.Project project: the project into which the file will be restored
        :param java.lang.String or str programName: the name of the program zip file without the ".gzf" extension
        :return: the file
        :rtype: ghidra.framework.model.DomainFile
        :raises FileNotFoundException: if the file cannot be found
        """

    @typing.overload
    def addProgramToProject(self, folder: ghidra.framework.model.DomainFolder, programName: typing.Union[java.lang.String, str]) -> ghidra.framework.model.DomainFile:
        """
        Copies the specified program zip file to the JUnit test project's folder. **This
        means that the program will appear in the FrontEndTool as part of the project.**  That is
        the only reason to use this method vice openProgram().
        
        :param ghidra.framework.model.DomainFolder folder: the folder into which the domain file will be inserted
        :param java.lang.String or str programName: the name of the program zip file without the ".gzf" extension.
        :return: the file
        :rtype: ghidra.framework.model.DomainFile
        :raises FileNotFoundException: if the file cannot be found
        """

    @staticmethod
    def cleanDbTestDir():
        ...

    def disposeOpenPrograms(self):
        ...

    @staticmethod
    def getDbTestDir() -> java.io.File:
        ...

    def getOpenPrograms(self) -> java.util.Set[ghidra.program.model.listing.Program]:
        ...

    def getProgram(self, progName: typing.Union[java.lang.String, str]) -> ghidra.program.database.ProgramDB:
        """
        Open a read-only test program from the test data directory.
        This program must be released prior to disposing this test environment.
        NOTE: Some tests rely on this method returning null when file does
        not yet exist within the resource area (e.g., test binaries for P-Code Tests)
        
        :param java.lang.String or str progName: name of program database within the test data directory.
        :return: program or null if program file not found
        :rtype: ghidra.program.database.ProgramDB
        """

    def isProgramCached(self, name: typing.Union[java.lang.String, str]) -> bool:
        """
        Determine if the specified program already exists with the program cache
        
        :param java.lang.String or str name: the program name
        :return: true if the specified program already exists with the program cache
        :rtype: bool
        """

    def markAllProgramsAsUnchanged(self):
        ...

    def release(self, program: ghidra.program.model.listing.Program):
        ...

    def removeAllConsumersExcept(self, p: ghidra.program.model.listing.Program, consumer: java.lang.Object):
        ...

    def removeFromProgramCache(self, name: typing.Union[java.lang.String, str]):
        """
        Remove specified program from cache
        
        :param java.lang.String or str name: the program name
        """

    def saveToCache(self, progName: typing.Union[java.lang.String, str], program: ghidra.program.database.ProgramDB, replace: typing.Union[jpype.JBoolean, bool], monitor: ghidra.util.task.TaskMonitor):
        """
        Save a program to the cached program store.  A SaveAs will be performed on the
        program to its cached storage location.
        
        :param java.lang.String or str progName: program name
        :param ghidra.program.database.ProgramDB program: program object
        :param jpype.JBoolean or bool replace: if true any existing cached database with the same name will be replaced
        :param ghidra.util.task.TaskMonitor monitor: task monitor
        :raises IOException: if the database cannot be created
        :raises DuplicateNameException: if already cached
        :raises CancelledException: if the save operation is cancelled
        """

    @staticmethod
    def setDbTestDir(newDbTestDir: jpype.protocol.SupportsPath):
        ...

    @property
    def programCached(self) -> jpype.JBoolean:
        ...

    @property
    def program(self) -> ghidra.program.database.ProgramDB:
        ...

    @property
    def openPrograms(self) -> java.util.Set[ghidra.program.model.listing.Program]:
        ...


class TestEnv(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        Constructor for Ghidra
        A new test project is established.
        If it already exists it will first be deleted.
        
        :raises IOException: if there is an issue creating a test project
        """

    @typing.overload
    def __init__(self, projectName: typing.Union[java.lang.String, str]):
        """
        Constructor for Ghidra
        A new test project is established using the specified projectName.
        If it already exists it will first be deleted.
        If the test environment is not disposed within 1 minute the tests iwll be aborted
        
        :param java.lang.String or str projectName: the name of the project
        :raises IOException: if there is an issue creating a test project
        """

    @typing.overload
    def __init__(self, abortTimeout: typing.Union[jpype.JLong, int], projectName: typing.Union[java.lang.String, str]):
        """
        Constructor for Ghidra
        A new test project is established using the specified projectName.
        If it already exists it will first be deleted.
        
        :param jpype.JLong or int abortTimeout: number of minutes within which this test environment must be
                disposed.  If not disposed in a timely manner, System.exit will be invoked.
        :param java.lang.String or str projectName: the name of the project
        :raises IOException: if there is an issue creating a test project
        """

    def addPlugin(self, c: java.lang.Class[T]) -> T:
        """
        Adds and returns the plugin to this env's tool for the given class.
         
         
        If you have not created a tool using this env, then the default
        tool from :meth:`lazyTool() <.lazyTool>` is used.  If you have launched a tool, then that tool
        is used.   In the following example, the given plugin is added to the default tool:
         
                TestEnv env = new TestEnv();
                env.launchDefaultTool();
                FooPlugin foo = env.addPlugin(FooPlugin.class);
         
        
        :param java.lang.Class[T] c: the plugin class
        :return: the plugin instance
        :rtype: T
        :raises PluginException: if there is an exception adding the given tool
        """

    def close(self, p: ghidra.program.model.listing.Program):
        """
        Closes the given program, ignoring all changes, for each tool known to this TestEnv.
        
        :param ghidra.program.model.listing.Program p: the program to close
        """

    def closeAndReopenProject(self):
        """
        A convenience method to close and then reopen the default project created by this TestEnv
        instance.  This will not delete the project between opening and closing and will restore
        the project to its previous state.
        
        :raises java.lang.Exception: if any exception occurs while saving and reopening
        """

    @typing.overload
    def closeTool(self):
        """
        Closes the TestEnv's default tool.  This method is asynchronous, so you
        must wait for the Swing thread to perform the work yourself.
        Watch out for modal dialogs.
        """

    @typing.overload
    def closeTool(self, toolToClose: ghidra.framework.plugintool.PluginTool):
        """
        Closes the given tool.  This method is asynchronous, so you must wait for the Swing thread
        to perform the work yourself.  Watch out for modal dialogs.
        
        :param ghidra.framework.plugintool.PluginTool toolToClose: The tool to close.
        """

    @typing.overload
    def closeTool(self, toolToClose: ghidra.framework.plugintool.PluginTool, ignoreChanges: typing.Union[jpype.JBoolean, bool]):
        ...

    def connectTools(self, producer: ghidra.framework.plugintool.PluginTool, consumer: ghidra.framework.plugintool.PluginTool) -> ghidra.framework.model.ToolConnection:
        ...

    def createDefaultTool(self) -> ghidra.framework.plugintool.PluginTool:
        """
        This method differs from :meth:`launchDefaultTool() <.launchDefaultTool>` in that this method does not set the
        ``tool`` variable in of this ``TestEnv`` instance.
        
        :return: the tool
        :rtype: ghidra.framework.plugintool.PluginTool
        """

    def disconnectTools(self, producer: ghidra.framework.plugintool.PluginTool, consumer: ghidra.framework.plugintool.PluginTool):
        ...

    def dispose(self):
        ...

    @staticmethod
    def findProvidedDataTypeArchive(relativePathName: typing.Union[java.lang.String, str]) -> generic.jar.ResourceFile:
        ...

    def getFrontEndProvider(self) -> docking.ComponentProvider:
        ...

    def getFrontEndTool(self) -> ghidra.framework.main.FrontEndTool:
        ...

    def getGhidraCreatedTools(self) -> jpype.JArray[ghidra.framework.plugintool.PluginTool]:
        """
        Returns an array of tools spawned by the Ghidra environment.
        NOTE: This array will not contain any of the TestTools!
        
        :return: an array of tools spawned by the Ghidra environment
        :rtype: jpype.JArray[ghidra.framework.plugintool.PluginTool]
        """

    def getGhidraProject(self) -> ghidra.base.project.GhidraProject:
        """
        Returns GhidraProject associated with this environment
        
        :return: the project
        :rtype: ghidra.base.project.GhidraProject
        """

    def getPlugin(self, c: java.lang.Class[T]) -> T:
        ...

    def getProgram(self, programName: typing.Union[java.lang.String, str]) -> ghidra.program.database.ProgramDB:
        """
        Open a read-only test program from the test data directory. The returned program must be 
        :meth:`released <.release>` prior to disposing this test environment.
         
        
        NOTE: Some tests rely on this method returning null when file does
        not yet exist within the resource area (e.g., test binaries for P-Code Tests)
        
        :param java.lang.String or str programName: name of program database within the test data directory.
        :return: program or null if program file not found
        :rtype: ghidra.program.database.ProgramDB
        """

    def getProject(self) -> ghidra.framework.model.Project:
        ...

    def getProjectManager(self) -> ghidra.framework.model.ProjectManager:
        ...

    def getTool(self) -> ghidra.framework.plugintool.PluginTool:
        """
        Get the tool associated with this test environment.
        
        :return: the default test tool for this environment
        :rtype: ghidra.framework.plugintool.PluginTool
        """

    def isProgramCached(self, programName: typing.Union[java.lang.String, str]) -> bool:
        """
        Determine if specified program already exists with the program cache
        
        :param java.lang.String or str programName: the name
        :return: true if specified program already exists with the program cache
        :rtype: bool
        """

    def launchAnotherDefaultTool(self) -> ghidra.framework.plugintool.PluginTool:
        """
        Launches another default tool, not overwriting this env's current tool.
        
        :return: the new tool
        :rtype: ghidra.framework.plugintool.PluginTool
        """

    @typing.overload
    def launchDefaultTool(self) -> ghidra.framework.plugintool.PluginTool:
        """
        Launches the default tool of the test system ("CodeBrowser").
        This method will load the tool from resources and **not from the
        user's Ghidra settings**.
         
        
        **Note:** Calling this method also changes the tool that this
        instance of the TestEnv is using, which is the reason for the existence
        of this method.
        
        :return: the tool that is launched
        :rtype: ghidra.framework.plugintool.PluginTool
        """

    @typing.overload
    def launchDefaultTool(self, program: ghidra.program.model.listing.Program) -> ghidra.framework.plugintool.PluginTool:
        """
        Launches the default tool of the test system ("CodeBrowser") using the
        given program.   This method will load the tool from resources and **not from the
        user's Ghidra settings**.
         
        
        **Note:** Calling this method also changes the tool that this
        instance of the TestEnv is using, which is the reason for the existence
        of this method.
        
        :param ghidra.program.model.listing.Program program: The program to load into the default tool; may be null
        :return: the tool that is launched
        :rtype: ghidra.framework.plugintool.PluginTool
        """

    @typing.overload
    def launchTool(self, toolName: typing.Union[java.lang.String, str]) -> ghidra.framework.plugintool.PluginTool:
        """
        Launches a tool of the given name using the given domain file.
         
        
        Note: the tool returned will have auto save disabled by default.
        
        :param java.lang.String or str toolName: the tool's name
        :return: the tool that is launched
        :rtype: ghidra.framework.plugintool.PluginTool
        """

    @typing.overload
    def launchTool(self, toolName: typing.Union[java.lang.String, str], domainFile: ghidra.framework.model.DomainFile) -> ghidra.framework.plugintool.PluginTool:
        """
        Launches a tool of the given name using the given domain file.
         
        
        Note: the tool returned will have auto save disabled by default.
        
        :param java.lang.String or str toolName: the name of the tool to launch
        :param ghidra.framework.model.DomainFile domainFile: The domain file used to launch the tool; may be null
        :return: the tool that is launched
        :rtype: ghidra.framework.plugintool.PluginTool
        """

    def launchToolWithURL(self, toolName: typing.Union[java.lang.String, str], ghidraUrl: java.net.URL) -> ghidra.framework.plugintool.PluginTool:
        """
        Launches a tool of the given name using the given Ghidra URL.
         
        
        Note: the tool returned will have auto save disabled by default.
        
        :param java.lang.String or str toolName: the name of the tool to launch
        :param java.net.URL ghidraUrl: The Ghidra URL to be opened in tool (see :obj:`GhidraURL`)
        :return: the tool that is launched
        :rtype: ghidra.framework.plugintool.PluginTool
        """

    def loadAnalyzedNotepad(self) -> ghidra.program.database.ProgramDB:
        ...

    @typing.overload
    def loadResourceProgramAsBinary(self, programName: typing.Union[java.lang.String, str], language: ghidra.program.model.lang.Language, compilerSpec: ghidra.program.model.lang.CompilerSpec) -> ghidra.program.model.listing.Program:
        ...

    @typing.overload
    def loadResourceProgramAsBinary(self, programName: typing.Union[java.lang.String, str], processor: ghidra.program.model.lang.Processor) -> ghidra.program.model.listing.Program:
        ...

    def open(self, program: ghidra.program.model.listing.Program):
        """
        Opens the given program in the test tool.
        
        :param ghidra.program.model.listing.Program program: the program to open
        """

    def release(self, program: ghidra.program.model.listing.Program):
        """
        Release a program which was obtained from this test environment.
        
        :param ghidra.program.model.listing.Program program: the program
        """

    def removeFromProgramCache(self, programName: typing.Union[java.lang.String, str]):
        """
        Remove specified program from cache
        
        :param java.lang.String or str programName: the name
        """

    def resetDefaultTools(self):
        ...

    def restartTool(self) -> ghidra.framework.plugintool.PluginTool:
        ...

    def restoreDataTypeArchive(self, relativePathName: typing.Union[java.lang.String, str], domainFolder: ghidra.framework.model.DomainFolder) -> ghidra.framework.model.DomainFile:
        """
        Creates a project data type archive in the indicated test project folder from the ".gdt"
        file indicated by the relative pathname.
        
        :param java.lang.String or str relativePathName: This should be a pathname relative to the "test_resources/testdata"
                director or relative to the "typeinfo" directory. The name should
                include the ".gdt" suffix.
        :param ghidra.framework.model.DomainFolder domainFolder: the folder in the test project where the archive should be created
        :return: the domain file  that was created in the project
        :rtype: ghidra.framework.model.DomainFile
        :raises java.lang.Exception: if an exception occurs
        """

    def restoreProgram(self, programName: typing.Union[java.lang.String, str]) -> ghidra.framework.model.DomainFile:
        """
        Copies the specified program zip file to the JUnit test project's root folder. **This
        means that the program will appear in the FrontEndTool as part of the project.**  That is
        the only reason to use this method vice openProgram().
        
        :param java.lang.String or str programName: the name of the program zip file without the ".gzf" extension.
        :return: the restored domain file
        :rtype: ghidra.framework.model.DomainFile
        :raises FileNotFoundException: if the program file cannot be found
        """

    def runScript(self, scriptFile: jpype.protocol.SupportsPath) -> ScriptTaskListener:
        ...

    def saveRestoreToolState(self):
        ...

    def saveToCache(self, progName: typing.Union[java.lang.String, str], program: ghidra.program.database.ProgramDB, replace: typing.Union[jpype.JBoolean, bool], monitor: ghidra.util.task.TaskMonitor):
        """
        Save a program to the cached program store.  A SaveAs will be performed on the
        program to its cached storage location.
        
        :param java.lang.String or str progName: program name
        :param ghidra.program.database.ProgramDB program: program object
        :param jpype.JBoolean or bool replace: if true any existing cached database with the same name will be replaced
        :param ghidra.util.task.TaskMonitor monitor: task monitor
        :raises java.lang.Exception: if already cached
        """

    def setAutoSaveEnabled(self, enabled: typing.Union[jpype.JBoolean, bool]):
        """
        Sets the auto-save feature for all tool instances running under the :obj:`FrontEndTool`
        created by this TestEnv instance.  Auto-save is off by default when testing.
        
        :param jpype.JBoolean or bool enabled: true enables auto-save
        """

    def showFrontEndTool(self) -> ghidra.framework.main.FrontEndTool:
        ...

    @typing.overload
    def showTool(self) -> ghidra.framework.plugintool.PluginTool:
        """
        Shows any previously created tool, creating a simple empty tool if not tool has yet
        been created.
         
         
        This method is considered sub-standard and users should prefer instead
        :meth:`launchDefaultTool() <.launchDefaultTool>` or :meth:`launchDefaultTool(Program) <.launchDefaultTool>`.
        
        :return: the newly shown tool
        :rtype: ghidra.framework.plugintool.PluginTool
        """

    @typing.overload
    def showTool(self, p: ghidra.program.model.listing.Program) -> ghidra.framework.plugintool.PluginTool:
        """
        Shows any previously created tool, creating a simple empty tool if not tool has yet
        been created.  The given program will be opened in the tool.
         
         
        This method is considered sub-standard and users should prefer instead
        :meth:`launchDefaultTool() <.launchDefaultTool>` or :meth:`launchDefaultTool(Program) <.launchDefaultTool>`.
        
        :param ghidra.program.model.listing.Program p: the program
        :return: the newly shown tool
        :rtype: ghidra.framework.plugintool.PluginTool
        """

    @deprecated("use instead AbstractDockingTest.waitForDialogComponent(Class)")
    def waitForDialogComponent(self, ghidraClass: java.lang.Class[T], maxTimeMS: typing.Union[jpype.JInt, int]) -> T:
        """
        Waits for the first window of the given class.  This method is the same as
        :meth:`waitForDialogComponent(Class, int) <.waitForDialogComponent>` with the exception that the parent
        window is assumed to be this instance's tool frame.
        
        :param java.lang.Class[T] ghidraClass: The class of the dialog the user desires
        :param jpype.JInt or int maxTimeMS: The max amount of time in milliseconds to wait for the requested dialog
                to appear.
        :return: The first occurrence of a dialog that extends the given ``ghidraClass``
        :rtype: T
        
        .. deprecated::
        
        use instead :meth:`AbstractDockingTest.waitForDialogComponent(Class) <AbstractDockingTest.waitForDialogComponent>`
        """

    def waitForWindow(self, title: typing.Union[java.lang.String, str], timeoutMS: typing.Union[jpype.JInt, int]) -> java.awt.Window:
        ...

    @property
    def projectManager(self) -> ghidra.framework.model.ProjectManager:
        ...

    @property
    def plugin(self) -> T:
        ...

    @property
    def ghidraCreatedTools(self) -> jpype.JArray[ghidra.framework.plugintool.PluginTool]:
        ...

    @property
    def frontEndProvider(self) -> docking.ComponentProvider:
        ...

    @property
    def programCached(self) -> jpype.JBoolean:
        ...

    @property
    def project(self) -> ghidra.framework.model.Project:
        ...

    @property
    def frontEndTool(self) -> ghidra.framework.main.FrontEndTool:
        ...

    @property
    def ghidraProject(self) -> ghidra.base.project.GhidraProject:
        ...

    @property
    def program(self) -> ghidra.program.database.ProgramDB:
        ...

    @property
    def tool(self) -> ghidra.framework.plugintool.PluginTool:
        ...


class TestProcessorConstants(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    PROCESSOR_8051: typing.Final[ghidra.program.model.lang.Processor]
    PROCESSOR_Z80: typing.Final[ghidra.program.model.lang.Processor]
    PROCESSOR_POWERPC: typing.Final[ghidra.program.model.lang.Processor]
    PROCESSOR_SPARC: typing.Final[ghidra.program.model.lang.Processor]
    PROCESSOR_X86: typing.Final[ghidra.program.model.lang.Processor]
    PROCESSOR_TMS320C3x: typing.Final[ghidra.program.model.lang.Processor]
    PROCESSOR_ARM: typing.Final[ghidra.program.model.lang.Processor]
    PROCESSOR_DATA: typing.Final[ghidra.program.model.lang.Processor]

    def __init__(self):
        ...


class AbstractGhidraHeadlessIntegrationTest(docking.test.AbstractDockingTest):

    class_: typing.ClassVar[java.lang.Class]
    PROJECT_NAME: typing.Final[java.lang.String]

    def __init__(self):
        ...

    @staticmethod
    def applyCmd(program: ghidra.program.model.listing.Program, cmd: ghidra.framework.cmd.Command[ghidra.program.model.listing.Program]) -> bool:
        """
        Run a command against the specified program within a transaction. The transaction will be
        committed unless the command throws a RollbackException.
        
        :param ghidra.program.model.listing.Program program: the program
        :param ghidra.framework.cmd.Command[ghidra.program.model.listing.Program] cmd: the command to apply
        :return: result of command applyTo method
        :rtype: bool
        :raises RollbackException: thrown if thrown by command applyTo method
        """

    @staticmethod
    def cleanDbTestDir():
        ...

    def clearSelection(self, tool: ghidra.framework.plugintool.PluginTool, p: ghidra.program.model.listing.Program):
        ...

    @staticmethod
    @typing.overload
    def createDefaultProgram(name: typing.Union[java.lang.String, str], languageString: typing.Union[java.lang.String, str], consumer: java.lang.Object) -> ghidra.program.database.ProgramDB:
        """
        Creates an in-memory program with the given language
        
        :param java.lang.String or str name: the program name
        :param java.lang.String or str languageString: a language string of the format ``x86:LE:32:default``
        :param java.lang.Object consumer: a consumer for the program
        :return: a new program
        :rtype: ghidra.program.database.ProgramDB
        :raises java.lang.Exception: if there is any issue creating the language
        """

    @staticmethod
    @typing.overload
    def createDefaultProgram(name: typing.Union[java.lang.String, str], languageString: typing.Union[java.lang.String, str], compilerSpecID: typing.Union[java.lang.String, str], consumer: java.lang.Object) -> ghidra.program.database.ProgramDB:
        """
        Creates an in-memory program with the given language
        
        :param java.lang.String or str name: the program name
        :param java.lang.String or str languageString: a language string of the format ``x86:LE:32:default``
        :param java.lang.String or str compilerSpecID: the ID
        :param java.lang.Object consumer: a consumer for the program
        :return: a new program
        :rtype: ghidra.program.database.ProgramDB
        :raises java.lang.Exception: if there is any issue creating the language
        """

    def debugProgramInTool(self, p: ghidra.program.model.listing.Program, address: typing.Union[java.lang.String, str]):
        """
        A convenience method that allows you to open the given program in a default tool, navigating
        to the given address.
        
         
        
        Note: this is a blocking operation. Your test will not proceed while this method is sleeping.
        
         
        
        **Do not leave this call in your test when committing changes.**
        
        :param ghidra.program.model.listing.Program p: the program
        :param java.lang.String or str address: the address
        :raises java.lang.Exception: if there is an issue create a :obj:`TestEnv`
        """

    @staticmethod
    def deleteProject(directory: typing.Union[java.lang.String, str], name: typing.Union[java.lang.String, str]) -> bool:
        ...

    @staticmethod
    def getLanguageCompilerSpecPair(oldLanguageName: typing.Union[java.lang.String, str]) -> ghidra.program.model.lang.LanguageCompilerSpecPair:
        """
        Get the language and compiler spec associated with an old language name string. If the
        language no longer exists, and suitable replacement language will be returned if found. If no
        language is found, an exception will be thrown.
        
        :param java.lang.String or str oldLanguageName: old language name string
        :return: the language compiler and spec
        :rtype: ghidra.program.model.lang.LanguageCompilerSpecPair
        :raises LanguageNotFoundException: if the language is not found
        """

    @staticmethod
    def getLanguageService() -> ghidra.program.model.lang.LanguageService:
        """
        Get language service used for testing.
        
        :return: language service.
        :rtype: ghidra.program.model.lang.LanguageService
        """

    @staticmethod
    def getPlugin(tool: ghidra.framework.plugintool.PluginTool, c: java.lang.Class[T]) -> T:
        ...

    @staticmethod
    def getSLEIGH_8051_LANGUAGE() -> ghidra.program.model.lang.Language:
        ...

    @staticmethod
    def getSLEIGH_X86_64_LANGUAGE() -> ghidra.program.model.lang.Language:
        ...

    @staticmethod
    def getSLEIGH_X86_LANGUAGE() -> ghidra.program.model.lang.Language:
        ...

    @typing.overload
    def getUniqueSymbol(self, program: ghidra.program.model.listing.Program, name: typing.Union[java.lang.String, str]) -> ghidra.program.model.symbol.Symbol:
        """
        Returns the global symbol with the given name if and only if it is the only global symbol
        with that name.
        
        :param ghidra.program.model.listing.Program program: the program to search.
        :param java.lang.String or str name: the name of the global symbol to find.
        :return: the global symbol with the given name if and only if it is the only one.
        :rtype: ghidra.program.model.symbol.Symbol
        """

    @typing.overload
    def getUniqueSymbol(self, program: ghidra.program.model.listing.Program, name: typing.Union[java.lang.String, str], namespace: ghidra.program.model.symbol.Namespace) -> ghidra.program.model.symbol.Symbol:
        """
        Returns the symbol in the given namespace with the given name if and only if it is the only
        symbol in that namespace with that name.
        
        :param ghidra.program.model.listing.Program program: the program to search.
        :param java.lang.String or str name: the name of the symbol to find.
        :param ghidra.program.model.symbol.Namespace namespace: the parent namespace; may be null
        :return: the symbol with the given name if and only if it is the only one in that namespace
        :rtype: ghidra.program.model.symbol.Symbol
        """

    @staticmethod
    def getZ80_LANGUAGE() -> ghidra.program.model.lang.Language:
        ...

    @typing.overload
    def goTo(self, tool: ghidra.framework.plugintool.PluginTool, p: ghidra.program.model.listing.Program, addr: ghidra.program.model.address.Address):
        ...

    @typing.overload
    def goTo(self, tool: ghidra.framework.plugintool.PluginTool, p: ghidra.program.model.listing.Program, addrString: typing.Union[java.lang.String, str]):
        ...

    @typing.overload
    def makeSelection(self, tool: ghidra.framework.plugintool.PluginTool, p: ghidra.program.model.listing.Program, addrs: java.util.List[ghidra.program.model.address.Address]):
        ...

    @typing.overload
    def makeSelection(self, tool: ghidra.framework.plugintool.PluginTool, p: ghidra.program.model.listing.Program, from_: ghidra.program.model.address.Address, to: ghidra.program.model.address.Address):
        ...

    @typing.overload
    def makeSelection(self, tool: ghidra.framework.plugintool.PluginTool, p: ghidra.program.model.listing.Program, *ranges: ghidra.program.model.address.AddressRange):
        ...

    @typing.overload
    def makeSelection(self, tool: ghidra.framework.plugintool.PluginTool, p: ghidra.program.model.listing.Program, addresses: ghidra.program.model.address.AddressSetView):
        ...

    @staticmethod
    @typing.overload
    def modifyProgram(p: ghidra.program.model.listing.Program, c: utility.function.ExceptionalCallback[E]):
        """
        Provides a convenient method for modifying the current program, handling the transaction
        logic. This method is calls :meth:`tx(DomainObject, ExceptionalCallback) <.tx>`, but helps with
        semantics.
        
        :param ghidra.program.model.listing.Program p: the program
        :param utility.function.ExceptionalCallback[E] c: the code to execute
        
        .. seealso::
        
            | :obj:`.modifyProgram(Program, ExceptionalFunction)`
        """

    @typing.overload
    def modifyProgram(self, program: ghidra.program.model.listing.Program, f: utility.function.ExceptionalFunction[ghidra.program.model.listing.Program, R, E]) -> R:
        """
        Provides a convenient method for modifying the current program, handling the transaction
        logic and returning a new item as a result
        
        :param ghidra.program.model.listing.Program program: the program
        :param utility.function.ExceptionalFunction[ghidra.program.model.listing.Program, R, E] f: the function for modifying the program and creating the desired result
        :return: the result
        :rtype: R
        
        .. seealso::
        
            | :obj:`.modifyProgram(Program, ExceptionalCallback)`
        """

    @staticmethod
    @typing.overload
    def redo(dobj: ghidra.framework.model.DomainObject, wait: typing.Union[jpype.JBoolean, bool]):
        """
        Redo the last undone transaction on the domain object and wait for all events to be flushed.
        
        :param ghidra.framework.model.DomainObject dobj: The domain object upon which to perform the redo.
        :param jpype.JBoolean or bool wait: if true, wait for redo to fully complete in Swing thread. If a modal dialog may
                    result from this redo, wait should be set false.
        """

    @staticmethod
    @typing.overload
    def redo(dobj: ghidra.framework.model.DomainObject):
        """
        Redo the last undone transaction on domain object and wait for all events to be flushed.
        
        :param ghidra.framework.model.DomainObject dobj: The domain object upon which to perform the redo.
        """

    @staticmethod
    @typing.overload
    def redo(dobj: ghidra.framework.model.DomainObject, count: typing.Union[jpype.JInt, int]):
        """
        Redo the last 'count' undone transactions on the domain object and wait for all events to be
        flushed.
        
        :param ghidra.framework.model.DomainObject dobj: The domain object upon which to perform the redo.
        :param jpype.JInt or int count: number of transactions to redo
        """

    @staticmethod
    def replaceService(tool: ghidra.framework.plugintool.PluginTool, service: java.lang.Class[T], replacement: T):
        """
        Replaces the given implementations of the provided service class with the given class.
        
        :param ghidra.framework.plugintool.PluginTool tool: the tool whose services to update (optional)
        :param java.lang.Class[T] service: the service to override
        :param T replacement: the new version of the service
        :param T: the service type
        """

    @typing.overload
    def toAddressSet(self, p: ghidra.program.model.listing.Program, from_: typing.Union[java.lang.String, str], to: typing.Union[java.lang.String, str]) -> ghidra.program.model.address.AddressSet:
        ...

    @typing.overload
    def toAddressSet(self, addrs: java.util.List[ghidra.program.model.address.Address]) -> ghidra.program.model.address.AddressSet:
        ...

    @typing.overload
    def toAddressSet(self, start: ghidra.program.model.address.Address, end: ghidra.program.model.address.Address) -> ghidra.program.model.address.AddressSet:
        ...

    @typing.overload
    def toAddressSet(self, *ranges: ghidra.program.model.address.AddressRange) -> ghidra.program.model.address.AddressSet:
        ...

    @staticmethod
    @typing.overload
    def tx(dobj: ghidra.framework.model.DomainObject, c: utility.function.ExceptionalCallback[E]):
        """
        Provides a convenient method for modifying the current program, handling the transaction
        logic.
        
        :param ghidra.framework.model.DomainObject dobj: the domain object (e.g., a program)
        :param utility.function.ExceptionalCallback[E] c: the code to execute
        
        .. seealso::
        
            | :obj:`.modifyProgram(Program, ExceptionalCallback)`
        
            | :obj:`.modifyProgram(Program, ExceptionalFunction)`
        """

    @staticmethod
    @typing.overload
    def tx(dtm: ghidra.program.model.data.DataTypeManager, c: utility.function.ExceptionalCallback[E]):
        """
        Provides a convenient method for modifying the given data type manager, handling the 
        transaction logic.
        
        :param ghidra.program.model.data.DataTypeManager dtm: the data type manager
        :param utility.function.ExceptionalCallback[E] c: the code to execute
        
        .. seealso::
        
            | :obj:`.modifyProgram(Program, ExceptionalCallback)`
        
            | :obj:`.modifyProgram(Program, ExceptionalFunction)`
        """

    @staticmethod
    @typing.overload
    def tx(p: ghidra.program.model.listing.Program, s: utility.function.ExceptionalSupplier[T, E]) -> T:
        """
        Provides a convenient method for modifying the current program, handling the transaction
        logic and returning a result.
        
        :param T: the return type:param E: the exception type:param ghidra.program.model.listing.Program p: the program
        :param utility.function.ExceptionalSupplier[T, E] s: the code to execute
        :return: the supplier's return value
        :rtype: T
        
        .. seealso::
        
            | :obj:`.modifyProgram(Program, ExceptionalCallback)`
        
            | :obj:`.modifyProgram(Program, ExceptionalFunction)`
        """

    @staticmethod
    @typing.overload
    def undo(dobj: ghidra.framework.model.DomainObject, wait: typing.Union[jpype.JBoolean, bool]):
        """
        Undo the last transaction on the domain object and wait for all events to be flushed.
        
        :param ghidra.framework.model.DomainObject dobj: The domain object upon which to perform the undo.
        :param jpype.JBoolean or bool wait: if true, wait for undo to fully complete in Swing thread. If a modal dialog may
                    result from this undo, wait should be set false.
        """

    @staticmethod
    @typing.overload
    def undo(dobj: ghidra.framework.model.DomainObject, name: typing.Union[java.lang.String, str]):
        """
        Undo the last transaction on the domain object and wait for all events to be flushed.  This
        method takes the undo item name, which is used to find the undo item.  Once found, all items
        before and including that undo item will be undone.
        
        :param ghidra.framework.model.DomainObject dobj: The domain object upon which to perform the undo.
        :param java.lang.String or str name: the name of the undo item on the stack.
        """

    @staticmethod
    @typing.overload
    def undo(dobj: ghidra.framework.model.DomainObject):
        """
        Undo the last transaction on the domain object and wait for all events to be flushed.
        
        :param ghidra.framework.model.DomainObject dobj: The domain object upon which to perform the undo.
        """

    @staticmethod
    @typing.overload
    def undo(dobj: ghidra.framework.model.DomainObject, count: typing.Union[jpype.JInt, int]):
        """
        Undo the last 'count' transactions on the domain object and wait for all events to be
        flushed.
        
        :param ghidra.framework.model.DomainObject dobj: The domain object upon which to perform the undo.
        :param jpype.JInt or int count: number of transactions to undo
        """

    def waitForScriptCompletion(self, listener: ScriptTaskListener, timeoutMS: typing.Union[jpype.JLong, int]):
        """
        Waits for a launched script to complete by using the given listener.
        
        :param ScriptTaskListener listener: the listener used to track script progress
        :param jpype.JLong or int timeoutMS: the max time to wait; failing if exceeded
        """


class ToyProgramBuilder(ghidra.program.database.ProgramBuilder):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], languageName: typing.Union[java.lang.String, str], consumer: java.lang.Object):
        """
        Construct toy program builder using specified toy language
        
        :param java.lang.String or str name: program name
        :param java.lang.String or str languageName: toy language ID (note: only builder variant supports all instructions)
        :param java.lang.Object consumer: program consumer (if null this builder will be used as consumer and must be disposed to release program)
        :raises java.lang.Exception:
        """

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], bigEndian: typing.Union[jpype.JBoolean, bool]):
        """
        Construct toy program builder using toy language "builder" variant.
        This builder will be the program consumer and must be disposed
        
        :param java.lang.String or str name: program name
        :param jpype.JBoolean or bool bigEndian: language endianness
        :raises java.lang.Exception:
        """

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], bigEndian: typing.Union[jpype.JBoolean, bool], consumer: java.lang.Object):
        """
        Construct toy program builder using toy language "builder" variant.
        This builder will be the program consumer and must be disposed
        
        :param java.lang.String or str name: program name
        :param jpype.JBoolean or bool bigEndian: language endianness
        :param java.lang.Object consumer: program consumer (if null this builder will be used as consumer and must be disposed to release program)
        :raises java.lang.Exception:
        """

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], bigEndian: typing.Union[jpype.JBoolean, bool], wordAligned: typing.Union[jpype.JBoolean, bool], consumer: java.lang.Object):
        """
        Construct toy program builder using toy language "builder" variant.
        This builder will be the program consumer and must be disposed
        
        :param java.lang.String or str name: program name
        :param jpype.JBoolean or bool bigEndian: language endianness
        :param java.lang.Object consumer: program consumer (if null this builder will be used as consumer and must be disposed to release program)
        :raises java.lang.Exception:
        """

    @typing.overload
    def addBytesBadInstruction(self, offset: typing.Union[jpype.JLong, int]):
        """
        Add BAD instruction (consumes 2-bytes).  Location will not be added to
        defined instruction address list.
        
        :param jpype.JLong or int offset: bad instruction address offset
        :raises MemoryAccessException:
        """

    @typing.overload
    def addBytesBadInstruction(self, addr: typing.Union[java.lang.String, str]):
        """
        Add BAD instruction (consumes 2-bytes).  Location will not be added to
        defined instruction address list.
        
        :param java.lang.String or str addr: bad instruction address
        :raises MemoryAccessException:
        """

    @typing.overload
    def addBytesBranch(self, offset: typing.Union[jpype.JLong, int], dest: typing.Union[jpype.JLong, int]):
        """
        Add branch (consumes 2-bytes)
        
        :param jpype.JLong or int offset: address offset
        :param jpype.JLong or int dest: call destination offset
        :raises MemoryAccessException:
        """

    @typing.overload
    def addBytesBranch(self, addr: typing.Union[java.lang.String, str], destAddr: typing.Union[java.lang.String, str]):
        """
        Add branch (consumes 2-bytes)
        
        :param java.lang.String or str addr: instruction address offset
        :param java.lang.String or str destAddr: call destination address
        :raises MemoryAccessException:
        """

    @typing.overload
    def addBytesBranchConditional(self, offset: typing.Union[jpype.JLong, int], dest: typing.Union[jpype.JLong, int]):
        """
        Add branch (consumes 2-bytes)
        
        :param jpype.JLong or int offset: instruction address offset
        :param jpype.JLong or int dest: call destination offset
        :raises MemoryAccessException:
        """

    @typing.overload
    def addBytesBranchConditional(self, addr: typing.Union[java.lang.String, str], destAddr: typing.Union[java.lang.String, str]):
        """
        Add branch (consumes 2-bytes)
        
        :param java.lang.String or str addr: instruction address
        :param java.lang.String or str destAddr: call destination address
        :raises MemoryAccessException:
        """

    @typing.overload
    def addBytesBranchWithDelaySlot(self, offset: typing.Union[jpype.JLong, int], dest: typing.Union[jpype.JLong, int]):
        """
        Add branch w/ delay slot (consumes 4-bytes)
        
        :param jpype.JLong or int offset: instruction address offset
        :param jpype.JLong or int dest: call destination offset
        :raises MemoryAccessException:
        """

    @typing.overload
    def addBytesBranchWithDelaySlot(self, addr: typing.Union[java.lang.String, str], destAddr: typing.Union[java.lang.String, str]):
        """
        Add branch w/ delay slot (consumes 4-bytes)
        
        :param java.lang.String or str addr: instruction address
        :param java.lang.String or str destAddr: call destination address
        :raises MemoryAccessException:
        """

    @typing.overload
    def addBytesCall(self, offset: typing.Union[jpype.JLong, int], dest: typing.Union[jpype.JLong, int]):
        """
        Add call (consumes 2-bytes)
        
        :param jpype.JLong or int offset: instruction address offset
        :param jpype.JLong or int dest: call destination offset
        :raises MemoryAccessException:
        """

    @typing.overload
    def addBytesCall(self, offset: typing.Union[java.lang.String, str], dest: typing.Union[jpype.JLong, int]):
        """
        Add call (consumes 2-bytes)
        
        :param java.lang.String or str offset: instruction address offset
        :param jpype.JLong or int dest: call destination offset
        :raises MemoryAccessException:
        """

    @typing.overload
    def addBytesCall(self, addr: typing.Union[java.lang.String, str], destAddr: typing.Union[java.lang.String, str]):
        """
        Add call (consumes 2-bytes)
        
        :param java.lang.String or str addr: instruction address
        :param java.lang.String or str destAddr: call destination address
        :raises MemoryAccessException:
        """

    @typing.overload
    def addBytesCallWithDelaySlot(self, offset: typing.Union[jpype.JLong, int], dest: typing.Union[jpype.JLong, int]):
        """
        Add call w/ delayslot (consumes 4-bytes)
        
        :param jpype.JLong or int offset: instruction address offset
        :param jpype.JLong or int dest: call destination offset
        :raises MemoryAccessException:
        """

    @typing.overload
    def addBytesCallWithDelaySlot(self, addr: typing.Union[java.lang.String, str], destAddr: typing.Union[java.lang.String, str]):
        """
        Add call w/ delayslot (consumes 4-bytes)
        
        :param java.lang.String or str addr: instruction address
        :param java.lang.String or str destAddr: call destination address
        :raises MemoryAccessException:
        """

    @typing.overload
    def addBytesCopInstruction(self, offset: typing.Union[jpype.JLong, int]):
        """
        Add COP instruction for exercising nfctx context (consumes 2-bytes).  Location will not be added to
        defined instruction address list.
        
        :param jpype.JLong or int offset: instruction address offset
        :raises MemoryAccessException:
        """

    @typing.overload
    def addBytesCopInstruction(self, addr: typing.Union[java.lang.String, str]):
        """
        Add COP instruction for exercising nfctx context (consumes 2-bytes).  Location will not be added to
        defined instruction address list.
        
        :param java.lang.String or str addr: instruction address
        :raises MemoryAccessException:
        """

    @typing.overload
    def addBytesFallthrough(self, offset: typing.Union[jpype.JLong, int]):
        """
        Add simple fall-through (consumes 2-bytes)
        
        :param jpype.JLong or int offset: instruction address offset
        :raises MemoryAccessException:
        """

    @typing.overload
    def addBytesFallthrough(self, addr: typing.Union[java.lang.String, str]):
        """
        Add simple fall-through (consumes 2-bytes)
        
        :param java.lang.String or str addr: instruction address
        :raises MemoryAccessException:
        """

    @typing.overload
    def addBytesFallthroughSetFlowContext(self, offset: typing.Union[jpype.JLong, int], ctxVal: typing.Union[jpype.JInt, int]):
        """
        Add simple fall-through which sets flowing context value on next instruction (consumes 2-bytes)
        
        :param jpype.JLong or int offset: instruction address offset
        :param jpype.JInt or int ctxVal: context value (0-15)
        :raises MemoryAccessException:
        """

    @typing.overload
    def addBytesFallthroughSetFlowContext(self, addr: typing.Union[java.lang.String, str], ctxVal: typing.Union[jpype.JInt, int]):
        """
        Add simple fall-through which sets flowing context value on next instruction (consumes 2-bytes)
        
        :param java.lang.String or str addr: instruction address
        :param jpype.JInt or int ctxVal: context value (0-15)
        :raises MemoryAccessException:
        """

    @typing.overload
    def addBytesFallthroughSetNoFlowContext(self, offset: typing.Union[jpype.JLong, int], ctxVal: typing.Union[jpype.JInt, int]):
        """
        Add simple fall-through which sets noflow context value on next instruction (consumes 2-bytes)
        
        :param jpype.JLong or int offset: instruction address offset
        :param jpype.JInt or int ctxVal: context value (0-15)
        :raises MemoryAccessException:
        """

    @typing.overload
    def addBytesFallthroughSetNoFlowContext(self, addr: typing.Union[java.lang.String, str], ctxVal: typing.Union[jpype.JInt, int]):
        """
        Add simple fall-through which sets noflow context value on next instruction (consumes 2-bytes)
        
        :param java.lang.String or str addr: instruction address
        :param jpype.JInt or int ctxVal: context value (0-15)
        :raises MemoryAccessException:
        """

    @typing.overload
    def addBytesFallthroughSetNoFlowContext(self, offset: typing.Union[jpype.JLong, int], ctxVal: typing.Union[jpype.JInt, int], target: typing.Union[jpype.JLong, int]):
        """
        Add simple fall-through which sets noflow context value on target address (consumes 2-bytes)
        
        :param jpype.JLong or int offset: instruction address offset
        :param jpype.JInt or int ctxVal: context value (0-15)
        :param jpype.JLong or int target: context target address offset
        :raises MemoryAccessException:
        """

    @typing.overload
    def addBytesFallthroughSetNoFlowContext(self, addr: typing.Union[java.lang.String, str], ctxVal: typing.Union[jpype.JInt, int], targetAddr: typing.Union[java.lang.String, str]):
        """
        Add simple fall-through which sets noflow context value on target address (consumes 2-bytes)
        
        :param java.lang.String or str addr: instruction address
        :param jpype.JInt or int ctxVal: context value (0-15)
        :param java.lang.String or str targetAddr: context target address
        :raises MemoryAccessException:
        """

    @typing.overload
    def addBytesLoad(self, offset: typing.Union[jpype.JLong, int], srcRegIndex: typing.Union[jpype.JInt, int], destRegIndex: typing.Union[jpype.JInt, int]):
        """
        Add load indirect (consumes 2-bytes)
        
        :param jpype.JLong or int offset: instruction address offset
        :param jpype.JInt or int srcRegIndex: source register index (contained indirect memory address) (0..15)
        :param jpype.JInt or int destRegIndex: destination register index (0..15)
        :raises MemoryAccessException:
        """

    @typing.overload
    def addBytesLoad(self, addr: typing.Union[java.lang.String, str], srcRegIndex: typing.Union[jpype.JInt, int], destRegIndex: typing.Union[jpype.JInt, int]):
        """
        Add load indirect (consumes 2-bytes)
        
        :param java.lang.String or str addr: instruction address
        :param jpype.JInt or int srcRegIndex: source register index (contained indirect memory address) (0..15)
        :param jpype.JInt or int destRegIndex: destination register index (0..15)
        :raises MemoryAccessException:
        """

    @typing.overload
    def addBytesMoveImmediate(self, offset: typing.Union[jpype.JLong, int], imm: typing.Union[jpype.JShort, int]):
        """
        Add move immediate instruction (consumes 2-bytes)
        
        :param jpype.JLong or int offset: instruction offset
        :param jpype.JShort or int imm: immediate byte value
        :raises MemoryAccessException:
        """

    @typing.overload
    def addBytesMoveImmediate(self, addr: typing.Union[java.lang.String, str], imm: typing.Union[jpype.JShort, int]):
        """
        Add move immediate instruction (consumes 2-bytes)
        
        :param java.lang.String or str addr: instruction address
        :param jpype.JShort or int imm: immediate byte value
        :raises MemoryAccessException:
        """

    @typing.overload
    def addBytesNOP(self, offset: typing.Union[jpype.JLong, int], length: typing.Union[jpype.JInt, int]):
        """
        Add NOP instruction bytes of specified byte length
        
        :param jpype.JLong or int offset: instruction address offset
        :param jpype.JInt or int length: length of NOP instruction in bytes
        :raises MemoryAccessException:
        """

    @typing.overload
    def addBytesNOP(self, addr: typing.Union[java.lang.String, str], length: typing.Union[jpype.JInt, int]):
        """
        Add NOP instruction bytes of specified byte length
        
        :param java.lang.String or str addr: instruction address
        :param jpype.JInt or int length: length of NOP instruction in bytes
        :raises MemoryAccessException:
        """

    @typing.overload
    def addBytesReturn(self, offset: typing.Union[jpype.JLong, int]):
        """
        Add terminal/return (consumes 2-bytes)
        
        :param jpype.JLong or int offset: instruction address offset
        :raises MemoryAccessException:
        """

    @typing.overload
    def addBytesReturn(self, addr: typing.Union[java.lang.String, str]):
        """
        Add terminal/return (consumes 2-bytes)
        
        :param java.lang.String or str addr: instruction address
        :raises MemoryAccessException:
        """

    @typing.overload
    def addBytesSkipConditional(self, offset: typing.Union[jpype.JLong, int]):
        """
        Add conditional skip (consumes 2-bytes)
        
        :param jpype.JLong or int offset: instruction address offset
        :raises MemoryAccessException:
        """

    @typing.overload
    def addBytesSkipConditional(self, addr: typing.Union[java.lang.String, str]):
        """
        Add conditional skip (consumes 2-bytes)
        
        :param java.lang.String or str addr: instruction address
        :raises MemoryAccessException:
        """

    @typing.overload
    def addBytesStore(self, offset: typing.Union[jpype.JLong, int], srcRegIndex: typing.Union[jpype.JInt, int], destRegIndex: typing.Union[jpype.JInt, int]):
        """
        Add store indirect (consumes 2-bytes)
        
        :param jpype.JLong or int offset: instruction address offset
        :param jpype.JInt or int srcRegIndex: source register index (0..15)
        :param jpype.JInt or int destRegIndex: destination register index (contained indirect memory address)  (0..15)
        :raises MemoryAccessException:
        """

    @typing.overload
    def addBytesStore(self, addr: typing.Union[java.lang.String, str], srcRegIndex: typing.Union[jpype.JInt, int], destRegIndex: typing.Union[jpype.JInt, int]):
        """
        Add store indirect (consumes 2-bytes)
        
        :param java.lang.String or str addr: instruction address
        :param jpype.JInt or int srcRegIndex: source register index (0..15)
        :param jpype.JInt or int destRegIndex: destination register index (contained indirect memory address)  (0..15)
        :raises MemoryAccessException:
        """

    def createCallInstruction(self, address: typing.Union[java.lang.String, str], callAddress: typing.Union[java.lang.String, str]):
        ...

    def createConditionalJmpInstruction(self, address: typing.Union[java.lang.String, str], destAddress: typing.Union[java.lang.String, str]):
        ...

    def createJmpInstruction(self, address: typing.Union[java.lang.String, str], destAddress: typing.Union[java.lang.String, str]):
        ...

    def createJmpWithDelaySlot(self, address: typing.Union[java.lang.String, str], destAddress: typing.Union[java.lang.String, str]):
        ...

    def createNOPInstruction(self, address: typing.Union[java.lang.String, str], size: typing.Union[jpype.JInt, int]):
        ...

    def createReturnInstruction(self, address: typing.Union[java.lang.String, str]):
        ...

    def getAddress(self, offset: typing.Union[jpype.JLong, int]) -> ghidra.program.model.address.Address:
        """
        Get address in default ram space
        
        :param jpype.JLong or int offset: address offset
        :return: the address
        :rtype: ghidra.program.model.address.Address
        """

    def getDefinedInstructionAddress(self) -> java.util.List[ghidra.program.model.address.Address]:
        """
        Get locations where instruction bytes have been added
        
        :return: instruction start locations
        :rtype: java.util.List[ghidra.program.model.address.Address]
        """

    def resetDefinedInstructionAddresses(self):
        """
        Reset/clear the list of defined instruction addresses
        """

    @property
    def address(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def definedInstructionAddress(self) -> java.util.List[ghidra.program.model.address.Address]:
        ...


class ClassicSampleX86ProgramBuilder(ghidra.program.database.ProgramBuilder):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        Construct sample program builder using the x86 language and default compiler spec.
        A set of predefined memory bytes, code units and functions will be added.
        This builder object will be the program consumer and must be disposed to properly
        release the program.
        
        :raises java.lang.Exception: if an unexpected exception happens
        """

    @typing.overload
    def __init__(self, disableAnalysis: typing.Union[jpype.JBoolean, bool]):
        """
        Construct sample program builder using the x86 language and default compiler spec.
        A set of predefined memory bytes, code units and functions will be added.
        This builder object will be the program consumer and must be disposed to properly
        release the program.
        
        :param jpype.JBoolean or bool disableAnalysis: if true, the analysis manager will be disabled
        :raises java.lang.Exception: if an unexpected exception happens
        """

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], disableAnalysis: typing.Union[jpype.JBoolean, bool]):
        """
        Construct sample program builder using the x86 language and default compiler spec.
        A set of predefined memory bytes, code units and functions will be added.
        This builder object will be the program consumer and must be disposed to properly
        release the program.
        
        :param java.lang.String or str name: program name
        :param jpype.JBoolean or bool disableAnalysis: if true, the analysis manager will be disabled
        :raises java.lang.Exception: if an unexpected exception happens
        """

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], disableAnalysis: typing.Union[jpype.JBoolean, bool], consumer: java.lang.Object):
        """
        Construct sample program builder using the x86 language and default compiler spec.
        A set of predefined memory bytes, code units and functions will be added.
        
        :param java.lang.String or str name: program name
        :param jpype.JBoolean or bool disableAnalysis: if true, the analysis manager will be disabled
        :param java.lang.Object consumer: program consumer (if null this builder will be used as consumer and must be disposed to release program)
        :raises java.lang.Exception:
        """


class ProjectTestUtils(java.lang.Object):
    """
    Ghidra framework and program test utilities
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def createProgramFile(proj: ghidra.framework.model.Project, progName: typing.Union[java.lang.String, str], language: ghidra.program.model.lang.Language, compilerSpec: ghidra.program.model.lang.CompilerSpec, folder: ghidra.framework.model.DomainFolder) -> ghidra.framework.model.DomainFile:
        """
        Create an empty program file within the specified project folder.
        
        :param ghidra.framework.model.Project proj: active project.
        :param java.lang.String or str progName: name of program and domain file to be created.
        :param ghidra.program.model.lang.Language language: a specified language, or 0 if it does not matter.
        :param ghidra.program.model.lang.CompilerSpec compilerSpec: the compiler spec
        :param ghidra.framework.model.DomainFolder folder: domain folder within the specified project which the
        user has permission to write.  If null, the root data folder will be used.
        :return: new domain file.
        :rtype: ghidra.framework.model.DomainFile
        :raises InvalidNameException: if the filename is invalid
        :raises CancelledException: if the opening is cancelled
        :raises LanguageNotFoundException: if the language cannot be found
        :raises IOException: if there is an exception creating the program or domain file
        """

    @staticmethod
    def deleteProject(directory: typing.Union[java.lang.String, str], name: typing.Union[java.lang.String, str]) -> bool:
        """
        Remove entire project.  Note: this will not remove the parent ``directory`` of
        the project.
        
        :param java.lang.String or str directory: directory of the project.
        :param java.lang.String or str name: The name of the project to delete
        :return: True if the project was deleted.
        :rtype: bool
        """

    @staticmethod
    def deleteTool(project: ghidra.framework.model.Project, toolName: typing.Union[java.lang.String, str]) -> bool:
        """
        Remove the specified tool if it exists.
        
        :param ghidra.framework.model.Project project: the project
        :param java.lang.String or str toolName: the tool name
        :return: true if it existed and was removed from the local tool chest.
        :rtype: bool
        """

    @staticmethod
    def getProject(directory: typing.Union[java.lang.String, str], name: typing.Union[java.lang.String, str]) -> ghidra.framework.model.Project:
        """
        Open the project for the given directory and name.
        If the project does not exist, create one. 
        Only once instance of a given project may be open at any given
        point in time.  Be sure to close the project if you will be
        re-opening.
        
        :param java.lang.String or str directory: directory for the project
        :param java.lang.String or str name: name of the project
        :return: the project
        :rtype: ghidra.framework.model.Project
        :raises IOException: if there was a problem creating the project
        :raises LockException: if the project is already open
        :raises IllegalArgumentException: if the name has illegal characters such that a URL could
        not be created
        """

    @staticmethod
    def getTool(project: ghidra.framework.model.Project, toolName: typing.Union[java.lang.String, str]) -> ghidra.framework.plugintool.PluginTool:
        """
        Launch a tool.
        
        :param ghidra.framework.model.Project project: the project to which the tool belongs
        :param java.lang.String or str toolName: name of the tool to get from the active workspace.
        If null, launch a new empty tool in the active workspace.
        :return: the tool
        :rtype: ghidra.framework.plugintool.PluginTool
        """

    @staticmethod
    def saveTool(project: ghidra.framework.model.Project, tool: ghidra.framework.plugintool.PluginTool) -> ghidra.framework.model.ToolTemplate:
        """
        Save a tool to the project tool chest.
        
        :param ghidra.framework.model.Project project: The project which with the tool is associated.
        :param ghidra.framework.plugintool.PluginTool tool: The tool to be saved
        :return: The tool template for the given tool.
        :rtype: ghidra.framework.model.ToolTemplate
        """


class ScriptTaskListener(ghidra.util.task.TaskListener):
    ...
    class_: typing.ClassVar[java.lang.Class]



__all__ = ["AbstractProgramBasedTest", "TestTool", "AbstractGhidraHeadedIntegrationTest", "TestProgramManager", "TestEnv", "TestProcessorConstants", "AbstractGhidraHeadlessIntegrationTest", "ToyProgramBuilder", "ClassicSampleX86ProgramBuilder", "ProjectTestUtils", "ScriptTaskListener"]
