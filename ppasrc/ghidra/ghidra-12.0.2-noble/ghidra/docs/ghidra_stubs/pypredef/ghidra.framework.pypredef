from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import generic.jar
import ghidra.framework.model
import ghidra.util
import ghidra.util.classfinder
import ghidra.util.task
import java.io # type: ignore
import java.lang # type: ignore
import java.util # type: ignore
import utility.application


T = typing.TypeVar("T")


class GhidraApplicationConfiguration(HeadlessGhidraApplicationConfiguration):

    @typing.type_check_only
    class StatusReportingTaskMonitor(ghidra.util.task.TaskMonitorAdapter):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def setShowSplashScreen(self, b: typing.Union[jpype.JBoolean, bool]):
        ...


class HeadlessGhidraApplicationConfiguration(ApplicationConfiguration):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class ToolUtils(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    TOOL_EXTENSION: typing.Final = ".tool"

    @staticmethod
    def deleteTool(template: ghidra.framework.model.ToolTemplate):
        ...

    @staticmethod
    def getAllApplicationTools() -> java.util.Set[ghidra.framework.model.ToolTemplate]:
        """
        Returns all tools found in the classpath that live under a root
        'defaultTools' directory or a root 'extraTools' directory
        
        :return: the tools
        :rtype: java.util.Set[ghidra.framework.model.ToolTemplate]
        """

    @staticmethod
    def getApplicationToolDirPath() -> str:
        """
        Returns the user's personal tool chest directory path
        
        :return: the path
        :rtype: str
        """

    @staticmethod
    def getDefaultApplicationTools() -> java.util.Set[ghidra.framework.model.ToolTemplate]:
        """
        Returns all tools found in the classpath that live under a root
        'defaultTools' directory
        
        :return: the default tools
        :rtype: java.util.Set[ghidra.framework.model.ToolTemplate]
        """

    @staticmethod
    def getExtraApplicationTools() -> java.util.Set[ghidra.framework.model.ToolTemplate]:
        """
        Returns all tools found in the classpath that live under a root
        'extraTools' directory
        
        :return: the extra tools
        :rtype: java.util.Set[ghidra.framework.model.ToolTemplate]
        """

    @staticmethod
    def getToolFile(name: typing.Union[java.lang.String, str]) -> java.io.File:
        ...

    @staticmethod
    def getUniqueToolName(template: ghidra.framework.model.ToolTemplate) -> str:
        ...

    @staticmethod
    def getUserToolsDirectory() -> java.io.File:
        ...

    @staticmethod
    def loadUserTools() -> java.util.Map[java.lang.String, ghidra.framework.model.ToolTemplate]:
        ...

    @staticmethod
    @typing.overload
    def readToolTemplate(toolFile: jpype.protocol.SupportsPath) -> ghidra.framework.model.ToolTemplate:
        ...

    @staticmethod
    @typing.overload
    def readToolTemplate(resourceFileName: typing.Union[java.lang.String, str]) -> ghidra.framework.model.ToolTemplate:
        ...

    @staticmethod
    def removeInvalidPlugins(template: ghidra.framework.model.ToolTemplate):
        ...

    @staticmethod
    def renameToolTemplate(toolTemplate: ghidra.framework.model.ToolTemplate, newName: typing.Union[java.lang.String, str]):
        ...

    @staticmethod
    def writeToolTemplate(template: ghidra.framework.model.ToolTemplate) -> bool:
        ...


class ShutdownHookRegistry(java.lang.Object):

    class ShutdownHook(java.lang.Comparable[ShutdownHookRegistry.ShutdownHook]):
        """
        ``ShutdownHook`` wrapper class for shutdown callback
        """

        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def addShutdownHook(r: java.lang.Runnable, priority: ShutdownPriority) -> ShutdownHookRegistry.ShutdownHook:
        """
        Install a shutdown hook at the specified priority.  If the hook has no specific 
        priority or sensitivity to when it runs, the standard Java Runtime shutdown hook
        mechanism should be used.
        Hooks with a higher priority value will run first
        
        :param java.lang.Runnable r: shutdown hook runnable
        :param ShutdownPriority priority: relative priority
        """

    @staticmethod
    def removeShutdownHook(hook: ShutdownHookRegistry.ShutdownHook):
        """
        Remove a shutdown hook previously registered.
        Hooks with a higher priority value will run first
        
        :param ShutdownHookRegistry.ShutdownHook hook: shutdown hook
        """


class LoggingInitialization(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    LOG4J2_CONFIGURATION_PROPERTY: typing.Final = "log4j.configurationFile"

    def __init__(self):
        ...

    @staticmethod
    def getApplicationLogFile() -> java.io.File:
        """
        Returns the default file used for logging messages.
        
        :return: the file
        :rtype: java.io.File
        """

    @staticmethod
    def getScriptLogFile() -> java.io.File:
        """
        Returns the default file used for logging messages.
        
        :return: the file
        :rtype: java.io.File
        """

    @staticmethod
    def initializeLoggingSystem():
        ...

    @staticmethod
    def reinitialize():
        """
        Signals to reload the log settings from the log configuration files in use.  This is useful
        for tests that wish to temporarily change log settings, restoring them when done.
         
        
        This method will do nothing if :meth:`initializeLoggingSystem() <.initializeLoggingSystem>` has not been called.
        """


class ModuleInitializer(ghidra.util.classfinder.ExtensionPoint, java.lang.Runnable):
    """
    An :obj:`ExtensionPoint` that users can implement to perform work before the application
    is loaded.
     
     
            To create a module initializer:
            
            1) Implement ModuleInitializer.java
            2) Have the name of your implementation end with the keyword 'Initializer'
    """

    class_: typing.ClassVar[java.lang.Class]

    def getName(self) -> str:
        """
        
        
        :return: initializer name
        :rtype: str
        """

    @property
    def name(self) -> java.lang.String:
        ...


class Log4jErrorLogger(ghidra.util.ErrorLogger):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class TestApplicationUtils(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def getInstallationDirectory() -> java.io.File:
        """
        Returns the directory containing the installation of this application.   The value returned
        here will either be an actual installation directory or the parent directory of a cloned
        repository.  This method will work in the various modes of operation, including:
         
        * Development Mode - running from a repo clone, from inside of an IDE or the 
        command-line.   In this mode a sample directory structure is:
        
                /.../git_repos/ghidra_clone/ghidra/Ghidra/Features/Base/src/...
         
                which means this method will return 'ghidra_clone'
         
        * Batch Testing Mode - running from a test server, but not from inside a 
        complete build.  This mode uses jar files for the compiled source code, but is running
        from within the structure of a cloned repo.  In this mode a sample directory structure is:
        
                /.../git_repos/ghidra_clone/ghidra/Ghidra/Features/Base/src/...
         
                which means this method will return 'ghidra_clone'
         
        * Eclipse Release Development Mode - running from a full application release.  
        This mode uses jar files from the installation for dependencies.  The user test files
        are run from within an Eclipse that has been linked with the application installation.
        In this mode a sample directory structure is:
        
                /.../Software/ghidra_10.0/Ghidra/Features/Base/lib/Base.jar
         
                which means this method will return 'ghidra_10.0'
         
        
        
        :return: the installation directory
        :rtype: java.io.File
        """

    @staticmethod
    def getUniqueTempDir() -> java.io.File:
        """
        Creates a directory that is unique for the current installation. This allows clients to 
        have multiple clones (for development mode) or multiple installations (for release mode)
        on their machine, running tests from each repo simultaneously.
        
        :return: an absolute form directory that is unique for the current installation
        :rtype: java.io.File
        """


class ShutdownPriority(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    FIRST: typing.Final[ShutdownPriority]
    DISPOSE_DATABASES: typing.Final[ShutdownPriority]
    DISPOSE_FILE_HANDLES: typing.Final[ShutdownPriority]
    SHUTDOWN_LOGGING: typing.Final[ShutdownPriority]
    LAST: typing.Final[ShutdownPriority]

    def after(self) -> ShutdownPriority:
        ...

    def before(self) -> ShutdownPriority:
        ...


class Architecture(java.lang.Enum[Architecture]):

    class_: typing.ClassVar[java.lang.Class]
    X86: typing.Final[Architecture]
    X86_64: typing.Final[Architecture]
    POWERPC: typing.Final[Architecture]
    POWERPC_64: typing.Final[Architecture]
    ARM_64: typing.Final[Architecture]
    UNKNOWN: typing.Final[Architecture]

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> Architecture:
        ...

    @staticmethod
    def values() -> jpype.JArray[Architecture]:
        ...


class Platform(java.lang.Enum[Platform]):
    """
    Identifies the current platform (operating system and architecture) and
    identifies the appropriate module OS directory which contains native binaries
    """

    class_: typing.ClassVar[java.lang.Class]
    WIN_X86_32: typing.Final[Platform]
    """
    Identifies a Windows x86 32-bit OS.
    """

    WIN_X86_64: typing.Final[Platform]
    """
    Identifies a Windows x86 64-bit OS.
    """

    WIN_ARM_64: typing.Final[Platform]
    """
    Identifies a Windows ARM 64-bit OS.
    """

    LINUX_X86_32: typing.Final[Platform]
    """
    Identifies a Linux x86 32-bit OS.
    """

    LINUX_X86_64: typing.Final[Platform]
    """
    Identifies a Linux x86 64-bit OS.
    """

    LINUX_ARM_64: typing.Final[Platform]
    """
    Identifies a Linux ARM 64-bit OS.
    """

    MAC_X86_32: typing.Final[Platform]
    """
    Identifies a macOS x86 32-bit OS.
    """

    MAC_X86_64: typing.Final[Platform]
    """
    Identifies a macOS x86 64-bit OS.
    """

    MAC_ARM_64: typing.Final[Platform]
    """
    Identifies a macOS ARM 64-bit OS.
    """

    FREEBSD_X86_64: typing.Final[Platform]
    """
    Identifies a FreeBSD x86 64-bit OS.
    """

    FREEBSD_ARM_64: typing.Final[Platform]
    """
    Identifies a FreeBSD ARM 64-bit OS.
    """

    UNSUPPORTED: typing.Final[Platform]
    """
    Identifies an unsupported OS.
    """

    WIN_64: typing.Final[Platform]
    """
    Identifies a Windows 64-bit OS.
    
    
    .. deprecated::
    
    Use :obj:`.WIN_X86_64` instead.
    """

    WIN_UNKOWN: typing.Final[Platform]
    """
    Identifies a Windows OS, the architecture for which we do not know or have not encountered.
    We'll treat it as :obj:`.WIN_X86_64` and hope for the best.
    
    
    .. deprecated::
    
    Unknown architectures are not supported
    """

    LINUX: typing.Final[Platform]
    """
    Identifies a Linux X86 32-bit OS.
    
    
    .. deprecated::
    
    Use :obj:`.LINUX_X86_32` instead.
    """

    LINUX_64: typing.Final[Platform]
    """
    Identifies a Linux X86 64-bit OS.
    
    
    .. deprecated::
    
    Use :obj:`.LINUX_X86_64` instead.
    """

    LINUX_UKNOWN: typing.Final[Platform]
    """
    Identifies a Linux OS, the architecture for which we do not know or have not encountered.
    We'll treat it as :obj:`.LINUX_X86_64` and hope for the best.
    
    
    .. deprecated::
    
    Unknown architectures are not supported
    """

    MAC_OSX_32: typing.Final[Platform]
    """
    Identifies a macOS X86 32-bit OS.
    
    
    .. deprecated::
    
    Use :obj:`.MAC_OSX_32` instead.
    """

    MAC_OSX_64: typing.Final[Platform]
    """
    Identifies a macOS X86 64-bit OS.
    
    
    .. deprecated::
    
    Use :obj:`.MAC_X86_64` instead.
    """

    MAC_UNKNOWN: typing.Final[Platform]
    """
    Identifies a macOS OS, the architecture for which we do not know or have not encountered.
    We'll treat it as :obj:`.MAC_X86_64` and hope for the best.
    
    
    .. deprecated::
    
    Use :obj:`.MAC_X86_64` instead.
    """

    CURRENT_PLATFORM: typing.Final[Platform]
    """
    A constant identifying the current platform.
    """


    def getAdditionalLibraryPaths(self) -> java.util.List[java.lang.String]:
        """
        Based on the current platform, 
        returns an operating system specific
        library paths that are not found on the
        PATH environment variable.
        
        :return: additional library paths
        :rtype: java.util.List[java.lang.String]
        """

    def getArchitecture(self) -> Architecture:
        """
        Returns the architecture for this platform.
        
        :return: the architecture for this platform
        :rtype: Architecture
        """

    def getDirectoryName(self) -> str:
        """
        Returns the directory name of the current platform.
        
        :return: the directory name of the current platform
        :rtype: str
        """

    def getExecutableExtension(self) -> str:
        ...

    def getLibraryExtension(self) -> str:
        """
        Returns the library extension for this platform.
        
        :return: the library extension for this platform
        :rtype: str
        """

    def getOperatingSystem(self) -> OperatingSystem:
        """
        Returns the operating system for this platform.
        
        :return: the operating system for this platform
        :rtype: OperatingSystem
        """

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> Platform:
        ...

    @staticmethod
    def values() -> jpype.JArray[Platform]:
        ...

    @property
    def libraryExtension(self) -> java.lang.String:
        ...

    @property
    def additionalLibraryPaths(self) -> java.util.List[java.lang.String]:
        ...

    @property
    def executableExtension(self) -> java.lang.String:
        ...

    @property
    def operatingSystem(self) -> OperatingSystem:
        ...

    @property
    def directoryName(self) -> java.lang.String:
        ...

    @property
    def architecture(self) -> Architecture:
        ...


class ApplicationConfiguration(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def getApplicationLogFile(self) -> java.io.File:
        """
        Returns the **user-defined** log file.
        
        :return: The **user-defined** log file. This is null by default and will only return a
        non-null value if it has been set by the user.
        :rtype: java.io.File
        """

    def getErrorDisplay(self) -> ghidra.util.ErrorDisplay:
        ...

    def getScriptLogFile(self) -> java.io.File:
        """
        Returns the **user-defined** script log file.
        
        :return: Returns the **user-defined** script log file.  This is null by default and will 
        only return a non-null value if it has been set by the user.
        :rtype: java.io.File
        """

    def getTaskMonitor(self) -> ghidra.util.task.TaskMonitor:
        """
        Returns the currently set task monitor.
        
        :return: The currently set task monitor, which is by default a dummy monitor.
        :rtype: ghidra.util.task.TaskMonitor
        """

    def installStaticFactories(self):
        ...

    def isHeadless(self) -> bool:
        """
        Returns whether or not the application is headless.
        
        :return: true if the application is headless; otherwise, false.
        :rtype: bool
        """

    def isInitializeLogging(self) -> bool:
        """
        Returns whether or not logging is to be initialized.
        
        :return: True if logging is to be initialized; otherwise, false.  This is true by default, 
        but may be set to false by the user.
        :rtype: bool
        
        .. seealso::
        
            | :obj:`.setInitializeLogging`
        """

    def setApplicationLogFile(self, logFile: jpype.protocol.SupportsPath):
        ...

    def setInitializeLogging(self, initializeLogging: typing.Union[jpype.JBoolean, bool]):
        ...

    def setScriptLogFile(self, scriptLogFile: jpype.protocol.SupportsPath):
        ...

    def setTaskMonitor(self, monitor: ghidra.util.task.TaskMonitor):
        """
        Sets a task monitor that will be called back with messages that report the status of the
        initialization process.
        
        :param ghidra.util.task.TaskMonitor monitor: The monitor to set.
        """

    @property
    def headless(self) -> jpype.JBoolean:
        ...

    @property
    def errorDisplay(self) -> ghidra.util.ErrorDisplay:
        ...

    @property
    def scriptLogFile(self) -> java.io.File:
        ...

    @scriptLogFile.setter
    def scriptLogFile(self, value: java.io.File):
        ...

    @property
    def applicationLogFile(self) -> java.io.File:
        ...

    @applicationLogFile.setter
    def applicationLogFile(self, value: java.io.File):
        ...

    @property
    def taskMonitor(self) -> ghidra.util.task.TaskMonitor:
        ...

    @taskMonitor.setter
    def taskMonitor(self, value: ghidra.util.task.TaskMonitor):
        ...

    @property
    def initializeLogging(self) -> jpype.JBoolean:
        ...

    @initializeLogging.setter
    def initializeLogging(self, value: jpype.JBoolean):
        ...


class Application(java.lang.Object):
    """
    The Application class provides a variety of static convenience methods for accessing Application
    elements that can be used once the :obj:`.initializeApplication` call has been made.
    
     
    In order to initialize an application, an :obj:`ApplicationLayout` and an
    :obj:`ApplicationConfiguration` must be provided.  The layout and configuration come in a
    variety of flavors, and are what makes the Application class usable across a range of tools.
    
     
    Example use case:
     
    ApplicationLayout layout = new GhidraApplicationLayout();
    ApplicationConfiguration configuration = new GhidraApplicationConfiguration();
    Application.initializeApplication(layout, configuration);
    """

    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def createTempFile(prefix: typing.Union[java.lang.String, str], suffix: typing.Union[java.lang.String, str]) -> java.io.File:
        """
        Creates a new empty file in the Application's temp directory, using the given prefix and 
        suffix strings to generate its name.
        
        :param java.lang.String or str prefix: The prefix string to be used in generating the file's name; must be at least 
        three characters long
        :param java.lang.String or str suffix: The suffix string to be used in generating the file's name; may be 
        ``null``, in which case the suffix ``".tmp"`` will be used
        :return: A :obj:`File` denoting a newly-created empty file
        :rtype: java.io.File
        :raises IllegalArgumentException: If the ``prefix`` argument contains fewer than three 
        characters
        :raises IOException: If a file could not be created
        
        .. seealso::
        
            | :obj:`File.createTempFile(String, String, File)`
        """

    @staticmethod
    def findDataFileInAnyModule(relativePath: typing.Union[java.lang.String, str]) -> generic.jar.ResourceFile:
        """
        Finds the first file that exists with the relative path in any module.
        
        :param java.lang.String or str relativePath: the path from the module root
        :return: the first file that exists with the relative path in any module.
        :rtype: generic.jar.ResourceFile
        """

    @staticmethod
    def findFilesByExtension(moduleName: typing.Union[java.lang.String, str], extension: typing.Union[java.lang.String, str]) -> java.util.List[generic.jar.ResourceFile]:
        """
        Returns a list of all files with the given extension that are located in the named module.
        
        :param java.lang.String or str moduleName: the name of the module for which to look for files with the given extension.
        :param java.lang.String or str extension: the filename extension for which to find file.s
        :return: a list of all files with the given extension that are located in the named module.
        :rtype: java.util.List[generic.jar.ResourceFile]
        """

    @staticmethod
    def findFilesByExtensionInApplication(extension: typing.Union[java.lang.String, str]) -> java.util.List[generic.jar.ResourceFile]:
        """
        Returns all files within any module's data directory that end with the given extension.
        
        :param java.lang.String or str extension: the extension of files to be found.
        :return: all files within any module's data directory that end with the given extension.
        :rtype: java.util.List[generic.jar.ResourceFile]
        """

    @staticmethod
    def findFilesByExtensionInMyModule(extension: typing.Union[java.lang.String, str]) -> java.util.List[generic.jar.ResourceFile]:
        """
        Returns a list of all files with the given extension that are located in the module
        of the calling class.
        
        :param java.lang.String or str extension: the filename extension for which to find file.s
        :return: a list of all files with the given extension that are located in the module
        of the calling class.
        :rtype: java.util.List[generic.jar.ResourceFile]
        """

    @staticmethod
    def findModuleSubDirectories(relativePath: typing.Union[java.lang.String, str]) -> java.util.List[generic.jar.ResourceFile]:
        """
        Returns a list of all directories in any module that have the given module relative path.  For
        example, a relative path of "foo/bar" will return all directories that are of the form
        ``<module root>/data/foo/bar``
        
        :param java.lang.String or str relativePath: the module relative path to search for.
        :return: a list of all directories in any module that have the given module relative path.
        :rtype: java.util.List[generic.jar.ResourceFile]
        """

    @staticmethod
    def getApplicationLayout() -> utility.application.ApplicationLayout:
        ...

    @staticmethod
    def getApplicationProperty(propertyName: typing.Union[java.lang.String, str]) -> str:
        """
        Returns the value of the give application property name.
        
        :param java.lang.String or str propertyName: the name of the application property to retrieve.
        :return: the value of the give application property name.
        :rtype: str
        """

    @staticmethod
    def getApplicationReleaseName() -> str:
        """
        Returns the release name for this build.
        
        :return: the application release name.
        :rtype: str
        """

    @staticmethod
    def getApplicationRootDirectories() -> java.util.Collection[generic.jar.ResourceFile]:
        """
        Returns a list of the application root directories.  An application root directory is a
        directory containing one or more modules.  Applications support multiple application root
        directories so that it can contain modules that don't have a common file system root.  This
        is useful if the application contains modules from more than one source code repository.
        Application roots are returned in the order they appear in the classpath.
        
        :return: a list of root directories containing modules for this application.
        :rtype: java.util.Collection[generic.jar.ResourceFile]
        """

    @staticmethod
    def getApplicationRootDirectory() -> generic.jar.ResourceFile:
        """
        Returns the application root directory.   An application root directory is a
        directory containing one or more modules.  In development mode there may be multiple
        application root directories, which can be retrieved via
        :meth:`getApplicationRootDirectories() <.getApplicationRootDirectories>`.
         
        
        In an installation of the application, there will only be one application root directory.
         
        
        **Note:  Be sure you understand that there may be multiple application root
        directories in development mode.**  In general you should not be using this method for
        searching for files yourself, but instead using
        the various ``find*`` methods of this class.
        
        :return: Returns the application root directory.
        :rtype: generic.jar.ResourceFile
        
        .. seealso::
        
            | :obj:`.getApplicationRootDirectories()`
        """

    @staticmethod
    def getApplicationSourceRevisions() -> java.util.Map[java.lang.String, java.lang.String]:
        """
        Return the source repository revisions used in the build process
        or null if not applicable.
        
        :return: source revision map or null if not applicable
        :rtype: java.util.Map[java.lang.String, java.lang.String]
        """

    @staticmethod
    def getApplicationVersion() -> str:
        """
        Returns the version of this build.
        
        :return: the version of this build.
        :rtype: str
        """

    @staticmethod
    def getBuildDate() -> str:
        """
        Returns the date this build was created.
        
        :return: the date this build was created.
        :rtype: str
        """

    @staticmethod
    def getInstallationDirectory() -> generic.jar.ResourceFile:
        """
        Returns the installation directory.  In an installation, there is only one application root
        and its parent is the installation directory.  If not an installation, then this call doesn't
        really make sense, but it will return the parent of the first installation root.
        
        :return: the directory
        :rtype: generic.jar.ResourceFile
        """

    @staticmethod
    def getLibraryDirectories() -> java.util.Collection[generic.jar.ResourceFile]:
        """
        Returns a collection of module library directories. Library directories are optional for a module.
        
        :return: a collection of module library directories.
        :rtype: java.util.Collection[generic.jar.ResourceFile]
        
        .. seealso::
        
            | :obj:`ModuleUtilities.getModuleLibDirectories(Collection)`
        """

    @staticmethod
    @typing.overload
    def getModuleContainingClass(className: typing.Union[java.lang.String, str]) -> generic.jar.ResourceFile:
        ...

    @staticmethod
    @typing.overload
    def getModuleContainingClass(c: java.lang.Class[typing.Any]) -> generic.jar.ResourceFile:
        ...

    @staticmethod
    def getModuleContainingResourceFile(file: generic.jar.ResourceFile) -> generic.jar.ResourceFile:
        ...

    @staticmethod
    @typing.overload
    def getModuleDataFile(relativeDataPath: typing.Union[java.lang.String, str]) -> generic.jar.ResourceFile:
        """
        Returns the file relative to the calling class's module's data directory
        
        :param java.lang.String or str relativeDataPath: the path relative the to module's data directory
        :return: the file
        :rtype: generic.jar.ResourceFile
        :raises FileNotFoundException: if the file or module does not exist.
        """

    @staticmethod
    @typing.overload
    def getModuleDataFile(moduleName: typing.Union[java.lang.String, str], relativeDataPath: typing.Union[java.lang.String, str]) -> generic.jar.ResourceFile:
        """
        Returns the file relative to the named module's data directory. (i.e. "data/" will
        be prepended to the give path)
        
        :param java.lang.String or str moduleName: the name of the module.
        :param java.lang.String or str relativeDataPath: the path relative to the module's data directory.
        :return: the file
        :rtype: generic.jar.ResourceFile
        :raises FileNotFoundException: if the file does not exist.
        """

    @staticmethod
    @typing.overload
    def getModuleDataSubDirectory(relativePath: typing.Union[java.lang.String, str]) -> generic.jar.ResourceFile:
        """
        Returns the directory relative to the calling class's module's data directory.
        
        :param java.lang.String or str relativePath: the path relative the module's data directory
        :return: the directory
        :rtype: generic.jar.ResourceFile
        :raises FileNotFoundException: if the directory does not exist.
        :raises IOException: if an error occurred trying to access the directory.
        """

    @staticmethod
    @typing.overload
    def getModuleDataSubDirectory(moduleName: typing.Union[java.lang.String, str], relativePath: typing.Union[java.lang.String, str]) -> generic.jar.ResourceFile:
        """
        Return the directory relative to the name module's data directory. (i.e. "/data" will
        be prepended to the given path)
        
        :param java.lang.String or str moduleName: the name of the module.
        :param java.lang.String or str relativePath: the path relative to the module's data directory.
        :return: @return the directory
        :rtype: generic.jar.ResourceFile
        :raises FileNotFoundException: if the directory does not exist
        :raises IOException: if an error occurred trying to access the directory.
        """

    @staticmethod
    def getModuleFile(moduleName: typing.Union[java.lang.String, str], relativePath: typing.Union[java.lang.String, str]) -> generic.jar.ResourceFile:
        """
        Returns the file relative to the named module's directory.
        
        :param java.lang.String or str moduleName: the name of the module.
        :param java.lang.String or str relativePath: the path relative to the module's data directory.
        :return: the file
        :rtype: generic.jar.ResourceFile
        :raises FileNotFoundException: if the file does not exist.
        """

    @staticmethod
    def getModuleRootDir(moduleName: typing.Union[java.lang.String, str]) -> generic.jar.ResourceFile:
        """
        Return the module root directory for the module with the given name.
        
        :param java.lang.String or str moduleName: the name of the module.
        :return: the module root directory for the module with the given name or null if not found.
        :rtype: generic.jar.ResourceFile
        """

    @staticmethod
    def getModuleRootDirectories() -> java.util.Collection[generic.jar.ResourceFile]:
        """
        Returns a collection of all the module root directories. A module root directory is
        the top-level directory of a module.
        
        :return: a collection of all the module root directories.
        :rtype: java.util.Collection[generic.jar.ResourceFile]
        """

    @staticmethod
    def getModuleSubDirectory(moduleName: typing.Union[java.lang.String, str], relativePath: typing.Union[java.lang.String, str]) -> generic.jar.ResourceFile:
        """
        Return the directory relative to the name module's directory.
        
        :param java.lang.String or str moduleName: the name of the module.
        :param java.lang.String or str relativePath: the path relative to the module's root directory.
        :return: the directory
        :rtype: generic.jar.ResourceFile
        :raises FileNotFoundException: if the directory does not exist
        :raises IOException: if an error occurred trying to access the directory.
        """

    @staticmethod
    def getMyModuleRootDirectory() -> generic.jar.ResourceFile:
        """
        Returns the module root directory that contains the class that called this method.
        
        :return: the module root directory that contains the class that called this method.
        :rtype: generic.jar.ResourceFile
        """

    @staticmethod
    def getName() -> str:
        """
        Returns the name of the application.
        
        :return: the name of the application.
        :rtype: str
        """

    @staticmethod
    @typing.overload
    def getOSFile(moduleName: typing.Union[java.lang.String, str], exactFilename: typing.Union[java.lang.String, str]) -> java.io.File:
        """
        Returns the OS specific file within the given module with the given name.
        
        :param java.lang.String or str moduleName: the name of the module
        :param java.lang.String or str exactFilename: the name of the OS file within the module.
        :return: the OS specific file.
        :rtype: java.io.File
        :raises OSFileNotFoundException: if the file does not exist.
        """

    @staticmethod
    @typing.overload
    def getOSFile(exactFilename: typing.Union[java.lang.String, str]) -> java.io.File:
        """
        Returns the specified OS specific file.  It is first searched for in the calling class's
        module.  If it is not found there, it is searched for in all modules.
        
        :param java.lang.String or str exactFilename: the name of the OS specific file.
        :return: the OS specific file.
        :rtype: java.io.File
        :raises OSFileNotFoundException: if the file does not exist.
        """

    @staticmethod
    def getUserCacheDirectory() -> java.io.File:
        """
        Returns the cache directory specific to the user and the application.
        The intention is for directory contents to be preserved, however the
        specific location is platform specific and contents may be removed when
        not in use.
        This directory is specific to the application name but not the version.
        Resources stored within this directory should utilize some
        form of access locking and/or unique naming.
        
        :return: cache directory
        :rtype: java.io.File
        """

    @staticmethod
    def getUserSettingsDirectory() -> java.io.File:
        """
        Returns the File containing the user configuration settings for this application.
        
        :return: the File containing the user configuration settings for this application.
        :rtype: java.io.File
        """

    @staticmethod
    def getUserSettingsFiles(dirName: typing.Union[java.lang.String, str], fileExtension: typing.Union[java.lang.String, str]) -> java.util.List[java.io.File]:
        """
        Returns a list of files in a setting subdirectory that have the given file extension,
        copying files from older versions of Ghidra if the settings dir is not yet established.
        
        :param java.lang.String or str dirName: the name of the settings subdirectory.
        :param java.lang.String or str fileExtension: the file name suffix
        :return: a list of files in a setting sub directory that have the given file extension
        :rtype: java.util.List[java.io.File]
        """

    @staticmethod
    def getUserTempDirectory() -> java.io.File:
        """
        Returns the temporary directory specific to the user and the application.
        This directory may be removed at system reboot or during periodic
        system cleanup of unused temp files.
        This directory is specific to the application name but not the version.
        Resources stored within this directory should utilize some
        form of access locking or unique naming.  Transient resources should be
        deleted when no longer in use.
        
        :return: temp directory
        :rtype: java.io.File
        """

    @staticmethod
    def inSingleJarMode() -> bool:
        """
        Checks whether or not the application is in "single jar" mode.
        
        :return: true if the application is in "single jar" mode; otherwise, false.
        :rtype: bool
        """

    @staticmethod
    def initializeApplication(layout: utility.application.ApplicationLayout, configuration: ApplicationConfiguration):
        """
        Initializes the application.  The static methods of this class cannot be used until the
        application is initialized.
        
        :param utility.application.ApplicationLayout layout: The application layout to be used by the application.
        :param ApplicationConfiguration configuration: The application configuration to be used by the application.
        """

    @staticmethod
    def initializeLogging(logFile: jpype.protocol.SupportsPath, scriptLogFile: jpype.protocol.SupportsPath):
        """
        If the Application was previously initialized with logging disabled, this method
        may be used to perform delayed logging initialization.
        
        :param jpype.protocol.SupportsPath logFile: application log file, if null the default *application.log* will be stored
        within the user's application settings directory
        :param jpype.protocol.SupportsPath scriptLogFile: scripting log file, if null the default *script.log* will be stored
        within the user's application settings directory
        :raises AssertException: if Application has not yet been initialized, or logging
        was previously configured for the application.
        """

    @staticmethod
    def isInitialized() -> bool:
        """
        Checks to see if the application has been initialized.
        
        :return: true if the application has been initialized; otherwise, false.
        :rtype: bool
        """

    @staticmethod
    def isTestBuild() -> bool:
        """
        Returns true if this build was not built through the official build process, but instead
        was created using the "buildLocal" call.
        
        :return: true if this build was not built using the official build process.
        :rtype: bool
        """


class GenericRunInfo(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    TEST_DIRECTORY_SUFFIX: typing.Final = "-Test"
    """
    The name appended to application directories during testing
    """


    def __init__(self):
        ...

    @staticmethod
    def getPreviousApplicationSettingsDir(dirName: typing.Union[java.lang.String, str], filter: java.io.FileFilter) -> java.io.File:
        """
        Searches previous Application Settings directories 
        (:meth:`getUserSettingsDirsByTime() <.getUserSettingsDirsByTime>`) to find a settings directory containing
        files that match the given file filter.  This is 
        useful for loading previous directories of saved settings files of a particular type.
         
         
        Note: this method will ignore any test versions of settings directories.
        
        :param java.lang.String or str dirName: the name of a settings subdir; must be relative to a settings directory
        :param java.io.FileFilter filter: the file filter for the files of interest
        :return: the most recent file matching that name and containing at least one file
        of the given type, in a previous version's settings directory.
        :rtype: java.io.File
        """

    @staticmethod
    def getPreviousApplicationSettingsDirsByTime() -> java.util.List[java.io.File]:
        """
        This is the same as :meth:`getUserSettingsDirsByTime() <.getUserSettingsDirsByTime>` except that it doesn't include the 
        current installation or installations with different release names
        
        :return: the list of previous directories, sorted by time
        :rtype: java.util.List[java.io.File]
        """

    @staticmethod
    def getPreviousApplicationSettingsFile(filename: typing.Union[java.lang.String, str]) -> java.io.File:
        """
        Searches previous Application Settings directories 
        (:meth:`getUserSettingsDirsByTime() <.getUserSettingsDirsByTime>`) to find a file by the given name.   This is 
        useful for loading previous user settings, such as preferences.
         
         
        Note: this method will ignore any test versions of settings directories.
        
        :param java.lang.String or str filename: the name for which to seek; must be relative to a settings directory
        :return: the most recent file matching that name found in a previous settings dir
        :rtype: java.io.File
        """

    @staticmethod
    def getProjectsDirPath() -> str:
        """
        Get the user's preferred projects directory.
        
        :return: projects directory path.
        :rtype: str
        """

    @staticmethod
    def setProjectsDirPath(path: typing.Union[java.lang.String, str]):
        """
        Set the user's current projects directory path.  Value is also retained
        within user's set of preferences.
        
        :param java.lang.String or str path: projects directory path.
        """


class OSFileNotFoundException(java.io.FileNotFoundException):
    """
    Signals that an attempt to find a Ghidra "OS-file" (native binary) has failed.
     
    
    This exception provides a consistent way to display information about the missing OS-file that 
    will aid in error reporting and debugging.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, platform: Platform, moduleName: typing.Union[java.lang.String, str], fileName: typing.Union[java.lang.String, str]):
        """
        Creates a new :obj:`OSFileNotFoundException`
        
        :param Platform platform: The :obj:`Platform` associated with this exception
        :param java.lang.String or str moduleName: The module name associated with this exception
        :param java.lang.String or str fileName: The file name associated with this exception, from the given module
        """

    @typing.overload
    def __init__(self, platform: Platform, fileName: typing.Union[java.lang.String, str]):
        """
        Creates a new :obj:`OSFileNotFoundException` with an unknown module
        
        :param Platform platform: The :obj:`Platform` associated with this exception
        :param java.lang.String or str fileName: The file name associated with this exception, from an unknown module
        """

    @typing.overload
    def __init__(self, moduleName: typing.Union[java.lang.String, str], fileName: typing.Union[java.lang.String, str]):
        """
        Creates a new :obj:`OSFileNotFoundException` for the current :obj:`Platform`
        
        :param java.lang.String or str moduleName: The module name associated with this exception
        :param java.lang.String or str fileName: The file name associated with this exception, from the given module
        """

    @typing.overload
    def __init__(self, fileName: typing.Union[java.lang.String, str]):
        """
        Creates a new :obj:`OSFileNotFoundException` for the current :obj:`Platform` with an
        unknown module
        
        :param java.lang.String or str fileName: The file name associated with this exception, from an unknown module
        """

    def getPlatform(self) -> Platform:
        """
        Gets the :obj:`Platform` associated with this exception
        
        :return: The :obj:`Platform` associated with this exception
        :rtype: Platform
        """

    @property
    def platform(self) -> Platform:
        ...


class ApplicationIdentifier(java.lang.Object):
    """
    Class to represent an application's unique identifier.  An application identifier is made up
    of an application name, an application version, and an application release name.
     
    The identifier format is (\.+) - \d\.\d(\.\d)?(\-.+)? _ (\.+)
                            name         version        release name
     
    Application names will be converted to all lowercase and application release names will be
    converted to all uppercase.  Both will have spaces removed from their names.
     
    
    Examples:
     
    * ghidra-7.4_DEV
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, applicationProperties: ApplicationProperties):
        """
        Creates a new :obj:`ApplicationIdentifier` object from an :obj:`ApplicationProperties`.
        
        :param ApplicationProperties applicationProperties: An :obj:`ApplicationProperties`.
        :raises java.lang.IllegalArgumentException: if required elements from the :obj:`ApplicationProperties` 
        were missing or otherwise failed to parse.  The exception's message has more detailed 
        information about why it failed.
        """

    @typing.overload
    def __init__(self, identifier: typing.Union[java.lang.String, str]):
        """
        Creates a new :obj:`ApplicationIdentifier` object from the given string.
        
        :param java.lang.String or str identifier: An identifier string.
        :raises java.lang.IllegalArgumentException: if the identifier string failed to parse.  The 
        exception's message has more detailed information about why it failed.
        """

    def getApplicationName(self) -> str:
        """
        Gets the application name.
        
        :return: The application name.
        :rtype: str
        """

    def getApplicationReleaseName(self) -> str:
        """
        Gets the application release name.
        
        :return: The application release name.
        :rtype: str
        """

    def getApplicationVersion(self) -> ApplicationVersion:
        """
        Gets the :obj:`application version <ApplicationVersion>`.
        
        :return: The :obj:`application version <ApplicationVersion>`.
        :rtype: ApplicationVersion
        """

    @property
    def applicationVersion(self) -> ApplicationVersion:
        ...

    @property
    def applicationReleaseName(self) -> java.lang.String:
        ...

    @property
    def applicationName(self) -> java.lang.String:
        ...


class PluggableServiceRegistry(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def getPluggableService(pluggableServiceClass: java.lang.Class[T]) -> T:
        ...

    @staticmethod
    def registerPluggableService(pluggableServiceClass: java.lang.Class[T], replacementInstance: T):
        ...


class ApplicationProperties(java.util.Properties):
    """
    The application properties.  Application properties may either be stored on disk, or created
    dynamically.
    """

    class_: typing.ClassVar[java.lang.Class]
    PROPERTY_FILE: typing.Final = "application.properties"
    """
    The name of the application properties file.
    """

    APPLICATION_NAME_PROPERTY: typing.Final = "application.name"
    """
    The application name.  For example, "Ghidra".
    """

    APPLICATION_VERSION_PROPERTY: typing.Final = "application.version"
    """
    The application version.  For example, "7.4.2".
    
    
    .. seealso::
    
        | :obj:`ApplicationVersion`
    """

    APPLICATION_LAYOUT_VERSION_PROPERTY: typing.Final = "application.layout.version"
    """
    The application's layout version.  The layout version should get incremented any time
    something changes about the application that could affect external tools that need to 
    navigate the application in some way (such as the Eclipse GhidraDev plugin).
     
    
    Current application versions are:
     
    * 1: Layout used by Ghidra < 11.1
    * 2: Introduced with Ghidra 11.1. Default user settings/cache/temp directories changed,
    and XDG environment variables are supported.
    * 3: Introduced with Ghidra 11.2. Ghidra no longer finds external modules by examining 
    the initial classpath. Instead, the "ghidra.external.modules" system property is used
    (see:obj:`GhidraApplicationLayout`).
    """

    APPLICATION_GRADLE_MIN_PROPERTY: typing.Final = "application.gradle.min"
    """
    The minimum version of gradle required to build the application.
    """

    APPLICATION_GRADLE_MAX_PROPERTY: typing.Final = "application.gradle.max"
    """
    The earliest version of gradle after :obj:`.APPLICATION_GRADLE_MIN_PROPERTY` that is
    unsupported.
     
    
    If all versions of Gradle greater than or equal to :obj:`.APPLICATION_GRADLE_MIN_PROPERTY`
    are supported, this property should not be set.
    """

    APPLICATION_JAVA_MIN_PROPERTY: typing.Final = "application.java.min"
    """
    The minimum major version of Java required to run the application.
    """

    APPLICATION_JAVA_MAX_PROPERTY: typing.Final = "application.java.max"
    """
    The maximum major version of Java the application will run under.
     
    
    If all versions of Java greater than or equal to :obj:`.APPLICATION_JAVA_MIN_PROPERTY` are
    supported, this property should not be set.
    """

    APPLICATION_JAVA_COMPILER_PROPERTY: typing.Final = "application.java.compiler"
    """
    The Java compiler compliance level that was used to build the application.
    For example, "1.8".
    """

    APPLICATION_PYTHON_SUPPORTED_PROPERTY: typing.Final = "application.python.supported"
    """
    A comma-delimted priority-ordred list of versions of Python supported by the application.
    """

    BUILD_DATE_PROPERTY: typing.Final = "application.build.date"
    """
    The date the application was built on, in a long format.
    For example, "2018-Jan-11 1346 EST".
    """

    BUILD_DATE_SHORT_PROPERTY: typing.Final = "application.build.date.short"
    """
    The date the application was built on, it a short format. For example, "20180111".
    """

    RELEASE_NAME_PROPERTY: typing.Final = "application.release.name"
    """
    The application's release name.  For example, "U".
    """

    RELEASE_MARKING_PROPERTY: typing.Final = "application.release.marking"
    """
    The application's release marking.
    """

    REVISION_PROPERTY_PREFIX: typing.Final = "application.revision."
    """
    Property prefix for dynamically generated version control revision number properties.
    """

    TEST_RELEASE_PROPERTY: typing.Final = "application.test.release"
    RELEASE_SOURCE_PROPERTY: typing.Final = "application.release.source"

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str]):
        """
        Creates a new application properties with the given name. Additional properties
        may be set with :obj:`.setProperty`.
        
        :param java.lang.String or str name: The application's name.
        """

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], version: typing.Union[java.lang.String, str], releaseName: typing.Union[java.lang.String, str]):
        """
        Creates a new application properties with the given name and version. Additional properties
        may be set with :obj:`.setProperty`.
        
        :param java.lang.String or str name: The application's name.
        :param java.lang.String or str version: The application's version.
        :param java.lang.String or str releaseName: The application's release name.
        """

    @typing.overload
    def __init__(self, appPropertiesFile: generic.jar.ResourceFile):
        """
        Creates a new application properties from the given application properties file.
        
        :param generic.jar.ResourceFile appPropertiesFile: The application properties file.
        :raises IOException: If there was a problem loading/reading a discovered properties file.
        """

    @typing.overload
    def __init__(self, applicationRootDirs: collections.abc.Sequence):
        """
        Creates a new application properties from the application properties files found
        in the given application root directories.  If multiple application properties files
        are found, the properties from the files will be combined.  If duplicate keys exist,
        the newest key encountered will overwrite the existing key.
        
        :param collections.abc.Sequence applicationRootDirs: The application root directories to look for the properties files in.
        :raises IOException: If there was a problem loading/reading a discovered properties file.
        """

    @staticmethod
    def fromFile(filename: typing.Union[java.lang.String, str]) -> ApplicationProperties:
        """
        Attempts to create an instance of this class by looking for the a properties file 
        with the give name in the current working directory.
        
        :param java.lang.String or str filename: the name of the properties file to load
        :return: the new instance of this class created from the properties file on disk
        :rtype: ApplicationProperties
        :raises IOException: if there is no properties file found in the expected location
        """

    def getApplicationBuildDate(self) -> str:
        """
        Gets the application's build date.
        
        :return: The application's build date.
        :rtype: str
        """

    def getApplicationName(self) -> str:
        """
        Gets the application's name.
        
        :return: The application's name (empty string if undefined).
        :rtype: str
        """

    def getApplicationReleaseName(self) -> str:
        """
        Gets the application's release name.
        
        :return: The application's release name (empty string if undefined).
        :rtype: str
        """

    def getApplicationVersion(self) -> str:
        """
        Gets the application's version.
        
        :return: The application's version (empty string if undefined).
        :rtype: str
        """

    def getProperty(self, propertyName: typing.Union[java.lang.String, str]) -> str:
        """
        Gets the given application property.  Note that if the specified property is defined
        as a system property, the system property will be given precedence and returned.
        
        :param java.lang.String or str propertyName: The property name to get.
        :return: The property.
        :rtype: str
        """

    @property
    def applicationVersion(self) -> java.lang.String:
        ...

    @property
    def applicationBuildDate(self) -> java.lang.String:
        ...

    @property
    def applicationReleaseName(self) -> java.lang.String:
        ...

    @property
    def applicationName(self) -> java.lang.String:
        ...


class OperatingSystem(java.lang.Enum[OperatingSystem]):

    class_: typing.ClassVar[java.lang.Class]
    WINDOWS: typing.Final[OperatingSystem]
    LINUX: typing.Final[OperatingSystem]
    MAC_OS_X: typing.Final[OperatingSystem]
    FREE_BSD: typing.Final[OperatingSystem]
    UNSUPPORTED: typing.Final[OperatingSystem]
    CURRENT_OPERATING_SYSTEM: typing.Final[OperatingSystem]
    """
    Do not access this property directly. Access using Platform class.
    """


    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> OperatingSystem:
        ...

    @staticmethod
    def values() -> jpype.JArray[OperatingSystem]:
        ...


class ApplicationVersion(java.lang.Comparable[ApplicationVersion]):
    """
    Class to represent an application's version information.
     
    
    The version format is ``\d\.\d(\.\d)?(\-.+)?``
     
    
    Note: this class has a natural ordering that is inconsistent with equals (the ``tag``
    part of the version is disregarded in the :meth:`compareTo(ApplicationVersion) <.compareTo>` method).
     
    
    Examples:
     
    * 7.4
    * 7.4.1
    * 7.4.1-BETA
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, version: typing.Union[java.lang.String, str]):
        """
        Creates a new :obj:`ApplicationVersion` object from the given version string.
        
        :param java.lang.String or str version: A version string.
        :raises java.lang.IllegalArgumentException: if the version string failed to parse.  The 
        exception's message has more detailed information about why it failed.
        """

    def getMajor(self) -> int:
        """
        Gets the major version.
        
        :return: The major version.
        :rtype: int
        """

    def getMinor(self) -> int:
        """
        Gets the minor version.
        
        :return: The minor version.
        :rtype: int
        """

    def getPatch(self) -> int:
        """
        Gets the patch version.
        
        :return: The patch version.
        :rtype: int
        """

    def getTag(self) -> str:
        """
        Gets the tag.
        
        :return: The tag.  Could be the empty string.
        :rtype: str
        """

    @property
    def patch(self) -> jpype.JInt:
        ...

    @property
    def minor(self) -> jpype.JInt:
        ...

    @property
    def major(self) -> jpype.JInt:
        ...

    @property
    def tag(self) -> java.lang.String:
        ...


class GModule(java.lang.Object):
    """
    Represents a module in universe of repos.   This class has the notion of 'shadow' modules, which
    are those modules that live under a repo other than the module root directory, but in the same
    path structure.  This allows for optional repos to be used, adding content to the module when 
    that repo is present.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, appRoots: collections.abc.Sequence, moduleRoot: generic.jar.ResourceFile):
        ...

    def accumulateDataFilesByExtension(self, accumulator: java.util.List[generic.jar.ResourceFile], extension: typing.Union[java.lang.String, str]):
        ...

    def collectExistingModuleDirs(self, accumulator: java.util.List[generic.jar.ResourceFile], moduleRelativePath: typing.Union[java.lang.String, str]):
        ...

    def findModuleFile(self, relativeDataFilePath: typing.Union[java.lang.String, str]) -> generic.jar.ResourceFile:
        ...

    def getFatJars(self) -> java.util.Set[java.lang.String]:
        ...

    def getModuleRoot(self) -> generic.jar.ResourceFile:
        ...

    def getName(self) -> str:
        ...

    @property
    def fatJars(self) -> java.util.Set[java.lang.String]:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def moduleRoot(self) -> generic.jar.ResourceFile:
        ...


class PluggableServiceRegistryException(java.lang.RuntimeException):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, pluggableServiceClass: java.lang.Class[java.lang.Object], alreadyRegisteredPluggableServiceClass: java.lang.Class[java.lang.Object], pluggableServiceReplacementInstanceClass: java.lang.Class[java.lang.Object]):
        ...



__all__ = ["GhidraApplicationConfiguration", "HeadlessGhidraApplicationConfiguration", "ToolUtils", "ShutdownHookRegistry", "LoggingInitialization", "ModuleInitializer", "Log4jErrorLogger", "TestApplicationUtils", "ShutdownPriority", "Architecture", "Platform", "ApplicationConfiguration", "Application", "GenericRunInfo", "OSFileNotFoundException", "ApplicationIdentifier", "PluggableServiceRegistry", "ApplicationProperties", "OperatingSystem", "ApplicationVersion", "GModule", "PluggableServiceRegistryException"]
