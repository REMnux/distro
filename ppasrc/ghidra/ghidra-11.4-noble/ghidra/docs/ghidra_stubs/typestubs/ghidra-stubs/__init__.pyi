from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import generic.jar
import generic.theme
import ghidra.framework
import ghidra.framework.plugintool.util
import ghidra.framework.project
import java.io # type: ignore
import java.lang # type: ignore
import java.net # type: ignore
import java.util # type: ignore
import utility.application


class GhidraThreadGroup(java.lang.ThreadGroup):
    """
    ``GhidraThreadGroup`` provides a means of catching all uncaught
    exceptions which occur in any Ghidra thread.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        """
        Constructor for GhidraThreadGroup.
        """

    @staticmethod
    def handleUncaughtException(t: java.lang.Throwable):
        """
        Handle any uncaught throwable/exception.
        
        :param java.lang.Throwable t: throwable
        """


class JShellRun(GhidraLaunchable):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class JarRun(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def main(args: jpype.JArray[java.lang.String]):
        ...


class GhidraException(java.lang.Exception):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, cause: java.lang.Throwable):
        ...

    @typing.overload
    def __init__(self, string: typing.Union[java.lang.String, str]):
        ...


class GhidraOptions(java.lang.Object):
    """
    Contains miscellaneous defines used for options.
    """

    class CURSOR_MOUSE_BUTTON_NAMES(java.lang.Enum[GhidraOptions.CURSOR_MOUSE_BUTTON_NAMES]):

        class_: typing.ClassVar[java.lang.Class]
        LEFT: typing.Final[GhidraOptions.CURSOR_MOUSE_BUTTON_NAMES]
        MIDDLE: typing.Final[GhidraOptions.CURSOR_MOUSE_BUTTON_NAMES]
        RIGHT: typing.Final[GhidraOptions.CURSOR_MOUSE_BUTTON_NAMES]

        def getMouseEventID(self) -> int:
            ...

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> GhidraOptions.CURSOR_MOUSE_BUTTON_NAMES:
            ...

        @staticmethod
        def values() -> jpype.JArray[GhidraOptions.CURSOR_MOUSE_BUTTON_NAMES]:
            ...

        @property
        def mouseEventID(self) -> jpype.JInt:
            ...


    class_: typing.ClassVar[java.lang.Class]
    DELIMITER: typing.Final = '.'
    """
    Character used to create a "hierarchy" for a property name; the delimiter creates a
    new "level."
    """

    CATEGORY_BROWSER_DISPLAY: typing.Final = "Listing Display"
    """
    Category name for the Browser options that affect the display.
    """

    CATEGORY_BROWSER_NAVIGATION_MARKERS: typing.Final = "Navigation Markers"
    """
    Category name for the Browser Navigation Marker options.
    """

    OPTION_BASE_FONT: typing.Final = "BASE FONT"
    """
    Option for the base font.
    """

    CATEGORY_FLOW_OPTIONS: typing.Final = "Selection by Flow"
    """
    Category name for the "Select by Flow" options.
    """

    OPTION_FOLLOW_COMPUTED_CALL: typing.Final = "Follow computed call"
    """
    Option for the following computed calls when selecting by flow.
    """

    OPTION_FOLLOW_CONDITIONAL_CALL: typing.Final = "Follow conditional call"
    """
    Option for the following conditional calls when selecting by flow.
    """

    OPTION_FOLLOW_UNCONDITIONAL_CALL: typing.Final = "Follow unconditional call"
    """
    Option for the following unconditional calls when selecting by flow.
    """

    OPTION_FOLLOW_COMPUTED_JUMP: typing.Final = "Follow computed jump"
    """
    Option for the following computed jumps when selecting by flow.
    """

    OPTION_FOLLOW_CONDITIONAL_JUMP: typing.Final = "Follow conditional jump"
    """
    Option for the following conditional jumps when selecting by flow.
    """

    OPTION_FOLLOW_UNCONDITIONAL_JUMP: typing.Final = "Follow unconditional jump"
    """
    Option for the following unconditional jumps when selecting by flow.
    """

    OPTION_FOLLOW_POINTERS: typing.Final = "Follow pointers"
    """
    Option for the following pointers when selecting by flow.
    """

    OPTION_SEARCH_LIMIT: typing.Final = "Search Limit"
    """
    Option for the max number of hits found in a search; the search
    stops when it reaches this limit.
    
    
    .. deprecated::
    
    use :obj:`SearchConstants.SEARCH_LIMIT_NAME`
    """

    OPTION_SEARCH_TITLE: typing.Final = "Search"
    """
    Options title the search category
    
    
    .. deprecated::
    
    use :obj:`SearchConstants.SEARCH_OPTION_NAME`
    """

    CATEGORY_AUTO_ANALYSIS: typing.Final = "Auto Analysis"
    """
    Category name for the "Auto Analysis" options.
    """

    CATEGORY_BROWSER_FIELDS: typing.Final = "Listing Fields"
    """
    Options name for Browser fields
    """

    MNEMONIC_GROUP_TITLE: typing.Final = "Mnemonic Field"
    """
    Options title for Mnemonic group.
    """

    OPERAND_GROUP_TITLE: typing.Final = "Operands Field"
    """
    Options title for Operand group.
    """

    LABEL_GROUP_TITLE: typing.Final = "Label Field"
    OPTION_SHOW_BLOCK_NAME: typing.Final = "Show Block Names"
    """
    Option name for whether to show the block name in the operand.
    """

    CATEGORY_BROWSER_POPUPS: typing.Final = "Listing Popups"
    """
    Category name for Browser Popup options
    """

    CATEGORY_DECOMPILER_POPUPS: typing.Final = "Decompiler Popups"
    """
    Category name for Decompiler Popup options
    """

    OPTION_NUMERIC_FORMATTING: typing.Final = "Use C-like Numeric Formatting for Addresses"
    """
    Option name for interpreting addresses as a number
    """

    OPTION_MAX_GO_TO_ENTRIES: typing.Final = "Max Goto Entries"
    """
    Option name for the max number of go to entries to be remembered.
    """

    SHOW_BLOCK_NAME_OPTION: typing.Final = "Operands Field.Show Block Names"
    DISPLAY_NAMESPACE: typing.Final = "Display Namespace"
    NAVIGATION_OPTIONS: typing.Final = "Navigation"
    NAVIGATION_RANGE_OPTION: typing.Final = "Range Navigation"
    EXTERNAL_NAVIGATION_OPTION: typing.Final = "External Navigation"
    FOLLOW_INDIRECTION_NAVIGATION_OPTION: typing.Final = "Follow Indirection"
    HIGHLIGHT_CURSOR_LINE_COLOR_OPTION_NAME: typing.Final = "Highlight Cursor Line Color"
    HIGHLIGHT_CURSOR_LINE_COLOR: typing.Final = "Cursor.Highlight Cursor Line Color"
    DEFAULT_CURSOR_LINE_COLOR: typing.Final[generic.theme.GColor]
    HIGHLIGHT_CURSOR_LINE_OPTION_NAME: typing.Final = "Highlight Cursor Line"
    HIGHLIGHT_CURSOR_LINE: typing.Final = "Cursor.Highlight Cursor Line"
    CURSOR_HIGHLIGHT_GROUP: typing.Final = "Cursor Text Highlight"
    CURSOR_HIGHLIGHT_BUTTON_NAME: typing.Final = "Cursor Text Highlight.Mouse Button To Activate"
    HIGHLIGHT_COLOR_NAME: typing.Final = "Cursor Text Highlight.Highlight Color"
    OPTION_SELECTION_COLOR: typing.Final = "Selection Colors.Selection Color"
    DEFAULT_SELECTION_COLOR: typing.Final[generic.theme.GColor]
    OPTION_HIGHLIGHT_COLOR: typing.Final = "Selection Colors.Highlight Color"
    DEFAULT_HIGHLIGHT_COLOR: typing.Final[generic.theme.GColor]
    APPLY_ENABLED: typing.Final = "apply.enabled"


class GhidraRun(GhidraLaunchable):
    """
    Main Ghidra application class. Creates
    the .ghidra folder that contains the user preferences and tools if it does
    not exist. Initializes JavaHelp and attempts to restore the last opened
    project.
     
    A list of classes for plugins, data types, and language providers is
    maintained so that a search of the classpath is not done every time
    Ghidra is run. The list is maintained in the GhidraClasses.xml file
    in the user's .ghidra folder. A search of the classpath is done if the
    (1) GhidraClasses.xml file is not found, (2) the classpath is different
    from when the last time Ghidra was run, (3) a class in the file was
    not found,  or (4) a modification date specified in the classes file for
    a jar file is older than the actual jar file's modification date.
    
     
    **Note**: The Plugin path is a user preference that
    indicates locations for where classes for plugins and data types should
    be searched; the Plugin path can include jar files just like a classpath.
    The Plugin path can be changed by using the *Edit Plugin Path* dialog,
    displayed from the *Edit->Edit Plugin Path...* menu option on the main
    Ghidra project window.
    
    
    .. seealso::
    
        | :obj:`ghidra.GhidraLauncher`
    """

    @typing.type_check_only
    class GhidraProjectManager(ghidra.framework.project.DefaultProjectManager):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class SoftwareModelingInitializer(ghidra.framework.ModuleInitializer):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class ProjectInitializer(ghidra.framework.ModuleInitializer):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def run(self):
        ...


class MiscellaneousPluginPackage(ghidra.framework.plugintool.util.PluginPackage):

    class_: typing.ClassVar[java.lang.Class]
    NAME: typing.Final = "Miscellaneous"

    def __init__(self):
        ...


class SwingExceptionHandler(java.lang.Thread.UncaughtExceptionHandler):
    """
    Class to handle exceptions caught within the Swing event dispatch thread.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def handle(self, t: java.lang.Throwable):
        """
        Handle exception caught within the Swing event dispatch thread.
        
        :param java.lang.Throwable t: exception
        :raises java.lang.Throwable: error occurred while attempting to handle exception
        """

    @staticmethod
    def handleUncaughtException(t: java.lang.Throwable):
        ...

    @staticmethod
    def registerHandler():
        """
        Register SwingExceptionHandler
        """


class Ghidra(java.lang.Object):
    """
    Ghidra entry point that forwards the command line arguments to :obj:`GhidraLaunchable`.
     
    
    This class was introduced so Ghidra's application name can be set to "ghidra-Ghidra" on Linux,
    rather than "ghidra-GhidraLauncher".
    
    
    .. seealso::
    
        | `JDK-6528430 <https://bugs.java.com/bugdatabase/view_bug.do?bug_id=6528430>`_
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def main(args: jpype.JArray[java.lang.String]):
        """
        Launches the given :obj:`GhidraLaunchable` specified in the first command line argument
        
        :param jpype.JArray[java.lang.String] args: The first argument is the name of the :obj:`GhidraLaunchable` to launch.
        The remaining args get passed through to the class's :obj:`GhidraLaunchable.launch` 
        method.
        :raises java.lang.Exception: If there was a problem launching.  See the exception's message for more
            details on what went wrong.
        """


class GhidraJarApplicationLayout(GhidraApplicationLayout):
    """
    The Ghidra jar application layout defines the customizable elements of the Ghidra application's
    directory structure when running in "single jar mode."
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        """
        Constructs a new Ghidra jar application layout object.
        
        :raises FileNotFoundException: if there was a problem getting a user directory.
        :raises IOException: if there was a problem getting the application properties or modules.
        """


class GhidraApplicationLayout(utility.application.ApplicationLayout):
    """
    The Ghidra application layout defines the customizable elements of the Ghidra
    application's directory structure.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        Constructs a new Ghidra application layout object.
        
        :raises IOException: if there was a problem getting a user directory or the application 
        properties or modules.
        """

    @typing.overload
    def __init__(self, applicationInstallationDir: jpype.protocol.SupportsPath):
        """
        Constructs a new Ghidra application layout object using a provided
        application installation directory instead of this layout's default.
         
        
        This is used when something external to Ghidra needs Ghidra's layout
        (like the Eclipse GhidraDevPlugin).
        
        :param jpype.protocol.SupportsPath applicationInstallationDir: The application installation directory.
        :raises IOException: if there was a problem getting a user directory or the application
        properties.
        """


class GhidraLauncher(java.lang.Object):
    """
    Class used to prepare Ghidra for launching
     
    
    A :meth:`main(String[]) <.main>` method is provided which redirects execution to a 
    :obj:`GhidraLaunchable` class passed in as a command line argument
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def findJarsInDir(dir: generic.jar.ResourceFile) -> java.util.List[java.lang.String]:
        """
        Searches the given directory (non-recursively) for jars and returns their paths in a list.
        The paths will be sorted by jar file name.
        
        :param generic.jar.ResourceFile dir: The directory to search for jars in
        :return: A list of discovered jar paths, sorted by jar file name
        :rtype: java.util.List[java.lang.String]
        """

    @staticmethod
    def getMillisecondsFromLaunch() -> int:
        """
        :return: the current number of milliseconds that have elapsed since execution began
        :rtype: int
        """

    @staticmethod
    def initializeGhidraEnvironment() -> GhidraApplicationLayout:
        """
        Initializes the Ghidra environment by discovering its :obj:`layout <GhidraApplicationLayout>`
        and adding all relevant modules and libraries to the classpath
         
        
        NOTE: This method expects that the :obj:`GhidraClassLoader` is the active classloader
        
        :return: Ghidra's :obj:`layout <GhidraApplicationLayout>`
        :rtype: GhidraApplicationLayout
        :raises IOException: if there was an issue getting the :obj:`layout <GhidraApplicationLayout>`
        :raises java.lang.ClassNotFoundException: if the :obj:`GhidraClassLoader` is not the active classloader
        """

    @staticmethod
    def launch(args: jpype.JArray[java.lang.String]):
        """
        Launches the given :obj:`GhidraLaunchable` specified in the first command line argument
        
        :param jpype.JArray[java.lang.String] args: The first argument is the name of the :obj:`GhidraLaunchable` to launch.
        The remaining args get passed through to the class's :obj:`GhidraLaunchable.launch` 
        method.
        :raises java.lang.Exception: If there was a problem launching.  See the exception's message for more
            details on what went wrong.
        """

    @staticmethod
    @deprecated("Use Ghidra.main(String[]) instead")
    def main(args: jpype.JArray[java.lang.String]):
        """
        Launches the given :obj:`GhidraLaunchable` specified in the first command line argument
        
        :param jpype.JArray[java.lang.String] args: The first argument is the name of the :obj:`GhidraLaunchable` to launch.
        The remaining args get passed through to the class's :obj:`GhidraLaunchable.launch` 
        method.
        :raises java.lang.Exception: If there was a problem launching.  See the exception's message for more
            details on what went wrong.
        
        .. deprecated::
        
        Use :meth:`Ghidra.main(String[]) <Ghidra.main>` instead
        """


class GhidraLaunchable(java.lang.Object):
    """
    Something intended to be launched by the :obj:`GhidraLauncher`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def launch(self, layout: GhidraApplicationLayout, args: jpype.JArray[java.lang.String]):
        """
        Launches the launchable.
        
        :param GhidraApplicationLayout layout: The application layout to use for the launch.
        :param jpype.JArray[java.lang.String] args: The arguments passed through by the :obj:`GhidraLauncher`.
        :raises java.lang.Exception: if there was a problem with the launch.
        """


class GhidraTestApplicationLayout(GhidraApplicationLayout):
    """
    The Ghidra test application layout defines the customizable elements of the Ghidra
    application's directory structure when running a test.
     
    
    This layout exists because tests often need to provide their own user settings
    directory, rather than using Ghidra's default.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, userSettingsDir: jpype.protocol.SupportsPath):
        """
        Constructs a new Ghidra application layout object with the provided user settings
        directory.
         
        
        This layout is useful when running Ghidra tests.
        
        :param jpype.protocol.SupportsPath userSettingsDir: The custom user settings directory to use.
        :raises FileNotFoundException: if there was a problem getting a user directory.
        :raises IOException: if there was a problem getting the application properties.
        """


class GhidraClassLoader(java.net.URLClassLoader):
    """
    Custom Ghidra URL class loader which exposes the addURL method so we can add to the classpath
    at runtime.  
     
    
    This class loader must be installed by setting the "java.system.class.loader" 
    system property prior to launch (i.e., the JVM should be launched with the following argument:
    -Djava.system.class.loader=ghidra.GhidraClassLoader.
    """

    class_: typing.ClassVar[java.lang.Class]
    ENABLE_RESTRICTED_EXTENSIONS_PROPERTY: typing.Final = "ghidra.extensions.classpath.restricted"
    """
    When 'true', this property will trigger the system to put each Extension module's lib jar 
    files into the :obj:`.CP_EXT` property.
    """

    CP: typing.Final = "java.class.path"
    """
    The classpath system property: ``java.class.path``
    """

    CP_EXT: typing.Final = "java.class.path.ext"
    """
    The extensions classpath system property: ``java.class.path.ext``
    """


    def __init__(self, parent: java.lang.ClassLoader):
        """
        This one-argument constructor is required for the JVM to successfully use this class loader
        via the java.system.class.loader system property.
        
        :param java.lang.ClassLoader parent: The parent class loader for delegation
        """

    def addPath(self, path: typing.Union[java.lang.String, str]) -> bool:
        """
        Converts the specified path to a :obj:`URL` and adds it to the classpath.
        
        :param java.lang.String or str path: The path to be added.
        :return: True if the path was successfully added; otherwise, false.  Failure can occur if the 
        path is not able to be converted to a URL.
        :rtype: bool
        
        .. seealso::
        
            | :obj:`.addURL(URL)`
        """

    @staticmethod
    def getClasspath(propertyName: typing.Union[java.lang.String, str]) -> java.util.List[java.lang.String]:
        """
        Gets a :obj:`List` containing the current classpath referenced by the given property name
        
        :param java.lang.String or str propertyName: The property name of the classpath to get
        :return: A :obj:`List` containing the current classpath referenced by the given property name
        :rtype: java.util.List[java.lang.String]
        """



__all__ = ["GhidraThreadGroup", "JShellRun", "JarRun", "GhidraException", "GhidraOptions", "GhidraRun", "SoftwareModelingInitializer", "ProjectInitializer", "MiscellaneousPluginPackage", "SwingExceptionHandler", "Ghidra", "GhidraJarApplicationLayout", "GhidraApplicationLayout", "GhidraLauncher", "GhidraLaunchable", "GhidraTestApplicationLayout", "GhidraClassLoader"]
