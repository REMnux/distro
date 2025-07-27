from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import generic.jar
import ghidra
import ghidra.app.plugin
import ghidra.app.plugin.core.console
import ghidra.app.plugin.core.interpreter
import ghidra.app.script
import ghidra.framework.options
import ghidra.framework.plugintool
import ghidra.util.task
import java.awt # type: ignore
import java.io # type: ignore
import java.lang # type: ignore
import java.util # type: ignore
import org.python.core # type: ignore
import org.python.util # type: ignore


class PyDevUtils(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    PYDEV_REMOTE_DEBUGGER_PORT: typing.Final = 5678

    @staticmethod
    def getPyDevSrcDir() -> java.io.File:
        """
        Gets The PyDev source directory.
        
        :return: The PyDev source directory, or null if it not known.
        :rtype: java.io.File
        """


@typing.type_check_only
class JythonScriptExecutionThread(java.lang.Thread):
    """
    Thread responsible for executing a jython script from a file.
    """

    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class JythonPluginExecutionThread(java.lang.Thread):
    """
    Thread responsible for executing a jython command for the plugin.
    """

    class_: typing.ClassVar[java.lang.Class]


class GhidraJythonInterpreter(org.python.util.InteractiveInterpreter):
    """
    A python interpreter meant for Ghidra's use.  Each interpreter you get will have its own
    variable space so they should not interfere with each other.
     
    
    There is no longer a way to reset an interpreter...it was too complicated to get right.
    Instead, you should :meth:`cleanup() <.cleanup>` your old interpreter and make a new one.
    """

    @typing.type_check_only
    class InterruptTraceFunction(org.python.core.TraceFunction):
        """
        Custom trace function that allows interruption of python code to occur when various code
        paths are encountered.
        """

        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def execFile(self, file: generic.jar.ResourceFile, script: JythonScript):
        """
        Execute a python file using this interpreter.
        
        :param generic.jar.ResourceFile file: The python file to execute.
        :param JythonScript script: A PythonScript from which we load state (or null).
        :raises java.lang.IllegalStateException: if this interpreter has been cleaned up.
        """

    @staticmethod
    def get() -> GhidraJythonInterpreter:
        """
        Gets a new GhidraPythonInterpreter instance.
        
        :return: A new GhidraPythonInterpreter. Could be null if it failed to be created.
        :rtype: GhidraJythonInterpreter
        """

    def push(self, line: typing.Union[java.lang.String, str], script: JythonScript) -> bool:
        """
        Pushes (executes) a line of Python to the interpreter.
        
        :param java.lang.String or str line: the line of Python to push to the interpreter
        :param JythonScript script: a PythonScript from which we load state (or null)
        :return: true if more input is needed before execution can occur
        :rtype: bool
        :raises PyException: if an unhandled exception occurred while executing the line of python
        :raises java.lang.IllegalStateException: if this interpreter has been cleaned up.
        """


class JythonScript(ghidra.app.script.GhidraScript):
    """
    A Jython version of a :obj:`GhidraScript`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class JythonUtils(java.lang.Object):
    """
    Python utility method class.
    """

    class_: typing.ClassVar[java.lang.Class]
    JYTHON_NAME: typing.Final = "jython-2.7.4"
    JYTHON_CACHEDIR: typing.Final = "jython_cachedir"
    JYTHON_SRC: typing.Final = "jython-src"

    def __init__(self):
        ...

    @staticmethod
    def setupJythonCacheDir(monitor: ghidra.util.task.TaskMonitor) -> java.io.File:
        """
        Sets up the jython cache directory.  This is a temporary space that jython source files
        get compiled to and cached.  It should NOT be in the Ghidra installation directory, because
        some installations will not have the appropriate directory permissions to create new files in.
        
        :param ghidra.util.task.TaskMonitor monitor: A monitor to use during the cache directory setup.
        :return: The jython cache directory.
        :rtype: java.io.File
        :raises IOException: If there was a disk-related problem setting up the cache directory.
        :raises CancelledException: If the user cancelled the setup.
        """

    @staticmethod
    def setupJythonHomeDir() -> java.io.File:
        """
        Sets up the jython home directory.  This is the directory that has the "Lib" directory in it.
        
        :return: The jython home directory.
        :rtype: java.io.File
        :raises IOException: If there was a disk-related problem setting up the home directory.
        """


class JythonPlugin(ghidra.app.plugin.ProgramPlugin, ghidra.app.plugin.core.interpreter.InterpreterConnection, ghidra.framework.options.OptionsChangeListener):
    """
    This plugin provides the interactive Jython interpreter.
    """

    @typing.type_check_only
    class JythonInteractiveTaskMonitor(ghidra.util.task.TaskMonitorAdapter):
        """
        Support for cancelling execution using a TaskMonitor.
        """

        class_: typing.ClassVar[java.lang.Class]

        @typing.overload
        def __init__(self, stdOut: java.io.PrintWriter):
            ...

        @typing.overload
        def __init__(self, stdout: java.io.OutputStream):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        """
        Creates a new :obj:`JythonPlugin` object.
        
        :param ghidra.framework.plugintool.PluginTool tool: The tool associated with this plugin.
        """

    @typing.overload
    def getCompletions(self, cmd: typing.Union[java.lang.String, str]) -> java.util.List[ghidra.app.plugin.core.console.CodeCompletion]:
        """
        Returns a list of possible command completion values.
        
        :param java.lang.String or str cmd: current command line (without prompt)
        :return: A list of possible command completion values.  Could be empty if there aren't any.
        :rtype: java.util.List[ghidra.app.plugin.core.console.CodeCompletion]
        """

    @typing.overload
    def getCompletions(self, cmd: typing.Union[java.lang.String, str], caretPos: typing.Union[jpype.JInt, int]) -> java.util.List[ghidra.app.plugin.core.console.CodeCompletion]:
        """
        Returns a list of possible command completion values at the given position.
        
        :param java.lang.String or str cmd: current command line (without prompt)
        :param jpype.JInt or int caretPos: The position of the caret in the input string 'cmd'
        :return: A list of possible command completion values. Could be empty if there aren't any.
        :rtype: java.util.List[ghidra.app.plugin.core.console.CodeCompletion]
        """

    def interrupt(self):
        """
        Interrupts what the interpreter is currently doing.
        """

    def optionsChanged(self, options: ghidra.framework.options.ToolOptions, optionName: typing.Union[java.lang.String, str], oldValue: java.lang.Object, newValue: java.lang.Object):
        """
        Handle a change in one of our options.
        
        :param ghidra.framework.options.ToolOptions options: the options handle
        :param java.lang.String or str optionName: name of the option changed
        :param java.lang.Object oldValue: the old value
        :param java.lang.Object newValue: the new value
        """

    def reset(self):
        """
        Resets the interpreter's state.
        """

    @property
    def completions(self) -> java.util.List[ghidra.app.plugin.core.console.CodeCompletion]:
        ...


@typing.type_check_only
class JythonPluginInputThread(java.lang.Thread):
    """
    Thread responsible for getting interactive lines of jython from the plugin.
    This class also kicks off the execution of that line in a new :obj:`JythonPluginExecutionThread`.
    """

    class_: typing.ClassVar[java.lang.Class]


class JythonScriptProvider(ghidra.app.script.AbstractPythonScriptProvider):
    """
    A :obj:`GhidraScriptProvider` used to run Jython scripts
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class JythonCodeCompletionFactory(java.lang.Object):
    """
    Generates CodeCompletions from Jython objects.
    """

    class_: typing.ClassVar[java.lang.Class]
    COMPLETION_LABEL: typing.Final = "Code Completion Colors"
    NULL_COLOR: typing.Final[java.awt.Color]
    FUNCTION_COLOR: typing.Final[java.awt.Color]
    PACKAGE_COLOR: typing.Final[java.awt.Color]
    CLASS_COLOR: typing.Final[java.awt.Color]
    METHOD_COLOR: typing.Final[java.awt.Color]
    CODE_COLOR: typing.Final[java.awt.Color]
    INSTANCE_COLOR: typing.Final[java.awt.Color]
    SEQUENCE_COLOR: typing.Final[java.awt.Color]
    MAP_COLOR: typing.Final[java.awt.Color]
    NUMBER_COLOR: typing.Final[java.awt.Color]
    SPECIAL_COLOR: typing.Final[java.awt.Color]

    def __init__(self):
        ...

    @staticmethod
    def changeOptions(options: ghidra.framework.options.Options, name: typing.Union[java.lang.String, str], oldValue: java.lang.Object, newValue: java.lang.Object):
        """
        Handle an Option change.
         
        This is named slightly differently because it is a static method, not
        an instance method.
         
        By the time we get here, we assume that the Option changed is indeed
        ours.
        
        :param ghidra.framework.options.Options options: the Options handle
        :param java.lang.String or str name: name of the Option changed
        :param java.lang.Object oldValue: the old value
        :param java.lang.Object newValue: the new value
        """

    @staticmethod
    def getCallMethods(obj: org.python.core.PyObject) -> jpype.JArray[java.lang.Object]:
        """
        Returns the Java __call__ methods declared for a Jython object.
         
        Some Jython "methods" in the new-style Jython objects are actually
        classes in and of themselves, re-implementing __call__ methods to
        tell us how to call them.  This returns an array of those Methods
        (for code completion help).
        
        :param org.python.core.PyObject obj: a PyObject
        :return: the Java __call__ methods declared for the Jython object
        :rtype: jpype.JArray[java.lang.Object]
        """

    @staticmethod
    @typing.overload
    @deprecated("use newCodeCompletion(String, String, PyObject, String) instead,\n             it allows creation of substituting code completions")
    def newCodeCompletion(description: typing.Union[java.lang.String, str], insertion: typing.Union[java.lang.String, str], pyObj: org.python.core.PyObject) -> ghidra.app.plugin.core.console.CodeCompletion:
        """
        Creates a new CodeCompletion from the given Jython objects.
        
        :param java.lang.String or str description: description of the new CodeCompletion
        :param java.lang.String or str insertion: what will be inserted to make the code complete
        :param org.python.core.PyObject pyObj: a Jython Object
        :return: A new CodeCompletion from the given Jython objects.
        :rtype: ghidra.app.plugin.core.console.CodeCompletion
        
        .. deprecated::
        
        use :meth:`newCodeCompletion(String, String, PyObject, String) <.newCodeCompletion>` instead,
                    it allows creation of substituting code completions
        """

    @staticmethod
    @typing.overload
    def newCodeCompletion(description: typing.Union[java.lang.String, str], insertion: typing.Union[java.lang.String, str], pyObj: org.python.core.PyObject, userInput: typing.Union[java.lang.String, str]) -> ghidra.app.plugin.core.console.CodeCompletion:
        """
        Creates a new CodeCompletion from the given Jython objects.
        
        :param java.lang.String or str description: description of the new CodeCompletion
        :param java.lang.String or str insertion: what will be inserted to make the code complete
        :param org.python.core.PyObject pyObj: a Jython Object
        :param java.lang.String or str userInput: a word we want to complete, can be an empty string.
                It's used to determine which part (if any) of the input should be 
                removed before the insertion of the completion
        :return: A new CodeCompletion from the given Jython objects.
        :rtype: ghidra.app.plugin.core.console.CodeCompletion
        """

    @staticmethod
    def setupOptions(plugin: JythonPlugin, options: ghidra.framework.options.Options):
        """
        Sets up Jython code completion Options.
        
        :param JythonPlugin plugin: jython plugin as options owner
        :param ghidra.framework.options.Options options: an Options handle
        """


class JythonRun(ghidra.GhidraLaunchable):
    """
    Launcher entry point for running Ghidra from within Jython.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...



__all__ = ["PyDevUtils", "JythonScriptExecutionThread", "JythonPluginExecutionThread", "GhidraJythonInterpreter", "JythonScript", "JythonUtils", "JythonPlugin", "JythonPluginInputThread", "JythonScriptProvider", "JythonCodeCompletionFactory", "JythonRun"]
