from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking.action
import ghidra.app.plugin.core.console
import ghidra.app.plugin.core.interpreter
import ghidra.app.script
import ghidra.program.model.address
import ghidra.program.model.listing
import ghidra.program.util
import ghidra.pyghidra
import ghidra.util
import ghidra.util.task
import java.io # type: ignore
import java.lang # type: ignore
import java.util # type: ignore


@typing.type_check_only
class CancelAction(docking.action.DockingAction):
    ...
    class_: typing.ClassVar[java.lang.Class]


class InterpreterGhidraScript(ghidra.app.script.GhidraScript):
    """
    Custom :obj:`GhidraScript` only for use with the PyGhidra interpreter console
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def getCurrentAddress(self) -> ghidra.program.model.address.Address:
        ...

    def getCurrentHighlight(self) -> ghidra.program.util.ProgramSelection:
        ...

    def getCurrentLocation(self) -> ghidra.program.util.ProgramLocation:
        ...

    def getCurrentSelection(self) -> ghidra.program.util.ProgramSelection:
        ...

    def getWriter(self) -> java.io.PrintWriter:
        ...

    def set(self, state: ghidra.app.script.GhidraState, writer: java.io.PrintWriter):
        ...

    def setCurrentAddress(self, address: ghidra.program.model.address.Address):
        ...

    def setCurrentHighlight(self, highlight: ghidra.program.util.ProgramSelection):
        ...

    def setCurrentLocation(self, location: ghidra.program.util.ProgramLocation):
        ...

    def setCurrentProgram(self, program: ghidra.program.model.listing.Program):
        ...

    def setCurrentSelection(self, selection: ghidra.program.util.ProgramSelection):
        ...

    @property
    def currentSelection(self) -> ghidra.program.util.ProgramSelection:
        ...

    @currentSelection.setter
    def currentSelection(self, value: ghidra.program.util.ProgramSelection):
        ...

    @property
    def writer(self) -> java.io.PrintWriter:
        ...

    @property
    def currentHighlight(self) -> ghidra.program.util.ProgramSelection:
        ...

    @currentHighlight.setter
    def currentHighlight(self, value: ghidra.program.util.ProgramSelection):
        ...

    @property
    def currentLocation(self) -> ghidra.program.util.ProgramLocation:
        ...

    @currentLocation.setter
    def currentLocation(self, value: ghidra.program.util.ProgramLocation):
        ...

    @property
    def currentAddress(self) -> ghidra.program.model.address.Address:
        ...

    @currentAddress.setter
    def currentAddress(self, value: ghidra.program.model.address.Address):
        ...


class PyGhidraConsole(ghidra.util.Disposable):
    """
    Console interface providing only the methods which need to be implemented in Python.
     
    This interface is for **internal use only** and is only public so it can be
    implemented in Python.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getCompletions(self, cmd: typing.Union[java.lang.String, str], caretPos: typing.Union[jpype.JInt, int]) -> java.util.List[ghidra.app.plugin.core.console.CodeCompletion]:
        """
        Generates code completions for the PyGhidra interpreter
        
        :param java.lang.String or str cmd: The command to get code completions for
        :param jpype.JInt or int caretPos: The position of the caret in the input string 'cmd'.
                        It should satisfy the constraint "0 <= caretPos <= cmd.length()"
        :return: A :obj:`List` of :obj:`code completions <CodeCompletion>` for the given command
        :rtype: java.util.List[ghidra.app.plugin.core.console.CodeCompletion]
        
        .. seealso::
        
            | :obj:`InterpreterConnection`InterpreterConnection.getCompletions(String, int)
        """

    def interrupt(self):
        """
        Interrupts the code running in the PyGhidra console
        """

    def restart(self):
        """
        Restarts the PyGhidra console
        """


@typing.type_check_only
class InterpreterTaskMonitor(ghidra.util.task.TaskMonitorAdapter):
    ...
    class_: typing.ClassVar[java.lang.Class]


class PyGhidraInterpreter(ghidra.util.Disposable, ghidra.app.plugin.core.interpreter.InterpreterConnection):
    """
    The PyGhidra interpreter connection
    """

    class_: typing.ClassVar[java.lang.Class]
    console: typing.Final[ghidra.app.plugin.core.interpreter.InterpreterConsole]

    def __init__(self, plugin: ghidra.pyghidra.PyGhidraPlugin, isPythonAvailable: typing.Union[jpype.JBoolean, bool]):
        ...

    def init(self, pythonSideConsole: PyGhidraConsole):
        """
        Initializes the interpreter with the provided PyGhidraConsole.
         
        This method is for **internal use only** and is only public so it can be
        called from Python.
        
        :param PyGhidraConsole pythonSideConsole: the python side console
        :raises AssertException: if the interpreter has already been initialized
        """


@typing.type_check_only
class ResetAction(docking.action.DockingAction):
    ...
    class_: typing.ClassVar[java.lang.Class]



__all__ = ["CancelAction", "InterpreterGhidraScript", "PyGhidraConsole", "InterpreterTaskMonitor", "PyGhidraInterpreter", "ResetAction"]
