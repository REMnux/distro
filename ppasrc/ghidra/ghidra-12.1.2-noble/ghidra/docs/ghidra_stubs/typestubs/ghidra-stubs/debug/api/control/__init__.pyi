from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.debug.api.tracemgr
import ghidra.framework.plugintool
import ghidra.program.model.address
import java.lang # type: ignore
import java.util # type: ignore
import java.util.concurrent # type: ignore
import javax.swing # type: ignore


class ControlMode(java.lang.Enum[ControlMode]):
    """
    The control / state editing modes
    """

    class_: typing.ClassVar[java.lang.Class]
    RO_TARGET: typing.Final[ControlMode]
    """
    Control actions, breakpoint commands are directed to the target, but state edits are
    rejected.
    """

    RW_TARGET: typing.Final[ControlMode]
    """
    Control actions, breakpoint commands, and state edits are all directed to the target.
    """

    RO_TRACE: typing.Final[ControlMode]
    """
    Control actions activate trace snapshots, breakpoint commands are directed to the emulator,
    and state edits are rejected.
    """

    RW_TRACE: typing.Final[ControlMode]
    """
    Control actions activate trace snapshots, breakpoint commands are directed to the emulator,
    and state edits modify the current trace snapshot.
    """

    RW_EMULATOR: typing.Final[ControlMode]
    """
    Control actions, breakpoint commands, and state edits are directed to the emulator.
     
     
    
    Edits are accomplished by appending patch steps to the current schedule and activating that
    schedule.
    """

    ALL: typing.Final[java.util.List[ControlMode]]
    DEFAULT: typing.Final[ControlMode]
    name: typing.Final[java.lang.String]
    icon: typing.Final[javax.swing.Icon]

    def canEdit(self, coordinates: ghidra.debug.api.tracemgr.DebuggerCoordinates) -> bool:
        """
        Check if (broadly speaking) the mode supports editing the given coordinates
        
        :param ghidra.debug.api.tracemgr.DebuggerCoordinates coordinates: the coordinates to check
        :return: true if editable, false if not
        :rtype: bool
        """

    def followsPresent(self) -> bool:
        """
        Check if the UI should keep its active snapshot in sync with the recorder's latest.
        
        :return: true to follow, false if not
        :rtype: bool
        """

    def getAlternative(self, coordinates: ghidra.debug.api.tracemgr.DebuggerCoordinates) -> ControlMode:
        """
        If the mode can no longer be selected for new coordinates, get the new mode
         
         
        
        For example, if a target terminates while the mode is :obj:`.RO_TARGET`, this specifies the
        new mode.
        
        :param ghidra.debug.api.tracemgr.DebuggerCoordinates coordinates: the new coordinates
        :return: the new mode
        :rtype: ControlMode
        """

    def isSelectable(self, coordinates: ghidra.debug.api.tracemgr.DebuggerCoordinates) -> bool:
        """
        Check if this mode can be selected for the given coordinates
        
        :param ghidra.debug.api.tracemgr.DebuggerCoordinates coordinates: the current coordinates
        :return: true to enable selection, false to disable
        :rtype: bool
        """

    def isTarget(self) -> bool:
        """
        Indicates whether this mode controls the target
        
        :return: true if it controls the target
        :rtype: bool
        """

    def isVariableEditable(self, coordinates: ghidra.debug.api.tracemgr.DebuggerCoordinates, address: ghidra.program.model.address.Address, length: typing.Union[jpype.JInt, int]) -> bool:
        """
        Check if the given variable can be edited under this mode
        
        :param ghidra.debug.api.tracemgr.DebuggerCoordinates coordinates: the coordinates to check
        :param ghidra.program.model.address.Address address: the address of the variable
        :param jpype.JInt or int length: the length of the variable, in bytes
        :return: true if editable, false if not
        :rtype: bool
        """

    def modeOnChange(self, coordinates: ghidra.debug.api.tracemgr.DebuggerCoordinates) -> ControlMode:
        """
        Find the new mode (or same) mode when activating the given coordinates
         
         
        
        The default is implemented using :meth:`isSelectable(DebuggerCoordinates) <.isSelectable>` followed by
        :meth:`getAlternative(DebuggerCoordinates) <.getAlternative>`.
        
        :param ghidra.debug.api.tracemgr.DebuggerCoordinates coordinates: the new coordinates
        :return: the mode
        :rtype: ControlMode
        """

    def setVariable(self, tool: ghidra.framework.plugintool.PluginTool, coordinates: ghidra.debug.api.tracemgr.DebuggerCoordinates, address: ghidra.program.model.address.Address, data: jpype.JArray[jpype.JByte]) -> java.util.concurrent.CompletableFuture[java.lang.Void]:
        """
        Set the value of a variable
         
         
        
        Because the edit may be directed to a live target, the return value is a
        :obj:`CompletableFuture`. Additionally, when directed to the emulator, this allows the
        emulated state to be computed in the background.
        
        :param ghidra.framework.plugintool.PluginTool tool: the tool requesting the edit
        :param ghidra.debug.api.tracemgr.DebuggerCoordinates coordinates: the coordinates of the edit
        :param ghidra.program.model.address.Address address: the address of the variable
        :param jpype.JArray[jpype.JByte] data: the desired value of the variable
        :return: a future which completes when the edit is finished
        :rtype: java.util.concurrent.CompletableFuture[java.lang.Void]
        """

    def useEmulatedBreakpoints(self) -> bool:
        """
        Check if this mode operates on target breakpoints or emulator breakpoints
        
        :return: false for target, true for emulator
        :rtype: bool
        """

    def validateCoordinates(self, tool: ghidra.framework.plugintool.PluginTool, coordinates: ghidra.debug.api.tracemgr.DebuggerCoordinates, cause: ghidra.app.services.DebuggerTraceManagerService.ActivationCause) -> ghidra.debug.api.tracemgr.DebuggerCoordinates:
        """
        Validate and/or adjust the given coordinates pre-activation
         
         
        
        This is called by the trace manager whenever there is a request to activate new coordinates.
        The control mode may adjust or reject the request before the trace manager actually performs
        and notifies the activation.
        
        :param ghidra.framework.plugintool.PluginTool tool: the tool for displaying status messages
        :param ghidra.debug.api.tracemgr.DebuggerCoordinates coordinates: the requested coordinates
        :param ghidra.app.services.DebuggerTraceManagerService.ActivationCause cause: the cause of the activation
        :return: the effective coordinates or null to reject
        :rtype: ghidra.debug.api.tracemgr.DebuggerCoordinates
        """

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> ControlMode:
        ...

    @staticmethod
    def values() -> jpype.JArray[ControlMode]:
        ...

    @property
    def selectable(self) -> jpype.JBoolean:
        ...

    @property
    def alternative(self) -> ControlMode:
        ...

    @property
    def target(self) -> jpype.JBoolean:
        ...



__all__ = ["ControlMode"]
