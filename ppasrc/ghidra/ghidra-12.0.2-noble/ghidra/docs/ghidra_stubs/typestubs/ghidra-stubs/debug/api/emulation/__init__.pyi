from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.pcode.emu
import ghidra.pcode.exec_
import ghidra.pcode.exec_.trace.data
import ghidra.program.model.address
import ghidra.util.classfinder
import java.lang # type: ignore
import java.util.concurrent # type: ignore


class PcodeDebuggerAccess(ghidra.pcode.exec_.trace.data.PcodeTraceAccess):
    """
    A trace-and-debugger access shim
     
     
    
    In addition to the trace "coordinates" encapsulated by :obj:`PcodeTraceAccess`, this
    encapsulates the tool controlling a session and the session's target. This permits p-code
    executor/emulator states to access target data and to access session data, e.g., data from mapped
    static images. It supports the same method chain pattern as :obj:`PcodeTraceAccess`.
    """

    class_: typing.ClassVar[java.lang.Class]


class PcodeDebuggerDataAccess(ghidra.pcode.exec_.trace.data.PcodeTraceDataAccess):
    """
    A data-access shim for a trace and the debugger
     
     
    
    This shim, in addition to the trace, can also access its associated target, as well as session
    information maintained by the Debugger tool.
    """

    class_: typing.ClassVar[java.lang.Class]

    def isLive(self) -> bool:
        """
        Check if the associated trace represents a live session
         
         
        
        The session is live if it's trace has a recorder and the source snapshot matches the
        recorder's destination snapshot.
        
        :return: true if live, false otherwise
        :rtype: bool
        """

    @property
    def live(self) -> jpype.JBoolean:
        ...


class PcodeDebuggerRegistersAccess(ghidra.pcode.exec_.trace.data.PcodeTraceRegistersAccess, PcodeDebuggerDataAccess):
    """
    A data-access shim for a trace's registers and the debugger
    """

    class_: typing.ClassVar[java.lang.Class]

    def readFromTargetRegisters(self, unknown: ghidra.program.model.address.AddressSetView) -> java.util.concurrent.CompletableFuture[java.lang.Boolean]:
        """
        Instruct the associated recorder to read registers from the target
        
        :param ghidra.program.model.address.AddressSetView unknown: the address set (in the platform's ``register`` space) of registers to
                    read
        :return: a future which completes when the read is complete and its results recorded to the
                trace. It completes with true when any part of target state was successfully read. It
                completes with false if there is no target, or if the target was not read.
        :rtype: java.util.concurrent.CompletableFuture[java.lang.Boolean]
        """

    def writeTargetRegister(self, address: ghidra.program.model.address.Address, data: jpype.JArray[jpype.JByte]) -> java.util.concurrent.CompletableFuture[java.lang.Boolean]:
        """
        Instruct the associated recorder to write target registers
         
         
        
        In normal operation, this will also cause the recorder, upon a successful write, to record
        the same values into the destination trace. If this shim is not associated with a live
        session, the returned future completes immediately with false.
        
        :param ghidra.program.model.address.Address address: the address of the first byte to write (in the platform's ``register``
                    space)
        :param jpype.JArray[jpype.JByte] data: the bytes to write
        :return: a future which completes when the write is complete and its results recorded to the
                trace. It completes with true when the target was written. It completes with false if
                there is no target, or if the target is not effected.
        :rtype: java.util.concurrent.CompletableFuture[java.lang.Boolean]
        """


class PcodeDebuggerMemoryAccess(ghidra.pcode.exec_.trace.data.PcodeTraceMemoryAccess, PcodeDebuggerDataAccess):
    """
    A data-access shim for a trace's memory and the debugger
    """

    class_: typing.ClassVar[java.lang.Class]

    def readFromStaticImages(self, piece: ghidra.pcode.exec_.PcodeExecutorStatePiece[jpype.JArray[jpype.JByte], jpype.JArray[jpype.JByte]], unknown: ghidra.program.model.address.AddressSetView) -> ghidra.program.model.address.AddressSetView:
        """
        Use the Debugger's static mapping service to read bytes from relocated program images
         
         
        
        To be read, the program database for the static image must be open in the same tool as the
        trace being emulated. Depending on the use case, this may only be approximately correct. In
        particular, if the trace was from a live session that has since been terminated, and the
        image was relocated with fixups, reads at those fixups which fall through to static images
        will be incorrect, and may lead to undefined behavior in the emulated program.
        
        :param ghidra.pcode.exec_.PcodeExecutorStatePiece[jpype.JArray[jpype.JByte], jpype.JArray[jpype.JByte]] piece: the destination state piece
        :param ghidra.program.model.address.AddressSetView unknown: the address set to read
        :return: the parts of ``unknown`` that *still haven't* been read
        :rtype: ghidra.program.model.address.AddressSetView
        """

    def readFromTargetMemory(self, unknown: ghidra.program.model.address.AddressSetView) -> java.util.concurrent.CompletableFuture[java.lang.Boolean]:
        """
        Instruct the associated recorder to read memory from the target
         
         
        
        The recorder may quantize the given address set to pages. It will include all the requested
        addresses, though. If this shim is not associated with a live session, the returned future
        completes immediately with false.
        
        :param ghidra.program.model.address.AddressSetView unknown: the address set to read
        :return: a future which completes when the read is complete and its results recorded to the
                trace. It completes with true when any part of target memory was successfully read.
                It completes with false if there is no target, or if the target was not read.
        :rtype: java.util.concurrent.CompletableFuture[java.lang.Boolean]
        """

    def writeTargetMemory(self, address: ghidra.program.model.address.Address, data: jpype.JArray[jpype.JByte]) -> java.util.concurrent.CompletableFuture[java.lang.Boolean]:
        """
        Instruct the associated recorder to write target memory
         
         
        
        In normal operation, this will also cause the recorder, upon a successful write, to record
        the same bytes into the destination trace. If this shim is not associated with a live
        session, the returned future completes immediately with false.
        
        :param ghidra.program.model.address.Address address: the address of the first byte to write
        :param jpype.JArray[jpype.JByte] data: the bytes to write
        :return: a future which completes when the write is complete and its results recorded to the
                trace. It completes with true when the target was written. It completes with false if
                there is no target, or if the target is not effected.
        :rtype: java.util.concurrent.CompletableFuture[java.lang.Boolean]
        """


class EmulatorFactory(ghidra.util.classfinder.ExtensionPoint):
    """
    A factory for configuring and creating a Debugger-integrated emulator
    """

    class_: typing.ClassVar[java.lang.Class]

    def create(self, access: PcodeDebuggerAccess, writer: ghidra.pcode.exec_.trace.TraceEmulationIntegration.Writer) -> ghidra.pcode.emu.PcodeMachine[typing.Any]:
        """
        Create the emulator
        
        :param PcodeDebuggerAccess access: the trace-and-debugger access shim
        :param ghidra.pcode.exec_.trace.TraceEmulationIntegration.Writer writer: the Debugger's emulation callbacks for UI integration
        :return: the emulator with callbacks installed
        :rtype: ghidra.pcode.emu.PcodeMachine[typing.Any]
        """

    def getTitle(self) -> str:
        """
        Get the title, to appear in menus and dialogs
        
        :return: the title
        :rtype: str
        """

    @property
    def title(self) -> java.lang.String:
        ...



__all__ = ["PcodeDebuggerAccess", "PcodeDebuggerDataAccess", "PcodeDebuggerRegistersAccess", "PcodeDebuggerMemoryAccess", "EmulatorFactory"]
