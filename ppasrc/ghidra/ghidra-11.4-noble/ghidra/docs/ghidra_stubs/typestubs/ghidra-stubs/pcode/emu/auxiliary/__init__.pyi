from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.pcode.emu
import ghidra.pcode.exec_
import ghidra.program.model.lang
import java.lang # type: ignore
import org.apache.commons.lang3.tuple # type: ignore


U = typing.TypeVar("U")


class AuxPcodeThread(ghidra.pcode.emu.ModifiedPcodeThread[org.apache.commons.lang3.tuple.Pair[jpype.JArray[jpype.JByte], U]], typing.Generic[U]):
    """
    The default thread for :obj:`AuxPcodeEmulator`
    
     
    
    Generally, extending this class should not be necessary, as it already defers to the emulator's
    parts factory
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, name: typing.Union[java.lang.String, str], emulator: AuxPcodeEmulator[U]):
        ...


class AuxEmulatorPartsFactory(java.lang.Object, typing.Generic[U]):
    """
    An auxiliary emulator parts factory for stand-alone emulation
    
     
    
    This can manufacture all the parts needed for a stand-alone emulator with concrete and some
    implementation-defined auxiliary state. More capable emulators may also use many of these parts.
    Usually, the additional capabilities deal with how state is loaded and stored or otherwise made
    available to the user. The pattern of use for a stand-alone emulator is usually in a script:
    Create an emulator, initialize its state, write instructions to its memory, create and initialize
    a thread, point its counter at the instructions, instrument, step/run, inspect, and finally
    terminate.
     
     
    
    This "parts factory" pattern aims to flatten the extension points of the
    :obj:`AbstractPcodeMachine` and its components into a single class. Its use is not required, but
    may make things easier. It also encapsulates some "special knowledge," that might not otherwise
    be obvious to a developer, e.g., it creates the concrete state pieces, so the developer need not
    guess (or keep up to date) the concrete state piece classes to instantiate.
     
     
    
    The factory itself should be a singleton object. See the Taint Analyzer for a complete example
    solution using this interface.
    """

    class_: typing.ClassVar[java.lang.Class]

    def createExecutor(self, emulator: AuxPcodeEmulator[U], thread: ghidra.pcode.emu.DefaultPcodeThread[org.apache.commons.lang3.tuple.Pair[jpype.JArray[jpype.JByte], U]]) -> ghidra.pcode.emu.DefaultPcodeThread.PcodeThreadExecutor[org.apache.commons.lang3.tuple.Pair[jpype.JArray[jpype.JByte], U]]:
        """
        Create an executor for the given thread
         
         
        
        This allows the implementor to override or intercept the logic for individual p-code
        operations that would not otherwise be possible in the arithmetic, e.g., to print diagnostics
        on a conditional branch.
        
        :param AuxPcodeEmulator[U] emulator: the emulator
        :param ghidra.pcode.emu.DefaultPcodeThread[org.apache.commons.lang3.tuple.Pair[jpype.JArray[jpype.JByte], U]] thread: the thread
        :return: the executor
        :rtype: ghidra.pcode.emu.DefaultPcodeThread.PcodeThreadExecutor[org.apache.commons.lang3.tuple.Pair[jpype.JArray[jpype.JByte], U]]
        """

    def createLocalState(self, emulator: AuxPcodeEmulator[U], thread: ghidra.pcode.emu.PcodeThread[org.apache.commons.lang3.tuple.Pair[jpype.JArray[jpype.JByte], U]], concrete: ghidra.pcode.exec_.BytesPcodeExecutorStatePiece) -> ghidra.pcode.exec_.PcodeExecutorState[org.apache.commons.lang3.tuple.Pair[jpype.JArray[jpype.JByte], U]]:
        """
        Create the local (register) state of a new stand-alone emulator
         
         
        
        This is usually composed of pieces using :obj:`PairedPcodeExecutorStatePiece`, but it does
        not have to be. It must incorporate the concrete piece provided. It should be self contained
        and relatively fast.
        
        :param AuxPcodeEmulator[U] emulator: the emulator
        :param ghidra.pcode.emu.PcodeThread[org.apache.commons.lang3.tuple.Pair[jpype.JArray[jpype.JByte], U]] thread: the thread
        :param ghidra.pcode.exec_.BytesPcodeExecutorStatePiece concrete: the concrete piece
        :return: the composed state
        :rtype: ghidra.pcode.exec_.PcodeExecutorState[org.apache.commons.lang3.tuple.Pair[jpype.JArray[jpype.JByte], U]]
        """

    def createLocalUseropLibrary(self, emulator: AuxPcodeEmulator[U], thread: ghidra.pcode.emu.PcodeThread[org.apache.commons.lang3.tuple.Pair[jpype.JArray[jpype.JByte], U]]) -> ghidra.pcode.exec_.PcodeUseropLibrary[org.apache.commons.lang3.tuple.Pair[jpype.JArray[jpype.JByte], U]]:
        """
        Create a userop library for a given thread
        
        :param AuxPcodeEmulator[U] emulator: the emulator
        :param ghidra.pcode.emu.PcodeThread[org.apache.commons.lang3.tuple.Pair[jpype.JArray[jpype.JByte], U]] thread: the thread
        :return: the userop library
        :rtype: ghidra.pcode.exec_.PcodeUseropLibrary[org.apache.commons.lang3.tuple.Pair[jpype.JArray[jpype.JByte], U]]
        """

    def createLocalUseropStub(self, emulator: AuxPcodeEmulator[U]) -> ghidra.pcode.exec_.PcodeUseropLibrary[org.apache.commons.lang3.tuple.Pair[jpype.JArray[jpype.JByte], U]]:
        """
        Create a stub userop library for the emulator's threads
        
        :param AuxPcodeEmulator[U] emulator: the emulator
        :return: the library of stubs
        :rtype: ghidra.pcode.exec_.PcodeUseropLibrary[org.apache.commons.lang3.tuple.Pair[jpype.JArray[jpype.JByte], U]]
        """

    def createSharedState(self, emulator: AuxPcodeEmulator[U], concrete: ghidra.pcode.exec_.BytesPcodeExecutorStatePiece) -> ghidra.pcode.exec_.PcodeExecutorState[org.apache.commons.lang3.tuple.Pair[jpype.JArray[jpype.JByte], U]]:
        """
        Create the shared (memory) state of a new stand-alone emulator
         
         
        
        This is usually composed of pieces using :obj:`PairedPcodeExecutorStatePiece`, but it does
        not have to be. It must incorporate the concrete piece provided. It should be self contained
        and relatively fast.
        
        :param AuxPcodeEmulator[U] emulator: the emulator
        :param ghidra.pcode.exec_.BytesPcodeExecutorStatePiece concrete: the concrete piece
        :return: the composed state
        :rtype: ghidra.pcode.exec_.PcodeExecutorState[org.apache.commons.lang3.tuple.Pair[jpype.JArray[jpype.JByte], U]]
        """

    def createSharedUseropLibrary(self, emulator: AuxPcodeEmulator[U]) -> ghidra.pcode.exec_.PcodeUseropLibrary[org.apache.commons.lang3.tuple.Pair[jpype.JArray[jpype.JByte], U]]:
        """
        Create the userop library for the emulator (used by all threads)
        
        :param AuxPcodeEmulator[U] emulator: the emulator
        :return: the userop library
        :rtype: ghidra.pcode.exec_.PcodeUseropLibrary[org.apache.commons.lang3.tuple.Pair[jpype.JArray[jpype.JByte], U]]
        """

    def createThread(self, emulator: AuxPcodeEmulator[U], name: typing.Union[java.lang.String, str]) -> ghidra.pcode.emu.PcodeThread[org.apache.commons.lang3.tuple.Pair[jpype.JArray[jpype.JByte], U]]:
        """
        Create a thread with the given name
        
        :param AuxPcodeEmulator[U] emulator: the emulator
        :param java.lang.String or str name: the thread's name
        :return: the thread
        :rtype: ghidra.pcode.emu.PcodeThread[org.apache.commons.lang3.tuple.Pair[jpype.JArray[jpype.JByte], U]]
        """

    def getArithmetic(self, language: ghidra.program.model.lang.Language) -> ghidra.pcode.exec_.PcodeArithmetic[U]:
        """
        Get the arithmetic for the emulator given a target langauge
        
        :param ghidra.program.model.lang.Language language: the language
        :return: the arithmetic
        :rtype: ghidra.pcode.exec_.PcodeArithmetic[U]
        """

    @property
    def arithmetic(self) -> ghidra.pcode.exec_.PcodeArithmetic[U]:
        ...


class AuxPcodeEmulator(ghidra.pcode.emu.AbstractPcodeMachine[org.apache.commons.lang3.tuple.Pair[jpype.JArray[jpype.JByte], U]], typing.Generic[U]):
    """
    A stand-alone emulator whose parts are manufactured by a :obj:`AuxEmulatorPartsFactory`
     
     
    
    See the parts factory interface: :obj:`AuxEmulatorPartsFactory`. Also see the Taint Analyzer for
    a complete solution based on this class.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, language: ghidra.program.model.lang.Language):
        """
        Create a new emulator
        
        :param ghidra.program.model.lang.Language language: the language (processor model)
        """



__all__ = ["AuxPcodeThread", "AuxEmulatorPartsFactory", "AuxPcodeEmulator"]
