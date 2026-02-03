"""
The Taint Emulator
 
 

This and the :obj:`ghidra.pcode.emu.taint.state` packages contain all the parts necessary to
construct the emulator.
 
 

For this package, I recommend a top-down approach, since the top component provides a flat
catalog of the lower components. That top piece is actually in a separate package. See
:obj:`ghidra.pcode.emu.taint.TaintPartsFactory`. That factory is then used in
:obj:`ghidra.pcode.emu.taint.TaintPcodeEmulator` to realize the emulator.
"""
from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.debug.api.emulation
import ghidra.pcode.emu
import ghidra.pcode.emu.auxiliary
import ghidra.pcode.exec_
import ghidra.pcode.exec_.trace.data
import ghidra.program.model.lang
import ghidra.taint.model
import java.lang # type: ignore
import org.apache.commons.lang3.tuple # type: ignore


class TaintPcodeUseropLibrary(ghidra.pcode.exec_.AnnotatedPcodeUseropLibrary[org.apache.commons.lang3.tuple.Pair[jpype.JArray[jpype.JByte], ghidra.taint.model.TaintVec]]):
    """
    A userop library for tainting machine state variables
     
     
    
    Because Sleigh doesn't allow string literals, we're somewhat limited in what we allow a client to
    express. We'll allow the generation of taint variables and taint arrays on a 0-up basis, instead
    of allowing users to "name" the variable. These p-code ops become accessible to scripts, can be
    used in p-code injects, and can also be used in a :obj:`TraceSchedule`, i.e., in the "go to
    time" dialog.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def taint_arr(self, in_: org.apache.commons.lang3.tuple.Pair[jpype.JArray[jpype.JByte], ghidra.taint.model.TaintVec]) -> org.apache.commons.lang3.tuple.Pair[jpype.JArray[jpype.JByte], ghidra.taint.model.TaintVec]:
        """
        Taint the given machine variable with an array of taint symbols
         
         
        
        This generates a 0-up indexed sequence of taint symbols, unioning each with the corresponding
        taint set of the input taint vector. For example, assuming an initial state with no taints,
        the Sleigh code ``RAX = taint_arr(RAX)`` will cause RAX to be tainted as
        [arr_0_0][arr_0_1]...[arr_0_7].
        
        :param org.apache.commons.lang3.tuple.Pair[jpype.JArray[jpype.JByte], ghidra.taint.model.TaintVec] in: the input value
        :return: the same value, with the generated taint unioned in
        :rtype: org.apache.commons.lang3.tuple.Pair[jpype.JArray[jpype.JByte], ghidra.taint.model.TaintVec]
        """

    def taint_var(self, in_: org.apache.commons.lang3.tuple.Pair[jpype.JArray[jpype.JByte], ghidra.taint.model.TaintVec]) -> org.apache.commons.lang3.tuple.Pair[jpype.JArray[jpype.JByte], ghidra.taint.model.TaintVec]:
        """
        Taint the given machine variable with a single taint symbol
         
         
        
        This generates a single taint symbol (mark), places it in a singleton set, and then broadcast
        unions it with the taint vector already on the input variable. For example, assuming an
        initial state with no taints, the Sleigh code ``RAX = taint_var(RAX)`` will cause every
        byte of RAX to be tainted with "var_0".
        
        :param org.apache.commons.lang3.tuple.Pair[jpype.JArray[jpype.JByte], ghidra.taint.model.TaintVec] in: the input value
        :return: the same value, with the generated taint unioned in
        :rtype: org.apache.commons.lang3.tuple.Pair[jpype.JArray[jpype.JByte], ghidra.taint.model.TaintVec]
        """


class TaintPcodeEmulator(ghidra.pcode.emu.auxiliary.AuxPcodeEmulator[ghidra.taint.model.TaintVec]):
    """
    An emulator with taint analysis
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, language: ghidra.program.model.lang.Language, cb: ghidra.pcode.emu.PcodeEmulationCallbacks[org.apache.commons.lang3.tuple.Pair[jpype.JArray[jpype.JByte], ghidra.taint.model.TaintVec]]):
        """
        Create an emulator
        
        :param ghidra.program.model.lang.Language language: the language (processor model)
        :param ghidra.pcode.emu.PcodeEmulationCallbacks[org.apache.commons.lang3.tuple.Pair[jpype.JArray[jpype.JByte], ghidra.taint.model.TaintVec]] cb: callbacks to receive emulation events
        """

    @typing.overload
    def __init__(self, language: ghidra.program.model.lang.Language):
        """
        Create an emulator
        
        :param ghidra.program.model.lang.Language language: the language (processor model)
        """


class TaintPcodeArithmetic(java.lang.Enum[TaintPcodeArithmetic], ghidra.pcode.exec_.PcodeArithmetic[ghidra.taint.model.TaintVec]):
    """
    The p-code arithmetic on the taint domain
     
     
    
    The p-code arithmetic serves as the bridge between p-code and the domain of analysis.
    Technically, the state itself also contributes minimally to that bridge.
    """

    class_: typing.ClassVar[java.lang.Class]
    BIG_ENDIAN: typing.Final[TaintPcodeArithmetic]
    """
    The instance for big-endian languages
    """

    LITTLE_ENDIAN: typing.Final[TaintPcodeArithmetic]
    """
    The instance for little-endian languages
    """


    @staticmethod
    def forEndian(bigEndian: typing.Union[jpype.JBoolean, bool]) -> TaintPcodeArithmetic:
        """
        Get the taint arithmetic for the given endianness
         
         
        
        This method is provided since clients of this class may expect it, as they would for any
        realization of :obj:`PcodeArithmetic`.
        
        :param jpype.JBoolean or bool bigEndian: true for big endian, false for little
        :return: the arithmetic
        :rtype: TaintPcodeArithmetic
        """

    @staticmethod
    def forLanguage(language: ghidra.program.model.lang.Language) -> TaintPcodeArithmetic:
        """
        Get the taint arithmetic for the given langauge
         
         
        
        This method is provided since clients of this class may expect it, as they would for any
        realization of :obj:`PcodeArithmetic`.
        
        :param ghidra.program.model.lang.Language language: the langauge
        :return: the arithmetic
        :rtype: TaintPcodeArithmetic
        """

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> TaintPcodeArithmetic:
        ...

    @staticmethod
    def values() -> jpype.JArray[TaintPcodeArithmetic]:
        ...


class TaintPartsFactory(java.lang.Enum[TaintPartsFactory], ghidra.pcode.emu.auxiliary.AuxEmulatorPartsFactory[ghidra.taint.model.TaintVec]):
    """
    The parts factory for creating emulators with taint analysis
     
     
    
    This is probably the most straightforward means of implementing a concrete-plus-auxiliary
    emulator in Ghidra. For our case, the auxiliary piece is the :obj:`TaintVec`. Ideally, the
    auxiliary piece implements the analog of a byte array, so that each byte in the concrete piece
    corresponds to an element in the abstract piece. We've done that here by letting each taint set
    in the vector be the taint on the corresponding byte. Each part we implement must adhere to that
    rule. For an overview of the parts of a p-code emulator, see :obj:`PcodeEmulator`.
     
     
    
    As recommended by the documentation, we've implemented the factory as a singleton. As presented
    in the source, we'll visit each component in this order:
     
    * P-code Arithmetic: :obj:`TaintPcodeArithmetic`
    * Userop Library: :obj:`TaintPcodeUseropLibrary`
    * P-code Executor: :obj:`TaintPcodeThreadExecutor`
    * Machine State: :obj:`TaintPcodeExecutorState`
    """

    class_: typing.ClassVar[java.lang.Class]
    INSTANCE: typing.Final[TaintPartsFactory]
    """
    This singleton factory instance
    """


    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> TaintPartsFactory:
        ...

    @staticmethod
    def values() -> jpype.JArray[TaintPartsFactory]:
        ...


class TaintEmulatorFactory(ghidra.debug.api.emulation.EmulatorFactory):
    """
    An emulator factory for making the :obj:`TaintPcodeEmulator` discoverable to the UI
     
     
    
    This is the final class to create a full Debugger-integrated emulator. This class is what makes
    it appear in the menu of possible emulators the user may configure.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def addHandlers(writer: ghidra.pcode.exec_.trace.TraceEmulationIntegration.Writer):
        """
        A common place to factor addition of the required handler.
         
         
        
        It is presumed something else has or will add the other handlers, e.g., for the bytes.
        
        :param ghidra.pcode.exec_.trace.TraceEmulationIntegration.Writer writer: the writer to add handlers to
        """

    @staticmethod
    def delayedWriteTrace(access: ghidra.pcode.exec_.trace.data.PcodeTraceAccess) -> ghidra.pcode.exec_.trace.TraceEmulationIntegration.Writer:
        """
        This is conventionally available for testing and for scripts that would like to create a
        trace-integrated emulator without using the service.
        
        :param ghidra.pcode.exec_.trace.data.PcodeTraceAccess access: the means of accessing the integrated trace
        :return: a writer with callbacks for trace integration
        :rtype: ghidra.pcode.exec_.trace.TraceEmulationIntegration.Writer
        """


class TaintPcodeThreadExecutor(ghidra.pcode.emu.DefaultPcodeThread.PcodeThreadExecutor[org.apache.commons.lang3.tuple.Pair[jpype.JArray[jpype.JByte], ghidra.taint.model.TaintVec]]):
    """
    An instrumented executor for the Taint Analyzer
     
     
    
    This part is responsible for executing all the actual p-code operations generated by each decoded
    instruction. Each thread in the emulator gets a distinct executor. So far, we haven't actually
    added any instrumentation, but the conditions of :obj:`PcodeOp.CBRANCH` operations will likely
    be examined by the user, so we set up the skeleton here.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, thread: ghidra.pcode.emu.DefaultPcodeThread[org.apache.commons.lang3.tuple.Pair[jpype.JArray[jpype.JByte], ghidra.taint.model.TaintVec]]):
        """
        Create the executor
        
        :param ghidra.pcode.emu.DefaultPcodeThread[org.apache.commons.lang3.tuple.Pair[jpype.JArray[jpype.JByte], ghidra.taint.model.TaintVec]] thread: the thread being created
        """



__all__ = ["TaintPcodeUseropLibrary", "TaintPcodeEmulator", "TaintPcodeArithmetic", "TaintPartsFactory", "TaintEmulatorFactory", "TaintPcodeThreadExecutor"]
