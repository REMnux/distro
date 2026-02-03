from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.pcode.exec_
import ghidra.program.model.address
import ghidra.program.model.lang
import ghidra.taint.model
import java.lang # type: ignore
import java.util # type: ignore


class TaintPcodeExecutorState(ghidra.pcode.exec_.PairedPcodeExecutorState[jpype.JArray[jpype.JByte], ghidra.taint.model.TaintVec]):
    """
    A paired concrete-plus-taint state
     
     
    
    This contains the emulator's machine state along with the taint markings. Technically, one of
    these will hold the machine's memory, while another (for each thread) will hold the machine's
    registers. It's composed of two pieces. The concrete piece holds the actual concrete bytes, while
    the taint piece holds the taint markings. A request to get a variable's value from this state
    will return a pair where the left element comes from the concrete piece and the right element
    comes from the taint piece.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, language: ghidra.program.model.lang.Language, concrete: ghidra.pcode.exec_.BytesPcodeExecutorStatePiece, cb: ghidra.pcode.exec_.PcodeStateCallbacks):
        """
        Create a state from the given concrete piece and an internally constructed taint piece
        
        :param ghidra.program.model.lang.Language language: the language for creating the taint piece
        :param ghidra.pcode.exec_.BytesPcodeExecutorStatePiece concrete: the concrete piece
        :param ghidra.pcode.exec_.PcodeStateCallbacks cb: callbacks to receive emulation events
        """


class TaintSpace(java.lang.Object):
    """
    The storage space for taint sets in a single address space (possibly the register space)
     
     
    
    This is the actual implementation of the in-memory storage for taint marks. For a stand-alone
    emulator, this is the full state. For a trace- or Debugger-integrated emulator, this is a cache
    of taints loaded from a trace backing this emulator. (See :obj:`TaintPieceHandler`.) Most
    likely, that trace is the user's current trace.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, space: ghidra.program.model.address.AddressSpace, piece: TaintPcodeExecutorStatePiece):
        ...

    def clear(self):
        ...

    def get(self, offset: typing.Union[jpype.JLong, int], size: typing.Union[jpype.JInt, int], cb: ghidra.pcode.exec_.PcodeStateCallbacks) -> ghidra.taint.model.TaintVec:
        """
        Retrieve the taint sets for the variable at the given offset
         
         
        
        This works the same as :meth:`getInto(long, TaintVec, PcodeStateCallbacks) <.getInto>`, but creates a
        new vector of the given size, reads the taint sets, and returns the vector.
        
        :param jpype.JLong or int offset: the offset
        :param jpype.JInt or int size: the size of the variable
        :param ghidra.pcode.exec_.PcodeStateCallbacks cb: callbacks to receive emulation events
        :return: the taint vector for that variable
        :rtype: ghidra.taint.model.TaintVec
        """

    def getInto(self, offset: typing.Union[jpype.JLong, int], buf: ghidra.taint.model.TaintVec, cb: ghidra.pcode.exec_.PcodeStateCallbacks):
        """
        Retrieve the taint sets for the variable at the given offset
         
         
        
        This retrieves as many taint sets as there are elements in the given buffer vector. The first
        element becomes the taint set at the given offset, then each subsequent element becomes the
        taint set at each subsequent offset until the vector is filled. This is analogous to the
        manner in which bytes would be "read" from concrete state, starting at a given offset, into a
        destination array.
        
        :param jpype.JLong or int offset: the offset
        :param ghidra.taint.model.TaintVec buf: the vector to receive taint sets
        :param ghidra.pcode.exec_.PcodeStateCallbacks cb: callbacks to receive emulation events
        """

    def getNextEntry(self, offset: typing.Union[jpype.JLong, int]) -> java.util.Map.Entry[java.lang.Long, ghidra.taint.model.TaintVec]:
        ...

    def getRegisterValues(self, registers: java.util.List[ghidra.program.model.lang.Register]) -> java.util.Map[ghidra.program.model.lang.Register, ghidra.taint.model.TaintVec]:
        ...

    def set(self, offset: typing.Union[jpype.JLong, int], val: ghidra.taint.model.TaintVec, cb: ghidra.pcode.exec_.PcodeStateCallbacks):
        """
        Mark the variable at offset with the given taint sets
         
         
        
        This marks possibly several offsets, starting at the given offset. The first taint set in the
        vector is used to mark the given offset, then each subsequent set marks each subsequent
        offset. This is analogous to the manner in which bytes would be "written" from a source array
        into concrete state, starting at a given offset.
        
        :param jpype.JLong or int offset: the starting offset
        :param ghidra.taint.model.TaintVec val: the vector of taint sets
        :param ghidra.pcode.exec_.PcodeStateCallbacks cb: callbacks to receive emulation events
        """

    @property
    def nextEntry(self) -> java.util.Map.Entry[java.lang.Long, ghidra.taint.model.TaintVec]:
        ...

    @property
    def registerValues(self) -> java.util.Map[ghidra.program.model.lang.Register, ghidra.taint.model.TaintVec]:
        ...


class TaintPieceHandler(ghidra.pcode.exec_.trace.TraceEmulationIntegration.AbstractPropertyBasedPieceHandler[jpype.JArray[jpype.JByte], ghidra.taint.model.TaintVec, java.lang.String]):
    """
    The piece handler for :obj:`TaintVec`
     
     
    
    This contains the logic for integrating the Taint emulator with traces. That is, it is the
    mechanism that loads previous taint analysis from a trace and stores new results back into the
    trace. The object passed into these methods as ``piece`` is almost certainly a
    :obj:`TaintPcodeExecutorStatePiece`, but not necessarily. As a matter of best practice, it
    should not be necessary to cast. The given :obj:`PcodeExecutorStatePiece` interface should be
    sufficient as internals can often be reached via
    :meth:`PcodeExecutorStatePiece.getVarInternal(AddressSpace, long, int, Reason) <PcodeExecutorStatePiece.getVarInternal>`.
    """

    class_: typing.ClassVar[java.lang.Class]
    NAME: typing.Final = "Taint"
    """
    The name we will use for the property map
    """


    def __init__(self):
        ...


class TaintPcodeExecutorStatePiece(ghidra.pcode.exec_.AbstractLongOffsetPcodeExecutorStatePiece[jpype.JArray[jpype.JByte], ghidra.taint.model.TaintVec, TaintSpace]):
    """
    The taint state piece
    
     
    
    The framework-provided class from which this derives expects us to implement state for each
    address space using a separate storage object. We do this by providing :obj:`TaintSpace`, which
    is where all the taint storage logic is actually located. We then use a map :obj:`.spaceMap` to
    lazily create a keep each of those spaces.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, language: ghidra.program.model.lang.Language, addressArithmetic: ghidra.pcode.exec_.PcodeArithmetic[jpype.JArray[jpype.JByte]], arithmetic: ghidra.pcode.exec_.PcodeArithmetic[ghidra.taint.model.TaintVec], cb: ghidra.pcode.exec_.PcodeStateCallbacks):
        """
        Create a state piece
        
        :param ghidra.program.model.lang.Language language: the emulator's language
        :param ghidra.pcode.exec_.PcodeArithmetic[jpype.JArray[jpype.JByte]] addressArithmetic: the arithmetic for the address type
        :param ghidra.pcode.exec_.PcodeArithmetic[ghidra.taint.model.TaintVec] arithmetic: the arithmetic for the value type
        :param ghidra.pcode.exec_.PcodeStateCallbacks cb: callbacks to receive emulation events
        """

    @typing.overload
    def __init__(self, language: ghidra.program.model.lang.Language, addressArithmetic: ghidra.pcode.exec_.PcodeArithmetic[jpype.JArray[jpype.JByte]], cb: ghidra.pcode.exec_.PcodeStateCallbacks):
        """
        Create the taint piece
        
        :param ghidra.program.model.lang.Language language: the language of the emulator
        :param ghidra.pcode.exec_.PcodeArithmetic[jpype.JArray[jpype.JByte]] addressArithmetic: the address arithmetic, likely taken from the concrete piece
        :param ghidra.pcode.exec_.PcodeStateCallbacks cb: callbacks to receive emulation events
        """



__all__ = ["TaintPcodeExecutorState", "TaintSpace", "TaintPieceHandler", "TaintPcodeExecutorStatePiece"]
