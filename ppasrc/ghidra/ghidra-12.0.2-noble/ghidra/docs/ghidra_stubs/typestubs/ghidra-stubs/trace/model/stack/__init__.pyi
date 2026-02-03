from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.program.model.address
import ghidra.trace.model
import ghidra.trace.model.target.iface
import ghidra.trace.model.thread
import java.lang # type: ignore
import java.util # type: ignore


class TraceStackFrame(ghidra.trace.model.target.iface.TraceObjectInterface):
    """
    A frame in a :obj:`TraceStack`
    """

    class_: typing.ClassVar[java.lang.Class]
    KEY_PC: typing.Final = "_pc"

    def getComment(self, snap: typing.Union[jpype.JLong, int]) -> str:
        """
        Get the user comment for the frame
         
         
        
        In the experimental objects mode, this actually gets the comment in the listing at the
        frame's program counter for the given snap.
        
        :param jpype.JLong or int snap: the snap (only relevant in the experimental objects mode)
        :return: the (nullable) comment
        :rtype: str
        """

    def getLevel(self) -> int:
        """
        Get the frame's position in the containing stack
         
         
        
        0 represents the innermost frame or top of the stack.
        
        :return: the frame's level
        :rtype: int
        """

    def getProgramCounter(self, snap: typing.Union[jpype.JLong, int]) -> ghidra.program.model.address.Address:
        """
        Get the program counter at the given snap
        
        :param jpype.JLong or int snap: the snap (only relevant in the experimental objects mode. Ordinarily, the PC is
                    fixed over the containing stack's lifetime)
        :return: the program counter
        :rtype: ghidra.program.model.address.Address
        """

    def getStack(self) -> TraceStack:
        """
        Get the containing stack
        
        :return: the stack
        :rtype: TraceStack
        """

    def getTrace(self) -> ghidra.trace.model.Trace:
        """
        Get the trace containing this frame
        
        :return: the trace
        :rtype: ghidra.trace.model.Trace
        """

    def setComment(self, snap: typing.Union[jpype.JLong, int], comment: typing.Union[java.lang.String, str]):
        """
        Set the user comment for the frame
         
         
        
        In the experimental objects mode, this actually sets the comment in the listing at the
        frame's program counter for the given snap.
        
        :param jpype.JLong or int snap: the snap (only relevant in the experimental objects mode)
        :param java.lang.String or str comment: the (nullable) comment
        """

    def setProgramCounter(self, span: ghidra.trace.model.Lifespan, pc: ghidra.program.model.address.Address):
        """
        Set the program counter over the given span
        
        :param ghidra.trace.model.Lifespan span: the span (only relevant in the experimental objects mode. Ordinarily, the PC is
                    fixed over the containing stack's lifetime)
        :param ghidra.program.model.address.Address pc: the program counter
        """

    @property
    def trace(self) -> ghidra.trace.model.Trace:
        ...

    @property
    def stack(self) -> TraceStack:
        ...

    @property
    def level(self) -> jpype.JInt:
        ...

    @property
    def programCounter(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def comment(self) -> java.lang.String:
        ...


class TraceStack(ghidra.trace.model.TraceUniqueObject, ghidra.trace.model.target.iface.TraceObjectInterface):
    """
    A trace of the connected debugger's stack unwind
     
     
    
    Most of the information stored here is ancillary, since with sufficient analysis of associated
    images, it could be recovered, in the same fashion as the connected debugger did. Nevertheless,
    during a debug session, this information should be recorded if offered, as it makes it
    immediately accessible, before sufficient analysis has been performed, and provides some check
    for that analysis. If this information wasn't recorded during a session, this can store the
    result of that analysis.
     
     
    
    Conventionally, if the debugger can also unwind register values, then each frame should present a
    register bank. Otherwise, the same object presenting this stack should present the register bank.
    """

    class_: typing.ClassVar[java.lang.Class]

    def delete(self):
        """
        Delete this stack and its frames
        """

    def getDepth(self, snap: typing.Union[jpype.JLong, int]) -> int:
        """
        Get the depth (as recorded) of this stack
        
        :param jpype.JLong or int snap: the snap
        :return: the depth
        :rtype: int
        """

    def getFrame(self, snap: typing.Union[jpype.JLong, int], level: typing.Union[jpype.JInt, int], ensureDepth: typing.Union[jpype.JBoolean, bool]) -> TraceStackFrame:
        """
        Get the frame at the given level
        
        :param jpype.JLong or int snap: the snap
        :param jpype.JInt or int level: the level, where 0 indicates the inner-most frame.
        :param jpype.JBoolean or bool ensureDepth: true to expand the depth to accomodate the requested frame
        :return: the frame, or ``null`` if level exceeds the depth without ensureDepth set
        :rtype: TraceStackFrame
        :raises IndexOutOfBoundsException: if the level is negative
        """

    def getFrames(self, snap: typing.Union[jpype.JLong, int]) -> java.util.List[TraceStackFrame]:
        """
        Get all (known) frames in this stack
        
        :param jpype.JLong or int snap: the snap (only relevant in the experimental objects mode. Ordinarily, the frames
                    are fixed over the stack's lifetime)
        :return: the list of frames
        :rtype: java.util.List[TraceStackFrame]
        """

    def getThread(self) -> ghidra.trace.model.thread.TraceThread:
        """
        Get the thread whose stack this is
        
        :return: the thread
        :rtype: ghidra.trace.model.thread.TraceThread
        """

    def hasFixedFrames(self) -> bool:
        """
        Check if this stack'sframes are fixed for its lifetime
         
         
        
        This is a transitional method, since the experimental objects mode breaks with the normal
        stack/frame model. Essentially, this returns true if the normal model is being used, and
        false if the object-based model is being used.
        
        :return: true if fixed, false if object-based (dynamic)
        :rtype: bool
        """

    def isValid(self, snap: typing.Union[jpype.JLong, int]) -> bool:
        """
        Check if this stack is valid at the given snap
        
        :param jpype.JLong or int snap: the snap
        :return: true if valid
        :rtype: bool
        """

    def remove(self, snap: typing.Union[jpype.JLong, int]):
        """
        Remove this stack and its frame rom the given snapshot on
        
        :param jpype.JLong or int snap: the snapshot key
        """

    def setDepth(self, snap: typing.Union[jpype.JLong, int], depth: typing.Union[jpype.JInt, int], atInner: typing.Union[jpype.JBoolean, bool]):
        """
        Set the depth of the stack by adding or deleting frames to or from the specified end
         
         
        
        Note that pushing new frames onto a stack does not adjust the frame level of any
        frame-associated managers or spaces, e.g., that returned by
        :meth:`TraceMemoryManager.getMemoryRegisterSpace(TraceThread, int, boolean) <TraceMemoryManager.getMemoryRegisterSpace>`.
         
         
        
        If the experimental object mode is successful, this method should be deleted.
        
        :param jpype.JLong or int snap: the snap
        :param jpype.JInt or int depth: the desired depth
        :param jpype.JBoolean or bool atInner: true if frames should be "pushed"
        """

    @property
    def valid(self) -> jpype.JBoolean:
        ...

    @property
    def depth(self) -> jpype.JInt:
        ...

    @property
    def frames(self) -> java.util.List[TraceStackFrame]:
        ...

    @property
    def thread(self) -> ghidra.trace.model.thread.TraceThread:
        ...


class TraceStackManager(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def getFramesIn(self, set: ghidra.program.model.address.AddressSetView) -> java.lang.Iterable[TraceStackFrame]:
        ...

    def getLatestStack(self, thread: ghidra.trace.model.thread.TraceThread, snap: typing.Union[jpype.JLong, int]) -> TraceStack:
        ...

    def getStack(self, thread: ghidra.trace.model.thread.TraceThread, snap: typing.Union[jpype.JLong, int], createIfAbsent: typing.Union[jpype.JBoolean, bool]) -> TraceStack:
        ...

    @property
    def framesIn(self) -> java.lang.Iterable[TraceStackFrame]:
        ...



__all__ = ["TraceStackFrame", "TraceStack", "TraceStackManager"]
