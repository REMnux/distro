from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.pcode.emu.jit.gen
import ghidra.pcode.emu.jit.gen.opnd
import ghidra.pcode.emu.jit.gen.util
import ghidra.program.model.address
import ghidra.program.model.lang
import ghidra.program.model.pcode
import java.lang # type: ignore


JT = typing.TypeVar("JT")
N = typing.TypeVar("N")
N0 = typing.TypeVar("N0")
N1 = typing.TypeVar("N1")
T = typing.TypeVar("T")
THIS = typing.TypeVar("THIS")


class IntAccessGen(java.lang.Enum[IntAccessGen], MethodAccessGen, ExportsLegAccessGen):
    """
    The generator for writing integers.
    """

    class_: typing.ClassVar[java.lang.Class]
    BE: typing.Final[IntAccessGen]
    """
    The big-endian instance
    """

    LE: typing.Final[IntAccessGen]
    """
    The little-endian instance
    """


    @staticmethod
    def forEndian(endian: ghidra.program.model.lang.Endian) -> IntAccessGen:
        """
        Get the ``int`` access generator for the given byte order
        
        :param ghidra.program.model.lang.Endian endian: the byte order
        :return: the access generator
        :rtype: IntAccessGen
        """

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> IntAccessGen:
        ...

    @staticmethod
    def values() -> jpype.JArray[IntAccessGen]:
        ...


class SimpleAccessGen(AccessGen[JT], typing.Generic[T, JT]):
    """
    An access generator for simple-typed variables
    """

    class_: typing.ClassVar[java.lang.Class]

    def genReadToStack(self, em: ghidra.pcode.emu.jit.gen.util.Emitter[N], localThis: ghidra.pcode.emu.jit.gen.util.Local[ghidra.pcode.emu.jit.gen.util.Types.TRef[THIS]], gen: ghidra.pcode.emu.jit.gen.JitCodeGenerator[THIS], vn: ghidra.program.model.pcode.Varnode) -> ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[N, T]]:
        """
        Emit code to read a varnode
         
        
        If the varnode fits completely in the block (the common case), then this accesses the bytes
        from the one block, using the method chosen by size. If the varnode extends into the next
        block, then this will split the varnode into two portions according to machine byte order.
        Each portion is accessed using the method for the size of that portion. The results are
        reassembled into a single operand.
        
        :param N: the incoming stack:param ghidra.pcode.emu.jit.gen.util.Emitter[N] em: the emitter typed with the incoming stack
        :param ghidra.pcode.emu.jit.gen.util.Local[ghidra.pcode.emu.jit.gen.util.Types.TRef[THIS]] localThis: a handle to the local holding the ``this`` reference
        :param ghidra.pcode.emu.jit.gen.JitCodeGenerator[THIS] gen: the code generator
        :param ghidra.program.model.pcode.Varnode vn: the varnode
        :return: the code generator with the resulting stack, i.e., having pushed the value
        :rtype: ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[N, T]]
        """

    def genWriteFromStack(self, em: ghidra.pcode.emu.jit.gen.util.Emitter[N0], localThis: ghidra.pcode.emu.jit.gen.util.Local[ghidra.pcode.emu.jit.gen.util.Types.TRef[THIS]], gen: ghidra.pcode.emu.jit.gen.JitCodeGenerator[THIS], vn: ghidra.program.model.pcode.Varnode) -> ghidra.pcode.emu.jit.gen.util.Emitter[N1]:
        """
        Emit code to write a varnode
         
        
        If the varnode fits completely in the block (the common case), then this accesses the bytes
        from the one block, using the method chosen by size. If the varnode extends into the next
        block, then this will split the varnode into two portions according to machine byte order.
        Each portion is accessed using the method for the size of that portion.
        
        :param N1: the tail of the incoming stack:param N0: the incoming stack having the value on top:param ghidra.pcode.emu.jit.gen.util.Emitter[N0] em: the emitter typed with the incoming stack
        :param ghidra.pcode.emu.jit.gen.util.Local[ghidra.pcode.emu.jit.gen.util.Types.TRef[THIS]] localThis: a handle to the local holding the ``this`` reference
        :param ghidra.pcode.emu.jit.gen.JitCodeGenerator[THIS] gen: the code generator
        :param ghidra.program.model.pcode.Varnode vn: the varnode
        :return: the code generator with the resulting stack, i.e., having popped the value
        :rtype: ghidra.pcode.emu.jit.gen.util.Emitter[N1]
        """


class FloatAccessGen(java.lang.Enum[FloatAccessGen], SimpleAccessGen[ghidra.pcode.emu.jit.gen.util.Types.TFloat, ghidra.pcode.emu.jit.analysis.JitType.FloatJitType]):
    """
    The generator for writing floats
     
     
    
    This is accomplished by delegating to the int access generator with type conversion.
    """

    class_: typing.ClassVar[java.lang.Class]
    BE: typing.Final[FloatAccessGen]
    """
    The big-endian instance
    """

    LE: typing.Final[FloatAccessGen]
    """
    The little-endian instance
    """


    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> FloatAccessGen:
        ...

    @staticmethod
    def values() -> jpype.JArray[FloatAccessGen]:
        ...


class LongAccessGen(java.lang.Enum[LongAccessGen], MethodAccessGen, SimpleAccessGen[ghidra.pcode.emu.jit.gen.util.Types.TLong, ghidra.pcode.emu.jit.analysis.JitType.LongJitType]):
    """
    Bytes writer for longs in big endian order.
    """

    class_: typing.ClassVar[java.lang.Class]
    BE: typing.Final[LongAccessGen]
    """
    The big-endian instance
    """

    LE: typing.Final[LongAccessGen]
    """
    The little-endian instance
    """


    @staticmethod
    def forEndian(endian: ghidra.program.model.lang.Endian) -> LongAccessGen:
        """
        Get the ``long`` access generator for the given byte order
        
        :param ghidra.program.model.lang.Endian endian: the byte order
        :return: the access generator
        :rtype: LongAccessGen
        """

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> LongAccessGen:
        ...

    @staticmethod
    def values() -> jpype.JArray[LongAccessGen]:
        ...


class MpAccessGen(AccessGen[ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType]):
    """
    An access generator for a multi-precision integer variable
    """

    class_: typing.ClassVar[java.lang.Class]

    def genReadToArray(self, em: ghidra.pcode.emu.jit.gen.util.Emitter[N], localThis: ghidra.pcode.emu.jit.gen.util.Local[ghidra.pcode.emu.jit.gen.util.Types.TRef[THIS]], gen: ghidra.pcode.emu.jit.gen.JitCodeGenerator[THIS], vn: ghidra.program.model.pcode.Varnode, type: ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType, ext: ghidra.pcode.emu.jit.gen.opnd.Opnd.Ext, scope: ghidra.pcode.emu.jit.gen.util.Scope, slack: typing.Union[jpype.JInt, int]) -> ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[N, ghidra.pcode.emu.jit.gen.util.Types.TRef[jpype.JArray[jpype.JInt]]]]:
        """
        Emit bytecode to load the varnode's value into an integer array in little-endian order,
        pushing its ref onto the JVM stack.
        
        :param THIS: the type of the generated passage:param N: the incoming stack:param ghidra.pcode.emu.jit.gen.util.Emitter[N] em: the emitter typed with the incoming stack
        :param ghidra.pcode.emu.jit.gen.util.Local[ghidra.pcode.emu.jit.gen.util.Types.TRef[THIS]] localThis: a handle to the local holding the ``this`` reference
        :param ghidra.pcode.emu.jit.gen.JitCodeGenerator[THIS] gen: the code generator
        :param ghidra.program.model.pcode.Varnode vn: the varnode
        :param ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType type: desired the p-code type of the value
        :param ghidra.pcode.emu.jit.gen.opnd.Opnd.Ext ext: the kind of extension to apply
        :param ghidra.pcode.emu.jit.gen.util.Scope scope: a scope for generating temporary local storage
        :param jpype.JInt or int slack: the number of additional, more significant, elements to allocate in the array
        :return: the emitter typed with the resulting stack, i.e., having the ref pushed onto it
        :rtype: ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[N, ghidra.pcode.emu.jit.gen.util.Types.TRef[jpype.JArray[jpype.JInt]]]]
        """

    def genReadToOpnd(self, em: ghidra.pcode.emu.jit.gen.util.Emitter[N], localThis: ghidra.pcode.emu.jit.gen.util.Local[ghidra.pcode.emu.jit.gen.util.Types.TRef[THIS]], gen: ghidra.pcode.emu.jit.gen.JitCodeGenerator[THIS], vn: ghidra.program.model.pcode.Varnode, type: ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType, ext: ghidra.pcode.emu.jit.gen.opnd.Opnd.Ext, scope: ghidra.pcode.emu.jit.gen.util.Scope) -> ghidra.pcode.emu.jit.gen.opnd.Opnd.OpndEm[ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType, N]:
        """
        Emit bytecode to load the varnode's value into several locals.
        
        :param THIS: the type of the generated passage:param N: the incoming stack:param ghidra.pcode.emu.jit.gen.util.Emitter[N] em: the emitter typed with the incoming stack
        :param ghidra.pcode.emu.jit.gen.util.Local[ghidra.pcode.emu.jit.gen.util.Types.TRef[THIS]] localThis: a handle to the local holding the ``this`` reference
        :param ghidra.pcode.emu.jit.gen.JitCodeGenerator[THIS] gen: the code generator
        :param ghidra.program.model.pcode.Varnode vn: the varnode
        :param ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType type: desired the p-code type of the value
        :param ghidra.pcode.emu.jit.gen.opnd.Opnd.Ext ext: the kind of extension to apply
        :param ghidra.pcode.emu.jit.gen.util.Scope scope: a scope for generating temporary local storage
        :return: the operand containing the locals, and the emitter typed with the incoming stack
        :rtype: ghidra.pcode.emu.jit.gen.opnd.Opnd.OpndEm[ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType, N]
        """

    def genWriteFromArray(self, em: ghidra.pcode.emu.jit.gen.util.Emitter[N0], localThis: ghidra.pcode.emu.jit.gen.util.Local[ghidra.pcode.emu.jit.gen.util.Types.TRef[THIS]], gen: ghidra.pcode.emu.jit.gen.JitCodeGenerator[THIS], vn: ghidra.program.model.pcode.Varnode, scope: ghidra.pcode.emu.jit.gen.util.Scope) -> ghidra.pcode.emu.jit.gen.util.Emitter[N1]:
        """
        Emit bytecode to store a varnode's value from an array of integer legs, in little endian
        order
        
        :param THIS: the type of the generated passage:param N1: the tail of the incoming stack:param N0: the incoming stack having the array ref on top:param ghidra.pcode.emu.jit.gen.util.Emitter[N0] em: the emitter typed with the incoming stack
        :param ghidra.pcode.emu.jit.gen.util.Local[ghidra.pcode.emu.jit.gen.util.Types.TRef[THIS]] localThis: a handle to the local holding the ``this`` reference
        :param ghidra.pcode.emu.jit.gen.JitCodeGenerator[THIS] gen: the code generator
        :param ghidra.program.model.pcode.Varnode vn: the varnode
        :param ghidra.pcode.emu.jit.gen.util.Scope scope: a scope for generating temporary local storage
        :return: the emitter typed with the resulting stack, i.e., having popped the array
        :rtype: ghidra.pcode.emu.jit.gen.util.Emitter[N1]
        """

    def genWriteFromOpnd(self, em: ghidra.pcode.emu.jit.gen.util.Emitter[N], localThis: ghidra.pcode.emu.jit.gen.util.Local[ghidra.pcode.emu.jit.gen.util.Types.TRef[THIS]], gen: ghidra.pcode.emu.jit.gen.JitCodeGenerator[THIS], opnd: ghidra.pcode.emu.jit.gen.opnd.Opnd[ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType], vn: ghidra.program.model.pcode.Varnode) -> ghidra.pcode.emu.jit.gen.util.Emitter[N]:
        """
        Emit bytecode to store a value into a variable from the JVM stack.
        
        :param THIS: the type of the generated passage:param N: the incoming stack:param ghidra.pcode.emu.jit.gen.util.Emitter[N] em: the emitter typed with the incoming stack
        :param ghidra.pcode.emu.jit.gen.util.Local[ghidra.pcode.emu.jit.gen.util.Types.TRef[THIS]] localThis: a handle to the local holding the ``this`` reference
        :param ghidra.pcode.emu.jit.gen.JitCodeGenerator[THIS] gen: the code generator
        :param ghidra.pcode.emu.jit.gen.opnd.Opnd[ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType] opnd: the operand whose locals contain the value to be stored
        :param ghidra.program.model.pcode.Varnode vn: the varnode
        :return: the emitter typed with the incoming stack
        :rtype: ghidra.pcode.emu.jit.gen.util.Emitter[N]
        """


class MethodAccessGen(java.lang.Object):
    """
    A generator whose implementation is to emit invocations of a named method in
    :obj:`JitCompiledPassage`.
     
     
    
    This is needed by :obj:`LoadOpGen` and :obj:`StoreOpGen`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def chooseReadName(self, size: typing.Union[jpype.JInt, int]) -> str:
        """
        Choose the name of the read method, e.g. :meth:`JitCompiledPassage.readInt1(byte[], int) <JitCompiledPassage.readInt1>` to
        use for the given variable size.
        
        :param jpype.JInt or int size: the size in bytes
        :return: the name of the method
        :rtype: str
        """

    def chooseWriteName(self, size: typing.Union[jpype.JInt, int]) -> str:
        """
        Choose the name of the write method, e.g.
        :meth:`JitCompiledPassage.writeInt1(int,byte[], int) <JitCompiledPassage.writeInt1>` to use for the given variable size.
        
        :param jpype.JInt or int size: the size in bytes
        :return: the name of the method
        :rtype: str
        """


class DoubleAccessGen(java.lang.Enum[DoubleAccessGen], SimpleAccessGen[ghidra.pcode.emu.jit.gen.util.Types.TDouble, ghidra.pcode.emu.jit.analysis.JitType.DoubleJitType]):
    """
    The generator for accessing doubles
     
     
    
    This is accomplished by delegating to the long access generator with type conversion.
    """

    class_: typing.ClassVar[java.lang.Class]
    BE: typing.Final[DoubleAccessGen]
    """
    The big-endian instance
    """

    LE: typing.Final[DoubleAccessGen]
    """
    The little-endian instance
    """


    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> DoubleAccessGen:
        ...

    @staticmethod
    def values() -> jpype.JArray[DoubleAccessGen]:
        ...


class AccessGen(java.lang.Object, typing.Generic[JT]):
    """
    A generator to emit code that accesses variables of various size in a
    :obj:`state <JitBytesPcodeExecutorState>`, for a specific type and byte order.
     
    
    This is used by variable birthing and retirement as well as direct memory accesses. Dynamic
    memory accesses, i.e., :obj:`store <JitStoreOp>` and :obj:`load <JitLoadOp>` do not use this,
    though they may borrow some portions.
    """

    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def genReadToBool(em: ghidra.pcode.emu.jit.gen.util.Emitter[N], localThis: ghidra.pcode.emu.jit.gen.util.Local[ghidra.pcode.emu.jit.gen.util.Types.TRef[THIS]], gen: ghidra.pcode.emu.jit.gen.JitCodeGenerator[THIS], vn: ghidra.program.model.pcode.Varnode) -> ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[N, ghidra.pcode.emu.jit.gen.util.Types.TInt]]:
        """
        Emit bytecode to read the given varnode onto the stack as a p-code bool (JVM int)
        
        :param THIS: the type of the generated passage:param N: the incoming stack:param ghidra.pcode.emu.jit.gen.util.Emitter[N] em: the emitter typed with the incoming stack
        :param ghidra.pcode.emu.jit.gen.util.Local[ghidra.pcode.emu.jit.gen.util.Types.TRef[THIS]] localThis: a handle to the local holding the ``this`` reference
        :param ghidra.pcode.emu.jit.gen.JitCodeGenerator[THIS] gen: the code generator
        :param ghidra.program.model.pcode.Varnode vn: the varnode
        :return: the emitter typed with the resulting stack, i.e., having pushed the value
        :rtype: ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[N, ghidra.pcode.emu.jit.gen.util.Types.TInt]]
        """

    @staticmethod
    def lookup(endian: ghidra.program.model.lang.Endian, type: T) -> AccessGen[T]:
        """
        Lookup the generator for accessing variables for the given type and byte order
        
        :param ghidra.program.model.lang.Endian endian: the byte order
        :param T type: the p-code type of the variable
        :return: the access generator
        :rtype: AccessGen[T]
        """

    @staticmethod
    def lookupMp(endian: ghidra.program.model.lang.Endian) -> MpIntAccessGen:
        """
        Lookup the generator for accessing variables of multi-precision integer type and the given
        byte order
        
        :param ghidra.program.model.lang.Endian endian: the byte order
        :return: the access generator
        :rtype: MpIntAccessGen
        """

    @staticmethod
    def lookupSimple(endian: ghidra.program.model.lang.Endian, type: JT) -> SimpleAccessGen[T, JT]:
        """
        Lookup the generator for accessing variables of simple types and the given byte order
        
        :param T: the JVM type of the variable:param JT: the p-code type of the variable:param ghidra.program.model.lang.Endian endian: the byte order
        :param JT type: the p-code type of the variable
        :return: the access generator
        :rtype: SimpleAccessGen[T, JT]
        """


class ExportsLegAccessGen(SimpleAccessGen[ghidra.pcode.emu.jit.gen.util.Types.TInt, ghidra.pcode.emu.jit.analysis.JitType.IntJitType]):
    """
    A generator that exports part of its implementation for use in a :obj:`MpIntAccessGen`.
     
     
    
    This really just avoids the re-creation of :obj:`Varnode` objects for each leg of a large
    varnode. The method instead takes the (space,offset,size) triple as well as the offset of the
    block containing its start.
    """

    class_: typing.ClassVar[java.lang.Class]

    def genReadLegToStack(self, em: ghidra.pcode.emu.jit.gen.util.Emitter[N], localThis: ghidra.pcode.emu.jit.gen.util.Local[ghidra.pcode.emu.jit.gen.util.Types.TRef[THIS]], gen: ghidra.pcode.emu.jit.gen.JitCodeGenerator[THIS], space: ghidra.program.model.address.AddressSpace, block: typing.Union[jpype.JLong, int], off: typing.Union[jpype.JInt, int], size: typing.Union[jpype.JInt, int]) -> ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[N, ghidra.pcode.emu.jit.gen.util.Types.TInt]]:
        """
        Emit code to read one JVM int, either a whole variable or one leg of a multi-precision int
        variable.
         
         
        
        Legs that span blocks are handled as in
        :meth:`genReadToStack(Emitter, Local, JitCodeGenerator, Varnode) <.genReadToStack>`
        
        :param THIS: the type of the generated passage:param N: the incoming stack:param ghidra.pcode.emu.jit.gen.util.Emitter[N] em: the emitter typed with the incoming stack
        :param ghidra.pcode.emu.jit.gen.util.Local[ghidra.pcode.emu.jit.gen.util.Types.TRef[THIS]] localThis: a handle to the local holding the ``this`` reference
        :param ghidra.pcode.emu.jit.gen.JitCodeGenerator[THIS] gen: the code generator
        :param ghidra.program.model.address.AddressSpace space: the address space of the varnode
        :param jpype.JLong or int block: the block offset containing the varnode (or leg)
        :param jpype.JInt or int off: the offset of the varnode (or leg)
        :param jpype.JInt or int size: the size of the varnode in bytes (or leg)
        :return: the emitter typed with the resulting stack, i.e., having pushed the value
        :rtype: ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[N, ghidra.pcode.emu.jit.gen.util.Types.TInt]]
        """

    def genWriteLegFromStack(self, em: ghidra.pcode.emu.jit.gen.util.Emitter[N0], localThis: ghidra.pcode.emu.jit.gen.util.Local[ghidra.pcode.emu.jit.gen.util.Types.TRef[THIS]], gen: ghidra.pcode.emu.jit.gen.JitCodeGenerator[THIS], space: ghidra.program.model.address.AddressSpace, block: typing.Union[jpype.JLong, int], off: typing.Union[jpype.JInt, int], size: typing.Union[jpype.JInt, int]) -> ghidra.pcode.emu.jit.gen.util.Emitter[N1]:
        """
        Emit code to write one JVM int, either a whole variable or one leg of a multi-precision int
        variable.
         
         
        
        Legs that span blocks are handled as in
        :meth:`genWriteFromStack(Emitter, Local, JitCodeGenerator, Varnode) <.genWriteFromStack>`
        
        :param THIS: the type of the generated passage:param N1: the tail of the incoming stack:param N0: the incoming stack with the value on top:param ghidra.pcode.emu.jit.gen.util.Emitter[N0] em: the emitter typed with the incoming stack
        :param ghidra.pcode.emu.jit.gen.util.Local[ghidra.pcode.emu.jit.gen.util.Types.TRef[THIS]] localThis: a handle to the local holding the ``this`` reference
        :param ghidra.pcode.emu.jit.gen.JitCodeGenerator[THIS] gen: the code generator
        :param ghidra.program.model.address.AddressSpace space: the address space of the varnode
        :param jpype.JLong or int block: the block offset containing the varnode (or leg)
        :param jpype.JInt or int off: the offset of the varnode (or leg)
        :param jpype.JInt or int size: the size of the varnode in bytes (or leg)
        :return: the emitter typed with the resulting stack, i.e., having popped the value
        :rtype: ghidra.pcode.emu.jit.gen.util.Emitter[N1]
        """


class MpIntAccessGen(java.lang.Enum[MpIntAccessGen], MpAccessGen):
    """
    The generator for writing multi-precision ints.
    """

    class_: typing.ClassVar[java.lang.Class]
    BE: typing.Final[MpIntAccessGen]
    """
    The big-endian instance
    """

    LE: typing.Final[MpIntAccessGen]
    """
    The little-endian instance
    """


    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> MpIntAccessGen:
        ...

    @staticmethod
    def values() -> jpype.JArray[MpIntAccessGen]:
        ...



__all__ = ["IntAccessGen", "SimpleAccessGen", "FloatAccessGen", "LongAccessGen", "MpAccessGen", "MethodAccessGen", "DoubleAccessGen", "AccessGen", "ExportsLegAccessGen", "MpIntAccessGen"]
