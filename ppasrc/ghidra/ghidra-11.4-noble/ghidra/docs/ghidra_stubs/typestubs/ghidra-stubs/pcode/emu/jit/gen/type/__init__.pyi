from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.pcode.emu.jit.analysis
import ghidra.pcode.emu.jit.gen
import ghidra.program.model.address
import ghidra.program.model.lang
import ghidra.program.model.pcode
import java.lang # type: ignore
import org.objectweb.asm # type: ignore


class LongReadGen(java.lang.Enum[LongReadGen], MethodAccessGen):
    """
    The generator for reading longs.
    """

    class_: typing.ClassVar[java.lang.Class]
    BE: typing.Final[LongReadGen]
    """
    The big-endian instance
    """

    LE: typing.Final[LongReadGen]
    """
    The little-endian instance
    """


    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> LongReadGen:
        ...

    @staticmethod
    def values() -> jpype.JArray[LongReadGen]:
        ...


class DoubleWriteGen(java.lang.Enum[DoubleWriteGen], TypedAccessGen):
    """
    The generator for writing doubles
     
     
    
    This is accomplished by converting to a long and then writing it.
    """

    class_: typing.ClassVar[java.lang.Class]
    BE: typing.Final[DoubleWriteGen]
    """
    The big-endian instance
    """

    LE: typing.Final[DoubleWriteGen]
    """
    The little-endian instance
    """


    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> DoubleWriteGen:
        ...

    @staticmethod
    def values() -> jpype.JArray[DoubleWriteGen]:
        ...


class IntWriteGen(java.lang.Enum[IntWriteGen], MethodAccessGen, ExportsLegAccessGen):
    """
    The generator for writing integers.
    """

    class_: typing.ClassVar[java.lang.Class]
    BE: typing.Final[IntWriteGen]
    """
    The big-endian instance
    """

    LE: typing.Final[IntWriteGen]
    """
    The little-endian instance
    """


    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> IntWriteGen:
        ...

    @staticmethod
    def values() -> jpype.JArray[IntWriteGen]:
        ...


class MpIntReadGen(java.lang.Enum[MpIntReadGen], MpTypedAccessGen):
    """
    The generator for reading multi-precision ints.
    """

    class_: typing.ClassVar[java.lang.Class]
    BE: typing.Final[MpIntReadGen]
    """
    The big-endian instance
    """

    LE: typing.Final[MpIntReadGen]
    """
    The little-endian instance
    """


    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> MpIntReadGen:
        ...

    @staticmethod
    def values() -> jpype.JArray[MpIntReadGen]:
        ...


class FloatWriteGen(java.lang.Enum[FloatWriteGen], TypedAccessGen):
    """
    The generator for writing floats
     
     
    
    This is accomplished by converting to an int and then writing it.
    """

    class_: typing.ClassVar[java.lang.Class]
    BE: typing.Final[FloatWriteGen]
    """
    The big-endian instance
    """

    LE: typing.Final[FloatWriteGen]
    """
    The little-endian instance
    """


    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> FloatWriteGen:
        ...

    @staticmethod
    def values() -> jpype.JArray[FloatWriteGen]:
        ...


class FloatReadGen(java.lang.Enum[FloatReadGen], TypedAccessGen):
    """
    The generator for reading floats
     
     
    
    This is accomplished by reading an int and then converting it.
    """

    class_: typing.ClassVar[java.lang.Class]
    BE: typing.Final[FloatReadGen]
    """
    The big-endian instance
    """

    LE: typing.Final[FloatReadGen]
    """
    The little-endian instance
    """


    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> FloatReadGen:
        ...

    @staticmethod
    def values() -> jpype.JArray[FloatReadGen]:
        ...


class MpTypedAccessGen(TypedAccessGen):
    """
    A generator for a multi-precision integer type.
     
     
    
    This depends on the generator for single integer types. Each will need to work out how to compose
    the leg generator given the stack ordering, byte order, and read/write operation.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getLegGen(self) -> ExportsLegAccessGen:
        """
        Get a generator for individual legs of this multi-precision access generator
        
        :return: the leg generator
        :rtype: ExportsLegAccessGen
        """

    @property
    def legGen(self) -> ExportsLegAccessGen:
        ...


class MethodAccessGen(TypedAccessGen):
    """
    A generator whose implementation is to emit invocations of a named method in
    :obj:`JitCompiledPassage`.
     
     
    
    This is needed by :obj:`LoadOpGen` and :obj:`StoreOpGen`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def chooseName(self, size: typing.Union[jpype.JInt, int]) -> str:
        """
        Choose the name of a method, e.g. :meth:`JitCompiledPassage.readInt1(byte[], int) <JitCompiledPassage.readInt1>` to use for
        the given variable size.
        
        :param jpype.JInt or int size: the size in bytes
        :return: the name of the method
        :rtype: str
        """


class TypedAccessGen(java.lang.Object):
    """
    A generator to emit code that accesses variables of various size in a
    :obj:`state <JitBytesPcodeExecutorState>`, for a specific type, byte order, and access.
     
     
    
    This is used by variable birthing and retirement as well as direct memory accesses. Dynamic
    memory accesses, i.e., :obj:`load <JitLoadOp>` and :obj:`store <JitStoreOp>` op do not use this,
    though they may borrow some portions.
    """

    class_: typing.ClassVar[java.lang.Class]

    def generateCode(self, gen: ghidra.pcode.emu.jit.gen.JitCodeGenerator, vn: ghidra.program.model.pcode.Varnode, rv: org.objectweb.asm.MethodVisitor):
        """
        Emit code to access a varnode.
         
         
        
        If reading, the result is placed on the JVM stack. If writing, the value is popped from the
        JVM stack.
         
         
        
        If the varnode fits completely in the block (the common case), then this accesses the bytes
        from the one block, using the method chosen by size. If the varnode extends into the next
        block, then this will split the varnode into two portions according to machine byte order.
        Each portion is accessed using the method for the size of that portion. If reading, the
        results are reassembled into a single value and pushed onto the JVM stack.
        
        :param ghidra.pcode.emu.jit.gen.JitCodeGenerator gen: the code generator
        :param ghidra.program.model.pcode.Varnode vn: the varnode
        :param org.objectweb.asm.MethodVisitor rv: the method visitor
        """

    @staticmethod
    def lookupReader(endian: ghidra.program.model.lang.Endian, type: ghidra.pcode.emu.jit.analysis.JitType) -> TypedAccessGen:
        """
        Lookup the generator for reading variables for the given type
        
        :param ghidra.program.model.lang.Endian endian: the byte order
        :param ghidra.pcode.emu.jit.analysis.JitType type: the variable's type
        :return: the access generator
        :rtype: TypedAccessGen
        """

    @staticmethod
    def lookupWriter(endian: ghidra.program.model.lang.Endian, type: ghidra.pcode.emu.jit.analysis.JitType) -> TypedAccessGen:
        """
        Lookup the generator for writing variables for the given type
        
        :param ghidra.program.model.lang.Endian endian: the byte order
        :param ghidra.pcode.emu.jit.analysis.JitType type: the variable's type
        :return: the access generator
        :rtype: TypedAccessGen
        """


class IntReadGen(java.lang.Enum[IntReadGen], MethodAccessGen, ExportsLegAccessGen):
    """
    The generator for reading integers.
    """

    class_: typing.ClassVar[java.lang.Class]
    BE: typing.Final[IntReadGen]
    """
    The big-endian instance
    """

    LE: typing.Final[IntReadGen]
    """
    The little-endian instance
    """


    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> IntReadGen:
        ...

    @staticmethod
    def values() -> jpype.JArray[IntReadGen]:
        ...


class MpIntWriteGen(java.lang.Enum[MpIntWriteGen], MpTypedAccessGen):
    """
    The generator for writing multi-precision ints.
    """

    class_: typing.ClassVar[java.lang.Class]
    BE: typing.Final[MpIntWriteGen]
    """
    The big-endian instance
    """

    LE: typing.Final[MpIntWriteGen]
    """
    The little-endian instance
    """


    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> MpIntWriteGen:
        ...

    @staticmethod
    def values() -> jpype.JArray[MpIntWriteGen]:
        ...


class TypeConversions(org.objectweb.asm.Opcodes):
    """
    The generator for various type conversion.
     
     
    
    These conversions are no more than bitwise casts. The underlying bits are unchanged, but the
    interpretation and/or the way the JVM has tagged them does.
     
     
    
    Many of the methods (and also many other bits of the code generator) follow a convention where
    the input type(s) are passed as parameter(s), and the resulting type is returned. In many cases
    the desired type is also taken as a parameter. Upon success, we'd expect that desired type to be
    the exact type returned, but this may not always be the case. This convention ensures all pieces
    of the generator know the p-code type (and thus JVM type) of the variable at the top of the JVM
    stack.
     
     
    
    Type conversions are applicable at a few boundaries:
     
    * To ensure use-def values conform to the requirements of the operands where they are used and
    defined. The:obj:`JitTypeModel` aims to reduce the number of conversions required by assigning
    appropriate types to the use-def value nodes, but this will not necessarily eliminate them
    all.
    * Within the implementation of an operator, type conversions may be necessary to ensure the
    p-code types of input operands conform with the JVM types required by the emitted bytecodes, and
    that the output JVM type conforms to the p-code type of the output operand.
    * When loading or storing as bytes from the :obj:`state <JitBytesPcodeExecutorState>`. The
    conversion from and to bytes is done using JVM integral types, and so the value may be converted
    if the operand requires a floating-point type.
    """

    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def checkGenIntMask(from_: ghidra.pcode.emu.jit.analysis.JitType, to: ghidra.pcode.emu.jit.analysis.JitType.IntJitType, mv: org.objectweb.asm.MethodVisitor):
        """
        Emit an :obj:`Opcodes.IAND` to reduce the number of bits to those permitted in an int of the
        given size.
         
         
        
        For example to mask from an :obj:`int4 <IntJitType.I4>` to an :obj:`IntJitType.I2`, this
        would emit ``iand 0xffff``. If the source size is smaller than or equal to that of the
        destination, nothing is emitted.
        
        :param ghidra.pcode.emu.jit.analysis.JitType from: the source type
        :param ghidra.pcode.emu.jit.analysis.JitType.IntJitType to: the destination type
        :param org.objectweb.asm.MethodVisitor mv: the method visitor
        """

    @staticmethod
    def checkGenLongMask(from_: ghidra.pcode.emu.jit.analysis.JitType, to: ghidra.pcode.emu.jit.analysis.JitType.LongJitType, mv: org.objectweb.asm.MethodVisitor):
        """
        Emit an :obj:`Opcodes.LAND` to reduce the number of bits to those permitted in an int of the
        given size.
         
         
        
        For example to mask from a :obj:`int8 <LongJitType.I8>` to a :obj:`LongJitType.I6`, this
        would emit ``land 0x0ffffffffffffL``. If the source size is smaller than or equal to that
        of the destination, nothing is emitted.
        
        :param ghidra.pcode.emu.jit.analysis.JitType from: the source type
        :param ghidra.pcode.emu.jit.analysis.JitType.LongJitType to: the destination type
        :param org.objectweb.asm.MethodVisitor mv: the method visitor
        """

    @staticmethod
    def forceUniformSExt(myType: ghidra.pcode.emu.jit.analysis.JitType, otherType: ghidra.pcode.emu.jit.analysis.JitType, mv: org.objectweb.asm.MethodVisitor) -> ghidra.pcode.emu.jit.analysis.JitType:
        """
        Do the same as :meth:`forceUniformZExt(JitType, JitType, MethodVisitor) <.forceUniformZExt>`, but with signed
        values.
        
        :param ghidra.pcode.emu.jit.analysis.JitType myType: the type of an operand, probably in a binary operator
        :param ghidra.pcode.emu.jit.analysis.JitType otherType: the type of the other operand of a binary operator
        :param org.objectweb.asm.MethodVisitor mv: the method visitor
        :return: the new type of the operand
        :rtype: ghidra.pcode.emu.jit.analysis.JitType
        """

    @staticmethod
    def forceUniformZExt(myType: ghidra.pcode.emu.jit.analysis.JitType, otherType: ghidra.pcode.emu.jit.analysis.JitType, mv: org.objectweb.asm.MethodVisitor) -> ghidra.pcode.emu.jit.analysis.JitType:
        """
        Select the larger of two types and emit code to convert an unsigned value of the first type
        to the host JVM type of the selected type.
         
         
        
        JVM bytecodes for binary operators often require that both operands have the same size.
        Consider that the JVM provides a :obj:`.IADD` and a :obj:`.LADD`, but no "``ILADD``".
        Both operands must be JVM ints, or both must be JVM longs. This method provides an idiom for
        converting both operands to the same type. Ideally, we choose the smallest type possible (as
        opposed to just converting everything to long always), but we must choose a type large enough
        to accommodate the larger of the two p-code operands.
         
         
        
        For a binary operator requiring type uniformity, we must apply this method immediately after
        loading each operand onto the stack. That operand's type is passed as ``myType`` and the
        type of the other operand as ``otherType``. Consider the left operand. We must override
        :meth:`afterLeft <BinOpGen.afterLeft>` if we're using :obj:`BinOpGen`. If the left type is the larger, then we select it
        and we need only extend the left operand to fill its host JVM type. (We'll deal with the
        right operand in a moment.) If the right type is larger, then we select it and we extend the
        left to fill *the right's* host JVM type. We then return the resulting left type so
        that we'll know what it was when emitting the actual operator bytecodes. Things work
        similarly for the right operand, which we handle within
        :meth:`generateBinOpRunCode <BinOpGen.generateBinOpRunCode>` if we're using it. The two resulting types should now be equal, and we
        can examine them and emit the correct bytecodes.
        
        :param ghidra.pcode.emu.jit.analysis.JitType myType: the type of an operand, probably in a binary operator
        :param ghidra.pcode.emu.jit.analysis.JitType otherType: the type of the other operand of a binary operator
        :param org.objectweb.asm.MethodVisitor mv: the method visitor
        :return: the new type of the operand
        :rtype: ghidra.pcode.emu.jit.analysis.JitType
        """

    @staticmethod
    def generate(gen: ghidra.pcode.emu.jit.gen.JitCodeGenerator, from_: ghidra.pcode.emu.jit.analysis.JitType, to: ghidra.pcode.emu.jit.analysis.JitType, mv: org.objectweb.asm.MethodVisitor) -> ghidra.pcode.emu.jit.analysis.JitType:
        """
        Emit bytecode to convert the value on top of the JVM stack from one p-code type to another.
         
         
        
        If the source and destination are already of the same type, or if conversion between them
        does not require any bytecode, then no bytecode is emitted.
        
        :param ghidra.pcode.emu.jit.gen.JitCodeGenerator gen: the code generator
        :param ghidra.pcode.emu.jit.analysis.JitType from: the source type
        :param ghidra.pcode.emu.jit.analysis.JitType to: the destination type
        :param org.objectweb.asm.MethodVisitor mv: the method visitor
        :return: the resulting (destination) type
        :rtype: ghidra.pcode.emu.jit.analysis.JitType
        """

    @staticmethod
    def generateDoubleToLong(from_: ghidra.pcode.emu.jit.analysis.JitType.DoubleJitType, to: ghidra.pcode.emu.jit.analysis.JitType.LongJitType, mv: org.objectweb.asm.MethodVisitor) -> ghidra.pcode.emu.jit.analysis.JitType.LongJitType:
        """
        Emit bytecode to convert a :obj:`float8 <DoubleJitType.F8>` to an :obj:`int8 <LongJitType.I8>`.
        
        :param ghidra.pcode.emu.jit.analysis.JitType.DoubleJitType from: the source type (must be :obj:`float8 <DoubleJitType.F8>`)
        :param ghidra.pcode.emu.jit.analysis.JitType.LongJitType to: the destination type (must be :obj:`int8 <LongJitType.I8>`)
        :param org.objectweb.asm.MethodVisitor mv: the method visitor
        :return: the destination type (:obj:`int8 <LongJitType.I8>`)
        :rtype: ghidra.pcode.emu.jit.analysis.JitType.LongJitType
        """

    @staticmethod
    def generateFloatToInt(from_: ghidra.pcode.emu.jit.analysis.JitType.FloatJitType, to: ghidra.pcode.emu.jit.analysis.JitType.IntJitType, mv: org.objectweb.asm.MethodVisitor) -> ghidra.pcode.emu.jit.analysis.JitType.IntJitType:
        """
        Emit bytecode to convert a :obj:`float4 <FloatJitType.F4>` to an :obj:`int4 <IntJitType.I4>`.
        
        :param ghidra.pcode.emu.jit.analysis.JitType.FloatJitType from: the source type (must be :obj:`float4 <FloatJitType.F4>`)
        :param ghidra.pcode.emu.jit.analysis.JitType.IntJitType to: the destination type (must be :obj:`int4 <IntJitType.I4>`)
        :param org.objectweb.asm.MethodVisitor mv: the method visitor
        :return: the destination type (:obj:`int4 <IntJitType.I4>`)
        :rtype: ghidra.pcode.emu.jit.analysis.JitType.IntJitType
        """

    @staticmethod
    def generateIntToBool(from_: ghidra.pcode.emu.jit.analysis.JitType, mv: org.objectweb.asm.MethodVisitor):
        """
        Collapse an mp-int or long to a single int.
         
         
        
        If and only if the input is all zeros will the output also be all zeros. Otherwise, the
        output can be any non-zero value.
         
         
        
        There is no explicit "``boolean``" p-code type. Instead, like C, many of the operators
        take an :obj:`int <JitTypeBehavior.INTEGER>` type and require "false" to be represented by the
        value 0. Any non-zero value is interpreted as "true." That said, conventionally, all p-code
        booleans ought to be an :obj:`int1 <IntJitType.I1>` where "true" is represented by 1 and
        "false" is represented by 0. The p-code operators that output "boolean" values are all
        implemented to follow this convention, except that size is determined by the Slaspec author.
         
         
        
        This conversion deals with input operands used as booleans that do not conform to these
        conventions. If, e.g., a :obj:`cbranch <PcodeOp.CBRANCH>` is given a condition operand of type
        :obj:`int8 <LongJitType.I8>`, we have to ensure that all bits, not just the lower 32, are
        considered. This is trivially accomplished by pushing ``0L`` and emitting an
        :obj:`.LCMP`, which consumes the JVM long and replaces it with a JVM int representing the
        same boolean value. For multi-precision ints, we reduce all the legs using :obj:`.IOR`. If a
        float is used as a boolean, it must be converted to an int first.
        
        :param ghidra.pcode.emu.jit.analysis.JitType from: the type of the value currently on the stack
        :param org.objectweb.asm.MethodVisitor mv: the method visitor
        
        .. seealso::
        
            | :obj:`.generateLdcFalse(JitType, MethodVisitor)`
        
            | :obj:`.generateLdcTrue(JitType, MethodVisitor)`
        """

    @staticmethod
    def generateIntToFloat(from_: ghidra.pcode.emu.jit.analysis.JitType.IntJitType, to: ghidra.pcode.emu.jit.analysis.JitType.FloatJitType, mv: org.objectweb.asm.MethodVisitor) -> ghidra.pcode.emu.jit.analysis.JitType.FloatJitType:
        """
        Emit bytecode to convert an :obj:`int4 <IntJitType.I4>` to a :obj:`float4 <FloatJitType.F4>`.
        
        :param ghidra.pcode.emu.jit.analysis.JitType.IntJitType from: the source type (must be :obj:`int4 <IntJitType.I4>`)
        :param ghidra.pcode.emu.jit.analysis.JitType.FloatJitType to: the destination type (must be :obj:`float4 <FloatJitType.F4>`)
        :param org.objectweb.asm.MethodVisitor mv: the method visitor
        :return: the destination type (:obj:`float4 <FloatJitType.F4>`)
        :rtype: ghidra.pcode.emu.jit.analysis.JitType.FloatJitType
        """

    @staticmethod
    def generateIntToInt(from_: ghidra.pcode.emu.jit.analysis.JitType.IntJitType, to: ghidra.pcode.emu.jit.analysis.JitType.IntJitType, mv: org.objectweb.asm.MethodVisitor) -> ghidra.pcode.emu.jit.analysis.JitType.IntJitType:
        """
        Emit bytecode to convert one p-code in (in a JVM int) to another
        
        :param ghidra.pcode.emu.jit.analysis.JitType.IntJitType from: the source type
        :param ghidra.pcode.emu.jit.analysis.JitType.IntJitType to: the destination type
        :param org.objectweb.asm.MethodVisitor mv: the method visitor
        :return: the destination type
        :rtype: ghidra.pcode.emu.jit.analysis.JitType.IntJitType
        """

    @staticmethod
    def generateIntToLong(from_: ghidra.pcode.emu.jit.analysis.JitType.IntJitType, to: ghidra.pcode.emu.jit.analysis.JitType.LongJitType, mv: org.objectweb.asm.MethodVisitor) -> ghidra.pcode.emu.jit.analysis.JitType.LongJitType:
        """
        Emit bytecode to convert one p-code int (in a JVM int) to one in a JVM long.
         
         
        
        Care must be taken to ensure conversions to larger types extend with zeros (unsigned).
        
        :param ghidra.pcode.emu.jit.analysis.JitType.IntJitType from: the source type
        :param ghidra.pcode.emu.jit.analysis.JitType.LongJitType to: the destination type
        :param org.objectweb.asm.MethodVisitor mv: the method visitor
        :return: the destination type
        :rtype: ghidra.pcode.emu.jit.analysis.JitType.LongJitType
        """

    @staticmethod
    def generateIntToMpInt(from_: ghidra.pcode.emu.jit.analysis.JitType.IntJitType, to: ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType, mv: org.objectweb.asm.MethodVisitor) -> ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType:
        """
        Emit bytecode to convert a p-code int that fits in a JVM int to a multi-precision int.
        
        :param ghidra.pcode.emu.jit.analysis.JitType.IntJitType from: the source type
        :param ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType to: the destination type
        :param org.objectweb.asm.MethodVisitor mv: the method visitor
        :return: the destination type
        :rtype: ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType
        """

    @staticmethod
    def generateLdcFalse(type: ghidra.pcode.emu.jit.analysis.JitType, mv: org.objectweb.asm.MethodVisitor):
        """
        Generate a "boolean" false value of the given type
         
         
        
        This performs the inverse of :meth:`generateIntToBool(JitType, MethodVisitor) <.generateIntToBool>`, but for the
        constant "false." Instead of loading a constant 0 into an :obj:`int1 <IntJitType.I1>` and then
        converting to the desired type, this can just load the constant 0 directly as the desired
        type.
         
         
        
        This is often used with conditional jumps to produce a boolean output.
        
        :param ghidra.pcode.emu.jit.analysis.JitType type: an integer type
        :param org.objectweb.asm.MethodVisitor mv: the method visitor
        
        .. seealso::
        
            | :obj:`.generateLdcFalse(JitType, MethodVisitor)`
        
            | :obj:`.generateIntToBool(JitType, MethodVisitor)`
        """

    @staticmethod
    def generateLdcTrue(type: ghidra.pcode.emu.jit.analysis.JitType, mv: org.objectweb.asm.MethodVisitor):
        """
        Generate a "boolean" true value of the given type
         
         
        
        This performs the inverse of :meth:`generateIntToBool(JitType, MethodVisitor) <.generateIntToBool>`, but for the
        constant "true." Instead of loading a constant 1 into an :obj:`int1 <IntJitType.I1>` and then
        converting to the desired type, this can just load the constant 1 directly as the desired
        type.
         
         
        
        This is often used with conditional jumps to produce a boolean output.
        
        :param ghidra.pcode.emu.jit.analysis.JitType type: an integer type
        :param org.objectweb.asm.MethodVisitor mv: the method visitor
        
        .. seealso::
        
            | :obj:`.generateLdcFalse(JitType, MethodVisitor)`
        
            | :obj:`.generateIntToBool(JitType, MethodVisitor)`
        """

    @staticmethod
    def generateLongToDouble(from_: ghidra.pcode.emu.jit.analysis.JitType.LongJitType, to: ghidra.pcode.emu.jit.analysis.JitType.DoubleJitType, mv: org.objectweb.asm.MethodVisitor) -> ghidra.pcode.emu.jit.analysis.JitType.DoubleJitType:
        """
        Emit bytecode to convert an :obj:`int8 <LongJitType.I8>` to a :obj:`float8 <DoubleJitType.F8>`.
        
        :param ghidra.pcode.emu.jit.analysis.JitType.LongJitType from: the source type (must be :obj:`int8 <LongJitType.I8>`)
        :param ghidra.pcode.emu.jit.analysis.JitType.DoubleJitType to: the destination type (must be :obj:`float8 <DoubleJitType.F8>`)
        :param org.objectweb.asm.MethodVisitor mv: the method visitor
        :return: the destination type (:obj:`float8 <DoubleJitType.F8>`)
        :rtype: ghidra.pcode.emu.jit.analysis.JitType.DoubleJitType
        """

    @staticmethod
    def generateLongToInt(from_: ghidra.pcode.emu.jit.analysis.JitType.LongJitType, to: ghidra.pcode.emu.jit.analysis.JitType.IntJitType, mv: org.objectweb.asm.MethodVisitor) -> ghidra.pcode.emu.jit.analysis.JitType.IntJitType:
        """
        Emit bytecode to convert one p-code int (in a JVM long) to one in a JVM int.
        
        :param ghidra.pcode.emu.jit.analysis.JitType.LongJitType from: the source type
        :param ghidra.pcode.emu.jit.analysis.JitType.IntJitType to: the destination type
        :param org.objectweb.asm.MethodVisitor mv: the method visitor
        :return: the destination type
        :rtype: ghidra.pcode.emu.jit.analysis.JitType.IntJitType
        """

    @staticmethod
    def generateLongToLong(from_: ghidra.pcode.emu.jit.analysis.JitType.LongJitType, to: ghidra.pcode.emu.jit.analysis.JitType.LongJitType, mv: org.objectweb.asm.MethodVisitor) -> ghidra.pcode.emu.jit.analysis.JitType.LongJitType:
        """
        Emit bytecode to convert one p-code in (in a JVM long) to another
        
        :param ghidra.pcode.emu.jit.analysis.JitType.LongJitType from: the source type
        :param ghidra.pcode.emu.jit.analysis.JitType.LongJitType to: the destination type
        :param org.objectweb.asm.MethodVisitor mv: the method visitor
        :return: the destination type
        :rtype: ghidra.pcode.emu.jit.analysis.JitType.LongJitType
        """

    @staticmethod
    def generateLongToMpInt(from_: ghidra.pcode.emu.jit.analysis.JitType.LongJitType, to: ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType, mv: org.objectweb.asm.MethodVisitor) -> ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType:
        """
        Emit bytecode to convert a p-code int that its int a JVM long to multi-precision int.
        
        :param ghidra.pcode.emu.jit.analysis.JitType.LongJitType from: the source type
        :param ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType to: the destination type
        :param org.objectweb.asm.MethodVisitor mv: the method visitor
        :return: the destination type
        :rtype: ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType
        """

    @staticmethod
    def generateMpIntToInt(from_: ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType, to: ghidra.pcode.emu.jit.analysis.JitType.IntJitType, mv: org.objectweb.asm.MethodVisitor) -> ghidra.pcode.emu.jit.analysis.JitType.IntJitType:
        """
        Emit bytecode to convert a mult-precision int to a p-code int that fits in a JVM int.
        
        :param ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType from: the source type
        :param ghidra.pcode.emu.jit.analysis.JitType.IntJitType to: the destination type
        :param org.objectweb.asm.MethodVisitor mv: the method visitor
        :return: the destination type
        :rtype: ghidra.pcode.emu.jit.analysis.JitType.IntJitType
        """

    @staticmethod
    def generateMpIntToLong(from_: ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType, to: ghidra.pcode.emu.jit.analysis.JitType.LongJitType, mv: org.objectweb.asm.MethodVisitor) -> ghidra.pcode.emu.jit.analysis.JitType.LongJitType:
        """
        Emit bytecode to convert a mult-precision int to a p-code int that fits in a JVM long.
        
        :param ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType from: the source type
        :param ghidra.pcode.emu.jit.analysis.JitType.LongJitType to: the destination type
        :param org.objectweb.asm.MethodVisitor mv: the method visitor
        :return: the destination type
        :rtype: ghidra.pcode.emu.jit.analysis.JitType.LongJitType
        """

    @staticmethod
    def generateMpIntToMpInt(gen: ghidra.pcode.emu.jit.gen.JitCodeGenerator, from_: ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType, to: ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType, mv: org.objectweb.asm.MethodVisitor) -> ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType:
        """
        Emit bytecode to convert a mult-precision int from one size to another
        
        :param ghidra.pcode.emu.jit.gen.JitCodeGenerator gen: the code generator
        :param ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType from: the source type
        :param ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType to: the destination type
        :param org.objectweb.asm.MethodVisitor mv: the method visitor
        :return: the destination type
        :rtype: ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType
        """

    @staticmethod
    def generatePop(type: ghidra.pcode.emu.jit.analysis.JitType, mv: org.objectweb.asm.MethodVisitor):
        """
        Remove a value of the given type from the JVM stack.
         
         
        
        Depending on the type, we must emit either :obj:`.POP` or :obj:`.POP2`. This is used to
        ignore an input or drop an output. For example, the boolean operators may short circuit
        examination of the second operand, in which case it must be popped. Also, if a userop returns
        a value, but the p-code does not provide an output operand, the return value must be popped.
        
        :param ghidra.pcode.emu.jit.analysis.JitType type: the type
        :param org.objectweb.asm.MethodVisitor mv: the method visitor
        """

    @staticmethod
    def generateSExt(type: ghidra.pcode.emu.jit.analysis.JitType, mv: org.objectweb.asm.MethodVisitor) -> ghidra.pcode.emu.jit.analysis.JitType:
        """
        Emit code to extend a signed value of the given type to fill its host JVM type.
         
         
        
        This is implemented in the same manner as :obj:`int_sext <IntSExtOpGen>`.
        
        :param ghidra.pcode.emu.jit.analysis.JitType type: the p-code type
        :param org.objectweb.asm.MethodVisitor mv: the method visitor
        :return: the p-code type that exactly fits the host JVM type, i.e., the resulting p-code type.
        :rtype: ghidra.pcode.emu.jit.analysis.JitType
        """

    @staticmethod
    def generateSExtIntToLong(mv: org.objectweb.asm.MethodVisitor) -> ghidra.pcode.emu.jit.analysis.JitType.LongJitType:
        """
        Convert a signed :obj:`int4 <IntJitType.I4>` to :obj:`int8 <LongJitType.I8>`.
         
         
        
        Note that if conversion from a smaller int type is needed, the generator must first call
        :meth:`generateSExt(JitType, MethodVisitor) <.generateSExt>`.
        
        :param org.objectweb.asm.MethodVisitor mv: the method visitor
        :return: the resulting type (:obj:`int8 <LongJitType.I8>`)
        :rtype: ghidra.pcode.emu.jit.analysis.JitType.LongJitType
        """

    @staticmethod
    def generateToDouble(from_: ghidra.pcode.emu.jit.analysis.JitType, to: ghidra.pcode.emu.jit.analysis.JitType.DoubleJitType, mv: org.objectweb.asm.MethodVisitor) -> ghidra.pcode.emu.jit.analysis.JitType.DoubleJitType:
        """
        Emit bytecode to convert any (compatible) type to a :obj:`float8 <DoubleJitType.F8>`.
        
        :param ghidra.pcode.emu.jit.analysis.JitType from: the source type (:obj:`int8 <LongJitType.I8>` or :obj:`float8 <DoubleJitType.F8>`)
        :param ghidra.pcode.emu.jit.analysis.JitType.DoubleJitType to: the destination type
        :param org.objectweb.asm.MethodVisitor mv: the method visitor
        :return: the destination type (:obj:`float8 <DoubleJitType.F8>`)
        :rtype: ghidra.pcode.emu.jit.analysis.JitType.DoubleJitType
        """

    @staticmethod
    def generateToFloat(from_: ghidra.pcode.emu.jit.analysis.JitType, to: ghidra.pcode.emu.jit.analysis.JitType.FloatJitType, mv: org.objectweb.asm.MethodVisitor) -> ghidra.pcode.emu.jit.analysis.JitType.FloatJitType:
        """
        Emit bytecode to convert any (compatible) type to a :obj:`float4 <FloatJitType.F4>`.
        
        :param ghidra.pcode.emu.jit.analysis.JitType from: the source type (:obj:`int4 <IntJitType.I4>` or :obj:`float4 <FloatJitType.F4>`)
        :param ghidra.pcode.emu.jit.analysis.JitType.FloatJitType to: the destination type
        :param org.objectweb.asm.MethodVisitor mv: the method visitor
        :return: the destination type (:obj:`float4 <FloatJitType.F4>`)
        :rtype: ghidra.pcode.emu.jit.analysis.JitType.FloatJitType
        """

    @staticmethod
    def generateToInt(from_: ghidra.pcode.emu.jit.analysis.JitType, to: ghidra.pcode.emu.jit.analysis.JitType.IntJitType, mv: org.objectweb.asm.MethodVisitor) -> ghidra.pcode.emu.jit.analysis.JitType.IntJitType:
        """
        Emit bytecode to convert any (compatible) type to a p-code int that fits in a JVM int.
         
         
        
        The only acceptable floating-point source type is :obj:`float4 <FloatJitType.F4>`.
        
        :param ghidra.pcode.emu.jit.analysis.JitType from: the source type
        :param ghidra.pcode.emu.jit.analysis.JitType.IntJitType to: the destination type
        :param org.objectweb.asm.MethodVisitor mv: the method visitor
        :return: the destination type
        :rtype: ghidra.pcode.emu.jit.analysis.JitType.IntJitType
        """

    @staticmethod
    def generateToLong(from_: ghidra.pcode.emu.jit.analysis.JitType, to: ghidra.pcode.emu.jit.analysis.JitType.LongJitType, mv: org.objectweb.asm.MethodVisitor) -> ghidra.pcode.emu.jit.analysis.JitType.LongJitType:
        """
        Emit bytecode to convert any (compatible) type to a p-code that fits in a JVM long.
         
         
        
        The only acceptable floating-point source type is :obj:`float8 <DoubleJitType.F8>`.
        
        :param ghidra.pcode.emu.jit.analysis.JitType from: the source type
        :param ghidra.pcode.emu.jit.analysis.JitType.LongJitType to: the destination type
        :param org.objectweb.asm.MethodVisitor mv: the method visitor
        :return: the destination type
        :rtype: ghidra.pcode.emu.jit.analysis.JitType.LongJitType
        """

    @staticmethod
    def generateToMpInt(gen: ghidra.pcode.emu.jit.gen.JitCodeGenerator, from_: ghidra.pcode.emu.jit.analysis.JitType, to: ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType, mv: org.objectweb.asm.MethodVisitor) -> ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType:
        """
        Emit bytecode to convert any (compatible) type to a p-code int that fits in a JVM int.
         
         
        
        No floating-point source types are currently acceptable. Support for floats of size other
        than 4 and 8 bytes is a work in progress.
        
        :param ghidra.pcode.emu.jit.gen.JitCodeGenerator gen: the code generator
        :param ghidra.pcode.emu.jit.analysis.JitType from: the source type
        :param ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType to: the destination type
        :param org.objectweb.asm.MethodVisitor mv: the method visitor
        :return: the destination type
        :rtype: ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType
        """


class DoubleReadGen(java.lang.Enum[DoubleReadGen], TypedAccessGen):
    """
    The generator for reading doubles
     
     
    
    This is accomplished by reading a long and then converting it.
    """

    class_: typing.ClassVar[java.lang.Class]
    BE: typing.Final[DoubleReadGen]
    """
    The big-endian instance
    """

    LE: typing.Final[DoubleReadGen]
    """
    The little-endian instance
    """


    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> DoubleReadGen:
        ...

    @staticmethod
    def values() -> jpype.JArray[DoubleReadGen]:
        ...


class LongWriteGen(java.lang.Enum[LongWriteGen], MethodAccessGen):
    """
    Bytes writer for longs in big endian order.
    """

    class_: typing.ClassVar[java.lang.Class]
    BE: typing.Final[LongWriteGen]
    """
    The big-endian instance
    """

    LE: typing.Final[LongWriteGen]
    """
    The little-endian instance
    """


    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> LongWriteGen:
        ...

    @staticmethod
    def values() -> jpype.JArray[LongWriteGen]:
        ...


class ExportsLegAccessGen(TypedAccessGen):
    """
    A generator that exports part of its implementation for use in a :obj:`MpTypedAccessGen`.
     
     
    
    This really just avoids the re-creation of :obj:`Varnode` objects for each leg of a large
    varnode. The method instead takes the (space,offset,size) triple as well as the offset of the
    block containing its start.
    """

    class_: typing.ClassVar[java.lang.Class]

    def generateMpCodeLeg(self, gen: ghidra.pcode.emu.jit.gen.JitCodeGenerator, space: ghidra.program.model.address.AddressSpace, block: typing.Union[jpype.JLong, int], off: typing.Union[jpype.JInt, int], size: typing.Union[jpype.JInt, int], rv: org.objectweb.asm.MethodVisitor):
        """
        Emit code to access one JVM int, either a whole variable or one leg of a multi-precision int
        variable.
         
         
        
        Legs that span blocks are handled as in
        :meth:`generateCode(JitCodeGenerator, Varnode, MethodVisitor) <.generateCode>`.
        
        :param ghidra.pcode.emu.jit.gen.JitCodeGenerator gen: the code generator
        :param ghidra.program.model.address.AddressSpace space: the address space of the varnode
        :param jpype.JLong or int block: the block offset containing the varnode (or leg)
        :param jpype.JInt or int off: the offset of the varnode (or leg)
        :param jpype.JInt or int size: the size of the varnode in bytes (or leg)
        :param org.objectweb.asm.MethodVisitor rv: the method visitor
        """



__all__ = ["LongReadGen", "DoubleWriteGen", "IntWriteGen", "MpIntReadGen", "FloatWriteGen", "FloatReadGen", "MpTypedAccessGen", "MethodAccessGen", "TypedAccessGen", "IntReadGen", "MpIntWriteGen", "TypeConversions", "DoubleReadGen", "LongWriteGen", "ExportsLegAccessGen"]
