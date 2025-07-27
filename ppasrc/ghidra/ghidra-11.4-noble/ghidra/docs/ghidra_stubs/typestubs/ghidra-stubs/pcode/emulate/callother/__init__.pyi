from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.pcode.emulate
import ghidra.program.model.pcode
import java.lang # type: ignore


class OpBehaviorOtherNOP(OpBehaviorOther):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class OpBehaviorOther(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def evaluate(self, emu: ghidra.pcode.emulate.Emulate, out: ghidra.program.model.pcode.Varnode, inputs: jpype.JArray[ghidra.program.model.pcode.Varnode]):
        """
        Evaluate the CALLOTHER op which corresponds to this behavior.
        
        :param ghidra.pcode.emulate.Emulate emu: emulator which contains associated memory state
        :param ghidra.program.model.pcode.Varnode out: output varnode or null if no assignment has been
        made.  Implementation is responsible for updating memory 
        state appropriately.
        :param jpype.JArray[ghidra.program.model.pcode.Varnode] inputs: input varnodes passed as parameters to this
        pcodeop.  The inputs[0] value corresponds to the index value of this 
        pcodeop and can generally be ignored.  The inputs[1] value
        corresponds to the first (leftmost) parameter passed to 
        this pcodeop within the language implementation.
        """



__all__ = ["OpBehaviorOtherNOP", "OpBehaviorOther"]
