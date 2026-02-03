from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.decompiler.parallel
import ghidra.app.plugin.core.analysis.validator
import ghidra.program.model.listing
import java.lang # type: ignore


class DecompilerValidator(ghidra.app.plugin.core.analysis.validator.PostAnalysisValidator):

    @typing.type_check_only
    class DecompilerValidatorConfigurer(ghidra.app.decompiler.parallel.DecompileConfigurer):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, program: ghidra.program.model.listing.Program):
        ...


class DecompilerParameterIDValidator(ghidra.app.plugin.core.analysis.validator.PostAnalysisValidator):

    class_: typing.ClassVar[java.lang.Class]
    MIN_NUM_FUNCS: typing.Final = "Minimum analysis threshold (% of funcs)"
    MIN_NUM_FUNCS_DEFAULT: typing.Final = 1

    def __init__(self, program: ghidra.program.model.listing.Program):
        ...



__all__ = ["DecompilerValidator", "DecompilerParameterIDValidator"]
