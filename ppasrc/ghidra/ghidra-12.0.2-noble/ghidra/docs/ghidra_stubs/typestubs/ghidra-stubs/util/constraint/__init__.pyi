from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import generic.constraint
import ghidra.util.classfinder
import java.lang # type: ignore


class ProgramConstraint(generic.constraint.Constraint[ghidra.program.model.listing.Program], ghidra.util.classfinder.ExtensionPoint):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, name: typing.Union[java.lang.String, str]):
        ...


class CompilerConstraint(ProgramConstraint):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class LanguageConstraint(ProgramConstraint):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class ExecutableFormatConstraint(ProgramConstraint):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class ProgramDecisionTree(generic.constraint.DecisionTree[ghidra.program.model.listing.Program]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class PropertyConstraint(ProgramConstraint):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...



__all__ = ["ProgramConstraint", "CompilerConstraint", "LanguageConstraint", "ExecutableFormatConstraint", "ProgramDecisionTree", "PropertyConstraint"]
