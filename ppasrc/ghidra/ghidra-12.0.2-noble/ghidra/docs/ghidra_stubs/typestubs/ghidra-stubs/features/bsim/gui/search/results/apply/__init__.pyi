from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.features.bsim.gui.search.results
import ghidra.framework.plugintool
import ghidra.program.model.listing
import ghidra.program.util
import java.lang # type: ignore
import java.util # type: ignore


class SignatureBSimApplyTask(AbstractBSimApplyTask):
    """
    Task for applying names, namespaces, and signatures from a match function to the queried function
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, program: ghidra.program.model.listing.Program, results: java.util.List[ghidra.features.bsim.gui.search.results.BSimMatchResult], applyEmptyStructures: typing.Union[jpype.JBoolean, bool], serviceProvider: ghidra.framework.plugintool.ServiceProvider):
        ...


class AbstractBSimApplyTask(ghidra.program.util.ProgramTask):
    """
    Generic task for applying information from a function match to the queried function
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, program: ghidra.program.model.listing.Program, taskName: typing.Union[java.lang.String, str], results: java.util.List[ghidra.features.bsim.gui.search.results.BSimMatchResult], serviceProvider: ghidra.framework.plugintool.ServiceProvider):
        ...


class NameAndNamespaceBSimApplyTask(AbstractBSimApplyTask):
    """
    Task for applying names and namespaces from a match function to the queried function
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, program: ghidra.program.model.listing.Program, results: java.util.List[ghidra.features.bsim.gui.search.results.BSimMatchResult], serviceProvider: ghidra.framework.plugintool.ServiceProvider):
        ...



__all__ = ["SignatureBSimApplyTask", "AbstractBSimApplyTask", "NameAndNamespaceBSimApplyTask"]
