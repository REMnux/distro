"""
UI components for the Taint Analyzer
 
 

This contains a few odds and ends for making the taint analyzer's machine state visible to the
user. It provides a custom column for the Registers panel, and a custom field for the Listing
panels. Both just render the taint markings using
:meth:`ghidra.taint.model.TaintVec.toDisplay() <ghidra.taint.model.TaintVec.toDisplay>`. There's no particular recommended reading order.
"""
from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import generic.theme
import ghidra.app.plugin.core.debug.gui.register
import ghidra.app.util.viewer.field
import ghidra.program.model.address
import ghidra.program.model.listing
import ghidra.program.util
import java.lang # type: ignore


class TaintFieldLocation(ghidra.program.util.CodeUnitLocation):
    """
    This is a :obj:`ProgramLocation` for when the user's cursor is in our "Taint" field
     
     
    
    I used the "sample" module's ``EntropyFieldLocation`` for reference.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, address: ghidra.program.model.address.Address, charOffset: typing.Union[jpype.JInt, int]):
        ...

    @typing.overload
    def __init__(self):
        ...


class TaintDebuggerRegisterColumnFactory(ghidra.app.plugin.core.debug.gui.register.DebuggerRegisterColumnFactory):
    """
    A factory for the "Taint" column in the "Registers" panel
     
     
    
    For the most part, this is just a matter of accessing the property map and rendering the value on
    screen.
    """

    class_: typing.ClassVar[java.lang.Class]
    COL_NAME: typing.Final = "Taint"

    def __init__(self):
        ...


class TaintFieldFactory(ghidra.app.util.viewer.field.FieldFactory):
    """
    A field factory for "Taint" in the Listing panels
     
     
    
    This implements an interface that is part of the core framework, even lower than the Debugger
    framework. I used the "sample" module's ``EntropyFieldFactory`` for reference.
    """

    class_: typing.ClassVar[java.lang.Class]
    PROPERTY_NAME: typing.Final = "Taint"
    COLOR: typing.Final[generic.theme.GColor]
    FIELD_NAME: typing.Final = "Taint"

    def __init__(self):
        ...



__all__ = ["TaintFieldLocation", "TaintDebuggerRegisterColumnFactory", "TaintFieldFactory"]
