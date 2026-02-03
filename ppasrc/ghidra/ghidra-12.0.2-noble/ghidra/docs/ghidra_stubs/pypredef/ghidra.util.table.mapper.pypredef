from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking.widgets.table
import ghidra.util.table


class SymbolToProgramLocationTableRowMapper(ghidra.util.table.ProgramLocationTableRowMapper[ghidra.program.model.symbol.Symbol, ghidra.program.util.ProgramLocation]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class ProgramLocationToFunctionContainingTableRowMapper(ghidra.util.table.ProgramLocationTableRowMapper[ghidra.program.util.ProgramLocation, ghidra.program.model.listing.Function]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class ReferenceEndpointToProgramLocationTableRowMapper(docking.widgets.table.TableRowMapper[ghidra.util.table.field.ReferenceEndpoint, ghidra.program.util.ProgramLocation, ghidra.program.model.listing.Program]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class ReferenceEndpointToFunctionTableRowMapper(docking.widgets.table.TableRowMapper[ghidra.util.table.field.ReferenceEndpoint, ghidra.program.model.listing.Function, ghidra.program.model.listing.Program]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class ProgramLocationToAddressTableRowMapper(ghidra.util.table.ProgramLocationTableRowMapper[ghidra.program.util.ProgramLocation, ghidra.program.model.address.Address]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class ProgramLocationToSymbolTableRowMapper(ghidra.util.table.ProgramLocationTableRowMapper[ghidra.program.util.ProgramLocation, ghidra.program.model.symbol.Symbol]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class AddressToSymbolTableRowMapper(ghidra.util.table.ProgramLocationTableRowMapper[ghidra.program.model.address.Address, ghidra.app.plugin.core.symtable.SymbolRowObject]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class ReferenceEndpointToAddressTableRowMapper(docking.widgets.table.TableRowMapper[ghidra.util.table.field.ReferenceEndpoint, ghidra.program.model.address.Address, ghidra.program.model.listing.Program]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class SymbolToAddressTableRowMapper(ghidra.util.table.ProgramLocationTableRowMapper[ghidra.program.model.symbol.Symbol, ghidra.program.model.address.Address]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class AddressToProgramLocationTableRowMapper(ghidra.util.table.ProgramLocationTableRowMapper[ghidra.program.model.address.Address, ghidra.program.util.ProgramLocation]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class ReferenceToReferenceAddressPairTableRowMapper(ghidra.util.table.ProgramLocationTableRowMapper[ghidra.program.model.symbol.Reference, ghidra.app.plugin.core.analysis.ReferenceAddressPair]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class AddressTableToAddressTableRowMapper(ghidra.util.table.ProgramLocationTableRowMapper[ghidra.app.plugin.core.disassembler.AddressTable, ghidra.program.model.address.Address]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class AddressTableToProgramLocationTableRowMapper(ghidra.util.table.ProgramLocationTableRowMapper[ghidra.app.plugin.core.disassembler.AddressTable, ghidra.program.util.ProgramLocation]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class AddressToFunctionContainingTableRowMapper(ghidra.util.table.ProgramLocationTableRowMapper[ghidra.program.model.address.Address, ghidra.program.model.listing.Function]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class ReferenceEndpointToReferenceTableRowMapper(docking.widgets.table.TableRowMapper[ghidra.util.table.field.ReferenceEndpoint, ghidra.program.model.symbol.Reference, ghidra.program.model.listing.Program]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...



__all__ = ["SymbolToProgramLocationTableRowMapper", "ProgramLocationToFunctionContainingTableRowMapper", "ReferenceEndpointToProgramLocationTableRowMapper", "ReferenceEndpointToFunctionTableRowMapper", "ProgramLocationToAddressTableRowMapper", "ProgramLocationToSymbolTableRowMapper", "AddressToSymbolTableRowMapper", "ReferenceEndpointToAddressTableRowMapper", "SymbolToAddressTableRowMapper", "AddressToProgramLocationTableRowMapper", "ReferenceToReferenceAddressPairTableRowMapper", "AddressTableToAddressTableRowMapper", "AddressTableToProgramLocationTableRowMapper", "AddressToFunctionContainingTableRowMapper", "ReferenceEndpointToReferenceTableRowMapper"]
