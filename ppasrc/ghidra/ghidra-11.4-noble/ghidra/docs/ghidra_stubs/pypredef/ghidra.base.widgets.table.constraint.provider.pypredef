from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking.widgets.table.constraint
import java.lang # type: ignore
import java.math # type: ignore


class SymbolColumnTypeMapper(docking.widgets.table.constraint.ColumnTypeMapper[ghidra.program.model.symbol.Symbol, java.lang.String]):
    """
    Converts Symbol Column objects to Strings so that column gets String type column
    filters
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class ProgramLocationColumnTypeMapper(docking.widgets.table.constraint.ColumnTypeMapper[ghidra.program.util.ProgramLocation, ghidra.program.model.address.Address]):
    """
    Converts ProgramLocation Column objects to Addresses so that column gets Address type column
    filters
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class DataTypeColumnTypeMapper(docking.widgets.table.constraint.ColumnTypeMapper[ghidra.program.model.data.DataType, java.lang.String]):
    """
    Converts DataType Column objects to Strings so that column gets String type column
    filters
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class AddressBasedLocationColumnTypeMapper(docking.widgets.table.constraint.ColumnTypeMapper[ghidra.util.table.field.AddressBasedLocation, ghidra.program.model.address.Address]):
    """
    Converts AddressBasedLocation Column objects to Address so that column gets Address type column
    filters
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class NamespaceColumnTypeMapper(docking.widgets.table.constraint.ColumnTypeMapper[ghidra.program.model.symbol.Namespace, java.lang.String]):
    """
    Converts Namespace Column objects to Strings so that column gets String type column
    filters
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class ScalarToLongColumnTypeMapper(docking.widgets.table.constraint.ColumnTypeMapper[ghidra.program.model.scalar.Scalar, java.lang.Long]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class ProgramColumnConstraintProvider(docking.widgets.table.constraint.ColumnConstraintProvider):
    """
    Class for providing Program related column type constraints.  Addresses get converted to
    UnsignedLong (via BigInteger) and many others get converted to Strings.  For example, some
    tables have a column whose type is "Symbol", but the column just displays the symbol's name.
    So we created a number of "Symbol" constraints, but they are just adapters to the
    various String constraints.
    """

    @typing.type_check_only
    class AddressToBigIntegerMapper(docking.widgets.table.constraint.ColumnTypeMapper[ghidra.program.model.address.Address, java.math.BigInteger]):
        """
        This is a special non-discoverable mapper to be used by the special AddressColumnConstraint
        class below.  This is special because we don't want to use any old BigInteger editor, but
        rather an unsigned editor that makes more sense for addresses.
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class AddressColumnConstraint(docking.widgets.table.constraint.MappedColumnConstraint[ghidra.program.model.address.Address, java.math.BigInteger]):
        """
        This is a special mapped constraint because we don't wan't a default BigInteger editor,
        but rather an unsigned editor that is more appropriate for addresses.
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, delegate: docking.widgets.table.constraint.ColumnConstraint[java.math.BigInteger]):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...



__all__ = ["SymbolColumnTypeMapper", "ProgramLocationColumnTypeMapper", "DataTypeColumnTypeMapper", "AddressBasedLocationColumnTypeMapper", "NamespaceColumnTypeMapper", "ScalarToLongColumnTypeMapper", "ProgramColumnConstraintProvider"]
