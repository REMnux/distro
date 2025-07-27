from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking
import docking.widgets.table
import docking.widgets.table.constraint
import docking.widgets.textfield
import ghidra.app.plugin
import ghidra.framework.model
import ghidra.framework.plugintool
import ghidra.program.model.address
import ghidra.program.model.listing
import ghidra.program.model.scalar
import ghidra.util.table
import ghidra.util.table.column
import ghidra.util.table.field
import java.lang # type: ignore
import java.util # type: ignore
import javax.swing # type: ignore


class ScalarRowObjectToProgramLocationTableRowMapper(ghidra.util.table.ProgramLocationTableRowMapper[ScalarRowObject, ghidra.program.util.ProgramLocation]):
    """
    This class will map a ScalarRowObject to a ProgramLocation
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class ScalarColumnConstraintProvider(docking.widgets.table.constraint.ColumnConstraintProvider):
    """
    Provides Scalar-related column constraints.
    """

    @typing.type_check_only
    class ScalarToSignedLongColumnTypeMapper(docking.widgets.table.constraint.ColumnTypeMapper[ghidra.program.model.scalar.Scalar, java.lang.Long]):
        """
        Class that converts a Scalar to a signed Long value
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ScalarToUnsignedLongColumnTypeMapper(docking.widgets.table.constraint.ColumnTypeMapper[ghidra.program.model.scalar.Scalar, java.lang.Long]):
        """
        Class that converts a Scalar to an unsigned Long value
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ScalarMappedColumnConstraint(docking.widgets.table.constraint.MappedColumnConstraint[ghidra.program.model.scalar.Scalar, java.lang.Long]):
        """
        Class to adapt Long-type constraints to Scalar-type columns.
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, mapper: docking.widgets.table.constraint.ColumnTypeMapper[ghidra.program.model.scalar.Scalar, java.lang.Long], delegate: docking.widgets.table.constraint.ColumnConstraint[java.lang.Long]):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class ScalarSearchModel(ghidra.util.table.AddressBasedTableModel[ScalarRowObject]):
    """
    Model that backs the table associated with the :obj:`ScalarSearchProvider`
    """

    @typing.type_check_only
    class ScalarComparator(java.util.Comparator[ghidra.program.model.scalar.Scalar]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class AbstractScalarValueRenderer(ghidra.util.table.column.AbstractGColumnRenderer[ghidra.program.model.scalar.Scalar]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class AbstractScalarValueTableColumn(docking.widgets.table.AbstractDynamicTableColumn[ScalarRowObject, ghidra.program.model.scalar.Scalar, ghidra.program.model.listing.Program], ghidra.util.table.field.ProgramLocationTableColumn[ScalarRowObject, ghidra.program.model.scalar.Scalar]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ScalarHexUnsignedValueTableColumn(ScalarSearchModel.AbstractScalarValueTableColumn):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ScalarSignedDecimalValueTableColumn(ScalarSearchModel.AbstractScalarValueTableColumn):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ScalarUnsignedDecimalValueTableColumn(ScalarSearchModel.AbstractScalarValueTableColumn):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ScalarBitCountTableColumn(docking.widgets.table.AbstractDynamicTableColumn[ScalarRowObject, java.lang.Integer, ghidra.program.model.listing.Program], ghidra.util.table.field.ProgramLocationTableColumn[ScalarRowObject, java.lang.Integer]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class Signedness(java.lang.Enum[ScalarSearchModel.Signedness]):

        class_: typing.ClassVar[java.lang.Class]
        Signed: typing.Final[ScalarSearchModel.Signedness]
        Unsigned: typing.Final[ScalarSearchModel.Signedness]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> ScalarSearchModel.Signedness:
            ...

        @staticmethod
        def values() -> jpype.JArray[ScalarSearchModel.Signedness]:
            ...


    @typing.type_check_only
    class ScalarSignednessTableColumn(docking.widgets.table.AbstractDynamicTableColumn[ScalarRowObject, ScalarSearchModel.Signedness, ghidra.program.model.listing.Program], ghidra.util.table.field.ProgramLocationTableColumn[ScalarRowObject, ScalarSearchModel.Signedness]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ScalarFunctionNameTableColumn(ghidra.util.table.field.FunctionNameTableColumn):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]


class ScalarRowObject(java.lang.Object):
    """
    Class for the Scalar plugin table that will contain the necessary elements for the table
    """

    class_: typing.ClassVar[java.lang.Class]

    def getAddress(self) -> ghidra.program.model.address.Address:
        ...

    def getCodeUnit(self) -> ghidra.program.model.listing.CodeUnit:
        ...

    def getScalar(self) -> ghidra.program.model.scalar.Scalar:
        ...

    @property
    def scalar(self) -> ghidra.program.model.scalar.Scalar:
        ...

    @property
    def address(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def codeUnit(self) -> ghidra.program.model.listing.CodeUnit:
        ...


class ScalarSearchProvider(ghidra.framework.plugintool.ComponentProviderAdapter):
    """
    Displays the results of a query from the :obj:`ScalarSearchPlugin`. Consists of 2 components:
     
    * The scalar table that is displayed to the user
    * The range filter that allows the user to filter the scalar table via a min and max value.
    """

    @typing.type_check_only
    class RangeFilterPanel(javax.swing.JPanel):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ScalarTableSecondaryFilter(docking.widgets.table.TableFilter[ScalarRowObject]):
        """
        Table filter for the range filter that will check the rowObject, in this case
        InstructionRowObject, and check if the scalar for that object fits
        within the minFilterValue and the maxFilterValue
        """

        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]
    ICON: typing.Final[javax.swing.Icon]

    def getProgram(self) -> ghidra.program.model.listing.Program:
        ...

    def getScalarModel(self) -> ScalarSearchModel:
        ...

    @property
    def scalarModel(self) -> ScalarSearchModel:
        ...

    @property
    def program(self) -> ghidra.program.model.listing.Program:
        ...


class RangeFilterTextField(docking.widgets.textfield.IntegerTextField):
    """
    Extends :obj:`IntegerTextField` to allow use as a range filter in the :obj:`ScalarSearchPlugin`. 
     
    
    Specifically this provides the following:
     
    * Ability to specify if this is a min/max range field
    * Allows hex input of the form "0x...." for hex values
    """

    class FilterType(java.lang.Enum[RangeFilterTextField.FilterType]):

        class_: typing.ClassVar[java.lang.Class]
        MIN: typing.Final[RangeFilterTextField.FilterType]
        MAX: typing.Final[RangeFilterTextField.FilterType]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> RangeFilterTextField.FilterType:
            ...

        @staticmethod
        def values() -> jpype.JArray[RangeFilterTextField.FilterType]:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, filterType: RangeFilterTextField.FilterType, program: ghidra.program.model.listing.Program):
        ...

    def getFilterType(self) -> RangeFilterTextField.FilterType:
        ...

    def getFilterValue(self) -> int:
        ...

    def getLimitValue(self) -> int:
        ...

    @property
    def limitValue(self) -> jpype.JInt:
        ...

    @property
    def filterValue(self) -> jpype.JLong:
        ...

    @property
    def filterType(self) -> RangeFilterTextField.FilterType:
        ...


class ScalarSearchContext(docking.DefaultActionContext):
    """
    Plugin context for the scalar plugin that will initialize an instance of ActionContext with the scalarTable
    """

    class_: typing.ClassVar[java.lang.Class]


class ScalarSearchDialog(docking.DialogComponentProvider):
    """
    Dialog allowing the user to set parameters when initiating a scalar search on a program.
    """

    @typing.type_check_only
    class SearchPanel(javax.swing.JPanel):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    @typing.type_check_only
    class RangeFilter(javax.swing.JPanel):
        """
        Panel consisting of two :obj:`RangeFilterTextField` instances, allowing the
        user to specify minimum/maximum values for filtering the scalar results.
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def setFilterValues(self, minFilterValue: typing.Union[jpype.JLong, int], maxFilterValue: typing.Union[jpype.JLong, int]):
        ...

    def setSearchAScalar(self):
        ...

    def setSpecificScalarValue(self, value: typing.Union[jpype.JInt, int]):
        ...

    def show(self):
        ...


class ScalarSearchPlugin(ghidra.app.plugin.ProgramPlugin, ghidra.framework.model.DomainObjectListener):
    """
    Allows users to search for scalar values within a program.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...

    def domainObjectChanged(self, ev: ghidra.framework.model.DomainObjectChangedEvent):
        """
        We need to be aware of changes to the program that could result in scalars being
        added/removed. When this happens we want to update the appropriate providers.
        
        :param ghidra.framework.model.DomainObjectChangedEvent ev: the domain change event
        """


class ScalarRowObjectToAddressTableRowMapper(ghidra.util.table.ProgramLocationTableRowMapper[ScalarRowObject, ghidra.program.model.address.Address]):
    """
    This class takes a ScalarRowObject and maps it to an Address
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...



__all__ = ["ScalarRowObjectToProgramLocationTableRowMapper", "ScalarColumnConstraintProvider", "ScalarSearchModel", "ScalarRowObject", "ScalarSearchProvider", "RangeFilterTextField", "ScalarSearchContext", "ScalarSearchDialog", "ScalarSearchPlugin", "ScalarRowObjectToAddressTableRowMapper"]
