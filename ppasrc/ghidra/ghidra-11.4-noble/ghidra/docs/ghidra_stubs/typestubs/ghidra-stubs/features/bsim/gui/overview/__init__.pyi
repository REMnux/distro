from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import generic.lsh.vector
import ghidra.features.bsim.gui
import ghidra.features.bsim.gui.search.dialog
import ghidra.features.bsim.query
import ghidra.features.bsim.query.protocol
import ghidra.framework.plugintool
import ghidra.program.model.address
import ghidra.program.model.listing
import ghidra.util.table
import ghidra.util.table.column
import ghidra.util.table.field
import java.lang # type: ignore


class BSimOverviewProvider(ghidra.framework.plugintool.ComponentProviderAdapter):
    """
    ComponentProvider to display the results of a BSim Overview query
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ghidra.features.bsim.gui.BSimSearchPlugin, serverInfo: ghidra.features.bsim.query.BSimServerInfo, program: ghidra.program.model.listing.Program, vFactory: generic.lsh.vector.LSHVectorFactory, settings: ghidra.features.bsim.gui.search.dialog.BSimSearchSettings):
        ...

    def getProgram(self) -> ghidra.program.model.listing.Program:
        ...

    def overviewResultAdded(self, result: ghidra.features.bsim.query.protocol.ResponseNearestVector):
        ...

    def setFinalOverviewResults(self, result: ghidra.features.bsim.query.protocol.ResponseNearestVector):
        ...

    @property
    def program(self) -> ghidra.program.model.listing.Program:
        ...


class BSimOverviewRowObject(java.lang.Object):
    """
    Table row object for BSim Overview results table
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, result: ghidra.features.bsim.query.protocol.SimilarityVectorResult, ad: ghidra.program.model.address.Address, vectorFactory: generic.lsh.vector.LSHVectorFactory, program: ghidra.program.model.listing.Program):
        """
        Constructor.
        
        :param ghidra.features.bsim.query.protocol.SimilarityVectorResult result: results for queried function
        :param ghidra.program.model.address.Address ad: address of function
        :param generic.lsh.vector.LSHVectorFactory vectorFactory: vectoryFactory
        :param ghidra.program.model.listing.Program program: program containing queried function
        """

    def getFunctionEntryPoint(self) -> ghidra.program.model.address.Address:
        ...

    def getFunctionName(self) -> str:
        ...

    def getHitCount(self) -> int:
        ...

    def getSelfSignificance(self) -> float:
        ...

    def getVectorHash(self) -> int:
        ...

    @property
    def vectorHash(self) -> jpype.JLong:
        ...

    @property
    def selfSignificance(self) -> jpype.JDouble:
        ...

    @property
    def hitCount(self) -> jpype.JInt:
        ...

    @property
    def functionName(self) -> java.lang.String:
        ...

    @property
    def functionEntryPoint(self) -> ghidra.program.model.address.Address:
        ...


class BSimOverviewModel(ghidra.util.table.AddressBasedTableModel[BSimOverviewRowObject]):
    """
    Table model for BSim Overview results
    """

    @typing.type_check_only
    class FuncNameColumn(ghidra.util.table.field.AbstractProgramBasedDynamicTableColumn[BSimOverviewRowObject, java.lang.String]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class HitCountColumn(ghidra.util.table.field.AbstractProgramBasedDynamicTableColumn[BSimOverviewRowObject, java.lang.Integer]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class SelfSignificanceColumn(ghidra.util.table.field.AbstractProgramBasedDynamicTableColumn[BSimOverviewRowObject, java.lang.Double]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class VectorHashColumn(ghidra.util.table.field.AbstractProgramBasedDynamicTableColumn[BSimOverviewRowObject, java.lang.Long]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class LongHexRenderer(ghidra.util.table.column.AbstractGColumnRenderer[java.lang.Long]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]


class BSimOverviewRowObjectToAddressTableRowMapper(ghidra.util.table.ProgramLocationTableRowMapper[BSimOverviewRowObject, ghidra.program.model.address.Address]):
    """
    Row object mapper for mapping BSimOverviewRowObjects to Addresses
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...



__all__ = ["BSimOverviewProvider", "BSimOverviewRowObject", "BSimOverviewModel", "BSimOverviewRowObjectToAddressTableRowMapper"]
