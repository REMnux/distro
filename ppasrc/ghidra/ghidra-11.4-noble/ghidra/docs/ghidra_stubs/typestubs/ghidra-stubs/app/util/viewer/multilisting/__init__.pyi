from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking.widgets.fieldpanel
import ghidra.app.util.viewer.field
import ghidra.app.util.viewer.format
import ghidra.app.util.viewer.listingpanel
import ghidra.program.model.address
import ghidra.program.model.listing
import ghidra.util.datastruct
import java.lang # type: ignore


class MultiListingLayoutModel(ghidra.app.util.viewer.listingpanel.ListingModelListener, ghidra.app.util.viewer.format.FormatModelListener):
    """
    Class for creating multiple coordinated ListingModels for multiple programs.
    """

    @typing.type_check_only
    class AlignedModel(ghidra.app.util.viewer.listingpanel.ListingModel):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, formatMgr: ghidra.app.util.viewer.format.FormatManager, programs: jpype.JArray[ghidra.program.model.listing.Program], primaryAddrSet: ghidra.program.model.address.AddressSetView):
        """
        Constructs a new MultiListingLayoutModel.
        
        :param ghidra.app.util.viewer.format.FormatManager formatMgr: the FormatManager used to layout the fields.
        :param jpype.JArray[ghidra.program.model.listing.Program] programs: the list of programs that will be coordinated using listing models.
        The first program in the array will be used as the primary program.
        :param ghidra.program.model.address.AddressSetView primaryAddrSet: the addressSet to use for the view. 
        This is compatible with the primary program, which is program[0].
        """

    def getAlignedModel(self, index: typing.Union[jpype.JInt, int]) -> ghidra.app.util.viewer.listingpanel.ListingModel:
        """
        Returns the ListingLayoutModel for the i'th program.
        
        :param jpype.JInt or int index: the index of program for which to return a listing model
        :return: the ListingLayoutModel for the i'th program.
        :rtype: ghidra.app.util.viewer.listingpanel.ListingModel
        """

    def getModel(self, index: typing.Union[jpype.JInt, int]) -> ghidra.app.util.viewer.listingpanel.ListingModel:
        """
        Returns the ListingModel for the program with the indicated index.
        
        :param jpype.JInt or int index: the index indicating which program's model to get.
        :return: the program's ListingModel.
        :rtype: ghidra.app.util.viewer.listingpanel.ListingModel
        """

    def setAddressSet(self, view: ghidra.program.model.address.AddressSetView):
        """
        Sets the address set for this MultiListingLayoutModel
        
        :param ghidra.program.model.address.AddressSetView view: the current address set, which must be compatible with the 
        primary program and listingModel
        """

    def setAddressTranslator(self, translator: AddressTranslator):
        ...

    @property
    def model(self) -> ghidra.app.util.viewer.listingpanel.ListingModel:
        ...

    @property
    def alignedModel(self) -> ghidra.app.util.viewer.listingpanel.ListingModel:
        ...


class AddressTranslator(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def translate(self, address: ghidra.program.model.address.Address, primaryProgram: ghidra.program.model.listing.Program, program: ghidra.program.model.listing.Program) -> ghidra.program.model.address.Address:
        ...


class LayoutCache(ghidra.util.datastruct.FixedSizeHashMap[ghidra.program.model.address.Address, MultiLayout]):
    """
    Cache for MultiLayout objects
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class ListingModelConverter(ghidra.app.util.viewer.listingpanel.ListingModel):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, primaryModel: ghidra.app.util.viewer.listingpanel.ListingModel, model: ghidra.app.util.viewer.listingpanel.ListingModel):
        """
        Converts addresses from the primary model into addresses for this converters model.
        
        :param ghidra.app.util.viewer.listingpanel.ListingModel primaryModel: the primary model
        :param ghidra.app.util.viewer.listingpanel.ListingModel model: this converter's model
        """

    def setAddressTranslator(self, translator: AddressTranslator):
        """
        Sets an address translator for this converter. If provided the translator converts
        addresses from the primary program to those in the program for this converter's model.
        
        :param AddressTranslator translator: translates addresses between the primary model and this converter's model
        """


@typing.type_check_only
class MultiLayout(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, layouts: jpype.JArray[docking.widgets.fieldpanel.Layout], factory: ghidra.app.util.viewer.field.DummyFieldFactory):
        ...

    def getLayout(self, modelID: typing.Union[jpype.JInt, int]) -> docking.widgets.fieldpanel.Layout:
        ...

    def isEmpty(self) -> bool:
        ...

    @property
    def layout(self) -> docking.widgets.fieldpanel.Layout:
        ...

    @property
    def empty(self) -> jpype.JBoolean:
        ...



__all__ = ["MultiListingLayoutModel", "AddressTranslator", "LayoutCache", "ListingModelConverter", "MultiLayout"]
