from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.plugin.core.overview
import ghidra.framework.model
import ghidra.framework.options
import ghidra.program.model.address
import java.awt # type: ignore
import java.lang # type: ignore
import javax.swing # type: ignore


class AddressTypeOverviewColorService(ghidra.app.plugin.core.overview.OverviewColorService, ghidra.framework.options.OptionsChangeListener, ghidra.framework.model.DomainObjectListener):
    """
    Service for associating colors with a programs addresses based on what program object is
    at those addresses (functions, instructions, defined data, etc.)
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def getAddressType(self, address: ghidra.program.model.address.Address) -> AddressType:
        """
        Determines the :obj:`AddressType` for the given address
        
        :param ghidra.program.model.address.Address address: the address for which to get an AddressType.
        :return: the :obj:`AddressType` for the given address.
        :rtype: AddressType
        """

    def getColor(self, addressType: AddressType) -> java.awt.Color:
        """
        Returns the color associated with the given :obj:`AddressType`
        
        :param AddressType addressType: the address type for which to get a color.
        :return: the color associated with the given :obj:`AddressType`
        :rtype: java.awt.Color
        """

    def setColor(self, type: AddressType, newColor: java.awt.Color):
        """
        Sets the color to be associated with a given :obj:`AddressType`
        
        :param AddressType type: the AddressType for which to assign the color.
        :param java.awt.Color newColor: the new color for the given :obj:`AddressType`
        """

    @property
    def color(self) -> java.awt.Color:
        ...

    @property
    def addressType(self) -> AddressType:
        ...


class AddressTypeOverviewLegendPanel(javax.swing.JPanel):
    """
    A component for displaying the color legend for the :obj:`AddressTypeOverviewColorService`
    """

    @typing.type_check_only
    class ColorPanel(javax.swing.JPanel):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, colorService: AddressTypeOverviewColorService):
        ...

    def updateColors(self):
        """
        Kick to repaint when the colors have changed.
        """


class AddressType(java.lang.Enum[AddressType]):
    """
    An enum for the different types that are represented by unique colors by the
    :obj:`AddressTypeOverviewColorService`
    """

    class_: typing.ClassVar[java.lang.Class]
    FUNCTION: typing.Final[AddressType]
    UNINITIALIZED: typing.Final[AddressType]
    EXTERNAL_REF: typing.Final[AddressType]
    INSTRUCTION: typing.Final[AddressType]
    DATA: typing.Final[AddressType]
    UNDEFINED: typing.Final[AddressType]

    def getDescription(self) -> str:
        """
        Returns a description of this enum value.
        
        :return: a description of this enum value.
        :rtype: str
        """

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> AddressType:
        ...

    @staticmethod
    def values() -> jpype.JArray[AddressType]:
        ...

    @property
    def description(self) -> java.lang.String:
        ...



__all__ = ["AddressTypeOverviewColorService", "AddressTypeOverviewLegendPanel", "AddressType"]
