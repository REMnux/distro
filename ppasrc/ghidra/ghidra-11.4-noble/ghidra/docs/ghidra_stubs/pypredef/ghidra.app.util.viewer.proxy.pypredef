from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.util.viewer.listingpanel
import ghidra.program.model.address
import ghidra.program.model.listing
import java.lang # type: ignore


T = typing.TypeVar("T")


class EmptyProxy(ProxyObj[java.lang.Object]):
    """
    Used as proxy for a null value.
    """

    class_: typing.ClassVar[java.lang.Class]
    EMPTY_PROXY: typing.Final[EmptyProxy]


class DataProxy(ProxyObj[ghidra.program.model.listing.Data]):
    """
    Stores information about a data item in a program such that the data item can 
    be retrieved when needed.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, model: ghidra.app.util.viewer.listingpanel.ListingModel, program: ghidra.program.model.listing.Program, data: ghidra.program.model.listing.Data):
        """
        Construct a proxy for the given Data object.
        
        :param ghidra.app.util.viewer.listingpanel.ListingModel model: the model
        :param ghidra.program.model.listing.Program program: the program containing the data object.
        :param ghidra.program.model.listing.Data data: the Data object to proxy.
        """


class CodeUnitProxy(ProxyObj[ghidra.program.model.listing.CodeUnit]):
    """
    Stores information about a code unit in a program.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, model: ghidra.app.util.viewer.listingpanel.ListingModel, program: ghidra.program.model.listing.Program, cu: ghidra.program.model.listing.CodeUnit):
        """
        Construct a proxy for a code unit
        
        :param ghidra.app.util.viewer.listingpanel.ListingModel model: the model
        :param ghidra.program.model.listing.Program program: the program containing the code unit
        :param ghidra.program.model.listing.CodeUnit cu: the code unit to proxy.
        """


class ProxyObj(java.lang.Object, typing.Generic[T]):
    """
    Implementing objects of this interface hold an object from a program (e.g.,  CodeUnit, Function,
    etc.) in such a way as to be robust against changes to the program.   In other words, it protects 
    against holding on to "stale" objects.  The getObject() method will return the represented object
    (refreshed if it was stale) or null if it no longer exists.
    """

    class_: typing.ClassVar[java.lang.Class]

    def contains(self, a: ghidra.program.model.address.Address) -> bool:
        """
        Returns true if the proxy object of this class contains the given address.
        
        :param ghidra.program.model.address.Address a: the address
        :return: true if the proxy object of this class contains the given address.
        :rtype: bool
        """

    def getListingLayoutModel(self) -> ghidra.app.util.viewer.listingpanel.ListingModel:
        """
        Returns the layout model which corresponds to this field proxy.
        
        :return: the model
        :rtype: ghidra.app.util.viewer.listingpanel.ListingModel
        """

    def getObject(self) -> T:
        """
        Returns the object that this proxy represents or null if the object no longer exists.
        
        :return: the object that this proxy represents or null if the object no longer exists.
        :rtype: T
        """

    @property
    def listingLayoutModel(self) -> ghidra.app.util.viewer.listingpanel.ListingModel:
        ...

    @property
    def object(self) -> T:
        ...


class FunctionProxy(ProxyObj[ghidra.program.model.listing.Function]):
    """
    Stores information about a function in a program such that the function can 
    be retrieved when needed.  The locationAddr and functionAddr may differ when the
    function object has been inferred via a reference at the locationAddr.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, model: ghidra.app.util.viewer.listingpanel.ListingModel, program: ghidra.program.model.listing.Program, locationAddr: ghidra.program.model.address.Address, function: ghidra.program.model.listing.Function):
        """
        Construct a proxy for a function
        
        :param ghidra.app.util.viewer.listingpanel.ListingModel model: listing model
        :param ghidra.program.model.listing.Program program: the program containing the function
        :param ghidra.program.model.address.Address locationAddr: the listing address at which the function exists or was inferred via reference
        :param ghidra.program.model.listing.Function function: the function to proxy
        """

    def getFunctionAddress(self) -> ghidra.program.model.address.Address:
        ...

    def getLocationAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def locationAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def functionAddress(self) -> ghidra.program.model.address.Address:
        ...


class VariableProxy(ProxyObj[ghidra.program.model.listing.Variable]):
    """
    Stores information about a variable in a program such that the variable can
    be retrieved when needed.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, model: ghidra.app.util.viewer.listingpanel.ListingModel, program: ghidra.program.model.listing.Program, locationAddr: ghidra.program.model.address.Address, fun: ghidra.program.model.listing.Function, var: ghidra.program.model.listing.Variable):
        """
        Constructs a proxy for a variable.
        
        :param ghidra.app.util.viewer.listingpanel.ListingModel model: listing model
        :param ghidra.program.model.listing.Program program: the program containing the variable.
        :param ghidra.program.model.address.Address locationAddr: the listing address at which the function exists or was inferred via reference
        :param ghidra.program.model.listing.Function fun: the function containing the variable.
        :param ghidra.program.model.listing.Variable var: the variable to proxy.
        """

    def getFunctionAddress(self) -> ghidra.program.model.address.Address:
        ...

    def getLocationAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def locationAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def functionAddress(self) -> ghidra.program.model.address.Address:
        ...


class AddressProxy(ProxyObj[ghidra.program.model.address.Address]):
    """
    Stores information about an address in a program.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, model: ghidra.app.util.viewer.listingpanel.ListingModel, addr: ghidra.program.model.address.Address):
        """
        Construct a address proxy
        
        :param ghidra.app.util.viewer.listingpanel.ListingModel model: the model
        :param ghidra.program.model.address.Address addr: the address to proxy
        """



__all__ = ["EmptyProxy", "DataProxy", "CodeUnitProxy", "ProxyObj", "FunctionProxy", "VariableProxy", "AddressProxy"]
