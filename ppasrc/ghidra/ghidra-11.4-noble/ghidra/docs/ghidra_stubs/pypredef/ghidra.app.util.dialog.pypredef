from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking
import ghidra.framework.model
import ghidra.framework.remote
import ghidra.program.model.address
import ghidra.program.model.listing
import java.lang # type: ignore


class AskAddrDialog(docking.DialogComponentProvider):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, title: typing.Union[java.lang.String, str], message: typing.Union[java.lang.String, str], program: ghidra.program.model.listing.Program, lastAddr: ghidra.program.model.address.Address):
        ...

    def getValueAsAddress(self) -> ghidra.program.model.address.Address:
        ...

    def isCanceled(self) -> bool:
        ...

    @property
    def canceled(self) -> jpype.JBoolean:
        ...

    @property
    def valueAsAddress(self) -> ghidra.program.model.address.Address:
        ...


class CheckoutDialog(docking.DialogComponentProvider):

    class_: typing.ClassVar[java.lang.Class]
    CHECKOUT: typing.Final = 0
    DO_NOT_CHECKOUT: typing.Final = 1

    def __init__(self, df: ghidra.framework.model.DomainFile, user: ghidra.framework.remote.User):
        ...

    def exclusiveCheckout(self) -> bool:
        ...

    def showDialog(self) -> int:
        """
        Show the dialog; return an ID for the action that the user chose.
        
        :return: OK, or CANCEL
        :rtype: int
        """



__all__ = ["AskAddrDialog", "CheckoutDialog"]
