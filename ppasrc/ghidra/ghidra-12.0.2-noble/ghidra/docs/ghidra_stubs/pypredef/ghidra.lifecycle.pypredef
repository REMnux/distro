from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import java.lang # type: ignore


T = typing.TypeVar("T")


class Unfinished(java.lang.Object):
    """
    This serves both as a marker interface for classes missing important methods and as container for
    the :meth:`TODO(String, Object...) <.TODO>` method.
     
     
    
    TODO: It'd be nice to optionally ignore TODO exceptions, but this seems to require a dependency
    on JUnit, which is a no-no within ``src/main``. Maybe there's a way via the abstract test
    case, or an interface mixin....
    """

    class TODOException(java.lang.UnsupportedOperationException):

        class_: typing.ClassVar[java.lang.Class]

        @typing.overload
        def __init__(self, message: typing.Union[java.lang.String, str]):
            ...

        @typing.overload
        def __init__(self):
            ...


    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    @typing.overload
    def TODO(message: typing.Union[java.lang.String, str], *ignore: java.lang.Object) -> T:
        """
        Perhaps a little better than returning ``null`` or throwing
        :obj:`UnsupportedOperationException` yourself, as references can be found in most IDEs.
        
        :param java.lang.String or str message: A message describing the task that is yet to be done
        :param jpype.JArray[java.lang.Object] ignore: variables involved in the implementation so far
        """

    @staticmethod
    @typing.overload
    def TODO() -> T:
        """
        Perhaps a little better than returning ``null`` or throwing
        :obj:`UnsupportedOperationException` yourself, as references can be found in most IDEs.
        """



__all__ = ["Unfinished"]
