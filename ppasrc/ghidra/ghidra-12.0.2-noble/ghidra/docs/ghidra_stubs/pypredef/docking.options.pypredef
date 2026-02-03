from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.framework.options
import java.lang # type: ignore


class OptionsService(java.lang.Object):
    """
    Provides a service interface that allows the user to get Options and to check for the
    existence of options.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def getOptions(self) -> jpype.JArray[ghidra.framework.options.Options]:
        """
        Get the list of options for all categories.
        
        :return: the list of options for all categories.
        :rtype: jpype.JArray[ghidra.framework.options.Options]
        """

    @typing.overload
    def getOptions(self, category: typing.Union[java.lang.String, str]) -> ghidra.framework.options.ToolOptions:
        """
        Get the options for the given category name.   If no options exist with the given name,
        then a new options object is created.
         
         
        Note: the given name should not contains options path separator characters.  Any
        sub-options needed must be retrieved from the ToolOptions object returned from this
        method.
        
        :param java.lang.String or str category: name of category
        :return: the options for the given category name.
        :rtype: ghidra.framework.options.ToolOptions
        """

    def hasOptions(self, category: typing.Union[java.lang.String, str]) -> bool:
        """
        Return whether an Options object exists for the given category.
        
        :param java.lang.String or str category: name of the category
        :return: true if an Options object exists
        :rtype: bool
        """

    def showOptionsDialog(self, category: typing.Union[java.lang.String, str], filterText: typing.Union[java.lang.String, str]):
        """
        Shows Options Dialog with the node denoted by "category" being displayed.  The value is
        expected to be the name of a node in the options tree, residing under the root node.  You
        may also provide the name of such a node, followed by the options delimiter, followed by
        the name of a child node under that node.  For example, suppose in the options tree exists
        a node Root->Foo  You may pass the value "Foo" to get that node.  Or, suppose
        in the options tree exists a node Root->Foo->childNode1  In this case, you may
        pass the value "Foo.childNode1", where the '.' character is the delimiter of the
        :obj:`ToolOptions` class (this is the value at the time of writing this documentation).
         
         
        
        The filter text parameter is used to set the contents filter text of the options.  You may
        use this parameter to filter the tree; for example, to show only the node in the tree that
        you want the user to see.
        
        :param java.lang.String or str category: The category of options to have displayed
        :param java.lang.String or str filterText: An optional value used to filter the nodes visible in the options tree.
                        You may pass ``null`` or the empty string ``""`` here if you
                        do not desire filtering.
        :raises IllegalArgumentException: if the given ``category`` value does not exist in
                                        the tree of options.
        """

    @property
    def options(self) -> jpype.JArray[ghidra.framework.options.Options]:
        ...



__all__ = ["OptionsService"]
