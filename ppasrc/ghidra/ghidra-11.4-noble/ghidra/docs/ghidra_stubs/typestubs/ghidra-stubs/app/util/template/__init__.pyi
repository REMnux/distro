from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.framework.options
import ghidra.program.model.symbol
import java.lang # type: ignore


class TemplateSimplifier(ghidra.program.model.symbol.NameTransformer):
    """
    Class for simplify names with template data. This class can be used with tool options or
    as a stand alone configurable simplifier.
    """

    @typing.type_check_only
    class TemplateString(java.lang.Record):

        class_: typing.ClassVar[java.lang.Class]

        def end(self) -> int:
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def input(self) -> str:
            ...

        def start(self) -> int:
            ...

        def toString(self) -> str:
            ...


    class_: typing.ClassVar[java.lang.Class]
    SUB_OPTION_NAME: typing.Final = "Templates"
    SIMPLIFY_TEMPLATES_OPTION: typing.Final = "Templates.Simplify Templated Names"
    TEMPLATE_NESTING_DEPTH_OPTION: typing.Final = "Templates.Max Template Depth"
    MAX_TEMPLATE_LENGTH_OPTION: typing.Final = "Templates.Max Template Length"
    MIN_TEMPLATE_LENGTH_OPTION: typing.Final = "Templates.Min Template Length"
    SIMPLY_TEMPLATES_DESCRIPTION: typing.Final = "Determines whether to diplay templated names in a simplified form."
    TEMPLATE_NESTING_DEPTH_DESCRIPTION: typing.Final = "Maximum template depth to display when simplify templated names."
    MAX_TEMPLATE_LENGTH_DESCRIPTION: typing.Final = "Maximum number of characters to display in a template before truncating the name in the middle."
    MIN_TEMPLATE_LENGTH_DESCRIPTION: typing.Final = "Minumum size of template to be simplified"

    @typing.overload
    def __init__(self):
        """
        Constructor to use for a TemplateSimplifier that doesn't use values from ToolOptions
        """

    @typing.overload
    def __init__(self, fieldOptions: ghidra.framework.options.ToolOptions):
        """
        Constructor to use for a TemplateSimplifier that operates using the current values in 
        the tool options
        
        :param ghidra.framework.options.ToolOptions fieldOptions: the "Listing Field" options
        """

    def fieldOptionsChanged(self, options: ghidra.framework.options.Options, optionName: typing.Union[java.lang.String, str], oldValue: java.lang.Object, newValue: java.lang.Object) -> bool:
        """
        Notification that options have changed
        
        :param ghidra.framework.options.Options options: the options object that has changed values
        :param java.lang.String or str optionName: the name of the options that changed
        :param java.lang.Object oldValue: the old value for the option that changed
        :param java.lang.Object newValue: the new value for the option that changed
        :return: true if the option that changed was a template simplification option
        :rtype: bool
        """

    def getMaxTemplateLength(self) -> int:
        """
        Gets the maximum length that a template will display.
        
        :return: the maximum length that a template will display
        :rtype: int
        """

    def getMinimumTemplateLength(self) -> int:
        """
        Returns the minimum length of a template string that will be simplified.
        
        :return: the minimum length of a template string that will be simplified.
        :rtype: int
        """

    def getNestingDepth(self) -> int:
        """
        Returns the nesting depth for simplification
        
        :return: the nesting depth for simplification
        :rtype: int
        """

    def isEnabled(self) -> bool:
        """
        Returns if this TemplateSimplifier is enabled.
        
        :return: if this TemplateSimplifier is enabled
        :rtype: bool
        """

    def reloadFromOptions(self, fieldOptions: ghidra.framework.options.ToolOptions):
        """
        Reloads the current simplification settings from the given field options
        
        :param ghidra.framework.options.ToolOptions fieldOptions: the options to retrieve the simplification settings.
        """

    def setEnabled(self, doSimplify: typing.Union[jpype.JBoolean, bool]):
        """
        Sets if this TemplateSimplifier is enabled. If disabled, the :meth:`simplify(String) <.simplify>` 
        method will return the input string.
        
        :param jpype.JBoolean or bool doSimplify: true to do simplification, false to do nothing
        """

    def setMaxTemplateLength(self, maxLength: typing.Union[jpype.JInt, int]):
        """
        Sets the maximum length do display the template portion. If, after any nesting,
        simplification, the resulting template string is longer that the max length, the middle
        portion will be replaced with "..." to reduce the template string to the given max length.
        
        :param jpype.JInt or int maxLength: the max length of a template to display
        """

    def setMinimumTemplateLength(self, minLength: typing.Union[jpype.JInt, int]):
        """
        Sets the minimum length for a template string to be simplified. In other words, template
        strings less than this length will not be changed.
        
        :param jpype.JInt or int minLength: the minimum length to simplify
        """

    def setNestingDepth(self, depth: typing.Union[jpype.JInt, int]):
        """
        Sets the template nesting depth to be simplified. A depth of 0 simplifies the entire 
        template portion of the name (everything in between ``<>``). A depth of 1 leaves one 
        level of template information
        
        :param jpype.JInt or int depth: the nesting depth
        """

    def simplify(self, input: typing.Union[java.lang.String, str]) -> str:
        """
        Simplifies any template string in the given input base on the current simplification
        settings.
        
        :param java.lang.String or str input: the input string to be simplified
        :return: a simplified string
        :rtype: str
        """

    @property
    def nestingDepth(self) -> jpype.JInt:
        ...

    @nestingDepth.setter
    def nestingDepth(self, value: jpype.JInt):
        ...

    @property
    def maxTemplateLength(self) -> jpype.JInt:
        ...

    @maxTemplateLength.setter
    def maxTemplateLength(self, value: jpype.JInt):
        ...

    @property
    def minimumTemplateLength(self) -> jpype.JInt:
        ...

    @minimumTemplateLength.setter
    def minimumTemplateLength(self, value: jpype.JInt):
        ...

    @property
    def enabled(self) -> jpype.JBoolean:
        ...

    @enabled.setter
    def enabled(self, value: jpype.JBoolean):
        ...



__all__ = ["TemplateSimplifier"]
