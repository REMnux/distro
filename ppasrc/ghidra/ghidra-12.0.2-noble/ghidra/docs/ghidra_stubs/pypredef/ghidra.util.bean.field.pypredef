from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking.widgets.fieldpanel.field
import ghidra.app.nav
import ghidra.app.util.viewer.field
import ghidra.framework.plugintool
import ghidra.program.model.listing
import java.lang # type: ignore


class AnnotatedTextFieldElement(docking.widgets.fieldpanel.field.AbstractTextFieldElement):
    """
    A subclass of :obj:`FieldElement` that allows for mouse handling callbacks via the
    :meth:`handleMouseClicked(Navigatable, ServiceProvider) <.handleMouseClicked>` method.  This class
    is based upon :obj:`Annotation` objects, which are elements that perform actions when the
    use clicks an instance of this class in the display.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, annotation: ghidra.app.util.viewer.field.Annotation, prototype: docking.widgets.fieldpanel.field.AttributedString, program: ghidra.program.model.listing.Program, row: typing.Union[jpype.JInt, int], column: typing.Union[jpype.JInt, int]):
        """
        Constructor that initializes this text field element with the given annotation and row
        and column information.  The text of this element is the display text created by the 
        annotation handler for the given annotation.
        
        :param ghidra.app.util.viewer.field.Annotation annotation: The Annotation that this element is describing.
        :param docking.widgets.fieldpanel.field.AttributedString prototype: the prototype string used to create new strings
        :param ghidra.program.model.listing.Program program: the program
        :param jpype.JInt or int row: The row that this element is on
        :param jpype.JInt or int column: The column value of this element (the column index where this element starts)
        """

    def getDisplayString(self) -> str:
        ...

    def getRawText(self) -> str:
        """
        Returns the original annotation text in the data model, which will differ from the display
        text.
        
        :return: the original annotation text in the data model.
        :rtype: str
        """

    def handleMouseClicked(self, sourceNavigatable: ghidra.app.nav.Navigatable, serviceProvider: ghidra.framework.plugintool.ServiceProvider) -> bool:
        """
        This method is designed to be called when a mouse click has occurred for a given
        :obj:`ProgramLocation`.
        
        :param ghidra.app.nav.Navigatable sourceNavigatable: The source Navigatable
        :param ghidra.framework.plugintool.ServiceProvider serviceProvider: A service provider from which system resources can be retrieved
        :return: true if this string handles the mouse click.
        :rtype: bool
        """

    @property
    def rawText(self) -> java.lang.String:
        ...

    @property
    def displayString(self) -> java.lang.String:
        ...



__all__ = ["AnnotatedTextFieldElement"]
