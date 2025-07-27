from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking.widgets.textfield
import java.lang # type: ignore
import javax.swing # type: ignore
import javax.swing.event # type: ignore


class IntegerSpinner(java.lang.Object):
    """
    Creates a component for editing Integer values using an :obj:`IntegerTextField` and a :obj:`JSpinner`.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, spinnerModel: javax.swing.SpinnerNumberModel):
        """
        Creates a new IntegerSpinner using the given spinner model.
        
        :param javax.swing.SpinnerNumberModel spinnerModel: the spinner model to use in the JSpinner.
        """

    @typing.overload
    def __init__(self, spinnerModel: javax.swing.SpinnerNumberModel, columns: typing.Union[jpype.JInt, int]):
        """
        Creates a new IntegerSpinner using the given spinner model.
        
        :param javax.swing.SpinnerNumberModel spinnerModel: the spinner model to use in the JSpinner.
        """

    def addChangeListener(self, listener: javax.swing.event.ChangeListener):
        """
        Adds a ChangeListener to the model's listener list.  The
        ChangeListeners must be notified when the models value changes.
        
        :param javax.swing.event.ChangeListener listener: the ChangeListener to add
        """

    def getSpinner(self) -> javax.swing.JSpinner:
        """
        Returns the JSpinner that has been attached to the text field.
        
        :return: the JSpinner that has been attached to the text field
        :rtype: javax.swing.JSpinner
        """

    def getTextField(self) -> docking.widgets.textfield.IntegerTextField:
        """
        Returns the IntegerTextField that has been attached to the spinner.
        
        :return: the IntegerTextField that has been attached to the spinner.
        :rtype: docking.widgets.textfield.IntegerTextField
        """

    def removeChangeListener(self, listener: javax.swing.event.ChangeListener):
        """
        Removes a ChangeListener from the model's listener list.
        
        :param javax.swing.event.ChangeListener listener: the ChangeListener to remove
        """

    def setValue(self, value: java.lang.Number):
        """
        Sets the given value to both the spinner and the text field.
        
        :param java.lang.Number value: the value to set.
        """

    @property
    def textField(self) -> docking.widgets.textfield.IntegerTextField:
        ...

    @property
    def spinner(self) -> javax.swing.JSpinner:
        ...



__all__ = ["IntegerSpinner"]
