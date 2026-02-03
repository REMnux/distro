from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking
import ghidra.util
import java.awt # type: ignore
import java.lang # type: ignore
import javax.swing # type: ignore


T = typing.TypeVar("T")


class WizardModel(java.lang.Object, typing.Generic[T]):
    """
    This is the main class for defining the steps and GUI for a :obj:`WizardDialog`.
     
    
    A wizard dialog is a dialog that uses multiple input Gui panels to gather all the
    information required before doing some complex action. Typically, a wizard dialog is used when 
    the user input is best gathered in steps, so as to not overwhelm the user with an overly complex
    screen. Additionally, the information from one step may determine which follow-on steps
    are needed.
     
    
    To create a wizard dialog, the developer needs to create the following:
    
     
    1.  A class that extends this WizardModel. 
    2.  One or more classes that extend :obj:`WizardStep`
    3.  A data class that holds that data being collected by this wizard.
    
    
    Subclasses must at a minimum implement two methods.
     
    1.  AddWizardSteps() - This is where the model defines the ordered list of
    :obj:`WizardStep` for this wizard.
    2.  doFinish() - This is where the model should perform the main action of the wizard. This
    will be called when the user presses theFinish button and all the panels have
    had a chance to update the wizard data object.
    
    
    Optionally, there are several additional methods clients may want to override.
     
    1. dispose() - This will be called when the wizard is completed or cancelled and this is
    where any cleanup, if any, should be done, including cleaning up the data object if
    necessary. The super of this method will call dispose on each wizard step, so that
    won't be necessary as long as this overridden dispose() calls super.dispose();
    2. cancel() - This will only be called if the dialog is cancelled. This is a chance to  
    perform cleanup that should only be done when the operation is cancelled.
    This is in addition to any cleanup in the dispose() call. This is not normally needed.
    An example of where this might be useful is suppose the purpose of the wizard is to
    pick and open two related files. If the wizard completes successfully, then the two
    files are supposed to remain open after the wizard is closed. However, suppose after
    one step that opened the first file, the user cancels the operation. Then you would
    want to close the first file that was opened in this cancelled cancel() call, because
    you don't want to do it in the dispose() since that will be called even if the wizard
    completed.
    3. getPreferredSize() - By default, this will return a preferred size that is the biggest
    width and height of all the preferred sizes of the step panels. Override this to
    simply specify the preferred size of the dialog.
    """

    class_: typing.ClassVar[java.lang.Class]

    def canCancel(self) -> bool:
        """
        Returns true if the cancel button should be enabled. The only time this is disabled is
        when the wizard is performing some expensive operation between steps.
        
        :return: true if the cancel button should be enabled
        :rtype: bool
        """

    def canFinish(self) -> bool:
        """
        Returns true if the "Finish" button should be enabled.
        
        :return: true if the "Finish" button should be enabled
        :rtype: bool
        """

    def canGoBack(self) -> bool:
        """
        Returns true if the "Back" button should be enabled.
        
        :return: true if the "Back" button should be enabled
        :rtype: bool
        """

    def canGoNext(self) -> bool:
        """
        Returns true if the "Next" button should be enabled.
        
        :return: true if the "Next" button should be enabled
        :rtype: bool
        """

    def dispose(self):
        """
        Calls dispose() on all the wizard steps. Subclasses can override this to do additional
        cleanup if needed.
        """

    def finish(self):
        """
        Completes the wizard. Gives each remaining panel a chance to validate and populate the data
        object before calling the :meth:`doFinish() <.doFinish>` method where subclasses can do the final task.
        """

    def getCurrentStep(self) -> WizardStep[T]:
        """
        Returns the current :obj:`WizardStep`.
        
        :return: the current wizard step
        :rtype: WizardStep[T]
        """

    def getData(self) -> T:
        """
        Returns the data object which is populated by the various wizard steps as they completed.
        
        :return: the data object
        :rtype: T
        """

    def getIcon(self) -> javax.swing.Icon:
        """
        Returns the icon for this wizard.
        
        :return: the icon for this wizard
        :rtype: javax.swing.Icon
        """

    def getStatusMessage(self) -> str:
        """
        Returns the current status message for the wizard.
        
        :return: the current status message for the wizard
        :rtype: str
        """

    def getTitle(self) -> str:
        """
        Returns the title of this wizard.
        
        :return: the title of this wizard
        :rtype: str
        """

    def goBack(self):
        """
        Returns the wizard back to the previous step.
        """

    def goNext(self):
        """
        Advances the wizard to the next step.
        """

    def wasCancelled(self) -> bool:
        """
        Returns true if the wizard was cancelled.
        
        :return: true if the wizard was cancelled
        :rtype: bool
        """

    @property
    def currentStep(self) -> WizardStep[T]:
        ...

    @property
    def data(self) -> T:
        ...

    @property
    def icon(self) -> javax.swing.Icon:
        ...

    @property
    def title(self) -> java.lang.String:
        ...

    @property
    def statusMessage(self) -> java.lang.String:
        ...


class WizardStep(java.lang.Object, typing.Generic[T]):
    """
    This is the base class for defining a step in a :obj:`WizardModel` to be displayed using
    a :obj:`WizardDialog`.
     
    
    A wizard dialog collects information from a user in a step by step process. Each step presents
    a Gui panel to the user that must be completed and validated before advancing to the next step.
     
    
    Each step in the wizard must implement several methods to support the wizard step's life cycle.
    The basic life cycle for a step that is shown is initialize(), getComponent(), then repeated
    calls to isValid() and populateData() while it is showing and being modified, followed by
    the apply() method when moving on to the next step.
     
    
    In addition, there are several methods that step's must implement that are called when the step
    is not showing and should not consider any Gui state that it may have (The Gui state may be stale
    if the user back tracked or it may never have been created or initialized) such as the 
    isApplicable() and canFinish().
     
    
    Each step must implement the following methods:
     
     
    * initialize(T data) - This method is called just before the step's Gui component
    is shown. This is were the step should use the information in the passed in data object
        to populate its Gui data fields. The component can be lazily created in this method
    if not created in the constructor, as the:meth:`getComponent() <.getComponent>` will not be called
    before the initialize method is called. Note that the initialize method can possibly
    be called multiple times if the user goes back to a previous panel and then forward
    again.
    * isValid() - This method is called repeatedly while the step is showing as the
    step calls back to the model as any Gui component is modified. When the step reports
    back that it is valid, then the next and finish buttons can be enabled. Also, if
    valid, this step's:meth:`populateData(Object) <.populateData>` will be called so its data can
    be seen by follow-on steps in their:meth:`canFinish(Object) <.canFinish>` calls.
    * canFinish(T data) - This method is called on steps that follow the current step
    if the current step is valid. When implementing this method, the data in the step's Gui
    should be ignored (it may not have been initialized yet or it may be stale if the user
    back tracked) and its determination if it can finish should be done
    purely based on the information in the passed in data object. The idea is that if
    a step returns true for canFinish(), it does not need to be shown before the wizard
    can complete.
    * populateData(T data) - This method is called on the current step whenever the 
    isValid() method of the current step returns true. The step should simply transfer data
    from it's Gui component to the data component. It should not do any time consuming
    operations in this method.
    * apply(T data) - This method is called on each step when it is the current step 
    and the next button is pressed. It is also called on each follow-on step when the finish
    button is pressed. Expensive operations should be done here when a step is completed and
    moving to the next step. Typically, the implementer of the apply method should perform
    the operation in a task. One example, might be the user is picking files to open, the
    populateData() method might copy the file names to the data object, but the apply()
    method is used to actually open the files and put them into the data object. Most
    wizard steps should just return true here.
    * isApplicable(T data) - this method is called to see if a step is applicable based
    on choices made in previous steps.
    """

    class_: typing.ClassVar[java.lang.Class]

    def apply(self, data: T) -> bool:
        """
        This method is called on the current step when advancing to the next step. It is also called
        on all subsequent steps when finishing the wizard as those steps are skipped because the
        finish button was pressed. This method is for steps to perform more extensive operations 
        when moving on to subsequent steps. Most steps can just return true here as simple data
        will be added during the :meth:`populateData(Object) <.populateData>` method.
        
        :param T data: the custom wizard data containing the information from all previous steps.
        :return: true if the apply completes successfully.
        :rtype: bool
        """

    def canFinish(self, data: T) -> bool:
        """
        Reports true if the information in the given data object is sufficient enough that this
        step does not need to be shown in order to complete the wizard. It is only called on steps
        subsequent to the current step. Wizard steps should only make their decisions based on the
        information in the data object and not their internal GUI, which might not have even been
        initialized at this point. This method is only called on steps whose
        :meth:`isApplicable(Object) <.isApplicable>` method returns true.
        
        :param T data: the custom wizard data containing the information from all previous steps.
        :return: true if this step does not need to be shown before completing the wizard
        :rtype: bool
        """

    def getComponent(self) -> javax.swing.JComponent:
        """
        Get the panel object
        
        :return: JPanel panel
        :rtype: javax.swing.JComponent
        """

    def getDefaultFocusComponent(self) -> java.awt.Component:
        """
        Returns the component, if any, that should receive focus when this panel is shown.
        
        :return: the component, if any, that should receive focus when this panel is shown; null
                if no preferred focus component exists.
        :rtype: java.awt.Component
        """

    def getHelpLocation(self) -> ghidra.util.HelpLocation:
        """
        Returns the help content location for this panel.
        
        :return: String help location for this panel; return null if default help
        location should be used.
        :rtype: ghidra.util.HelpLocation
        """

    def getTitle(self) -> str:
        """
        Get the title for this step.
        
        :return: the title for this step
        :rtype: str
        """

    def initialize(self, data: T):
        """
        Initialize the panel as though this is the first time it is
        being displayed. This is where the step should initialize all Gui fields from the given
        data object.
         
        
        Creating the Gui component can be done lazily in this method if not done in 
        the constructor, as the initialize() method will always be called before the getComponent()
        method is called. Just be careful as this method can be called multiple times if the user
        backtracks in the wizard dialog.
        
        :param T data: the custom wizard data containing the information from all previous steps.
        """

    def isApplicable(self, data: T) -> bool:
        """
        Returns true if a step is applicable base on the information in the given data object. 
        Data from previous steps may make a subsequent step applicable or not.
        
        :param T data: the custom wizard data containing the information from all previous steps.
        :return: 
        :rtype: bool
        """

    def isValid(self) -> bool:
        """
        Checks if the Gui component has completed and has valid information. Typically, whenever the
        Gui state changes, it notifies the model using the statusChangedCallback, which in turn
        will call the isValid() method on the current step. If the current step is valid, it will
        in turn trigger additional calls to follow-on steps to see if the wizard can finish.
        
        :return: true if the Gui component has completed and valid information and is eligible to
        continue to the next step.
        :rtype: bool
        """

    def populateData(self, data: T):
        """
        This method should populate the given data object with information from its Gui component.
        
        :param T data: the custom wizard data containing the information from all previous steps.
        """

    @property
    def valid(self) -> jpype.JBoolean:
        ...

    @property
    def defaultFocusComponent(self) -> java.awt.Component:
        ...

    @property
    def component(self) -> javax.swing.JComponent:
        ...

    @property
    def applicable(self) -> jpype.JBoolean:
        ...

    @property
    def helpLocation(self) -> ghidra.util.HelpLocation:
        ...

    @property
    def title(self) -> java.lang.String:
        ...


class WizardDialog(docking.DialogComponentProvider):
    """
    A dialog for displaying a series of wizard panels used to collect data from the user before
    performing some task with the collected data. This dialog is generic and is used to display 
    the wizard steps as defined by a :obj:`WizardModel`.
     
    
    To use this dialog, create an instance of a :obj:`WizardModel` and construct this dialog
    with that model, optionally specifying if the dialog is modal or not (default is modal). Then
    call either the :meth:`show() <.show>` or :meth:`show(Component) <.show>` method to display it. If the model's 
    purpose is to create some object, get it from the model when done.
     
    
    For example, 
     
            FooWizardModel model = new FooWizardModel();
            WizardDialog wizard = new WizardDialog(model);
            wizard.show();
            Foo foo = model.getFoo();
    """

    class_: typing.ClassVar[java.lang.Class]
    FINISH: typing.Final = "Finish"
    """
    Default text for the 'finish' button
    """

    NEXT: typing.Final = "Next >>"
    """
    Default text for the 'next' button
    """

    BACK: typing.Final = "<< Back"
    """
    Default text for the 'back' button
    """


    @typing.overload
    def __init__(self, model: WizardModel[typing.Any]):
        """
        Constructs a modal WizardDialog using the given model.
        
        :param WizardModel[typing.Any] model: the wizard model
        """

    @typing.overload
    def __init__(self, model: WizardModel[typing.Any], modal: typing.Union[jpype.JBoolean, bool]):
        """
        Constructs a WizardDialog using the given model.
        
        :param jpype.JBoolean or bool modal: true if the wizard should be modal
        :param WizardModel[typing.Any] model: the wizard model
        """

    def cancel(self):
        """
        Cancels the wizard
        """

    def focusFinish(self):
        """
        Places focus on the 'finish' button.
        """

    def focusNext(self):
        """
        Places focus on the 'next' button.
        """

    def getCurrentStep(self) -> WizardStep[typing.Any]:
        """
        Returns the current wizard panel.
        
        :return: the current wizard panel
        :rtype: WizardStep[typing.Any]
        """

    def getStatusMessage(self) -> str:
        """
        Returns the current status message being displayed in this dialog.
        
        :return: the current status message being displayed in this dialog
        :rtype: str
        """

    def setStatusMessage(self, message: typing.Union[java.lang.String, str]):
        """
        Sets the status message on the dialog
        
        :param java.lang.String or str message: the message to display in the dialog
        """

    @typing.overload
    def show(self):
        """
        Shows the wizard dialog.
        """

    @typing.overload
    def show(self, parent: java.awt.Component):
        """
        Shows the wizard dialog parented to the given component.
        
        :param java.awt.Component parent: the component to parent the dialog to
        """

    @property
    def currentStep(self) -> WizardStep[typing.Any]:
        ...

    @property
    def statusMessage(self) -> java.lang.String:
        ...

    @statusMessage.setter
    def statusMessage(self, value: java.lang.String):
        ...



__all__ = ["WizardModel", "WizardStep", "WizardDialog"]
