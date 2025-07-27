from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking.action
import docking.widgets.autocomplete
import ghidra
import ghidra.app.plugin
import ghidra.app.plugin.assembler
import ghidra.framework.plugintool
import ghidra.program.model.address
import ghidra.program.model.lang
import ghidra.program.model.listing
import ghidra.util.task
import java.awt # type: ignore
import java.awt.event # type: ignore
import java.lang # type: ignore
import javax.swing # type: ignore


class AssemblyDualTextField(java.lang.Object):
    """
    A pair of text fields suitable for guided assembly
     
     
    
    This object must be updated with program location information, so that it knows the applicable
    language and address. It then provides two text boxes: one for the mnemonic, and one for the
    operands. The two are linked so that the user can intuitively navigate between them as if they
    were a single text box. The boxes are also attached to an autocompleter. It provides suggestions
    based syntax errors returned by the assembler. When a valid instruction is present, it provides
    the resulting instruction bytes.
     
     
    
    To detect when the user has activated an instruction-bytes entry, add an
    :obj:`AutocompletionListener` and check that the selection is an :obj:`AssemblyInstruction`.
    Otherwise, the usual autocompletion behavior is applied automatically.
    """

    class AssemblyCompletion(java.lang.Comparable[AssemblyDualTextField.AssemblyCompletion]):
        """
        A generic class for all items listed by the autocompleter
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, text: typing.Union[java.lang.String, str], display: typing.Union[java.lang.String, str], color: java.awt.Color, order: typing.Union[jpype.JInt, int]):
            ...

        def getCanDefault(self) -> bool:
            """
            Override this to permit activation by default, i.e., on CTRL-SPACE
            
            :return: true to permit defaulting, false to prevent it
            :rtype: bool
            """

        def getColor(self) -> java.awt.Color:
            """
            Get the foreground color for the item
            
            :return: the color
            :rtype: java.awt.Color
            """

        def getDisplay(self) -> str:
            """
            Get the (possibly HTML) text to display for the item
            
            :return: the text
            :rtype: str
            """

        def getText(self) -> str:
            """
            Get the text to insert when the item is activated
            
            :return: the text
            :rtype: str
            """

        @property
        def canDefault(self) -> jpype.JBoolean:
            ...

        @property
        def color(self) -> java.awt.Color:
            ...

        @property
        def display(self) -> java.lang.String:
            ...

        @property
        def text(self) -> java.lang.String:
            ...


    @typing.type_check_only
    class AssemblySuggestion(AssemblyDualTextField.AssemblyCompletion):
        """
        Represents a textual suggestion to complete or partially complete an assembly instruction
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, text: typing.Union[java.lang.String, str], display: typing.Union[java.lang.String, str]):
            ...


    @typing.type_check_only
    class ContextChanges(ghidra.program.model.lang.DisassemblerContextAdapter):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, contextIn: ghidra.program.model.lang.RegisterValue):
            ...

        def addFlow(self, progCtx: ghidra.program.model.listing.ProgramContext, after: ghidra.program.model.address.Address):
            ...


    @typing.type_check_only
    class AssemblyInstruction(AssemblyDualTextField.AssemblyCompletion):
        """
        Represents an encoding for a complete assembly instruction
         
         
        
        These provide no insertion text, since their activation should be handled by a custom
        listener.
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, program: ghidra.program.model.listing.Program, language: ghidra.program.model.lang.Language, at: ghidra.program.model.address.Address, text: typing.Union[java.lang.String, str], data: jpype.JArray[jpype.JByte], ctxVal: ghidra.program.model.lang.RegisterValue, preference: typing.Union[jpype.JInt, int]):
            ...

        def getData(self) -> jpype.JArray[jpype.JByte]:
            """
            Get the assembled instruction bytes
            
            :return: the bytes
            :rtype: jpype.JArray[jpype.JByte]
            """

        @property
        def data(self) -> jpype.JArray[jpype.JByte]:
            ...


    @typing.type_check_only
    class AssemblyError(AssemblyDualTextField.AssemblyCompletion):
        """
        Represents the description of an error encountered during parsing or assembling
         
         
        
        **NOTE:** not used until error descriptions improve
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, text: typing.Union[java.lang.String, str], desc: typing.Union[java.lang.String, str]):
            ...


    @typing.type_check_only
    class AssemblyAutocompletionModel(docking.widgets.autocomplete.AutocompletionModel[AssemblyDualTextField.AssemblyCompletion]):
        """
        A model that just delegates to our completion function
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class AssemblyAutocompleter(docking.widgets.autocomplete.TextFieldAutocompleter[AssemblyDualTextField.AssemblyCompletion], docking.widgets.autocomplete.AutocompletionListener[AssemblyDualTextField.AssemblyCompletion]):
        """
        A customized autocompleter for assembly
         
         
        
        This positions the list at the bottom left of the field(s), and considers the full text of
        the linked text boxes when retrieving the prefix. It also delegates the item styling to the
        item instances.
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, model: docking.widgets.autocomplete.AutocompletionModel[AssemblyDualTextField.AssemblyCompletion]):
            ...


    @typing.type_check_only
    class EnterKeyListener(java.awt.event.KeyListener):
        """
        A listener which activates the autocompleter on ENTER (in addition to the default
        CTRL-SPACE).
         
         
        
        Because the user must activate an entry to specify the desired assembly, we make ENTER pull
        up the list, hinting that the user must make a selection.
        """

        class_: typing.ClassVar[java.lang.Class]


    class VisibilityMode(java.lang.Enum[AssemblyDualTextField.VisibilityMode]):
        """
        An enum type to specify which variant of the assembly input is shown.
        """

        class_: typing.ClassVar[java.lang.Class]
        INVISIBLE: typing.Final[AssemblyDualTextField.VisibilityMode]
        """
        Hide both variants. Nothing is shown.
        """

        DUAL_VISIBLE: typing.Final[AssemblyDualTextField.VisibilityMode]
        """
        Show the dual-box linked variant, suitable when the current instruction has operands.
        """

        SINGLE_VISIBLE: typing.Final[AssemblyDualTextField.VisibilityMode]
        """
        Show the single-box unlinked variant, suitable when the current instruction has no
        operands.
        """


        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> AssemblyDualTextField.VisibilityMode:
            ...

        @staticmethod
        def values() -> jpype.JArray[AssemblyDualTextField.VisibilityMode]:
            ...


    class AssemblyDualTextFieldDemo(ghidra.GhidraLaunchable):
        """
        A demonstration of the assembly GUI outside of Ghidra
        """

        class_: typing.ClassVar[java.lang.Class]
        DEMO_LANG_ID: typing.Final[ghidra.program.model.lang.LanguageID]
        ADDR_FORMAT: typing.Final = "@%08x:"

        def __init__(self):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        """
        Construct the assembly text fields
        """

    def addFocusListener(self, listener: java.awt.event.FocusListener):
        """
        Add a focus listener to the box(es)
         
         
        
        **NOTE:** The listener will not fire when focus passes among the linked boxes of the dual
        variant.
        
        :param java.awt.event.FocusListener listener: the listener
        """

    def addKeyListener(self, listener: java.awt.event.KeyListener):
        """
        Add a key listener to the box(es)
        
        :param java.awt.event.KeyListener listener: the listener
        """

    def clear(self):
        """
        Clear all text boxes
        """

    def getAssemblyField(self) -> javax.swing.JTextField:
        """
        For single mode: Get the text field containing the full assembly text
        
        :return: the text field
        :rtype: javax.swing.JTextField
        """

    def getAutocompleter(self) -> docking.widgets.autocomplete.TextFieldAutocompleter[AssemblyDualTextField.AssemblyCompletion]:
        """
        Get a reference to the autocompleter
         
         
        
        This is useful for adding the custom listener needed to detect activation of assembled
        instruction entries.
        
        :return: the autocompleter
        :rtype: docking.widgets.autocomplete.TextFieldAutocompleter[AssemblyDualTextField.AssemblyCompletion]
        """

    def getMnemonicField(self) -> javax.swing.JTextField:
        """
        For dual mode: Get the text field containing the mnemonic portion of the assembly
        
        :return: the text field
        :rtype: javax.swing.JTextField
        """

    def getOperandsField(self) -> javax.swing.JTextField:
        """
        For dual mode: Get the text field containing the operands portion of the assembly
        
        :return: the text field
        :rtype: javax.swing.JTextField
        """

    def getText(self) -> str:
        """
        Get the full assembly text
        
        :return: the text
        :rtype: str
        """

    def getVisible(self) -> AssemblyDualTextField.VisibilityMode:
        """
        Get the visibility of the text box(es)
         
         
        
        **NOTE:** This method assumes nothing else changes the visibility of the text boxes. If
        anything else does, then it should be sure to maintain a configuration consistent with one of
        the :obj:`VisibilityMode`s.
        
        :return: the current mode
        :rtype: AssemblyDualTextField.VisibilityMode
        """

    def setAddress(self, address: ghidra.program.model.address.Address):
        """
        Set the address of the assembly instruction
         
         
        
        Note this will reset the existing instruction to null to prevent its accidental re-use. See
        :meth:`setExisting(Instruction) <.setExisting>`.
        
        :param ghidra.program.model.address.Address address: the address
        """

    def setAssembler(self, assembler: ghidra.app.plugin.assembler.Assembler):
        """
        Set the assembler to use
        
        :param ghidra.app.plugin.assembler.Assembler assembler: the assembler
        """

    def setCaretPosition(self, pos: typing.Union[jpype.JInt, int]):
        """
        Set the caret position of the visible field(s)
        
        :param jpype.JInt or int pos: the position
        """

    def setExisting(self, existing: ghidra.program.model.listing.Instruction):
        """
        Set the "existing" instruction used for ordering proposed instructions by "most similar"
        
        :param ghidra.program.model.listing.Instruction existing: the existing instruction
        
        .. seealso::
        
            | :obj:`.computePreference(AssemblyResolvedPatterns)`
        """

    def setFont(self, font: java.awt.Font):
        """
        Set the font for all text fields
        
        :param java.awt.Font font: the new font
        """

    def setText(self, text: typing.Union[java.lang.String, str]):
        """
        Set the text of the visible field(s)
        
        :param java.lang.String or str text: the text
        """

    def setVisible(self, visibility: AssemblyDualTextField.VisibilityMode):
        """
        Set the visibility of the text box(es)
        
        :param AssemblyDualTextField.VisibilityMode visibility: the :obj:`VisibilityMode` to set.
        """

    @property
    def assemblyField(self) -> javax.swing.JTextField:
        ...

    @property
    def visible(self) -> AssemblyDualTextField.VisibilityMode:
        ...

    @visible.setter
    def visible(self, value: AssemblyDualTextField.VisibilityMode):
        ...

    @property
    def autocompleter(self) -> docking.widgets.autocomplete.TextFieldAutocompleter[AssemblyDualTextField.AssemblyCompletion]:
        ...

    @property
    def text(self) -> java.lang.String:
        ...

    @text.setter
    def text(self, value: java.lang.String):
        ...

    @property
    def mnemonicField(self) -> javax.swing.JTextField:
        ...

    @property
    def operandsField(self) -> javax.swing.JTextField:
        ...


class AssemblerPlugin(ghidra.app.plugin.ProgramPlugin):
    """
    A plugin for assembly
     
     
    
    This plugin currently provides two actions: :obj:`PatchInstructionAction`, which allows the user
    to assemble an instruction at the current address; and :obj:`PatchDataAction`, which allows the
    user to "assemble" data at the current address.
     
     
    
    The API for instruction assembly is available from :obj:`Assemblers`. For data assembly, the API
    is in :meth:`DataType.encodeRepresentation(String, MemBuffer, Settings, int) <DataType.encodeRepresentation>`.
    """

    class_: typing.ClassVar[java.lang.Class]
    ASSEMBLER_NAME: typing.Final = "Assembler"

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...


class PatchInstructionAction(AbstractPatchAction):
    """
    A context menu action to assemble an instruction at the current address
    """

    @typing.type_check_only
    class AssemblyRating(java.lang.Enum[PatchInstructionAction.AssemblyRating]):
        """
        Enumerated quality ratings and text to describe them.
        """

        class_: typing.ClassVar[java.lang.Class]
        UNRATED: typing.Final[PatchInstructionAction.AssemblyRating]
        POOR: typing.Final[PatchInstructionAction.AssemblyRating]
        BRONZE: typing.Final[PatchInstructionAction.AssemblyRating]
        SILVER: typing.Final[PatchInstructionAction.AssemblyRating]
        GOLD: typing.Final[PatchInstructionAction.AssemblyRating]
        PLATINUM: typing.Final[PatchInstructionAction.AssemblyRating]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> PatchInstructionAction.AssemblyRating:
            ...

        @staticmethod
        def values() -> jpype.JArray[PatchInstructionAction.AssemblyRating]:
            ...


    @typing.type_check_only
    class AssemblerConstructorWorker(ghidra.util.task.CachingSwingWorker[ghidra.app.plugin.assembler.Assembler]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, language: ghidra.program.model.lang.Language):
            ...


    @typing.type_check_only
    class ListenerForAccept(docking.widgets.autocomplete.AutocompletionListener[AssemblyDualTextField.AssemblyCompletion]):
        """
        A listener for activation of a completion item
        
         
        
        The :meth:`AbstractPatchAction.accept() <AbstractPatchAction.accept>` method does not suffice for this action, since one
        of the suggested byte sequences must be selected, as presented by the completer. Thus, we'll
        nop that method, and instead call our own acceptance logic from here.
        """

        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, owner: ghidra.framework.plugintool.Plugin):
        ...

    @typing.overload
    def __init__(self, owner: ghidra.framework.plugintool.Plugin, name: typing.Union[java.lang.String, str]):
        ...

    def accept(self, ins: AssemblyDualTextField.AssemblyInstruction):
        """
        Accept the given instruction selected by the user
        
        :param AssemblyDualTextField.AssemblyInstruction ins: the selected instruction from the completion list
        """


class AbstractPatchAction(docking.action.DockingAction):
    """
    An abstract action for patching
    
     
    
    This handles most of the field placement, but relies on quite a few callbacks.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, owner: ghidra.framework.plugintool.Plugin, name: typing.Union[java.lang.String, str]):
        """
        Create a new action owned by the given plugin, having the given name
        
        :param ghidra.framework.plugintool.Plugin owner: the plugin owning the action
        :param java.lang.String or str name: the name of the action
        """

    def accept(self):
        """
        Invoked when the user presses Enter
        
         
        
        This should validate the user's input and complete the action. If the action is completed
        successfully, then call :meth:`hide() <.hide>`. Note that the Enter key can be ignored by doing
        nothing, since the input field(s) will remain visible. In that case, you must provide another
        mechanism for completing the action.
        """

    def cancel(self):
        """
        Cancel the current patch action
        
         
        
        This hides the input field(s) without completing the action.
        """


class PatchDataAction(AbstractPatchAction):
    """
    A context menu action to patch data at the current address
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, owner: ghidra.framework.plugintool.Plugin):
        ...

    @typing.overload
    def __init__(self, owner: ghidra.framework.plugintool.Plugin, name: typing.Union[java.lang.String, str]):
        ...



__all__ = ["AssemblyDualTextField", "AssemblerPlugin", "PatchInstructionAction", "AbstractPatchAction", "PatchDataAction"]
