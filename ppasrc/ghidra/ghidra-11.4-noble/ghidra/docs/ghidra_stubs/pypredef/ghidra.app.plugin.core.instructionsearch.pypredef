from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.plugin
import ghidra.app.plugin.core.instructionsearch.model
import ghidra.app.plugin.core.instructionsearch.ui
import ghidra.framework.plugintool
import ghidra.program.model.address
import ghidra.program.model.listing
import ghidra.program.util
import java.lang # type: ignore
import java.util # type: ignore


class InstructionSearchPlugin(ghidra.app.plugin.ProgramPlugin):
    """
    Plugin allowing users to construct search criteria based on a set of selected
    instructions.
     
    Note: There's a bug here that is supposed to be fixed under JIRA ticket
    #2024. When a user switches programs we need to clear out the current
    instructions in the GUI; this works fine. However, if the user then hits the
    refresh button to load any selected instructions in the new program, nothing
    will be loaded because no selection event was generated on the program
    activation. This problem will be resolved when that bug is fixed.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        """
        Constructor.
        
        :param ghidra.framework.plugintool.PluginTool tool: the plugin tool
        """

    def getSearchDialog(self) -> ghidra.app.plugin.core.instructionsearch.ui.InstructionSearchDialog:
        ...

    def isSelectionValid(self, selection: ghidra.program.util.ProgramSelection, dialog: ghidra.app.plugin.core.instructionsearch.ui.InstructionSearchDialog) -> bool:
        """
        Checks the selection made by the user to make sure it is within
        acceptable bounds regarding size and number of ranges.
        
        :param ghidra.program.util.ProgramSelection selection: the user selection
        :param ghidra.app.plugin.core.instructionsearch.ui.InstructionSearchDialog dialog: the parent dialog
        :return: true if the selection is valid
        :rtype: bool
        """

    @property
    def searchDialog(self) -> ghidra.app.plugin.core.instructionsearch.ui.InstructionSearchDialog:
        ...


class InstructionSearchApi(java.lang.Object):
    """
    API for users who wish to perform instruction searching without the GUI. 
     
    Limitations:    
            1) Searches may only be performed on a single program.
            2) Only a single address range may be searched for.
     
    Results:
            Can be returned in 2 ways: 
                1) As a list of addresses representing the location of search matches.
                2) As a string (either binary or hex) representing the search string to be used.
            The latter results option is useful if using another tool to perform the search (ie yara).
     
    Extending:
            This class may be extended to provide an api for specific searching formats.  There is
            currently an extension for Yara: :obj:`InstructionSearchApi_Yara`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @typing.overload
    def getBinarySearchString(self, program: ghidra.program.model.listing.Program, addressRange: ghidra.program.model.address.AddressRange) -> str:
        """
        Returns a binary string representing the bytes in the address range provided.
        
        :param ghidra.program.model.listing.Program program: 
        :param ghidra.program.model.address.AddressRange addressRange: 
        :return: 
        :rtype: str
        :raises InvalidInputException:
        """

    @typing.overload
    def getBinarySearchString(self, program: ghidra.program.model.listing.Program, addressRange: ghidra.program.model.address.AddressRange, maskSettings: ghidra.app.plugin.core.instructionsearch.model.MaskSettings) -> str:
        """
        Returns a binary string representing the bytes in the address range provided, with masked 
        bits set according to the given :obj:`MaskSettings` object.
         
        Note: Masked bits will be represented by a '.' character.
        
        :param ghidra.app.plugin.core.instructionsearch.model.MaskSettings maskSettings: 
        :param ghidra.program.model.address.AddressRange addressRange: 
        :param ghidra.app.plugin.core.instructionsearch.model.MaskSettings maskSettings: 
        :return: 
        :rtype: str
        :raises InvalidInputException:
        """

    @typing.overload
    def getHexSearchString(self, program: ghidra.program.model.listing.Program, addressRange: ghidra.program.model.address.AddressRange) -> str:
        """
        Returns a hex version of the bytes representing the address range given.
        
        :param ghidra.program.model.listing.Program program: 
        :param ghidra.program.model.address.AddressRange addressRange: 
        :return: 
        :rtype: str
        :raises InvalidInputException:
        """

    @typing.overload
    def getHexSearchString(self, program: ghidra.program.model.listing.Program, addressRange: ghidra.program.model.address.AddressRange, maskSettings: ghidra.app.plugin.core.instructionsearch.model.MaskSettings) -> str:
        """
        Returns a hex version of the bytes representing the address range given.
        
        :param ghidra.program.model.listing.Program program: 
        :param ghidra.program.model.address.AddressRange addressRange: 
        :param ghidra.app.plugin.core.instructionsearch.model.MaskSettings maskSettings: 
        :return: 
        :rtype: str
        :raises InvalidInputException:
        """

    @typing.overload
    def loadInstructions(self, addresses: ghidra.program.model.address.AddressSet, tool: ghidra.framework.plugintool.PluginTool):
        """
        Opens the search dialog and populates it with instructions located in the
        address range given. A program must be loaded in Ghidra for this to work, as determining 
        the instructions would be impossible otherwise.
        
        :param ghidra.program.model.address.AddressSet addresses: the addresses to load
        :param ghidra.framework.plugintool.PluginTool tool: the current plugin tool
        """

    @typing.overload
    def loadInstructions(self, bytes: typing.Union[java.lang.String, str], tool: ghidra.framework.plugintool.PluginTool):
        """
        Opens the search dialog and populates it with instructions represented by the
        bytes given. A program must be loaded in Ghidra for this to work, as determining the 
        instructions would be impossible otherwise.
        
        :param java.lang.String or str bytes: binary or hex string representing the bytes to be loaded
        """

    @typing.overload
    def search(self, program: ghidra.program.model.listing.Program, addressRange: ghidra.program.model.address.AddressRange) -> java.util.List[ghidra.program.model.address.Address]:
        """
        Searches the given program for the instructions specified by the given address range.  No 
        filtering of results is performed; all matches regardless of operand type will be 
        returned.
        
        :param ghidra.program.model.listing.Program program: 
        :param ghidra.program.model.address.AddressRange addressRange: 
        :return: a list of addresses indicating starting positions of matches.
        :rtype: java.util.List[ghidra.program.model.address.Address]
        :raises InvalidInputException:
        """

    @typing.overload
    def search(self, program: ghidra.program.model.listing.Program, addressRange: ghidra.program.model.address.AddressRange, maskSettings: ghidra.app.plugin.core.instructionsearch.model.MaskSettings) -> java.util.List[ghidra.program.model.address.Address]:
        """
        Searches the given program for the instructions specified by the given address range, with
        masking set according to the given :obj:`MaskSettings` object
        
        :param ghidra.program.model.listing.Program program: 
        :param ghidra.program.model.address.AddressRange addressRange: 
        :param ghidra.app.plugin.core.instructionsearch.model.MaskSettings maskSettings: 
        :return: a list of addresses indicating starting positions of matches.
        :rtype: java.util.List[ghidra.program.model.address.Address]
        :raises InvalidInputException:
        """



__all__ = ["InstructionSearchPlugin", "InstructionSearchApi"]
