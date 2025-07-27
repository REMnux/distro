from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.framework.cmd
import ghidra.program.disassemble
import ghidra.program.model.address
import ghidra.program.model.lang
import ghidra.program.model.listing
import java.lang # type: ignore


class ArmDisassembleCommand(DisassembleCommand):
    """
    Command object for performing Arm/Thumb disassembly
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, startSet: ghidra.program.model.address.AddressSetView, restrictedSet: ghidra.program.model.address.AddressSetView, thumbMode: typing.Union[jpype.JBoolean, bool]):
        """
        Constructor for ArmDisassembleCommand.
        
        :param ghidra.program.model.address.AddressSetView startSet: set of addresses to be the start of a disassembly.  The
        Command object will attempt to start a disassembly at each address in this set.
        :param ghidra.program.model.address.AddressSetView restrictedSet: addresses that can be disassembled.
        a null set implies no restrictions
        :param jpype.JBoolean or bool thumbMode: pass true if the disassembling in Thumb Mode
        """

    @typing.overload
    def __init__(self, start: ghidra.program.model.address.Address, restrictedSet: ghidra.program.model.address.AddressSetView, thumbMode: typing.Union[jpype.JBoolean, bool]):
        """
        Constructor for ArmDisassembleCommand.
        
        :param ghidra.program.model.address.Address start: address to be the start of a disassembly.
        :param ghidra.program.model.address.AddressSetView restrictedSet: addresses that can be disassembled.
        a null set implies no restrictions
        :param jpype.JBoolean or bool thumbMode: pass true if the disassembling in Thumb Mode
        """


class X86_64DisassembleCommand(DisassembleCommand):
    """
    Command object for performing 64-/32-bit x86 disassembly
     
     
    
    This generally only comes up when debugging, since there can be multiple images loaded by an
    x86-64 target. For WoW64, the images may be mixed. Thus, this command allows you to disassemble
    64-bit or 32-bit instructions whenever the language is set to 64-bit x86.
     
     
    
    **WARNING:** If used in static programs, i.e., not debug traces, there are some potential
    remaining issues, particularly dealing with stored context and follow-on disassembly -- typically
    called for by the analyzers. In most cases, this does not matter, since mixed 64- and 32-bit code
    in a single image is likely a niche case and can be handled via careful commands from the user.
    Nevertheless, TODO: Rework x86-64 analyzers to call the correct mode of disassembly.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, startSet: ghidra.program.model.address.AddressSetView, restrictedSet: ghidra.program.model.address.AddressSetView, size32Mode: typing.Union[jpype.JBoolean, bool]):
        """
        Constructor for X86_64DisassembleCommand.
        
        :param ghidra.program.model.address.AddressSetView startSet: set of addresses to be the start of disassembly. The Command object will
                    attempt to start a disassembly at each address in this set.
        :param ghidra.program.model.address.AddressSetView restrictedSet: addresses that can be disassembled. a null set implies no restrictions.
        :param jpype.JBoolean or bool size32Mode: pass true if disassembling in 32-bit compatibility mode, otherwise normal
                    64-bit disassembly will be performed.
        """

    @typing.overload
    def __init__(self, start: ghidra.program.model.address.Address, restrictedSet: ghidra.program.model.address.AddressSetView, size32Mode: typing.Union[jpype.JBoolean, bool]):
        """
        Constructor for X86_64DisassembleCommand.
        
        :param ghidra.program.model.address.Address start: address to be the start of a disassembly.
        :param ghidra.program.model.address.AddressSetView restrictedSet: addresses that can be disassembled. a null set implies no restrictions.
        :param jpype.JBoolean or bool size32Mode: pass true if disassembling in 32-bit compatibility mode, otherwise normal
                    64-bit disassembly will be performed.
        """

    @staticmethod
    def alignSet(alignment: typing.Union[jpype.JInt, int], set: ghidra.program.model.address.AddressSetView) -> ghidra.program.model.address.AddressSet:
        ...


class DisassembleCommand(ghidra.framework.cmd.BackgroundCommand[ghidra.program.model.listing.Program]):
    """
    Command object for performing disassembly
    """

    @typing.type_check_only
    class MyListener(ghidra.program.disassemble.DisassemblerMessageListener):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, start: ghidra.program.model.address.Address, restrictedSet: ghidra.program.model.address.AddressSetView, followFlow: typing.Union[jpype.JBoolean, bool]):
        """
        Constructor for DisassembleCommand.
        
        :param ghidra.program.model.address.Address start: Address to start disassembly.
        :param ghidra.program.model.address.AddressSetView restrictedSet: addresses that can be disassembled. a null set implies no restrictions
        :param jpype.JBoolean or bool followFlow: true means the disassembly should follow flow
        """

    @typing.overload
    def __init__(self, startSet: ghidra.program.model.address.AddressSetView, restrictedSet: ghidra.program.model.address.AddressSetView):
        """
        Constructor for DisassembleCommand.
        
        :param ghidra.program.model.address.AddressSetView startSet: set of addresses to be the start of a disassembly. The Command object will
                    attempt to start a disassembly at each address in this set.
        :param ghidra.program.model.address.AddressSetView restrictedSet: addresses that can be disassembled. a null set implies no restrictions
        """

    @typing.overload
    def __init__(self, startSet: ghidra.program.model.address.AddressSetView, restrictedSet: ghidra.program.model.address.AddressSetView, followFlow: typing.Union[jpype.JBoolean, bool]):
        """
        Constructor for DisassembleCommand.
        
        :param ghidra.program.model.address.AddressSetView startSet: set of addresses to be the start of a disassembly. The Command object will
                    attempt to start a disassembly at each address in this set.
        :param ghidra.program.model.address.AddressSetView restrictedSet: addresses that can be disassembled. a null set implies no restrictions
        :param jpype.JBoolean or bool followFlow: follow all flows within restricted set if true, otherwise limit to using 
        startSet for flows.
        """

    def enableCodeAnalysis(self, enable: typing.Union[jpype.JBoolean, bool]):
        """
        Set code analysis enablement. By default new instructions will be submitted for
        auto-analysis.
        
        :param jpype.JBoolean or bool enable: true if incremental code analysis should be done, else false to prevent this.
        """

    def getDisassembledAddressSet(self) -> ghidra.program.model.address.AddressSet:
        """
        Returns an address set of all instructions that were disassembled.
        
        :return: an address set of all instructions that were disassembled
        :rtype: ghidra.program.model.address.AddressSet
        """

    def setInitialContext(self, initialContextValue: ghidra.program.model.lang.RegisterValue):
        """
        Allows a specified initial context to be used at all start points. This value will take
        precedence when combined with any individual seed context values specified by the
        :meth:`setSeedContext(DisassemblerContextImpl) <.setSeedContext>` method. The defaultSeedContext should remain
        unchanged while disassembler command is actively running.
        
        :param ghidra.program.model.lang.RegisterValue initialContextValue: the initial context value to set or null to clear it
        """

    def setSeedContext(self, seedContext: ghidra.program.disassemble.DisassemblerContextImpl):
        """
        Allows the disassembler context to be seeded for the various disassembly start points which
        may be encountered using the future flow state of the specified seedContext. Any initial
        context set via the :meth:`setInitialContext(RegisterValue) <.setInitialContext>` method will take precedence
        when combined with any seed values. The seedContext should remain unchanged while
        disassembler command is actively running.
        
        :param ghidra.program.disassemble.DisassemblerContextImpl seedContext: seed context or null
        """

    @property
    def disassembledAddressSet(self) -> ghidra.program.model.address.AddressSet:
        ...


class MipsDisassembleCommand(DisassembleCommand):
    """
    Command object for performing Mips disassembly
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, startSet: ghidra.program.model.address.AddressSetView, restrictedSet: ghidra.program.model.address.AddressSetView, mips16Mode: typing.Union[jpype.JBoolean, bool]):
        """
        Constructor for MipsDisassembleCommand.
        
        :param ghidra.program.model.address.AddressSetView startSet: set of addresses to be the start of a disassembly.  The
        Command object will attempt to start a disassembly at each address in this set.
        :param ghidra.program.model.address.AddressSetView restrictedSet: addresses that can be disassembled.
        a null set implies no restrictions
        :param jpype.JBoolean or bool mips16Mode: pass true if the disassembling in mips16e Mode
        """

    @typing.overload
    def __init__(self, start: ghidra.program.model.address.Address, restrictedSet: ghidra.program.model.address.AddressSetView, mips16Mode: typing.Union[jpype.JBoolean, bool]):
        """
        Constructor for MipsDisassembleCommand.
        
        :param ghidra.program.model.address.Address start: address to be the start of a disassembly.
        :param ghidra.program.model.address.AddressSetView restrictedSet: addresses that can be disassembled.
        a null set implies no restrictions
        :param jpype.JBoolean or bool mips16Mode: pass true if the disassembling in mips16e Mode
        """


class PowerPCDisassembleCommand(DisassembleCommand):
    """
    Command object for performing PPC disassembly when VLE instructions are supported.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, startSet: ghidra.program.model.address.AddressSetView, restrictedSet: ghidra.program.model.address.AddressSetView, vleMode: typing.Union[jpype.JBoolean, bool]):
        """
        Constructor for PowerPCDisassembleCommand.
        
        :param ghidra.program.model.address.AddressSetView startSet: set of addresses to be the start of a disassembly.  The
        Command object will attempt to start a disassembly at each address in this set.
        :param ghidra.program.model.address.AddressSetView restrictedSet: addresses that can be disassembled.
        a null set implies no restrictions
        :param jpype.JBoolean or bool vleMode: pass true if the disassembling in PowerISA VLE Mode, otherwise
        normal disassembly will be performed.
        """

    @typing.overload
    def __init__(self, start: ghidra.program.model.address.Address, restrictedSet: ghidra.program.model.address.AddressSetView, vleMode: typing.Union[jpype.JBoolean, bool]):
        """
        Constructor for PowerPCDisassembleCommand.
        
        :param ghidra.program.model.address.Address start: address to be the start of a disassembly.
        :param ghidra.program.model.address.AddressSetView restrictedSet: addresses that can be disassembled.
        a null set implies no restrictions
        :param jpype.JBoolean or bool vleMode: pass true if the disassembling in PowerISA VLE Mode, otherwise
        normal disassembly will be performed.
        """


class ReDisassembleCommand(ghidra.framework.cmd.BackgroundCommand[ghidra.program.model.listing.Program]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, seed: ghidra.program.model.address.Address):
        ...


class Hcs12DisassembleCommand(DisassembleCommand):
    """
    Command object for performing HCS12/XGate disassembly
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, startSet: ghidra.program.model.address.AddressSetView, restrictedSet: ghidra.program.model.address.AddressSetView, xgMode: typing.Union[jpype.JBoolean, bool]):
        """
        Constructor for Hcs12DisassembleCommand.
        
        :param ghidra.program.model.address.AddressSetView startSet: set of addresses to be the start of a disassembly.  The
        Command object will attempt to start a disassembly at each address in this set.
        :param ghidra.program.model.address.AddressSetView restrictedSet: addresses that can be disassembled.
        a null set implies no restrictions
        :param jpype.JBoolean or bool xgMode: pass true if the disassembling in XGATE Mode
        """

    @typing.overload
    def __init__(self, start: ghidra.program.model.address.Address, restrictedSet: ghidra.program.model.address.AddressSetView, xgMode: typing.Union[jpype.JBoolean, bool]):
        """
        Constructor for Hcs12DisassembleCommand.
        
        :param ghidra.program.model.address.Address start: address to be the start of a disassembly.
        :param ghidra.program.model.address.AddressSetView restrictedSet: addresses that can be disassembled.
        a null set implies no restrictions
        :param jpype.JBoolean or bool xgMode: pass true if the disassembling in XGATE Mode
        """


class SetFlowOverrideCmd(ghidra.framework.cmd.BackgroundCommand[ghidra.program.model.listing.Program]):
    """
    Command for setting the fallthrough property on an instruction.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, instAddr: ghidra.program.model.address.Address, flowOverride: ghidra.program.model.listing.FlowOverride):
        """
        Constructs a new command for overriding the flow  semantics of an instruction.
        
        :param ghidra.program.model.address.Address instAddr: the address of the instruction whose flow override is
        to be set.
        :param ghidra.program.model.listing.FlowOverride flowOverride: the type of flow override.
        """

    @typing.overload
    def __init__(self, set: ghidra.program.model.address.AddressSetView, flowOverride: ghidra.program.model.listing.FlowOverride):
        """
        Constructs a new command for overriding the flow  semantics of all instructions
        within the address set.
        
        :param ghidra.program.model.address.AddressSetView set: the address set of the instructions whose flow override is
        to be set.
        :param ghidra.program.model.listing.FlowOverride flowOverride: the type of flow override.
        """



__all__ = ["ArmDisassembleCommand", "X86_64DisassembleCommand", "DisassembleCommand", "MipsDisassembleCommand", "PowerPCDisassembleCommand", "ReDisassembleCommand", "Hcs12DisassembleCommand", "SetFlowOverrideCmd"]
