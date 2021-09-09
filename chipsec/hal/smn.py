#!/usr/bin/python
#CHIPSEC: Platform Security Assessment Framework
#Copyright (c) 2021, Intel Corporation
#
#This program is free software; you can redistribute it and/or
#modify it under the terms of the GNU General Public License
#as published by the Free Software Foundation; Version 2.
#
#This program is distributed in the hope that it will be useful,
#but WITHOUT ANY WARRANTY; without even the implied warranty of
#MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#GNU General Public License for more details.
#
#You should have received a copy of the GNU General Public License
#along with this program; if not, write to the Free Software
#Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
#
#Contact information:
#chipsec@intel.com
#
# Reference:
# SMN registers are not documented publicly by AMD. The best source of information
# is [illumos] implementation:
# https://github.com/illumos/illumos-gate/blob/master/usr/src/uts/intel/io/amdzen/amdzen.c
# The [Linux] implementation is also worth a read:
# https://github.com/torvalds/linux/blob/master/arch/x86/kernel/amd_nb.c

"""
Access to SMN (System Management Network) registers

usage:
    >>> read_SMN_reg(cs, bar_base, 0x0)
    >>> write_SMN_reg(cs, bar_base, 0x0, 0xFFFFFFFF)

    Access MMIO by BAR name:

    >>> read_SMN_BAR_reg(cs, 'SMUTHM', 0x0)
    >>> write_SMN_BAR_reg(cs, 'SMUTHM', 0x0, 0xFFFFFFFF)
    >>> get_SMN_BAR_base_address(cs, 'SMUTHM')
"""

from chipsec.hal import hal_base

# PCI registers in Northbridge (root complex) to perform indirect SMN reads and
# writes.
SMN_PCI_ADDR_REG  = 0x60
SMN_PCI_DATA_REG  = 0x64

class SMN(hal_base.HALBase):

    def __init__(self, cs):
        super(SMN, self).__init__(cs)

    #
    # Read SMN register as an offset off of MMIO range base address
    #
    def read_SMN_reg(self, bar_base, offset, bus=None):
        if bus is None:
            bus = 0
        # Device and function for the northbridge are always zero.
        # The bus can vary in case of multiple nodes.
        self.cs.pci.write_dword(bus, 0, 0, SMN_PCI_ADDR_REG, bar_base + offset)
        reg_value = self.cs.pci.read_dword(bus, 0, 0, SMN_PCI_DATA_REG)
        if self.logger.HAL: self.logger.log('[smn] 0x{:08X} + 0x{:08X} = 0x{:08X}'.format(bar_base, offset, reg_value))
        return reg_value

    #
    # Write SMN register as an offset off of MMIO range base address
    #
    def write_SMN_reg(self, bar_base, offset, value, bus=None):
        if bus is None:
            bus = 0
        if self.logger.HAL: self.logger.log('[smn] write 0x{:08X} + 0x{:08X} = 0x{:08X}'.format(bar_base, offset, value))
        self.cs.pci.write_dword(bus, 0, 0, SMN_PCI_ADDR_REG, bar_base + offset)
        self.cs.pci.write_dword(bus, 0, 0, SMN_PCI_DATA_REG, value)

    #
    # Get base address of MMIO range by MMIO BAR name
    #
    def get_SMN_BAR_base_address(self, bar_name):
        bar = self.cs.Cfg.SMN_BARS[ bar_name ]
        if bar is None or bar == {}: return -1
        if 'fixed_address' not in bar:
            raise Exception
        base = int(bar['fixed_address'], 16)
        if self.logger.HAL: self.logger.log('[smn] {}: 0x{:016X})'.format(bar_name, base))
        return base

    #
    # Read SMN register from SMN range defined by SMN BAR name
    #
    def read_SMN_BAR_reg(self, bar_name, offset, bus=None):
        bar_base = self.get_SMN_BAR_base_address(bar_name)
        return self.read_SMN_reg(bar_base, offset, bus)

    #
    # Write SMN register from SMN range defined by MMIO BAR name
    #
    def write_SMN_BAR_reg(self, bar_name, offset, value, bus=None):
        bar_base = self.get_SMN_BAR_base_address(bar_name)
        return self.write_SMN_reg(bar_base, offset, value, bus)

    # 
    # We do not support deriving the bus from cpu_thread, but it should be
    # possible, see [illumos] in the reference section.
    # For now, always return the bus of the default root complex (we do not
    # really support multi-node configurations for AMD yet).
    #
    def get_bus_from_cpu_thread(self, cpu_thread):
        return self.cs.get_device_bus("ROOT")
