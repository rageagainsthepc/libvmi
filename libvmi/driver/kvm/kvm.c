/* The LibVMI Library is an introspection library that simplifies access to
 * memory in a target virtual machine or in a file containing a dump of
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * Copyright 2011 Sandia Corporation. Under the terms of Contract
 * DE-AC04-94AL85000 with Sandia Corporation, the U.S. Government
 * retains certain rights in this software.
 *
 * Author: Bryan D. Payne (bdpayne@acm.org)
 * Author: Tamas K Lengyel (tamas.lengyel@zentific.com)
 *
 * This file is part of LibVMI.
 *
 * LibVMI is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 *
 * LibVMI is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
 * License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with LibVMI.  If not, see <http://www.gnu.org/licenses/>.
 */

#define _GNU_SOURCE
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <libmicrovmi.h>
#include "private.h"
#include "driver/memory_cache.h"
#include "driver/kvm/kvm_private.h"

void *
kvm_get_memory(
    vmi_instance_t vmi,
    addr_t paddr,
    uint32_t UNUSED(length))
{
    uint8_t * page_buffer = g_try_malloc0(vmi->page_size);
    if (!page_buffer)
    {
        return NULL;
    }

    // We are assuming an aligned address
    MicrovmiStatus status = microvmi_read_physical(kvm_get_instance(vmi)->microvmi_context, paddr, page_buffer,
                                                   vmi->page_size);
    if (status != MicrovmiSuccess)
    {
        g_free(page_buffer);
        return NULL;
    }

    return (void*) page_buffer;
}

void
kvm_release_memory(
    vmi_instance_t UNUSED(vmi),
    void *memory,
    size_t UNUSED(length))
{
    if (memory)
    {
        g_free(memory);
    }
}

status_t
kvm_init(
    vmi_instance_t vmi,
    uint32_t init_flags,
    vmi_init_data_t* UNUSED(init_data))
{
    if ((init_flags & VMI_INIT_DOMAINNAME) == 0)
    {
        errprint("%s: Currently only initialization by domain name is allowed.\n", __FUNCTION__);
        return VMI_FAILURE;
    }

    if (kvm_get_instance(vmi))
    {
        return VMI_SUCCESS;
    }

    kvm_instance_t *kvm = g_try_malloc0(sizeof(kvm_instance_t));

    // Since there is no general initialization vor libmicrovmi we cannot probe anything here.

    vmi->driver.driver_data = (void*) kvm;
    return VMI_SUCCESS;
}

status_t
kvm_setup_live_mode(vmi_instance_t vmi)
{
    dbprint(VMI_DEBUG_KVM, "--kvm: setup live mode\n");
    memory_cache_destroy(vmi);
    memory_cache_init(vmi, kvm_get_memory, kvm_release_memory, 1);
    return VMI_SUCCESS;
}

status_t
kvm_init_vmi(
    vmi_instance_t vmi,
    uint32_t UNUSED(init_flags),
    vmi_init_data_t* UNUSED(init_data))
{
    kvm_setup_live_mode(vmi);
    kvm_instance_t* kvm = kvm_get_instance(vmi);
    DriverType driver_type = KVM;
    kvm->microvmi_context = microvmi_init(kvm->name, &driver_type);

    return VMI_SUCCESS;
}

void
kvm_destroy(
    vmi_instance_t vmi)
{
    kvm_instance_t *kvm = kvm_get_instance(vmi);

    if (kvm->microvmi_context)
    {
        microvmi_destroy(kvm->microvmi_context);
    }

    free(kvm->name);
    g_free(kvm);
}

uint64_t
kvm_get_id_from_name(
    vmi_instance_t UNUSED(vmi),
    const char* UNUSED(name))
{
    // TODO: Return a valid domain id.
    return 0;
}

status_t
kvm_get_name_from_id(
    vmi_instance_t UNUSED(vmi),
    uint64_t UNUSED(domainid),
    char** UNUSED(name))
{
    return VMI_FAILURE;
}

uint64_t
kvm_get_id(
    vmi_instance_t vmi)
{
    return kvm_get_instance(vmi)->id;
}

void
kvm_set_id(
    vmi_instance_t vmi,
    uint64_t domainid)
{
    kvm_get_instance(vmi)->id = domainid;
}

status_t
kvm_check_id(
    vmi_instance_t UNUSED(vmi),
    uint64_t UNUSED(domainid))
{
    return VMI_SUCCESS;
}

status_t
kvm_get_name(
    vmi_instance_t vmi,
    char **name)
{
    kvm_instance_t *kvm = kvm_get_instance(vmi);
    *name = kvm->name;
    return VMI_SUCCESS;
}

void
kvm_set_name(
    vmi_instance_t vmi,
    const char *name)
{
    kvm_get_instance(vmi)->name = strndup(name, 500);
}

status_t
kvm_get_memsize(
    vmi_instance_t vmi,
    uint64_t *allocated_ram_size,
    addr_t *maximum_physical_address)
{
    kvm_instance_t *kvm = kvm_get_instance(vmi);

    // There is no call to get this value in libmicrovmi yet
    *allocated_ram_size = 0;
    if (microvmi_get_max_physical_addr(kvm->microvmi_context, maximum_physical_address) != MicrovmiSuccess)
    {
        return VMI_FAILURE;
    }
    return VMI_SUCCESS;
}

status_t
kvm_get_vcpureg(
    vmi_instance_t vmi,
    uint64_t *value,
    reg_t reg,
    unsigned long vcpu)
{
    kvm_instance_t *kvm = kvm_get_instance(vmi);

    Registers microvmi_regs = { 0 };
    if (microvmi_read_registers(kvm->microvmi_context, vcpu, &microvmi_regs) != MicrovmiSuccess)
    {
        return VMI_FAILURE;
    }

    status_t ret = VMI_SUCCESS;
    switch (reg)
    {
        case RAX:
            *value = microvmi_regs.x86._0.rax;
            break;
        case RBX:
            *value = microvmi_regs.x86._0.rbx;
            break;
        case RCX:
            *value = microvmi_regs.x86._0.rcx;
            break;
        case RDX:
            *value = microvmi_regs.x86._0.rdx;
            break;
        case RBP:
            *value = microvmi_regs.x86._0.rbp;
            break;
        case RSI:
            *value = microvmi_regs.x86._0.rsi;
            break;
        case RDI:
            *value = microvmi_regs.x86._0.rdi;
            break;
        case RSP:
            *value = microvmi_regs.x86._0.rsp;
            break;
        case R8:
            *value = microvmi_regs.x86._0.r8;
            break;
        case R9:
            *value = microvmi_regs.x86._0.r9;
            break;
        case R10:
            *value = microvmi_regs.x86._0.r10;
            break;
        case R11:
            *value = microvmi_regs.x86._0.r11;
            break;
        case R12:
            *value = microvmi_regs.x86._0.r12;
            break;
        case R13:
            *value = microvmi_regs.x86._0.r13;
            break;
        case R14:
            *value = microvmi_regs.x86._0.r14;
            break;
        case R15:
            *value = microvmi_regs.x86._0.r15;
            break;
        case RIP:
            *value = microvmi_regs.x86._0.rip;
            break;
        case RFLAGS:
            *value = microvmi_regs.x86._0.rflags;
            break;
        default:
            ret = VMI_FAILURE;
            break;
    }

    return ret;
}

void *
kvm_read_page(
    vmi_instance_t vmi,
    addr_t page)
{
    addr_t paddr = page << vmi->page_shift;

    return memory_cache_insert(vmi, paddr);
}

status_t
kvm_write(
    vmi_instance_t UNUSED(vmi),
    addr_t UNUSED(paddr),
    void* UNUSED(buf),
    uint32_t UNUSED(length))
{
    return VMI_FAILURE;
}

int
kvm_is_pv(
    vmi_instance_t UNUSED(vmi))
{
    return 0;
}

status_t
kvm_test(
    uint64_t UNUSED(domainid),
    const char *name,
    uint64_t init_flags,
    vmi_init_data_t* UNUSED(init_data))
{
    if ((init_flags & VMI_INIT_DOMAINNAME) == 0 )
    {
        errprint("%s: Currently only initialization by domain name is allowed.\n", __FUNCTION__);
        return VMI_FAILURE;
    }

    DriverType driver_type = KVM;
    MicrovmiContext* driver = microvmi_init(name, &driver_type);
    if (!driver)
    {
        return VMI_FAILURE;
    }
    microvmi_destroy(driver);

    return VMI_SUCCESS;
}

status_t
kvm_pause_vm(
    vmi_instance_t vmi)
{
    kvm_instance_t *kvm = kvm_get_instance(vmi);

    if (microvmi_pause(kvm->microvmi_context) != MicrovmiSuccess)
    {
        return VMI_FAILURE;
    }
    return VMI_SUCCESS;
}

status_t
kvm_resume_vm(
    vmi_instance_t vmi)
{
    kvm_instance_t *kvm = kvm_get_instance(vmi);

    if (microvmi_resume(kvm->microvmi_context) != MicrovmiSuccess)
    {
        return VMI_FAILURE;
    }
    return VMI_SUCCESS;
}
