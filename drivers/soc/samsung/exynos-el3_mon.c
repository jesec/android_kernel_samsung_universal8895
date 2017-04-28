/*
 * Copyright (c) 2015 Samsung Electronics Co., Ltd.
 *	      http://www.samsung.com/
 *
 * EXYNOS - EL3 monitor support
 * Author: Jang Hyunsung <hs79.jang@samsung.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/slab.h>
#include <linux/smc.h>
#include <linux/kallsyms.h>
#include <asm/cacheflush.h>

#include <soc/samsung/exynos-el3_mon.h>

static char *smc_lockup;

static int  __init exynos_set_debug_mem(void)
{
	int ret;
	static char *smc_debug_mem;
	char *phys;

	smc_debug_mem = kmalloc(PAGE_SIZE, GFP_KERNEL);

	if (!smc_debug_mem) {
		pr_err("%s: kmalloc for smc_debug failed.\n", __func__);
		return 0;
	}

	/* to map & flush memory */
	memset(smc_debug_mem, 0x00, PAGE_SIZE);
	__dma_flush_range(smc_debug_mem, smc_debug_mem+PAGE_SIZE);

	phys = (char *)virt_to_phys(smc_debug_mem);
	pr_err("%s: alloc kmem for smc_dbg virt: 0x%p phys: 0x%p size: %ld.\n",
			__func__, smc_debug_mem, phys, PAGE_SIZE);
	ret = exynos_smc(SMC_CMD_SET_DEBUG_MEM, (u64)phys, (u64)PAGE_SIZE, 0);

	/* correct return value is input size */
	if (ret != PAGE_SIZE) {
		pr_err("%s: Can not set the address to el3 monitor. "
				"ret = 0x%x. free the kmem\n", __func__, ret);
		kfree(smc_debug_mem);
	}

	return 0;
}
arch_initcall(exynos_set_debug_mem);

static int  __init exynos_get_reason_mem(void)
{
	smc_lockup = kmalloc(PAGE_SIZE, GFP_KERNEL);

	if (!smc_lockup) {
		pr_err("%s: kmalloc for smc_lockup failed.\n", __func__);
		smc_lockup = NULL;
	}

	return 0;
}
arch_initcall(exynos_get_reason_mem);

struct __exception_info {
	unsigned long exception_type;
	unsigned long sp_el1;
	unsigned long sp_el3;
	unsigned long elr_el3;
	unsigned long esr_el3;
};

struct __lockup_info {
	struct __exception_info exception_info[NR_CPUS];
};

static const char *ename[] = {
	"info38961",
	"sync",
	"irq",
	"fiq",
	"async",
	"stack corruption",
	"unknown"
};

static const char *el_mode[] = {
	"el1 mode",
	"el3 mode"
};

#define EXYNOS_EXCEPTION_FROM_SHIFT			(63)

#define EXYNOS_EXCEPTION_FROM_EL3			(1)
#define EXYNOS_EXCEPTION_FROM_EL1			(0)


static int exynos_parse_reason(struct __lockup_info *ptr)
{
	int i, count, ekind, efrom;
	struct __lockup_info *lockup_info = ptr;
	unsigned long etype, elr_el3, sp_el1, sp_el3, esr_el3;

	for(i = 0, count = 0; i < NR_CPUS; i++) {
		etype = lockup_info->exception_info[i].exception_type;

		if (!etype) {
			/* this core has not got stuck in EL3 monitor */
			continue;
		}

		/* add 1 to count for the core got stuck in EL3 monitor */
		count++;

		/* parsing the information */
		ekind = (etype & 0xf) > 6 ? 6 : (etype & 0xf) - 1;
		efrom = (etype >> EXYNOS_EXCEPTION_FROM_SHIFT) & 0x1;
		elr_el3 = lockup_info->exception_info[i].elr_el3;
		sp_el1 = lockup_info->exception_info[i].sp_el1;
		sp_el3 = lockup_info->exception_info[i].sp_el3;
		esr_el3 = lockup_info->exception_info[i].esr_el3;

		/* it got stuck due to unexpected exception */
		pr_emerg("%s: %dth core gets stuck in EL3 monitor due to " \
			"%s exception from %s.\n", \
			 __func__, i, ename[ekind], el_mode[efrom]);
		pr_emerg("%s: elr 0x%lx sp_el1 0x%lx sp_el3 0x%lx " \
			"esr_el3 0x%lx\n", __func__, elr_el3, sp_el1, \
			sp_el3, esr_el3);
	}

	/* count should be more than '1' */
	return !count;
}

int exynos_check_hardlockup_reason(void)
{
	int ret;
	char *phys;

	if (!smc_lockup) {
		pr_err("%s: fail to alloc memory for storing lockup info.\n",
			__func__);
		return 0;
	}

	/* to map & flush memory */
	memset(smc_lockup, 0x00, PAGE_SIZE);
	__dma_flush_range(smc_lockup, smc_lockup + PAGE_SIZE);

	phys = (char *)virt_to_phys(smc_lockup);
	pr_err("%s: smc_lockup virt: 0x%p phys: 0x%p size: %ld.\n",
			__func__, smc_lockup, phys, PAGE_SIZE);

	ret = exynos_smc(SMC_CMD_GET_LOCKUP_REASON, (u64)phys, (u64)PAGE_SIZE, 0);

	if (ret) {
		pr_emerg("%s: SMC_CMD_GET_LOCKUP_REASON returns 0x%x. fail " \
			"to get the information.\n",  __func__, ret);
		goto check_exit;
	}

	ret = exynos_parse_reason((struct __lockup_info *)smc_lockup);

check_exit:
	return ret;
}

static void exynos_smart_exception_handler(unsigned int id,
				unsigned long elr, unsigned long esr,
				unsigned long sctlr, unsigned long ttbr,
				unsigned long tcr, unsigned long x6)
{
	pr_err("========================================="
		"=========================================\n");

	if (id)
		pr_err("%s: There has been an unexpected exception from "
			"a LDFW which has smc id 0x%x\n\n", __func__, id);
	else
		pr_err("%s: There has been an unexpected exception from "
			"the EL3 monitor.\n\n", __func__);

	if (id) {
		pr_err("elr_el1   : 0x%016lx, \tesr_el1  : 0x%016lx\n",
								elr, esr);
		pr_err("sctlr_el1 : 0x%016lx, \tttbr_el1 : 0x%016lx\n",
								sctlr, ttbr);
		pr_err("tcr_el1   : 0x%016lx, \tlr (EL1) : 0x%016lx\n\n",
								tcr, x6);
	} else {
		pr_err("elr_el3   : 0x%016lx, \tesr_el3  : 0x%016lx\n",
								elr, esr);
		pr_err("sctlr_el3 : 0x%016lx, \tttbr_el3 : 0x%016lx\n",
								sctlr, ttbr);
		pr_err("tcr_el3   : 0x%016lx, \tscr_el3  : 0x%016lx\n\n",
								tcr, x6);
	}

	pr_err("[WARNING] IT'S GOING TO CAUSE KERNEL PANIC FOR DEBUGGING.\n\n");

	pr_err("========================================="
		"=========================================\n");
	/* make kernel panic */
	BUG();

	/* SHOULD NOT be here */
	while(1);
}

static int  __init exynos_set_seh_address(void)
{
	int ret;
	unsigned long addr = (unsigned long)exynos_smart_exception_handler;

	pr_info("%s: send smc call with SMC_CMD_SET_SEH_ADDRESS.\n", __func__);

	ret = exynos_smc(SMC_CMD_SET_SEH_ADDRESS, addr, 0, 0);

	/* return value not zero means failure */
	if (ret)
		pr_err("%s: did not set the seh address to el3 monitor. "
				"ret = 0x%x.\n", __func__, ret);
	else
		pr_err("%s: set the seh address to el3 monitor well.\n",
							__func__);

	return 0;
}
arch_initcall(exynos_set_seh_address);
