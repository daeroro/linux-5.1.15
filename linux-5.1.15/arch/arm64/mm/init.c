/*
 * Based on arch/arm/mm/init.c
 *
 * Copyright (C) 1995-2005 Russell King
 * Copyright (C) 2012 ARM Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <linux/kernel.h>
#include <linux/export.h>
#include <linux/errno.h>
#include <linux/swap.h>
#include <linux/init.h>
#include <linux/cache.h>
#include <linux/mman.h>
#include <linux/nodemask.h>
#include <linux/initrd.h>
#include <linux/gfp.h>
#include <linux/memblock.h>
#include <linux/sort.h>
#include <linux/of.h>
#include <linux/of_fdt.h>
#include <linux/dma-mapping.h>
#include <linux/dma-contiguous.h>
#include <linux/efi.h>
#include <linux/swiotlb.h>
#include <linux/vmalloc.h>
#include <linux/mm.h>
#include <linux/kexec.h>
#include <linux/crash_dump.h>

#include <asm/boot.h>
#include <asm/fixmap.h>
#include <asm/kasan.h>
#include <asm/kernel-pgtable.h>
#include <asm/memory.h>
#include <asm/numa.h>
#include <asm/sections.h>
#include <asm/setup.h>
#include <asm/sizes.h>
#include <asm/tlb.h>
#include <asm/alternative.h>

/*
 * We need to be able to catch inadvertent references to memstart_addr
 * that occur (potentially in generic code) before arm64_memblock_init()
 * executes, which assigns it its actual value. So use a default value
 * that cannot be mistaken for a real physical address.
 */
s64 memstart_addr __ro_after_init = -1;
EXPORT_SYMBOL(memstart_addr);

phys_addr_t arm64_dma_phys_limit __ro_after_init;

#ifdef CONFIG_KEXEC_CORE
/*
 * reserve_crashkernel() - reserves memory for crash kernel
 *
 * This function reserves memory area given in "crashkernel=" kernel command
 * line parameter. The memory reserved is used by dump capture kernel when
 * primary kernel is crashing.
 */
static void __init reserve_crashkernel(void)
{
	unsigned long long crash_base, crash_size;
	int ret;

	/*
		"crashkernel="커널 파라메터를 파싱하여
		crash_size와 crash_base를 알아온다.
	*/
	ret = parse_crashkernel(boot_command_line, memblock_phys_mem_size(),
				&crash_size, &crash_base);
	/* no crashkernel= or invalid value specified */
	/*
		parse_crashkernel()이 정상적으로 값을 읽어오지 않았거나,
		crash_size가 0이면 return
	*/
	if (ret || !crash_size)
		return;

	/*
	   	crash_size를 PAGE_SIZE에 맞춰 올림
	*/
	crash_size = PAGE_ALIGN(crash_size);

	// 파싱한 crash_base가 0일 때
	if (crash_base == 0) {
		/* Current arm64 boot protocol requires 2MB alignment */
		/*
			0~ARCH_LOW_ADDRESS_LIMIT 범위에서 SZ_2M로 정렬된 crash_size 사이즈가 있으면
			crash_base에 시작 주소를 갱신
		*/
		crash_base = memblock_find_in_range(0, ARCH_LOW_ADDRESS_LIMIT,
				crash_size, SZ_2M);

		if (crash_base == 0) {
			pr_warn("cannot allocate crashkernel (size:0x%llx)\n",
				crash_size);
			return;
		}
	// 파싱한 crash_base가 0이 아닐 때
	} else {
		/* User specifies base address explicitly. */
		/*
			crash_base에서 crash_size만큼의 크기가 memory region에 속하는지 확인
		*/
		if (!memblock_is_region_memory(crash_base, crash_size)) {
			pr_warn("cannot reserve crashkernel: region is not memory\n");
			return;
		}

		// crash_base에서 crash_size만큼의 크기가 reserve영역과 겹치는 지 확인
		if (memblock_is_region_reserved(crash_base, crash_size)) {
			pr_warn("cannot reserve crashkernel: region overlaps reserved memory\n");
			return;
		}

		// crash_base가 SZ_2M 단위로 정렬되어 있는지 확인
		if (!IS_ALIGNED(crash_base, SZ_2M)) {
			pr_warn("cannot reserve crashkernel: base address is not 2MB aligned\n");
			return;
		}
	}
	/*
		crash_base부터 crash_size만큼의 크기를 memblock에 삽입
	*/
	memblock_reserve(crash_base, crash_size);

	pr_info("crashkernel reserved: 0x%016llx - 0x%016llx (%lld MB)\n",
		crash_base, crash_base + crash_size, crash_size >> 20);

	/*
		struct resource 구조체인 crash_res의 start, end를 갱신
	*/
	crashk_res.start = crash_base;
	crashk_res.end = crash_base + crash_size - 1;
}
#else
static void __init reserve_crashkernel(void)
{
}
#endif /* CONFIG_KEXEC_CORE */

#ifdef CONFIG_CRASH_DUMP
static int __init early_init_dt_scan_elfcorehdr(unsigned long node,
		const char *uname, int depth, void *data)
{
	const __be32 *reg;
	int len;

	if (depth != 1 || strcmp(uname, "chosen") != 0)
		return 0;

	reg = of_get_flat_dt_prop(node, "linux,elfcorehdr", &len);
	if (!reg || (len < (dt_root_addr_cells + dt_root_size_cells)))
		return 1;

	elfcorehdr_addr = dt_mem_next_cell(dt_root_addr_cells, &reg);
	elfcorehdr_size = dt_mem_next_cell(dt_root_size_cells, &reg);

	return 1;
}

/*
 * reserve_elfcorehdr() - reserves memory for elf core header
 *
 * This function reserves the memory occupied by an elf core header
 * described in the device tree. This region contains all the
 * information about primary kernel's core image and is used by a dump
 * capture kernel to access the system memory on primary kernel.
 */
static void __init reserve_elfcorehdr(void)
{
	of_scan_flat_dt(early_init_dt_scan_elfcorehdr, NULL);

	if (!elfcorehdr_size)
		return;

	if (memblock_is_region_reserved(elfcorehdr_addr, elfcorehdr_size)) {
		pr_warn("elfcorehdr is overlapped\n");
		return;
	}

	memblock_reserve(elfcorehdr_addr, elfcorehdr_size);

	pr_info("Reserving %lldKB of memory at 0x%llx for elfcorehdr\n",
		elfcorehdr_size >> 10, elfcorehdr_addr);
}
#else
static void __init reserve_elfcorehdr(void)
{
}
#endif /* CONFIG_CRASH_DUMP */
/*
 * Return the maximum physical address for ZONE_DMA32 (DMA_BIT_MASK(32)). It
 * currently assumes that for memory starting above 4G, 32-bit devices will
 * use a DMA offset.
 */
static phys_addr_t __init max_zone_dma_phys(void)
{
	phys_addr_t offset = memblock_start_of_DRAM() & GENMASK_ULL(63, 32);
	return min(offset + (1ULL << 32), memblock_end_of_DRAM());
}

#ifdef CONFIG_NUMA

static void __init zone_sizes_init(unsigned long min, unsigned long max)
{
	unsigned long max_zone_pfns[MAX_NR_ZONES]  = {0};

	if (IS_ENABLED(CONFIG_ZONE_DMA32))
		max_zone_pfns[ZONE_DMA32] = PFN_DOWN(max_zone_dma_phys());
	max_zone_pfns[ZONE_NORMAL] = max;

	free_area_init_nodes(max_zone_pfns);
}

#else

static void __init zone_sizes_init(unsigned long min, unsigned long max)
{
	struct memblock_region *reg;
	unsigned long zone_size[MAX_NR_ZONES], zhole_size[MAX_NR_ZONES];
	unsigned long max_dma = min;

	memset(zone_size, 0, sizeof(zone_size));

	/* 4GB maximum for 32-bit only capable devices */
#ifdef CONFIG_ZONE_DMA32
	max_dma = PFN_DOWN(arm64_dma_phys_limit);
	zone_size[ZONE_DMA32] = max_dma - min;
#endif
	zone_size[ZONE_NORMAL] = max - max_dma;

	memcpy(zhole_size, zone_size, sizeof(zhole_size));

	for_each_memblock(memory, reg) {
		unsigned long start = memblock_region_memory_base_pfn(reg);
		unsigned long end = memblock_region_memory_end_pfn(reg);

		if (start >= max)
			continue;

#ifdef CONFIG_ZONE_DMA32
		if (start < max_dma) {
			unsigned long dma_end = min(end, max_dma);
			zhole_size[ZONE_DMA32] -= dma_end - start;
		}
#endif
		if (end > max_dma) {
			unsigned long normal_end = min(end, max);
			unsigned long normal_start = max(start, max_dma);
			zhole_size[ZONE_NORMAL] -= normal_end - normal_start;
		}
	}

	free_area_init_node(0, zone_size, min, zhole_size);
}

#endif /* CONFIG_NUMA */

int pfn_valid(unsigned long pfn)
{
	phys_addr_t addr = pfn << PAGE_SHIFT;

	if ((addr >> PAGE_SHIFT) != pfn)
		return 0;

#ifdef CONFIG_SPARSEMEM
	if (pfn_to_section_nr(pfn) >= NR_MEM_SECTIONS)
		return 0;

	if (!valid_section(__nr_to_section(pfn_to_section_nr(pfn))))
		return 0;
#endif
	return memblock_is_map_memory(addr);
}
EXPORT_SYMBOL(pfn_valid);

static phys_addr_t memory_limit = PHYS_ADDR_MAX;

/*
 * Limit the memory size that was specified via FDT.
 */
static int __init early_mem(char *p)
{
	if (!p)
		return 1;

	memory_limit = memparse(p, &p) & PAGE_MASK;
	pr_notice("Memory limited to %lldMB\n", memory_limit >> 20);

	return 0;
}
early_param("mem", early_mem);

static int __init early_init_dt_scan_usablemem(unsigned long node,
		const char *uname, int depth, void *data)
{
	/*
	struct memblock_region {
		phys_addr_t base;
		phys_addr_t size;
		enum memblock_flags flags;
	#ifdef CONFIG_HAVE_MEMBLOCK_NODE_MAP
		int nid;
	#endif
	*/
	struct memblock_region *usablemem = data;
	const __be32 *reg;
	int len;

	/*
		depth가 1이 아니거나,
		uname이 "chosen"이 아닌 경우 return 0;
	*/
	if (depth != 1 || strcmp(uname, "chosen") != 0)
		return 0;

	/*
		"chosen" 노드에서 "linux,usable-memory-range"의 이름을 가지는 property찾음
		
		- 반환 값 reg : data 저장
		- len : len 저장
	struct fdt_property {
		fdt32_t tag;
		fdt32_t len;
		fdt32_t nameoff;
		char data[0];
	};
	*/
	reg = of_get_flat_dt_prop(node, "linux,usable-memory-range", &len);
	/*
		reg가 NULL 이거나 -> node에서 "linux,usable-memory-range"에 해당하는 property를 찾지 x
		len이 ( + ) 보다 작음 경우 return 1
	*/
	if (!reg || (len < (dt_root_addr_cells + dt_root_size_cells)))
		return 1;

	/*
		memblock_region의 base, size를 저장

		ex) reg -> 0x9 0xf000_0000 0x0 0x1000_0000
	*/
	usablemem->base = dt_mem_next_cell(dt_root_addr_cells, &reg);
	usablemem->size = dt_mem_next_cell(dt_root_size_cells, &reg);

	return 1;
}

static void __init fdt_enforce_memory_region(void)
{
	struct memblock_region reg = {
		.size = 0,
	};

	/*
	   flatten dtb에서 모든 노드를 돌면서 early_init_dt_scan_usablemem을 수행한다.

	   - 수행 결과는 reg에 저장한다.
	*/
	of_scan_flat_dt(early_init_dt_scan_usablemem, &reg);

	/*
	   reg.base, reg.size 영역에 해당되지 않는 모든 region[]을 제거
	*/
	if (reg.size)
		memblock_cap_memory_range(reg.base, reg.size);
}

void __init arm64_memblock_init(void)
{
	/*
		linear_region_size에 64비트 커널에서 사용할 가상 주소 크기의 절반을 담음

		ex) VA_BITS = 48일 경우
		#define PAGE_OFFSET		(UL(0xffffffffffffffff) - (UL(1) << (VA_BITS - 1)) + 1)
								= 0xffff_ffff_ffff_ffff - 0x0000_8000_0000_0000 + 1
								= 0xffff_8000_0000_0000

		-> PAGE_OFFSET의 음수표현 : 2의 보수
		   -PAGE_OFFSET = 0x0000_8000_0000_0000 => 128TB를 나타냄
	*/
	const s64 linear_region_size = -(s64)PAGE_OFFSET;

	/* Handle linux,usable-memory-range property */
	/*
	   디바이스 트리(FDT)가 지정한 사용 메모리 영역이 제한된 경우
	   그 영역 이외의 memblock영역을 제거한다.
	   - chosen 노드에 "linux,usable-memory-range" 속성으로 사용할 수 있는 메모리 영역 제한 가능
	*/
	fdt_enforce_memory_region();

	/* Remove memory above our supported physical address size */
	/*
	   PHYS_MASK_SHIFT = 48
	   시스템 물리 메모리 영역을 초과하는 영역은 모두 제거한다.
	*/
	memblock_remove(1ULL << PHYS_MASK_SHIFT, ULLONG_MAX);

	/*
	 * Ensure that the linear region takes up exactly half of the kernel
	 * virtual address space. This way, we can distinguish a linear address
	 * from a kernel/module/vmalloc address by testing a single bit.
	 */
	BUILD_BUG_ON(linear_region_size != BIT(VA_BITS - 1));

	/*
	 * Select a suitable value for the base of physical memory.
	 */
	/*
		물리 메모리의 시작 주소는 커널 설정에 따라 섹션 크기 또는 pud 크기로 정렬하여 사용

		#define round_down(x, y) ((x) & ~__round_mask(x, y))
		#define __round_mask(x, y) ((__typeof__(x))((y)-1))
	*/
	memstart_addr = round_down(memblock_start_of_DRAM(),
				   ARM64_MEMSTART_ALIGN);

	/*
	 * Remove the memory that we will not be able to cover with the
	 * linear mapping. Take care not to clip the kernel which may be
	 * high in memory.
	 */
	/*
		커널 리니어 매핑 사이즈를 초과하는 물리 메모리의 끝을 memory memblock 영역에서 제거
		- 커널이 메모리의 끝 부분에 로드된 경우가 있으므로 이러한 경우 끝 부분을 기준으로 
		로드된 커널이 제거되지 않도록 제한.
	*/
	memblock_remove(max_t(u64, memstart_addr + linear_region_size,
			__pa_symbol(_end)), ULLONG_MAX);
	/*
	   로드된 커널이 커널 리니어 매핑 사이즈보다 큰 메모리의 상위쪽에 로드된 경우
	   메모리의 상위에 위치한 커널을 보호하기 위해 커널 리니어 매핑 사이즈를 초과한 
	   메모리의 아랫 부분을 제거한다.
	*/
	if (memstart_addr + linear_region_size < memblock_end_of_DRAM()) {
		/* ensure that memstart_addr remains sufficiently aligned */
		memstart_addr = round_up(memblock_end_of_DRAM() - linear_region_size,
					 ARM64_MEMSTART_ALIGN);
		memblock_remove(0, memstart_addr);
	}

	/*
	 * Apply the memory limit if it was set. Since the kernel may be loaded
	 * high up in memory, add back the kernel region that must be accessible
	 * via the linear mapping.
	 */
	/*
		DRAM 메모리 제한을 설정한 경우 제한 메모리 범위를 초과한 DRAM 메모리 영역을 
		memory memblock 영역에서 제거한다.

		- DRAM 메모리 제한은 early_mem()을 통해 가능
	*/
	if (memory_limit != PHYS_ADDR_MAX) {
		memblock_mem_limit_remove_map(memory_limit);
		memblock_add(__pa_symbol(_text), (u64)(_end - _text));
	}

	/*
	   램디스크 영역(initrd) 영역을 reserved memblock에 추가한다.
	*/
	if (IS_ENABLED(CONFIG_BLK_DEV_INITRD) && phys_initrd_size) {
		/*
		 * Add back the memory we just removed if it results in the
		 * initrd to become inaccessible via the linear mapping.
		 * Otherwise, this is a no-op
		 */
		/*
		   PAGE_MASK = (~(PAGE_SIZE-1))

		   phys_initrd_start, phys_initrd_size를 페이지 사이즈로 정렬한다
		 */
		u64 base = phys_initrd_start & PAGE_MASK;
		u64 size = PAGE_ALIGN(phys_initrd_start + phys_initrd_size) - base;

		/*
		 * We can only add back the initrd memory if we don't end up
		 * with more memory than we can address via the linear mapping.
		 * It is up to the bootloader to position the kernel and the
		 * initrd reasonably close to each other (i.e., within 32 GB of
		 * each other) so that all granule/#levels combinations can
		 * always access both.
		 */
		/*
		   램디스크의 시작과 끝이 DRAM의 memblock의 시작과 끝 영역에 포함되지 않을 때는 추가x
		*/
		if (WARN(base < memblock_start_of_DRAM() ||
			 base + size > memblock_start_of_DRAM() +
				       linear_region_size,
			"initrd not fully accessible via the linear mapping -- please check your bootloader ...\n")) {
			initrd_start = 0;
		/*
		   DRAM의 memblock의 시작과 끝 영역에 포함될 때는
		   - 그 영역을 remove, add, reserve 시켜줌
		*/
		} else {
			memblock_remove(base, size); /* clear MEMBLOCK_ flags */
			memblock_add(base, size);
			memblock_reserve(base, size);
		}
	}

	/*
	   보안 목적으로 CONFIG_RANDOMIZE_BASE 커널 옵션을 사용하여
	   커널 시작 주소가 랜덤하게 바뀌는 경우 memstart_addr을 구한다.
	*/
	if (IS_ENABLED(CONFIG_RANDOMIZE_BASE)) {
		extern u16 memstart_offset_seed;
		u64 range = linear_region_size -
			    (memblock_end_of_DRAM() - memblock_start_of_DRAM());

		/*
		 * If the size of the linear region exceeds, by a sufficient
		 * margin, the size of the region that the available physical
		 * memory spans, randomize the linear region as well.
		 */
		if (memstart_offset_seed > 0 && range >= ARM64_MEMSTART_ALIGN) {
			range /= ARM64_MEMSTART_ALIGN;
			memstart_addr -= ARM64_MEMSTART_ALIGN *
					 ((range * memstart_offset_seed) >> 16);
		}
	}

	/*
	 * Register the kernel text, kernel data, initrd, and initial
	 * pagetables with memblock.
	 */
	/*
	   커널 영역을 reserve 한다.
	*/
	memblock_reserve(__pa_symbol(_text), _end - _text);
	/*
	   램디스크(initrd) 영역 주소를 가상 주소로 변환하여 저장한다.
	*/
	if (IS_ENABLED(CONFIG_BLK_DEV_INITRD) && phys_initrd_size) {
		/* the generic initrd code expects virtual addresses */
		initrd_start = __phys_to_virt(phys_initrd_start);
		initrd_end = initrd_start + phys_initrd_size;
	}

	/*
		DTB에 관련된 세 가지 영역을 추가한다
		- DTB 자신의 영역
		- DTB 헤더의 off_mem_rsvmap 필드가 가리키는 memory reserve 블록(바이너리)에서 
		  읽은 메모리 영역들
		- DTB reserved-mem 노드 영역이 요청하는 영역들
	*/
	early_init_fdt_scan_reserved_mem();

	/* 4GB maximum for 32-bit only capable devices */
	/*
	   디바이스 드라이버(dma for coherent/cma for dma)가 필요로 하는 DMA 영역을 구한다.
	*/
	if (IS_ENABLED(CONFIG_ZONE_DMA32))
		arm64_dma_phys_limit = max_zone_dma_phys();
	else
		arm64_dma_phys_limit = PHYS_MASK + 1;

	/*
		crash 커널 영역을 reserve 한다.
	*/
	reserve_crashkernel();

	/*
	   	elf core 헤더 영역을 reserve 한다.
	*/
	reserve_elfcorehdr();

	/*
	   	ARM64의 경우 highmem을 사용하지 않는다.
		- 따라서 메모리의 끝 주소를 대입한다.
	*/
	high_memory = __va(memblock_end_of_DRAM() - 1) + 1;

	/*
	   	dma 영역을 reserved memblock에 추가하고 CMA(Contiguous Memory Allocator)에도 추가한다.
		- 전역 cma_areas[] 배열에 추가한 엔트리는 CMA 드라이버가 로드되면서 초기화할 때 사용
		- 또한 전역 dma_mmu_remap[] 배열에 추가된 엔트리는 추후
		  dma_contiguous_remap() 함수를 통해 지정된 영역에 대응하는 페이지 테이블 엔트리들을
		  IO 속성으로 매핑할 때 사용한다.
	*/
	dma_contiguous_reserve(arm64_dma_phys_limit);
}

void __init bootmem_init(void)
{
	unsigned long min, max;

	min = PFN_UP(memblock_start_of_DRAM());
	max = PFN_DOWN(memblock_end_of_DRAM());

	early_memtest(min << PAGE_SHIFT, max << PAGE_SHIFT);

	max_pfn = max_low_pfn = max;

	arm64_numa_init();
	/*
	 * Sparsemem tries to allocate bootmem in memory_present(), so must be
	 * done after the fixed reservations.
	 */
	memblocks_present();

	sparse_init();
	zone_sizes_init(min, max);

	memblock_dump_all();
}

#ifndef CONFIG_SPARSEMEM_VMEMMAP
static inline void free_memmap(unsigned long start_pfn, unsigned long end_pfn)
{
	struct page *start_pg, *end_pg;
	unsigned long pg, pgend;

	/*
	 * Convert start_pfn/end_pfn to a struct page pointer.
	 */
	start_pg = pfn_to_page(start_pfn - 1) + 1;
	end_pg = pfn_to_page(end_pfn - 1) + 1;

	/*
	 * Convert to physical addresses, and round start upwards and end
	 * downwards.
	 */
	pg = (unsigned long)PAGE_ALIGN(__pa(start_pg));
	pgend = (unsigned long)__pa(end_pg) & PAGE_MASK;

	/*
	 * If there are free pages between these, free the section of the
	 * memmap array.
	 */
	if (pg < pgend)
		memblock_free(pg, pgend - pg);
}

/*
 * The mem_map array can get very big. Free the unused area of the memory map.
 */
static void __init free_unused_memmap(void)
{
	unsigned long start, prev_end = 0;
	struct memblock_region *reg;

	for_each_memblock(memory, reg) {
		start = __phys_to_pfn(reg->base);

#ifdef CONFIG_SPARSEMEM
		/*
		 * Take care not to free memmap entries that don't exist due
		 * to SPARSEMEM sections which aren't present.
		 */
		start = min(start, ALIGN(prev_end, PAGES_PER_SECTION));
#endif
		/*
		 * If we had a previous bank, and there is a space between the
		 * current bank and the previous, free it.
		 */
		if (prev_end && prev_end < start)
			free_memmap(prev_end, start);

		/*
		 * Align up here since the VM subsystem insists that the
		 * memmap entries are valid from the bank end aligned to
		 * MAX_ORDER_NR_PAGES.
		 */
		prev_end = ALIGN(__phys_to_pfn(reg->base + reg->size),
				 MAX_ORDER_NR_PAGES);
	}

#ifdef CONFIG_SPARSEMEM
	if (!IS_ALIGNED(prev_end, PAGES_PER_SECTION))
		free_memmap(prev_end, ALIGN(prev_end, PAGES_PER_SECTION));
#endif
}
#endif	/* !CONFIG_SPARSEMEM_VMEMMAP */

/*
 * mem_init() marks the free areas in the mem_map and tells us how much memory
 * is free.  This is done after various parts of the system have claimed their
 * memory after the kernel image.
 */
void __init mem_init(void)
{
	if (swiotlb_force == SWIOTLB_FORCE ||
	    max_pfn > (arm64_dma_phys_limit >> PAGE_SHIFT))
		swiotlb_init(1);
	else
		swiotlb_force = SWIOTLB_NO_FORCE;

	set_max_mapnr(pfn_to_page(max_pfn) - mem_map);

#ifndef CONFIG_SPARSEMEM_VMEMMAP
	free_unused_memmap();
#endif
	/* this will put all unused low memory onto the freelists */
	memblock_free_all();

	mem_init_print_info(NULL);

	/*
	 * Check boundaries twice: Some fundamental inconsistencies can be
	 * detected at build time already.
	 */
#ifdef CONFIG_COMPAT
	BUILD_BUG_ON(TASK_SIZE_32 > DEFAULT_MAP_WINDOW_64);
#endif

	if (PAGE_SIZE >= 16384 && get_num_physpages() <= 128) {
		extern int sysctl_overcommit_memory;
		/*
		 * On a machine this small we won't get anywhere without
		 * overcommit, so turn it on by default.
		 */
		sysctl_overcommit_memory = OVERCOMMIT_ALWAYS;
	}
}

void free_initmem(void)
{
	free_reserved_area(lm_alias(__init_begin),
			   lm_alias(__init_end),
			   0, "unused kernel");
	/*
	 * Unmap the __init region but leave the VM area in place. This
	 * prevents the region from being reused for kernel modules, which
	 * is not supported by kallsyms.
	 */
	unmap_kernel_range((u64)__init_begin, (u64)(__init_end - __init_begin));
}

#ifdef CONFIG_BLK_DEV_INITRD

static int keep_initrd __initdata;

void __init free_initrd_mem(unsigned long start, unsigned long end)
{
	if (!keep_initrd) {
		free_reserved_area((void *)start, (void *)end, 0, "initrd");
		memblock_free(__virt_to_phys(start), end - start);
	}
}

static int __init keepinitrd_setup(char *__unused)
{
	keep_initrd = 1;
	return 1;
}

__setup("keepinitrd", keepinitrd_setup);
#endif

/*
 * Dump out memory limit information on panic.
 */
static int dump_mem_limit(struct notifier_block *self, unsigned long v, void *p)
{
	if (memory_limit != PHYS_ADDR_MAX) {
		pr_emerg("Memory Limit: %llu MB\n", memory_limit >> 20);
	} else {
		pr_emerg("Memory Limit: none\n");
	}
	return 0;
}

static struct notifier_block mem_limit_notifier = {
	.notifier_call = dump_mem_limit,
};

static int __init register_mem_limit_dumper(void)
{
	atomic_notifier_chain_register(&panic_notifier_list,
				       &mem_limit_notifier);
	return 0;
}
__initcall(register_mem_limit_dumper);
