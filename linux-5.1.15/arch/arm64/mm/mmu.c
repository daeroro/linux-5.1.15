/*
 * Based on arch/arm/mm/mmu.c
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

#include <linux/cache.h>
#include <linux/export.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/ioport.h>
#include <linux/kexec.h>
#include <linux/libfdt.h>
#include <linux/mman.h>
#include <linux/nodemask.h>
#include <linux/memblock.h>
#include <linux/fs.h>
#include <linux/io.h>
#include <linux/mm.h>
#include <linux/vmalloc.h>

#include <asm/barrier.h>
#include <asm/cputype.h>
#include <asm/fixmap.h>
#include <asm/kasan.h>
#include <asm/kernel-pgtable.h>
#include <asm/sections.h>
#include <asm/setup.h>
#include <asm/sizes.h>
#include <asm/tlb.h>
#include <asm/mmu_context.h>
#include <asm/ptdump.h>
#include <asm/tlbflush.h>

#define NO_BLOCK_MAPPINGS	BIT(0)
#define NO_CONT_MAPPINGS	BIT(1)

u64 idmap_t0sz = TCR_T0SZ(VA_BITS);
u64 idmap_ptrs_per_pgd = PTRS_PER_PGD;
u64 vabits_user __ro_after_init;
EXPORT_SYMBOL(vabits_user);

u64 kimage_voffset __ro_after_init;
EXPORT_SYMBOL(kimage_voffset);

/*
 * Empty_zero_page is a special page that is used for zero-initialized data
 * and COW.
 */
unsigned long empty_zero_page[PAGE_SIZE / sizeof(unsigned long)] __page_aligned_bss;
EXPORT_SYMBOL(empty_zero_page);

static pte_t bm_pte[PTRS_PER_PTE] __page_aligned_bss;
static pmd_t bm_pmd[PTRS_PER_PMD] __page_aligned_bss __maybe_unused;
static pud_t bm_pud[PTRS_PER_PUD] __page_aligned_bss __maybe_unused;

static DEFINE_SPINLOCK(swapper_pgdir_lock);

void set_swapper_pgd(pgd_t *pgdp, pgd_t pgd)
{
	pgd_t *fixmap_pgdp;

	spin_lock(&swapper_pgdir_lock);
	// FIX_PGD에 대한 가상 주소를 fixmap_pgdp에 저장
	fixmap_pgdp = pgd_set_fixmap(__pa_symbol(pgdp));
	WRITE_ONCE(*fixmap_pgdp, pgd);
	/*
	 * We need dsb(ishst) here to ensure the page-table-walker sees
	 * our new entry before set_p?d() returns. The fixmap's
	 * flush_tlb_kernel_range() via clear_fixmap() does this for us.
	 */
	pgd_clear_fixmap();
	spin_unlock(&swapper_pgdir_lock);
}

pgprot_t phys_mem_access_prot(struct file *file, unsigned long pfn,
			      unsigned long size, pgprot_t vma_prot)
{
	if (!pfn_valid(pfn))
		return pgprot_noncached(vma_prot);
	else if (file->f_flags & O_SYNC)
		return pgprot_writecombine(vma_prot);
	return vma_prot;
}
EXPORT_SYMBOL(phys_mem_access_prot);

static phys_addr_t __init early_pgtable_alloc(void)
{
	phys_addr_t phys;
	void *ptr;

	phys = memblock_phys_alloc(PAGE_SIZE, PAGE_SIZE);
	if (!phys)
		panic("Failed to allocate page table page\n");

	/*
	 * The FIX_{PGD,PUD,PMD} slots may be in active use, but the FIX_PTE
	 * slot will be free, so we can (ab)use the FIX_PTE slot to initialise
	 * any level of table.
	 */
	ptr = pte_set_fixmap(phys);

	memset(ptr, 0, PAGE_SIZE);

	/*
	 * Implicit barriers also ensure the zeroed page is visible to the page
	 * table walker
	 */
	pte_clear_fixmap();

	return phys;
}

static bool pgattr_change_is_safe(u64 old, u64 new)
{
	/*
	 * The following mapping attributes may be updated in live
	 * kernel mappings without the need for break-before-make.
	 */
	static const pteval_t mask = PTE_PXN | PTE_RDONLY | PTE_WRITE | PTE_NG;

	/* creating or taking down mappings is always safe */
	if (old == 0 || new == 0)
		return true;

	/* live contiguous mappings may not be manipulated at all */
	if ((old | new) & PTE_CONT)
		return false;

	/* Transitioning from Non-Global to Global is unsafe */
	if (old & ~new & PTE_NG)
		return false;

	return ((old ^ new) & ~mask) == 0;
}

static void init_pte(pmd_t *pmdp, unsigned long addr, unsigned long end,
		     phys_addr_t phys, pgprot_t prot)
{
	pte_t *ptep;

	ptep = pte_set_fixmap_offset(pmdp, addr);
	do {
		pte_t old_pte = READ_ONCE(*ptep);

		set_pte(ptep, pfn_pte(__phys_to_pfn(phys), prot));

		/*
		 * After the PTE entry has been populated once, we
		 * only allow updates to the permission attributes.
		 */
		BUG_ON(!pgattr_change_is_safe(pte_val(old_pte),
					      READ_ONCE(pte_val(*ptep))));

		phys += PAGE_SIZE;
	} while (ptep++, addr += PAGE_SIZE, addr != end);

	pte_clear_fixmap();
}

/*
	alloc_init_cont_pte() : 가상 주소 @addr~@end 범위에 물리 주소 @phys부터 @prot 속성으로 매핑

						- 요청 범위에 대해 cont pte 사이즈 단위로 순회하며
						  cont pte 사이즈에 해당하는 매핑을 수행하기 위해 init_pte() 호출
						- 각각의 단위 매핑 공간이 cont pte 단위로 사이즈와 가상 주소 및
						  물리 주소가 정렬되는 경우 속성에 연속(contiguous) 비트를 추가한다.
						- 연속 매핑 비트 사용 시, pte 엔트리에 해당하는 TLB 엔트리 절약 가능
*/
static void alloc_init_cont_pte(pmd_t *pmdp, unsigned long addr,
				unsigned long end, phys_addr_t phys,
				pgprot_t prot,
				phys_addr_t (*pgtable_alloc)(void),
				int flags)
{
	unsigned long next;
	pmd_t pmd = READ_ONCE(*pmdp);

	BUG_ON(pmd_sect(pmd));

	/*
		pmd 엔트리가 매핑되어 있지 않아 NULL 인 경우 pte 테이블을 할당받아 연결한다.
	*/
	if (pmd_none(pmd)) {
		phys_addr_t pte_phys;
		BUG_ON(!pgtable_alloc);
		pte_phys = pgtable_alloc();
		__pmd_populate(pmdp, pte_phys, PMD_TYPE_TABLE);
		pmd = READ_ONCE(*pmdp);
	}
	BUG_ON(pmd_bad(pmd));
	
	do {
		pgprot_t __prot = prot;
		
		/*
			루프를 돌며 다음 처리할 pmd 엔트리를 구해 둔다.
		*/
		next = pte_cont_addr_end(addr, end);

		/* use a contiguous mapping if the range is suitably aligned */
		/*
			cont pte 사이즈 이면서 가상 주소, 물리 주소가 모두 cont pte 사이즈로 정렬 된 경우
			매핑 플래그를 설정한다.

			ex) 4K 페이지 사용 : 4K * 16 = 64KB 단위
				16K 페이지 사용: 16K * 128 = 2MB 단위
				64K 페이지 사용: 64K * 32 = 2MB 단위
		*/
		if ((((addr | next | phys) & ~CONT_PTE_MASK) == 0) &&
		    (flags & NO_CONT_MAPPINGS) == 0)
			__prot = __pgprot(pgprot_val(prot) | PTE_CONT);

		// pte 엔트리와 해당 범위의 페이지들을 매핑한다
		init_pte(pmdp, addr, next, phys, __prot);

		phys += next - addr;
	} while (addr = next, addr != end);
}

/*
	init_pmd() : 가상주소 @addr ~ @end 범위에 물리 주소 @phys부터 @prot 속성으로 매핑함

				- 요청 범위에 대해 pmd 사이즈 단위로 순회하며
				  각각의 단위 매핑 공간이 섹션 단위로 정렬되는 경우 섹션 매핑 수행,
				  또는 alloc_init_cont_pte() 함수를 호출, pte 레벨에서 매핑을 계속함
*/
static void init_pmd(pud_t *pudp, unsigned long addr, unsigned long end,
		     phys_addr_t phys, pgprot_t prot,
		     phys_addr_t (*pgtable_alloc)(void), int flags)
{
	unsigned long next;
	pmd_t *pmdp;

	/*
		처리할 pmd 테이블을 fixmap에 매핑하고
		가상 주소 @addr에 해당하는 pmd 엔트리 포인터를 @pmdp에 저장
	*/
	pmdp = pmd_set_fixmap_offset(pudp, addr);
	do {
		// 루프를 돌며 pmd 엔트리 값을 읽어 old_pmd에 저장해 둠
		pmd_t old_pmd = READ_ONCE(*pmdp);

		/*
			 다음에 처리할 pmd 엔트리를 구해둠

			- 가상 주소(addr)와 가상 끝 주소(end) 범위 내에서 
			  다음 pmd 엔트리에 해당하는 가상 주소를 구한다.
			- 더 이상 처리할 수 없으면 가상 끝 주소(end)를 리턴한다.
		*/
		next = pmd_addr_end(addr, end);

		/* try section mapping first */
		/*
			pmd 사이즈 이면서 가상 주소, 물리 주소가 모두 pmd 사이즈로 정렬된 경우 
			pmd 타입 섹션 매핑을 수행한다.

			ex) 4K 페이지, VA_BITS = 48 인 경우 pmd 사이즈는 2M이다

			SECTION_MASK = ~(1<<21 - 1)
		*/
		if (((addr | next | phys) & ~SECTION_MASK) == 0 &&
		    (flags & NO_BLOCK_MAPPINGS) == 0) {
			pmd_set_huge(pmdp, phys, prot);

			/*
			 * After the PMD entry has been populated once, we
			 * only allow updates to the permission attributes.
			 */
			BUG_ON(!pgattr_change_is_safe(pmd_val(old_pmd),
						      READ_ONCE(pmd_val(*pmdp))));
		} else {

		/*
			다음 레벨 pte 테이블을 할당하고 범위 내의 페이지들을 매핑한다
		*/
			alloc_init_cont_pte(pmdp, addr, next, phys, prot,
					    pgtable_alloc, flags);

			BUG_ON(pmd_val(old_pmd) != 0 &&
			       pmd_val(old_pmd) != READ_ONCE(pmd_val(*pmdp)));
		}

		// 다음 처리할 pmd 엔트리를 위해 루프를 돈다
		phys += next - addr;
	} while (pmdp++, addr = next, addr != end);

	// pmd 테이블을 fixmap에서 해제한다.
	pmd_clear_fixmap();
}

/*
	alloc_init_cont_pmd() : pmd 테이블 할당 및 초기화

	- pmd 및 pte 테이블은 pgd 및 pud 테이블과 다르게 contiguous 매핑이 가능함
	- pmd contiguous 매핑 사이즈 단위(pmd contiguous 최대 횟수 * pmd 사이즈)로 루프를 돌며
	  init_pmd() 함수를 호출한다.

	- 가상 주소 @addr ~ @end 범위에 물리 주소 @phys부터 @prot 속성으로 매핑한다.
*/
static void alloc_init_cont_pmd(pud_t *pudp, unsigned long addr,
				unsigned long end, phys_addr_t phys,
				pgprot_t prot,
				phys_addr_t (*pgtable_alloc)(void), int flags)
{
	unsigned long next;
	pud_t pud = READ_ONCE(*pudp);

	/*
	 * Check for initial section mappings in the pgd/pud.
	 */
	BUG_ON(pud_sect(pud));

	/*
		pud 엔트리가 매핑되어 있지 않아 NULL이거나
		pud 섹션 페이지 매핑(64K 페이지가 아니면서 3레벨 이상의 변환 테이블에서만 유효)된 경우
		pmd 테이블을 할당받아 연결한다.
	*/
	if (pud_none(pud)) {
		phys_addr_t pmd_phys;
		BUG_ON(!pgtable_alloc);
		pmd_phys = pgtable_alloc();
		__pud_populate(pudp, pmd_phys, PUD_TYPE_TABLE);
		pud = READ_ONCE(*pudp);
	}
	BUG_ON(pud_bad(pud));

	do {
		pgprot_t __prot = prot;

		/*
			 처리할 cont pmd 엔트리에 대한 범위를 알아온다. 다음 주소는 next에 반환

			ex) 4K 페이지, VA_BITS = 48 시스템에서 cont pmd 사이즈는 
				- CONT_PMDS(16번) * PMD_SIZE(2M) = CONT_PMD_SIZE(32M) 이다

		*/
		next = pmd_cont_addr_end(addr, end);

		/* use a contiguous mapping if the range is suitably aligned */
		/*
			cont pmd 사이즈이면서 가상 주소, 물리 주소가 모두 cont pmd 사이즈로 정렬된 경우
			-> PTE_CONT 연속 매핑 플래그를 설정한다.
		*/
		if ((((addr | next | phys) & ~CONT_PMD_MASK) == 0) &&
		    (flags & NO_CONT_MAPPINGS) == 0)
			__prot = __pgprot(pgprot_val(prot) | PTE_CONT);

		/*
			pmd 엔트리 아래에 연결된 pte 테이블을 생성하고 이를 가리키게 한다.
		*/
		init_pmd(pudp, addr, next, phys, __prot, pgtable_alloc, flags);

		phys += next - addr;
	} while (addr = next, addr != end);
}

static inline bool use_1G_block(unsigned long addr, unsigned long next,
			unsigned long phys)
{
	if (PAGE_SHIFT != 12)
		return false;

	// PUD_MASK = ~(PUD_SIZE - 1) = ~(1<<30 -1)
	if (((addr | next | phys) & ~PUD_MASK) != 0)
		return false;

	return true;
}

/*
	alloc_init_pud() : pud 테이블 생성하기

	- 가상 주소 @addr ~ @end 범위에 물리 주소 @phys부터 @prot 속성으로 매핑한다.
	- 요청 범위에 때해 pud 사이즈 단위로 순회
	- 단위 매핑 공간이 1G 블럭 단위로 정렬되는 경우 블럭 매핑 수행
	  그렇지 않으면 pud 사이즈에 해당하는 공간을 처리하기 위해 
	  다음 레벨인 pmd 테이블 매핑을 수행하러 alloc_init_cont_pmd()를 호출한다.

	
	alloc_init_pud(pgdp, addr, next, phys, prot, pgtable_alloc, flags);
*/
static void alloc_init_pud(pgd_t *pgdp, unsigned long addr, unsigned long end,
			   phys_addr_t phys, pgprot_t prot,
			   phys_addr_t (*pgtable_alloc)(void),
			   int flags)
{
	unsigned long next;
	pud_t *pudp;
	pgd_t pgd = READ_ONCE(*pgdp);

	// pgd 엔트리가 NULL인 경우에는 pud 테이블을 할당받아 연결한다.
	if (pgd_none(pgd)) {
		phys_addr_t pud_phys;
		BUG_ON(!pgtable_alloc);

		/* pgtalbe_alloc() 이 NULL이 아닌 경우에
		   pud 페이지 테이블을 할당해 pud_phys에 물리 주소를 저장
		*/
		pud_phys = pgtable_alloc();
		// pgdp 엔트리가 pud_phys 테이블을 가리키도록 매핑 설정
		__pgd_populate(pgdp, pud_phys, PUD_TYPE_TABLE);
		pgd = READ_ONCE(*pgdp);
	}

	/*
		pgd_bad() : 섹션 매핑이나 엔트리가 할당되지 않았을 때 1이 됨
	*/
	BUG_ON(pgd_bad(pgd));

	/*
		fixmap의 FIX_PUD 가상 주소에 addr을 매핑한다

		- fixmap에서 pgd, pud, pmd, pte 테이블용으로 각각의 페이지가 준비되어 있음
		- 할당받은 페이지 테이블이 memblock으로부터 막 할당받아 아직 가상 주소에 매핑되어
		  사용하지 않는 경우 임시로 가상 주소에 매핑시켜 사용할 수 있도록 준비된 페이지
		- 페이지 테이블의 첫 구성 시에 사용함

		pgdp : pgd 테이블 엔트리 주소
		addr : fixmap 가상 주소
	*/
	pudp = pud_set_fixmap_offset(pgdp, addr);
	do {
		pud_t old_pud = READ_ONCE(*pudp);

		/*
			매핑 진행 중인 가상 주소 addr와 가상 주소 끝 end 범위 내에서
			다음 pud 엔트리에 해당하는 가상 주소를 구한다.

			- 더이상 처리할 수 없으면 가상 끝 주소(end)를 리턴한다.
		*/
		next = pud_addr_end(addr, end);

		/*
		 * For 4K granule only, attempt to put down a 1GB block
		 */
		/*
			4K 페이지 테이블을 사용하면서 addr, next, phys가 1G 단위로 정렬된 경우
			pud 타입 섹션 매핑 설정 -> 한 번에 1G 페이지가 매핑됨
		*/
		if (use_1G_block(addr, next, phys) &&
		    (flags & NO_BLOCK_MAPPINGS) == 0) {
			pud_set_huge(pudp, phys, prot);

			/*
			 * After the PUD entry has been populated once, we
			 * only allow updates to the permission attributes.
			 */
			BUG_ON(!pgattr_change_is_safe(pud_val(old_pud),
						      READ_ONCE(pud_val(*pudp))));
		} else {

			/*
				가상 주소 addr에 해당하는 pud 엔트리가 없으면 pmd 테이블을 생성하고 가리키게 함
			*/
			alloc_init_cont_pmd(pudp, addr, next, phys, prot,
					    pgtable_alloc, flags);

			BUG_ON(pud_val(old_pud) != 0 &&
			       pud_val(old_pud) != READ_ONCE(pud_val(*pudp)));
		}

		// 물리 주소 phys에 next - addr 한 값을 더한다ㅏ.
		phys += next - addr;

	/*
		pudp가 다음 pud 엔트리를 가리키도록 포인터를 증가시킴
		처리할 가상 주소 addr에 next를 설정
		매핑이 아직 다 완료 되지 않았으면 루프를 돈다.
	*/
	} while (pudp++, addr = next, addr != end);

	// pmd용 fixmap 페이지를 매핑 해제한다.
	pud_clear_fixmap();
}

/*
	__create_pgd_mapping() : 페이지 테이블 @pgdir에서 가상 주소 @virt 부터 @size 만큼에 해당하는
							pgd 테이블 엔트리에 물리 주소 @phys부터 매핑한다.
				
				- 요청 범위에 대해 pgd 사이즈 단위로 순회하며 각각의 단위 매핑을 처리하기 위해
				  다음 레벨인 pud 테이블 매핑을 수행하러 alloc_init_pud() 함수를 호출
				- 연결될 하위 페이지 테이블을 할당 받아야 할 때 인자로 전달받은
				  pgtable_alloc() 함수를 호출하여 페이지 테이블을 할당한다.
	
	pgdir = init_pg_dir
	phys = round_down(dt_phys, SWAPPER_BLOCK_SIZE)
	virt = dt_virt_base
	size = SWAPPER_BLOCK_SIZE
	pgtable_alloc = NULL
	prot = prot
	flags = NO_CONT_MAPPINGS
*/
static void __create_pgd_mapping(pgd_t *pgdir, phys_addr_t phys,
				 unsigned long virt, phys_addr_t size,
				 pgprot_t prot,
				 phys_addr_t (*pgtable_alloc)(void),
				 int flags)
{
	unsigned long addr, length, end, next;
	// pgdir에서 virt에 해당하는 엔트리 주소를 구함
	pgd_t *pgdp = pgd_offset_raw(pgdir, virt);

	/*
	 * If the virtual and physical address don't have the same offset
	 * within a page, we cannot map the region as the caller expects.
	 */
	// ~PAGE_MASK = 1<<12 - 1
	// 물리 주소와 가상 주소에서 PAGE 오프셋은 같아야 함 ->  같지 않으면 return
	if (WARN_ON((phys ^ virt) & ~PAGE_MASK))
		return;

	// phys에 물리 주소 페이지 오프셋을 0으로 만들어 저장
	phys &= PAGE_MASK;
	// addr에 가상 주소 virt의 페이지 오프셋을 0으로 만들어 저장
	addr = virt & PAGE_MASK;
	/*
		length : 매핑할 페이지 바이트 수를 계산해서 저장

		?? virt & ~PAGE_MASK를 왜 더하는 거임 ??

		-> virt의 PAGE에서 오프셋이 0이 아니면 한 페이지를 더 할당해야함.
		********************************************************
	*/
	length = PAGE_ALIGN(size + (virt & ~PAGE_MASK));

	// end : 매핑 끝 가상 주소를 저장(페이지 단위)
	end = addr + length;
	
	do {
		/*
			addr : 가상 주소 virt의 페이지 오프셋(12bits)을 0으로
			end : addr이 가리키는 pgd 블록의 끝 주소

			next : 다음 처리할 pgd 엔트리를 구해둠
			- 매핑 진행 중인 가상 주소(addr)와 가상 끝 주소(end) 범위 내에서
			  다음 pgd에 해당하는 가상 주소를 구한다.
			- 더 이상 처리할 수 없으면 가상 끝 주소(end)를 리턴한다.
		*/		
		next = pgd_addr_end(addr, end);

		/*
			가상 주소 addr에 해당하는 pgd 엔트리가 없으면 pud 테이블을 생성하고 가리키게 함
			
			pgdp : pgdir에서 virt가 가리키는 pgd 테이블 엔트리 주소
			addr : virt 페이지 단위 가상 주소
		*/
		alloc_init_pud(pgdp, addr, next, phys, prot, pgtable_alloc,
			       flags);
		/*
			루프를 순회하기 위해 다음에 매핑할 pgd 엔트리의 물리 주소를 구함	
		*/
		phys += next - addr;
		
	/*
		다음 pgd엔트리를 가리키도록 포인터 증가
		처리할 가상 주소(addr)에 next를 설정, 매핑이 완료 되지 않았으면 루프를 돔.
	*/
	} while (pgdp++, addr = next, addr != end);
}

static phys_addr_t pgd_pgtable_alloc(void)
{
	void *ptr = (void *)__get_free_page(PGALLOC_GFP);
	if (!ptr || !pgtable_page_ctor(virt_to_page(ptr)))
		BUG();

	/* Ensure the zeroed page is visible to the page table walker */
	dsb(ishst);
	return __pa(ptr);
}

/*
 * This function can only be used to modify existing table entries,
 * without allocating new levels of table. Note that this permits the
 * creation of new section or page entries.
 */
/*
	create_mapping_noalloc(round_down(dt_phys, SWAPPER_BLOCK_SIZE),
             dt_virt_base, SWAPPER_BLOCK_SIZE, prot);
*/
static void __init create_mapping_noalloc(phys_addr_t phys, unsigned long virt,
				  phys_addr_t size, pgprot_t prot)
{
	/*
		 수정하고자 하는 가상 주소 virt가
		 VMALLOC_START 보다 아래에 있으면 커널 범위 밖에 있는 것 -> return
	*/
	if (virt < VMALLOC_START) {
		pr_warn("BUG: not creating mapping for %pa at 0x%016lx - outside kernel range\n",
			&phys, virt);
		return;
	}
	/*
		init_mm.pgd = init_pg_dir
		phys = round_down(dt_phys, SWAPPER_BLOCK_SIZE)
		virt = dt_virt_base
		size = SWAPPER_BLOCK_SIZE
		prot = prot
		NO_CONT_MAPPINGS : 연속된 물리 페이지의 매핑 시 TBL 엔트리의 contiguous 비트를 설정
							-> TBL 엔트리를 절약할 수 있는데 이를 못하게 제한하는 플래그
	*/
	__create_pgd_mapping(init_mm.pgd, phys, virt, size, prot, NULL,
			     NO_CONT_MAPPINGS);
}

void __init create_pgd_mapping(struct mm_struct *mm, phys_addr_t phys,
			       unsigned long virt, phys_addr_t size,
			       pgprot_t prot, bool page_mappings_only)
{
	int flags = 0;

	BUG_ON(mm == &init_mm);

	if (page_mappings_only)
		flags = NO_BLOCK_MAPPINGS | NO_CONT_MAPPINGS;

	__create_pgd_mapping(mm->pgd, phys, virt, size, prot,
			     pgd_pgtable_alloc, flags);
}

static void update_mapping_prot(phys_addr_t phys, unsigned long virt,
				phys_addr_t size, pgprot_t prot)
{
	if (virt < VMALLOC_START) {
		pr_warn("BUG: not updating mapping for %pa at 0x%016lx - outside kernel range\n",
			&phys, virt);
		return;
	}

	__create_pgd_mapping(init_mm.pgd, phys, virt, size, prot, NULL,
			     NO_CONT_MAPPINGS);

	/* flush the TLBs after updating live kernel mappings */
	flush_tlb_kernel_range(virt, virt + size);
}

static void __init __map_memblock(pgd_t *pgdp, phys_addr_t start,
				  phys_addr_t end, pgprot_t prot, int flags)
{
	__create_pgd_mapping(pgdp, start, __phys_to_virt(start), end - start,
			     prot, early_pgtable_alloc, flags);
}

void __init mark_linear_text_alias_ro(void)
{
	/*
	 * Remove the write permissions from the linear alias of .text/.rodata
	 */
	update_mapping_prot(__pa_symbol(_text), (unsigned long)lm_alias(_text),
			    (unsigned long)__init_begin - (unsigned long)_text,
			    PAGE_KERNEL_RO);
}

static void __init map_mem(pgd_t *pgdp)
{
	phys_addr_t kernel_start = __pa_symbol(_text);
	phys_addr_t kernel_end = __pa_symbol(__init_begin);
	struct memblock_region *reg;
	int flags = 0;

	if (rodata_full || debug_pagealloc_enabled())
		flags = NO_BLOCK_MAPPINGS | NO_CONT_MAPPINGS;

	/*
	 * Take care not to create a writable alias for the
	 * read-only text and rodata sections of the kernel image.
	 * So temporarily mark them as NOMAP to skip mappings in
	 * the following for-loop
	 */
	memblock_mark_nomap(kernel_start, kernel_end - kernel_start);
#ifdef CONFIG_KEXEC_CORE
	if (crashk_res.end)
		memblock_mark_nomap(crashk_res.start,
				    resource_size(&crashk_res));
#endif

	/* map all the memory banks */
	for_each_memblock(memory, reg) {
		phys_addr_t start = reg->base;
		phys_addr_t end = start + reg->size;

		if (start >= end)
			break;
		if (memblock_is_nomap(reg))
			continue;

		__map_memblock(pgdp, start, end, PAGE_KERNEL, flags);
	}

	/*
	 * Map the linear alias of the [_text, __init_begin) interval
	 * as non-executable now, and remove the write permission in
	 * mark_linear_text_alias_ro() below (which will be called after
	 * alternative patching has completed). This makes the contents
	 * of the region accessible to subsystems such as hibernate,
	 * but protects it from inadvertent modification or execution.
	 * Note that contiguous mappings cannot be remapped in this way,
	 * so we should avoid them here.
	 */
	__map_memblock(pgdp, kernel_start, kernel_end,
		       PAGE_KERNEL, NO_CONT_MAPPINGS);
	memblock_clear_nomap(kernel_start, kernel_end - kernel_start);

#ifdef CONFIG_KEXEC_CORE
	/*
	 * Use page-level mappings here so that we can shrink the region
	 * in page granularity and put back unused memory to buddy system
	 * through /sys/kernel/kexec_crash_size interface.
	 */
	if (crashk_res.end) {
		__map_memblock(pgdp, crashk_res.start, crashk_res.end + 1,
			       PAGE_KERNEL,
			       NO_BLOCK_MAPPINGS | NO_CONT_MAPPINGS);
		memblock_clear_nomap(crashk_res.start,
				     resource_size(&crashk_res));
	}
#endif
}

void mark_rodata_ro(void)
{
	unsigned long section_size;

	/*
	 * mark .rodata as read only. Use __init_begin rather than __end_rodata
	 * to cover NOTES and EXCEPTION_TABLE.
	 */
	section_size = (unsigned long)__init_begin - (unsigned long)__start_rodata;
	update_mapping_prot(__pa_symbol(__start_rodata), (unsigned long)__start_rodata,
			    section_size, PAGE_KERNEL_RO);

	debug_checkwx();
}

static void __init map_kernel_segment(pgd_t *pgdp, void *va_start, void *va_end,
				      pgprot_t prot, struct vm_struct *vma,
				      int flags, unsigned long vm_flags)
{
	phys_addr_t pa_start = __pa_symbol(va_start);
	unsigned long size = va_end - va_start;

	BUG_ON(!PAGE_ALIGNED(pa_start));
	BUG_ON(!PAGE_ALIGNED(size));

	__create_pgd_mapping(pgdp, pa_start, (unsigned long)va_start, size, prot,
			     early_pgtable_alloc, flags);

	if (!(vm_flags & VM_NO_GUARD))
		size += PAGE_SIZE;

	vma->addr	= va_start;
	vma->phys_addr	= pa_start;
	vma->size	= size;
	vma->flags	= VM_MAP | vm_flags;
	vma->caller	= __builtin_return_address(0);

	vm_area_add_early(vma);
}

static int __init parse_rodata(char *arg)
{
	int ret = strtobool(arg, &rodata_enabled);
	if (!ret) {
		rodata_full = false;
		return 0;
	}

	/* permit 'full' in addition to boolean options */
	if (strcmp(arg, "full"))
		return -EINVAL;

	rodata_enabled = true;
	rodata_full = true;
	return 0;
}
early_param("rodata", parse_rodata);

#ifdef CONFIG_UNMAP_KERNEL_AT_EL0
static int __init map_entry_trampoline(void)
{
	pgprot_t prot = rodata_enabled ? PAGE_KERNEL_ROX : PAGE_KERNEL_EXEC;
	phys_addr_t pa_start = __pa_symbol(__entry_tramp_text_start);

	/* The trampoline is always mapped and can therefore be global */
	pgprot_val(prot) &= ~PTE_NG;

	/* Map only the text into the trampoline page table */
	memset(tramp_pg_dir, 0, PGD_SIZE);
	__create_pgd_mapping(tramp_pg_dir, pa_start, TRAMP_VALIAS, PAGE_SIZE,
			     prot, pgd_pgtable_alloc, 0);

	/* Map both the text and data into the kernel page table */
	__set_fixmap(FIX_ENTRY_TRAMP_TEXT, pa_start, prot);
	if (IS_ENABLED(CONFIG_RANDOMIZE_BASE)) {
		extern char __entry_tramp_data_start[];

		__set_fixmap(FIX_ENTRY_TRAMP_DATA,
			     __pa_symbol(__entry_tramp_data_start),
			     PAGE_KERNEL_RO);
	}

	return 0;
}
core_initcall(map_entry_trampoline);
#endif

/*
 * Create fine-grained mappings for the kernel.
 */
/*
	map_kernel() 
	: 커널 코드를 의도하지 않은 수정으로부터 보호하고 실행 영역과 비실행 영역 또한 보호하기 위해
	  커널 코드와 데이터의 읽기 전용 영역과 읽고 쓰기 영역을 나누어 각각의 적절한 매핑 속성으로
	  매핑한다. 매핑할 페이지 테이블은 요청한 pgd 테이블의 포인터 @pgdp 이며, 이곳에 매핑 수행
*/
static void __init map_kernel(pgd_t *pgdp)
{
	static struct vm_struct vmlinux_text, vmlinux_rodata, vmlinux_inittext,
				vmlinux_initdata, vmlinux_data;

	/*
	 * External debuggers may need to write directly to the text
	 * mapping to install SW breakpoints. Allow this (only) when
	 * explicitly requested with rodata=off.
	 */
	/*
		external 디버거를 사용 시 sw 브레이크 포인터를 사용하여 커널 코드가 매핑된 영역에
		직접 기록할 수 있다. 
		- 이런 경우 커널 파라메터에 "rodata=off"를 사용하여야 커널 영역을 read only로 하지 않고
		  기록도 가능하게 매핑할 수 있다.
	*/
	pgprot_t text_prot = rodata_enabled ? PAGE_KERNEL_ROX : PAGE_KERNEL_EXEC;

	/*
	 * Only rodata will be remapped with different permissions later on,
	 * all other segments are allowed to use contiguous mappings.
	 */
	/*
		커널 이미지의 일반 코드 영역을 커널 실행 페이지 타입으로 매핑함
	*/
	map_kernel_segment(pgdp, _text, _etext, text_prot, &vmlinux_text, 0,
			   VM_NO_GUARD);
	/*
		커널 이미지의 읽기 전용 데이터 영역을 임시로 읽기 쓰기가 가능한 커널 페이지 타입으로
		매핑하되 contiguous 매핑을 하지 않도록 한다.
		- rodata 섹션에 위치한 데이터들은 잠시 뒤 map_mem() 함수를 통해 PAGE_KERNEL 속성으로 
		  재 매핑될 예정인데, contiguous 매핑 상태에서는 속성을 바꾸는 매핑을 수행하면
		  TLB conflict가 발생하는 버그가 발견되었다. 따라서 이 영역에 대해서 contiguous 매핑을
		  하지 않도록 수정하였다.
	*/
	map_kernel_segment(pgdp, __start_rodata, __inittext_begin, PAGE_KERNEL,
			   &vmlinux_rodata, NO_CONT_MAPPINGS, VM_NO_GUARD);
	map_kernel_segment(pgdp, __inittext_begin, __inittext_end, text_prot,
			   &vmlinux_inittext, 0, VM_NO_GUARD);
	map_kernel_segment(pgdp, __initdata_begin, __initdata_end, PAGE_KERNEL,
			   &vmlinux_initdata, 0, VM_NO_GUARD);
	map_kernel_segment(pgdp, _data, _end, PAGE_KERNEL, &vmlinux_data, 0, 0);

	if (!READ_ONCE(pgd_val(*pgd_offset_raw(pgdp, FIXADDR_START)))) {
		/*
		 * The fixmap falls in a separate pgd to the kernel, and doesn't
		 * live in the carveout for the swapper_pg_dir. We can simply
		 * re-use the existing dir for the fixmap.
		 */
		set_pgd(pgd_offset_raw(pgdp, FIXADDR_START),
			READ_ONCE(*pgd_offset_k(FIXADDR_START)));
	} else if (CONFIG_PGTABLE_LEVELS > 3) {
		/*
		 * The fixmap shares its top level pgd entry with the kernel
		 * mapping. This can really only occur when we are running
		 * with 16k/4 levels, so we can simply reuse the pud level
		 * entry instead.
		 */
		BUG_ON(!IS_ENABLED(CONFIG_ARM64_16K_PAGES));
		pud_populate(&init_mm,
			     pud_set_fixmap_offset(pgdp, FIXADDR_START),
			     lm_alias(bm_pmd));
		pud_clear_fixmap();
	} else {
		BUG();
	}

	kasan_copy_shadow(pgdp);
}

void __init paging_init(void)
{
	pgd_t *pgdp = pgd_set_fixmap(__pa_symbol(swapper_pg_dir));

	map_kernel(pgdp);
	map_mem(pgdp);

	pgd_clear_fixmap();

	cpu_replace_ttbr1(lm_alias(swapper_pg_dir));
	init_mm.pgd = swapper_pg_dir;

	memblock_free(__pa_symbol(init_pg_dir),
		      __pa_symbol(init_pg_end) - __pa_symbol(init_pg_dir));

	memblock_allow_resize();
}

/*
 * Check whether a kernel address is valid (derived from arch/x86/).
 */
int kern_addr_valid(unsigned long addr)
{
	pgd_t *pgdp;
	pud_t *pudp, pud;
	pmd_t *pmdp, pmd;
	pte_t *ptep, pte;

	if ((((long)addr) >> VA_BITS) != -1UL)
		return 0;

	pgdp = pgd_offset_k(addr);
	if (pgd_none(READ_ONCE(*pgdp)))
		return 0;

	pudp = pud_offset(pgdp, addr);
	pud = READ_ONCE(*pudp);
	if (pud_none(pud))
		return 0;

	if (pud_sect(pud))
		return pfn_valid(pud_pfn(pud));

	pmdp = pmd_offset(pudp, addr);
	pmd = READ_ONCE(*pmdp);
	if (pmd_none(pmd))
		return 0;

	if (pmd_sect(pmd))
		return pfn_valid(pmd_pfn(pmd));

	ptep = pte_offset_kernel(pmdp, addr);
	pte = READ_ONCE(*ptep);
	if (pte_none(pte))
		return 0;

	return pfn_valid(pte_pfn(pte));
}
#ifdef CONFIG_SPARSEMEM_VMEMMAP
#if !ARM64_SWAPPER_USES_SECTION_MAPS
int __meminit vmemmap_populate(unsigned long start, unsigned long end, int node,
		struct vmem_altmap *altmap)
{
	return vmemmap_populate_basepages(start, end, node);
}
#else	/* !ARM64_SWAPPER_USES_SECTION_MAPS */
int __meminit vmemmap_populate(unsigned long start, unsigned long end, int node,
		struct vmem_altmap *altmap)
{
	unsigned long addr = start;
	unsigned long next;
	pgd_t *pgdp;
	pud_t *pudp;
	pmd_t *pmdp;

	do {
		next = pmd_addr_end(addr, end);

		pgdp = vmemmap_pgd_populate(addr, node);
		if (!pgdp)
			return -ENOMEM;

		pudp = vmemmap_pud_populate(pgdp, addr, node);
		if (!pudp)
			return -ENOMEM;

		pmdp = pmd_offset(pudp, addr);
		if (pmd_none(READ_ONCE(*pmdp))) {
			void *p = NULL;

			p = vmemmap_alloc_block_buf(PMD_SIZE, node);
			if (!p)
				return -ENOMEM;

			pmd_set_huge(pmdp, __pa(p), __pgprot(PROT_SECT_NORMAL));
		} else
			vmemmap_verify((pte_t *)pmdp, node, addr, next);
	} while (addr = next, addr != end);

	return 0;
}
#endif	/* CONFIG_ARM64_64K_PAGES */
void vmemmap_free(unsigned long start, unsigned long end,
		struct vmem_altmap *altmap)
{
}
#endif	/* CONFIG_SPARSEMEM_VMEMMAP */

/*
	fixmap_pud() : 가상 주소 addr에 대한 fixmap용 pud 엔트리 주소를 리턴
*/
static inline pud_t * fixmap_pud(unsigned long addr)
{
	// 가상 주소 addr에 대한 커널용 pgd 엔트리 주소를 구한다
	pgd_t *pgdp = pgd_offset_k(addr);
	pgd_t pgd = READ_ONCE(*pgdp);

	BUG_ON(pgd_none(pgd) || pgd_bad(pgd));

	// 커널 이미지용 pud 엔트리 주소를 구한다.
	return pud_offset_kimg(pgdp, addr);
}

static inline pmd_t * fixmap_pmd(unsigned long addr)
{
	pud_t *pudp = fixmap_pud(addr);
	pud_t pud = READ_ONCE(*pudp);

	BUG_ON(pud_none(pud) || pud_bad(pud));

	return pmd_offset_kimg(pudp, addr);
}

static inline pte_t * fixmap_pte(unsigned long addr)
{
	return &bm_pte[pte_index(addr)];
}

/*
 * The p*d_populate functions call virt_to_phys implicitly so they can't be used
 * directly on kernel symbols (bm_p*d). This function is called too early to use
 * lm_alias so __p*d_populate functions must be used to populate with the
 * physical address from __pa_symbol.
 */
/*
	early_fixmap_init() : 고정 매핑 초기화
		
		- dynamic 매핑이 활성화되기 이전에 일부 고정된 가상 주소 영역에 특정 물리 주소를 
		  매핑 시켜 사용할 수 있는 fixmap 가상 주소 영역을 먼저(early) 사용하려 한다.
*/
void __init early_fixmap_init(void)
{
	pgd_t *pgdp, pgd;
	pud_t *pudp;
	pmd_t *pmdp;

	// fixmap영역의 가장 낮은 주소를 addr에 대입한다.
	unsigned long addr = FIXADDR_START;

	/*
		가상 주소 addr에 해당하는 pgd 엔트리 값을 읽어온다.
		- pgd 테이블에서 pgd 엔트리 포인터인 pgdp를 알아온 후,
		  이 포인터를 통해 pgd 엔트리 값을 읽어 pgd에 대입한다.
	*/
	pgdp = pgd_offset_k(addr);
	pgd = READ_ONCE(*pgdp);

	/*
		페이지 테이블 변환 레벨이 4단계이고 페이지 크기로 16K를 사용하는 커널인 경우
		pgd 엔트리가 최대 2개밖에 존재하지 않는다. 
		- 그 중 하나는 커널 메모리용 가상 주소 공간이고,
		  나머지 하나는 커널에서 여러 용도로 사용되는 몇 가지 공간 주소를 모두 포함하여 사용되며
		  그 중에는 커널 이미지 영역이나 fixmap 영역도 포함
		- 커널 이미지와 fixmap 영역은 1개의 bm_pud[] 테이블에 존재하게 되고
		  이런 경우에는 bm_pud[] 페이지 테이블이 커널 이미지 용도로 이미 활성화되어 사용중이므로
		  다시 활성화할 필요가 없어진다.
		-> 곧바로 fixmap 시작 주소에 해당하는 pud 엔트리 포인터를 구한다.
	*/
	if (CONFIG_PGTABLE_LEVELS > 3 &&
	    !(pgd_none(pgd) || pgd_page_paddr(pgd) == __pa_symbol(bm_pud))) {
		/*
		 * We only end up here if the kernel mapping and the fixmap
		 * share the top level pgd entry, which should only happen on
		 * 16k/4 levels configurations.
		 */
		BUG_ON(!IS_ENABLED(CONFIG_ARM64_16K_PAGES));
		pudp = pud_offset_kimg(pgdp, addr);
	} else {
	/*
		그 외의 경우 bm_pud[]테이블은 fixmap 영역 및 커널 이미지 영역과 같이 공유하지 않고
		fixmap 영역 위주로 사용한다
		- fixmap 영역을 사용하기 위해 bm_pud[] 테이블을 pgd 엔트리와 연결하여 활성화한 후에
		  fixmap 시작 주소에 해당하는 pud 엔트리 주소를 구한다.
	*/

		// pgd_none(x) : x.pgd가 없으면 1
		if (pgd_none(pgd))
			__pgd_populate(pgdp, __pa_symbol(bm_pud), PUD_TYPE_TABLE);
		pudp = fixmap_pud(addr);
	}

	/*
		pud에 연결된 pmd 테이블이 없는 경우 bm_pmd[] 테이블을 사용하여 연결한다.
	*/
	if (pud_none(READ_ONCE(*pudp)))
		__pud_populate(pudp, __pa_symbol(bm_pmd), PMD_TYPE_TABLE);
	/*
		addr 주소에 해당하는 pmd 엔트리 포인터를 알아온다.
	*/
	pmdp = fixmap_pmd(addr);
	/*
		pmd에 연결된 pte 테이블이 없는 경우 bm_pte[] 테이블을 사용하여 연결한다.
	*/
	__pmd_populate(pmdp, __pa_symbol(bm_pte), PMD_TYPE_TABLE);

	/*
	 * The boot-ioremap range spans multiple pmds, for which
	 * we are not prepared:
	 */

	/*
		early_ioremap() 함수에서 사용하는 btmap 영역의 시작과 끝에 해당하는 
		pud 테이블의 pmd 엔트리 주소 값들이 위에서 읽어온 pmd 엔트리 주소 값과 다른 경우
		경고 메세지를 출력한다.
	*/
	BUILD_BUG_ON((__fix_to_virt(FIX_BTMAP_BEGIN) >> PMD_SHIFT)
		     != (__fix_to_virt(FIX_BTMAP_END) >> PMD_SHIFT));

	if ((pmdp != fixmap_pmd(fix_to_virt(FIX_BTMAP_BEGIN)))
	     || pmdp != fixmap_pmd(fix_to_virt(FIX_BTMAP_END))) {
		WARN_ON(1);
		pr_warn("pmdp %p != %p, %p\n",
			pmdp, fixmap_pmd(fix_to_virt(FIX_BTMAP_BEGIN)),
			fixmap_pmd(fix_to_virt(FIX_BTMAP_END)));
		pr_warn("fix_to_virt(FIX_BTMAP_BEGIN): %08lx\n",
			fix_to_virt(FIX_BTMAP_BEGIN));
		pr_warn("fix_to_virt(FIX_BTMAP_END):   %08lx\n",
			fix_to_virt(FIX_BTMAP_END));

		pr_warn("FIX_BTMAP_END:       %d\n", FIX_BTMAP_END);
		pr_warn("FIX_BTMAP_BEGIN:     %d\n", FIX_BTMAP_BEGIN);
	}
}

/*
 * Unusually, this is also called in IRQ context (ghes_iounmap_irq) so if we
 * ever need to use IPIs for TLB broadcasting, then we're in trouble here.
 */
/*
	__set_fixmap() : fixmap의 특정 인덱스에 플래그 정보와 같이 매핑하기
					 
*/
void __set_fixmap(enum fixed_addresses idx,
			       phys_addr_t phys, pgprot_t flags)
{
	// fixed_addresses 에서 idx 인덱스가 가리키는 가상 주소를 구함
	unsigned long addr = __fix_to_virt(idx);
	pte_t *ptep;

	// fixed_addresses가 FIX_HOLE ~ __end_of_fixed_addresses 까지 이므로 범위 검사
	BUG_ON(idx <= FIX_HOLE || idx >= __end_of_fixed_addresses);

	// 가상 주소 addr에 해당하는 bm_pte[] 엔트리 주소를 구한다.
	ptep = fixmap_pte(addr);

	// flags 속성이 있으면, flags 속성을 더해 pte 엔트리를 매핑함
	if (pgprot_val(flags)) {
		set_pte(ptep, pfn_pte(phys >> PAGE_SHIFT, flags));
	} else {
	/*
		 flags 속성이 없으면, pte 엔트리를 언매핑한다
		 - 그 후 pte 엔트리가 수정되었으므로 해당 페이지 1개의 영역에 대해 tlb_flush를 수행
	*/
		pte_clear(&init_mm, addr, ptep);
		flush_tlb_kernel_range(addr, addr+PAGE_SIZE);
	}
}

/*
	__fixmap_remap_fdt(dt_phys, &size, PAGE_KERNEL_RO)
*/
void *__init __fixmap_remap_fdt(phys_addr_t dt_phys, int *size, pgprot_t prot)
{
	/*
		FIX_FDT = 10
		FIX_FDT 가상 주소를 dt_virt_base에 저장
	*/ 
	const u64 dt_virt_base = __fix_to_virt(FIX_FDT);
	int offset;
	void *dt_virt;

	/*
	 * Check whether the physical FDT address is set and meets the minimum
	 * alignment requirement. Since we are relying on MIN_FDT_ALIGN to be
	 * at least 8 bytes so that we can always access the magic and size
	 * fields of the FDT header after mapping the first chunk, double check
	 * here if that is indeed the case.
	 */

	/*
		FDT 헤더에서 magic과 size 필드에 항상 접근할 수 있도록
		- MIN_FDT_ALIGN이 8이상인지 -> 에러 메세지
		- dt_phys가 존재하는지 / MIN_FDT_ALIGN으로 정렬되어 있는지 -> NULL 리턴
	*/
	BUILD_BUG_ON(MIN_FDT_ALIGN < 8);
	if (!dt_phys || dt_phys % MIN_FDT_ALIGN)
		return NULL;

	/*
	 * Make sure that the FDT region can be mapped without the need to
	 * allocate additional translation table pages, so that it is safe
	 * to call create_mapping_noalloc() this early.
	 *
	 * On 64k pages, the FDT will be mapped using PTEs, so we need to
	 * be in the same PMD as the rest of the fixmap.
	 * On 4k pages, we'll use section mappings for the FDT so we only
	 * have to be in the same PUD.
	 */
	BUILD_BUG_ON(dt_virt_base % SZ_2M);

	/*
		SWAPPER_TABLE_SHIFT : 30
		
		FIX_FDT_END 가상 주소와 FIX_BTMAP_BEGIN 가상 주소가 같은 PUD table에 있지 않으면 경고
	*/
	BUILD_BUG_ON(__fix_to_virt(FIX_FDT_END) >> SWAPPER_TABLE_SHIFT !=
		     __fix_to_virt(FIX_BTMAP_BEGIN) >> SWAPPER_TABLE_SHIFT);

	
	/*
		SWAPPER_BLOCK_SIZE : 1 << 21 (2M)

		dt_phys % SWAPPER_BLOCK_SIZE : SWAPPER_BLOCK_SIZE 크기 내에서 offset을 구함

		dt_virt : dt_virt_base에서 BLOCK 크기에 해당하는 offset 만큼을 더해서
				 dt_phys가 가리키는 가상 주소를 구함
		
	*/
	offset = dt_phys % SWAPPER_BLOCK_SIZE;
	dt_virt = (void *)dt_virt_base + offset;

	/* map the first chunk so we can read the size from the header */
	// round_down() : dt_phys 21~64비트
	create_mapping_noalloc(round_down(dt_phys, SWAPPER_BLOCK_SIZE),
			dt_virt_base, SWAPPER_BLOCK_SIZE, prot);

	/*
		magic number, size 검사
	*/
	if (fdt_magic(dt_virt) != FDT_MAGIC)
		return NULL;

	*size = fdt_totalsize(dt_virt);
	if (*size > MAX_FDT_SIZE)
		return NULL;

	/*
		fdt가 SWAPPER_BLOCK_SIZE(2MB)보다 크다면 
		한번 더 create_mapping_noalloc()을 실행해서 fdt를 매핑한다
	*/
	if (offset + *size > SWAPPER_BLOCK_SIZE)
		create_mapping_noalloc(round_down(dt_phys, SWAPPER_BLOCK_SIZE), dt_virt_base,
			       round_up(offset + *size, SWAPPER_BLOCK_SIZE), prot);

	return dt_virt;
}

/*
	fixmap_remap_fdt() : DTB를 fixmap에 매핑하고 가상주소를 구함

	fixmap_remap_fdt(dt_phys) - dt_phys : fdt의 물리 주소
*/
void *__init fixmap_remap_fdt(phys_addr_t dt_phys)
{
	void *dt_virt;
	int size;

	/*
		- dt_phys의 가상 주소를 dt_virt에 저장, 크기를 size에 저장
	*/
	dt_virt = __fixmap_remap_fdt(dt_phys, &size, PAGE_KERNEL_RO);
	if (!dt_virt)
		return NULL;

	/*
		물리 메모리 dt_phys부터 size 만큼을 reserved memblock에 추가한다.
	*/
	memblock_reserve(dt_phys, size);
	return dt_virt;
}

int __init arch_ioremap_pud_supported(void)
{
	/*
	 * Only 4k granule supports level 1 block mappings.
	 * SW table walks can't handle removal of intermediate entries.
	 */
	return IS_ENABLED(CONFIG_ARM64_4K_PAGES) &&
	       !IS_ENABLED(CONFIG_ARM64_PTDUMP_DEBUGFS);
}

int __init arch_ioremap_pmd_supported(void)
{
	/* See arch_ioremap_pud_supported() */
	return !IS_ENABLED(CONFIG_ARM64_PTDUMP_DEBUGFS);
}


/*
	
	pud_set_huge(pudp, phys, prot);
*/
int pud_set_huge(pud_t *pudp, phys_addr_t phys, pgprot_t prot)
{
	pgprot_t sect_prot = __pgprot(PUD_TYPE_SECT |
					pgprot_val(mk_sect_prot(prot)));
	pud_t new_pud = pfn_pud(__phys_to_pfn(phys), sect_prot);

	/* Only allow permission changes for now */
	if (!pgattr_change_is_safe(READ_ONCE(pud_val(*pudp)),
				   pud_val(new_pud)))
		return 0;

	BUG_ON(phys & ~PUD_MASK);
	set_pud(pudp, new_pud);
	return 1;
}

int pmd_set_huge(pmd_t *pmdp, phys_addr_t phys, pgprot_t prot)
{
	pgprot_t sect_prot = __pgprot(PMD_TYPE_SECT |
					pgprot_val(mk_sect_prot(prot)));
	pmd_t new_pmd = pfn_pmd(__phys_to_pfn(phys), sect_prot);

	/* Only allow permission changes for now */
	if (!pgattr_change_is_safe(READ_ONCE(pmd_val(*pmdp)),
				   pmd_val(new_pmd)))
		return 0;

	BUG_ON(phys & ~PMD_MASK);
	set_pmd(pmdp, new_pmd);
	return 1;
}

int pud_clear_huge(pud_t *pudp)
{
	if (!pud_sect(READ_ONCE(*pudp)))
		return 0;
	pud_clear(pudp);
	return 1;
}

int pmd_clear_huge(pmd_t *pmdp)
{
	if (!pmd_sect(READ_ONCE(*pmdp)))
		return 0;
	pmd_clear(pmdp);
	return 1;
}

int pmd_free_pte_page(pmd_t *pmdp, unsigned long addr)
{
	pte_t *table;
	pmd_t pmd;

	pmd = READ_ONCE(*pmdp);

	if (!pmd_table(pmd)) {
		VM_WARN_ON(1);
		return 1;
	}

	table = pte_offset_kernel(pmdp, addr);
	pmd_clear(pmdp);
	__flush_tlb_kernel_pgtable(addr);
	pte_free_kernel(NULL, table);
	return 1;
}

int pud_free_pmd_page(pud_t *pudp, unsigned long addr)
{
	pmd_t *table;
	pmd_t *pmdp;
	pud_t pud;
	unsigned long next, end;

	pud = READ_ONCE(*pudp);

	if (!pud_table(pud)) {
		VM_WARN_ON(1);
		return 1;
	}

	table = pmd_offset(pudp, addr);
	pmdp = table;
	next = addr;
	end = addr + PUD_SIZE;
	do {
		pmd_free_pte_page(pmdp, next);
	} while (pmdp++, next += PMD_SIZE, next != end);

	pud_clear(pudp);
	__flush_tlb_kernel_pgtable(addr);
	pmd_free(NULL, table);
	return 1;
}

int p4d_free_pud_page(p4d_t *p4d, unsigned long addr)
{
	return 0;	/* Don't attempt a block mapping */
}

#ifdef CONFIG_MEMORY_HOTPLUG
int arch_add_memory(int nid, u64 start, u64 size, struct vmem_altmap *altmap,
		    bool want_memblock)
{
	int flags = 0;

	if (rodata_full || debug_pagealloc_enabled())
		flags = NO_BLOCK_MAPPINGS | NO_CONT_MAPPINGS;

	__create_pgd_mapping(swapper_pg_dir, start, __phys_to_virt(start),
			     size, PAGE_KERNEL, pgd_pgtable_alloc, flags);

	return __add_pages(nid, start >> PAGE_SHIFT, size >> PAGE_SHIFT,
			   altmap, want_memblock);
}
#endif
