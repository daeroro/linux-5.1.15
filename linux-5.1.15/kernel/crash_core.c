/*
 * crash.c - kernel crash support code.
 * Copyright (C) 2002-2004 Eric Biederman  <ebiederm@xmission.com>
 *
 * This source code is licensed under the GNU General Public License,
 * Version 2.  See the file COPYING for more details.
 */

#include <linux/crash_core.h>
#include <linux/utsname.h>
#include <linux/vmalloc.h>

#include <asm/page.h>
#include <asm/sections.h>

/* vmcoreinfo stuff */
unsigned char *vmcoreinfo_data;
size_t vmcoreinfo_size;
u32 *vmcoreinfo_note;

/* trusted vmcoreinfo, e.g. we can make a copy in the crash memory */
static unsigned char *vmcoreinfo_data_safecopy;

/*
 * parsing the "crashkernel" commandline
 *
 * this code is intended to be called from architecture specific code
 */


/*
 * This function parses command lines in the format
 *
 *   crashkernel=ramsize-range:size[,...][@offset]
 *
 * The function returns 0 on success and -EINVAL on failure.
 */
/*
	parse_crashkernel_mem() :

	cmdline="start-end:size[,...][@offset]" 형태로 문자열이 전달된 경우
	','로 구분한 마지막 range에서 size를 파싱하여 출력 인수 crash_size에 담고,
	@offset를 파싱하여 crash_base에 담은 후 성공리에 0을 리턴한다.
	- 만일 range가 system_ram을 초과하는 경우에는 에러를 리턴한다.
*/
static int __init parse_crashkernel_mem(char *cmdline,
					unsigned long long system_ram,
					unsigned long long *crash_size,
					unsigned long long *crash_base)
{
	char *cur = cmdline, *tmp;

	/* for each entry of the comma-separated list */
	do {
		unsigned long long start, end = ULLONG_MAX, size;

		/* get the start of the range */
		/*
			cur 문자열을 파싱하여 start에 시작 주소를 알아오고 tmp는 다음 문자열을 가리킴
		*/
		start = memparse(cur, &tmp);
		if (cur == tmp) {
			pr_warn("crashkernel: Memory value expected\n");
			return -EINVAL;
		}
		/*
		   	다음 문자열이 '-'이 아니면 경고 메시지를 출력하고 에러를 리턴한다.
		*/
		cur = tmp;
		if (*cur != '-') {
			pr_warn("crashkernel: '-' expected\n");
			return -EINVAL;
		}
		cur++;

		/* if no ':' is here, than we read the end */
		/*
			':' 문자열이 아니면 cur 문자열을 파싱하여 end에 끝 주소를 알아오고
			tmp는 다음 문자열을 가리킨다.
		*/
		if (*cur != ':') {
			end = memparse(cur, &tmp);
			if (cur == tmp) {
				pr_warn("crashkernel: Memory value expected\n");
				return -EINVAL;
			}
			cur = tmp;
			if (end <= start) {
				pr_warn("crashkernel: end <= start\n");
				return -EINVAL;
			}
		}
		
		/*	
			다음 문자열이 ':'가 아니면 경고 메세지를 출력하고 에러를 리턴한다.
		*/
		if (*cur != ':') {
			pr_warn("crashkernel: ':' expected\n");
			return -EINVAL;
		}
		cur++;

		/*
			cur를 파싱하여 size를 읽는다.
		*/
		size = memparse(cur, &tmp);
		if (cur == tmp) {
			pr_warn("Memory value expected\n");
			return -EINVAL;
		}
		cur = tmp;
		/*
		   	읽어온 size가 system_ram보다 같거나 크면 에러
		*/
		if (size >= system_ram) {
			pr_warn("crashkernel: invalid size\n");
			return -EINVAL;
		}

		/* match ? */
		/*
		   	파싱한 start, end의 범위가 system_ram 범위를 포함하면 
			crash_size를 갱신하고 반복문 종료
		*/
		if (system_ram >= start && system_ram < end) {
			*crash_size = size;
			break;
		}
	/*
	   	"start1-end1:size1,start2-end2:size2,..."로 문자열이 들어오는 것 같음..
		그 중에서 마지막 start-end:size를 선택
	*/
	} while (*cur++ == ',');

	/*
	   	crash_size가 0이상이면 cur문자열이 ' '또는 '@'가 나올 때 까지 cur 증가
		@offset 형식을 찾아서 crash_base를 갱신 
	*/
	if (*crash_size > 0) {
		while (*cur && *cur != ' ' && *cur != '@')
			cur++;
		if (*cur == '@') {
			cur++;
			*crash_base = memparse(cur, &tmp);
			if (cur == tmp) {
				pr_warn("Memory value expected after '@'\n");
				return -EINVAL;
			}
		}
	} else
		pr_info("crashkernel size resulted in zero bytes\n");

	return 0;
}

/*
 * That function parses "simple" (old) crashkernel command lines like
 *
 *	crashkernel=size[@offset]
 *
 * It returns 0 on success and -EINVAL on failure.
 */
/*
	parse_crashkernel_simple()

	: cmdline에 "size[@offset]" 형태인 경우
	  이를 파싱하여 size 부분을 crash_size에 담고
	  offset 부분을 crash_base에 담는다.
*/
static int __init parse_crashkernel_simple(char *cmdline,
					   unsigned long long *crash_size,
					   unsigned long long *crash_base)
{
	char *cur = cmdline;

	/*
	   	cmdline에서 size를 파싱하여 crash_size에 담고
		cur에는 파싱한 문자열의 끝+1의 위치를 담는다.
	*/
	*crash_size = memparse(cmdline, &cur);
	if (cmdline == cur) {
		pr_warn("crashkernel: memory value expected\n");
		return -EINVAL;
	}

	/*
	   	다음 문자가 '@'인 경우 crash_base에 '@' 문자 다음을 파싱하여 가져온다.
	*/
	if (*cur == '@')
		*crash_base = memparse(cur+1, &cur);
	/*
		다음 문자가 space 문자 또는 null이 아닌 다른 문자인 경우
		경고 메세지를 출력하고 에러로 리턴한다.
	*/
	else if (*cur != ' ' && *cur != '\0') {
		pr_warn("crashkernel: unrecognized char: %c\n", *cur);
		return -EINVAL;
	}

	return 0;
}

#define SUFFIX_HIGH 0
#define SUFFIX_LOW  1
#define SUFFIX_NULL 2
static __initdata char *suffix_tbl[] = {
	[SUFFIX_HIGH] = ",high",
	[SUFFIX_LOW]  = ",low",
	[SUFFIX_NULL] = NULL,
};

/*
 * That function parses "suffix"  crashkernel command lines like
 *
 *	crashkernel=size,[high|low]
 *
 * It returns 0 on success and -EINVAL on failure.
 */
/*
	parse_crashkernel_suffix()

	: suffix 문자열로 끝나는 cmdline 문자열을 파싱하여 crashsize를 리턴한다.
*/
static int __init parse_crashkernel_suffix(char *cmdline,
					   unsigned long long	*crash_size,
					   const char *suffix)
{
	char *cur = cmdline;

	/*
		사이즈를 알아오고 cur에는 파싱 문자열의 끝+1 의 위치를 담는다.

		ex) cmdlne="64K,high"

		-> crash_size = 65536
		   cur=",high"
	*/
	*crash_size = memparse(cmdline, &cur);
	if (cmdline == cur) {
		pr_warn("crashkernel: memory value expected\n");
		return -EINVAL;
	}

	/* check with suffix */
	/*
	   	cur 문자열에서 인수로 지정한 suffix 문자열과 다르면
		경고 메세지 출력하고 에러로 리턴한다.
	*/
	if (strncmp(cur, suffix, strlen(suffix))) {
		pr_warn("crashkernel: unrecognized char: %c\n", *cur);
		return -EINVAL;
	}

	// cur이 suffix 다음 문자를 가리키도록 함
	cur += strlen(suffix);
	/*
		suffix 문자열 다음 문자가 space 또는 null 문자가 아닌 경우
		경고 메세지를 출력하고 에러로 리턴한다.
	*/
	if (*cur != ' ' && *cur != '\0') {
		pr_warn("crashkernel: unrecognized char: %c\n", *cur);
		return -EINVAL;
	}

	return 0;
}

static __init char *get_last_crashkernel(char *cmdline,
			     const char *name,
			     const char *suffix)
{
	char *p = cmdline, *ck_cmdline = NULL;

	/* find crashkernel and use the last one if there are more */
	/*
		cmdline으로 받은 문자열 중 name("crashkernel=") 문자열이 있는지 찾아본다.
	*/
	p = strstr(p, name);
	/*
	   	문자열이 검색된 경우 그 위치부터 space 문자열 또는 문자열의 끝가지 루프를 돈다.
	*/
	while (p) {
		char *end_p = strchr(p, ' ');
		char *q;

		// end_p에는 "crashkernel="의 끝을 저장한다.
		if (!end_p)
			end_p = p + strlen(p);

		/*
			suffix 인수가 지정되지 않은 경우 suffix_tbl[] 배열 수 만큼 루프를 돈다.
		*/
		if (!suffix) {
			int i;

			/* skip the one with any known suffix */
			for (i = 0; suffix_tbl[i]; i++) {
				//q에는 "crashkernel=~~"에서 suffix의 위치를 저장
				q = end_p - strlen(suffix_tbl[i]);
				// suffix_tbl[]과 q를 비교하여 일치하면 next로
				// suffix 인수가 지정되지 않은 "crashkernel=~~"을 찾기 위함
				if (!strncmp(q, suffix_tbl[i],
					     strlen(suffix_tbl[i])))
					goto next;
			}
			ck_cmdline = p;
		} else {
			/*
				인수가 지정된 경우, 인수로 지정한 suffix 문자열이 발견되는 경우
				일단 ck_cmdline에 발견된 위치를 기억한다.
			*/
			q = end_p - strlen(suffix);
			if (!strncmp(q, suffix, strlen(suffix)))
				ck_cmdline = p;
		}
next:
		/*
		   	발견된 위치 +1에서 다시 name 문자열을 찾아보고 발견되지 않으면
			루프 조건에 의해 루프를 빠져나온다.
		*/
		p = strstr(p+1, name);
	}

	if (!ck_cmdline)
		return NULL;

	return ck_cmdline;
}

/*
	__parse_crashkernel() : crash_size와 crash_base 값을 알아오는데
							3가지 문법 형태에 따라 호출함수를 달리한다.
	1) suffix가 주어진 경우
	   - "64M,high"
	2) ':'문자로 구분된 range가 주어진 경우
	   - "xxx-yyy:64M@0"
	3) 단순히 사이즈(및 시작 주소)가 주어진 경우
	   - "64M@0"
*/
static int __init __parse_crashkernel(char *cmdline,
			     unsigned long long system_ram,
			     unsigned long long *crash_size,
			     unsigned long long *crash_base,
			     const char *name,
			     const char *suffix)
{
	char	*first_colon, *first_space;
	char	*ck_cmdline;

	BUG_ON(!crash_size || !crash_base);
	*crash_size = 0;
	*crash_base = 0;

	/*
	   cmdline에서 name으로 검색된 마지막 위치에서 suffix가 일치하는 문자열을 알아온다.
	   
	   ex) cmdline="console=ttyS0 crashkernel=128M@0"
	   
	   -  name="crashkernel="
	      suffix=null
	   -> ck_cmdline="crashkernel=128M@0"
	*/
	ck_cmdline = get_last_crashkernel(cmdline, name, suffix);

	if (!ck_cmdline)
		return -EINVAL;

	/*
		ck_cmdline이 "crashkernel=" 문자열 다음을 가리키게 한다.
	*/
	ck_cmdline += strlen(name);

	/*
		1) suffix가 주어진 경우,
		   - suffix 문자열로 끝나는 cmdline 문자열을 파싱하여
		     crashsize를 리턴한다.
	*/
	if (suffix)
		return parse_crashkernel_suffix(ck_cmdline, crash_size,
				suffix);
	/*
	 * if the commandline contains a ':', then that's the extended
	 * syntax -- if not, it must be the classic syntax
	 */
	/*
	    2) 
	    first_colon : 처음 발견되는 ":" 문자열을 찾아본다.
		first_space : 처음 발견되는 space 문자열을 찾아본다.
	*/
	first_colon = strchr(ck_cmdline, ':');
	first_space = strchr(ck_cmdline, ' ');
	/*
	   	":"문자열이 space 문자열 이전에 있는 경우
		cmdline="ramsize-range:size[,...][@offset]"형태로 문자열이 전달되게 되는데
		','로 구분한 마지막 range에서 size를 파싱하여 출력 인수 crash_size에 담고,
		@offset를 파싱하여 crash_base에 담은 후 성공리에 0을 리턴한다.
		만일 range가 system_ram을 초과하는 경우에는 에러를 리턴한다.
	*/
	if (first_colon && (!first_space || first_colon < first_space))
		return parse_crashkernel_mem(ck_cmdline, system_ram,
				crash_size, crash_base);

	/*
		3) 단순하게 cmdline="size[@offset]" 형태로 문자열이 전달되는 경우
		size를 파싱하여 crash_size에 담고, @offset를 파싱하여 crash_base에 담는다.
	*/
	return parse_crashkernel_simple(ck_cmdline, crash_size, crash_base);
}

/*
 * That function is the entry point for command line parsing and should be
 * called from the arch-specific code.
 */
/*
	parse_crashkernel() : cmdline 문자열을 파싱하여 crash_base와 crash_size 값을 알아온다.
*/
int __init parse_crashkernel(char *cmdline,
			     unsigned long long system_ram,
			     unsigned long long *crash_size,
			     unsigned long long *crash_base)
{
	return __parse_crashkernel(cmdline, system_ram, crash_size, crash_base,
					"crashkernel=", NULL);
}

int __init parse_crashkernel_high(char *cmdline,
			     unsigned long long system_ram,
			     unsigned long long *crash_size,
			     unsigned long long *crash_base)
{
	return __parse_crashkernel(cmdline, system_ram, crash_size, crash_base,
				"crashkernel=", suffix_tbl[SUFFIX_HIGH]);
}

int __init parse_crashkernel_low(char *cmdline,
			     unsigned long long system_ram,
			     unsigned long long *crash_size,
			     unsigned long long *crash_base)
{
	return __parse_crashkernel(cmdline, system_ram, crash_size, crash_base,
				"crashkernel=", suffix_tbl[SUFFIX_LOW]);
}

Elf_Word *append_elf_note(Elf_Word *buf, char *name, unsigned int type,
			  void *data, size_t data_len)
{
	struct elf_note *note = (struct elf_note *)buf;

	note->n_namesz = strlen(name) + 1;
	note->n_descsz = data_len;
	note->n_type   = type;
	buf += DIV_ROUND_UP(sizeof(*note), sizeof(Elf_Word));
	memcpy(buf, name, note->n_namesz);
	buf += DIV_ROUND_UP(note->n_namesz, sizeof(Elf_Word));
	memcpy(buf, data, data_len);
	buf += DIV_ROUND_UP(data_len, sizeof(Elf_Word));

	return buf;
}

void final_note(Elf_Word *buf)
{
	memset(buf, 0, sizeof(struct elf_note));
}

static void update_vmcoreinfo_note(void)
{
	u32 *buf = vmcoreinfo_note;

	if (!vmcoreinfo_size)
		return;
	buf = append_elf_note(buf, VMCOREINFO_NOTE_NAME, 0, vmcoreinfo_data,
			      vmcoreinfo_size);
	final_note(buf);
}

void crash_update_vmcoreinfo_safecopy(void *ptr)
{
	if (ptr)
		memcpy(ptr, vmcoreinfo_data, vmcoreinfo_size);

	vmcoreinfo_data_safecopy = ptr;
}

void crash_save_vmcoreinfo(void)
{
	if (!vmcoreinfo_note)
		return;

	/* Use the safe copy to generate vmcoreinfo note if have */
	if (vmcoreinfo_data_safecopy)
		vmcoreinfo_data = vmcoreinfo_data_safecopy;

	vmcoreinfo_append_str("CRASHTIME=%lld\n", ktime_get_real_seconds());
	update_vmcoreinfo_note();
}

void vmcoreinfo_append_str(const char *fmt, ...)
{
	va_list args;
	char buf[0x50];
	size_t r;

	va_start(args, fmt);
	r = vscnprintf(buf, sizeof(buf), fmt, args);
	va_end(args);

	r = min(r, (size_t)VMCOREINFO_BYTES - vmcoreinfo_size);

	memcpy(&vmcoreinfo_data[vmcoreinfo_size], buf, r);

	vmcoreinfo_size += r;
}

/*
 * provide an empty default implementation here -- architecture
 * code may override this
 */
void __weak arch_crash_save_vmcoreinfo(void)
{}

phys_addr_t __weak paddr_vmcoreinfo_note(void)
{
	return __pa(vmcoreinfo_note);
}
EXPORT_SYMBOL(paddr_vmcoreinfo_note);

static int __init crash_save_vmcoreinfo_init(void)
{
	vmcoreinfo_data = (unsigned char *)get_zeroed_page(GFP_KERNEL);
	if (!vmcoreinfo_data) {
		pr_warn("Memory allocation for vmcoreinfo_data failed\n");
		return -ENOMEM;
	}

	vmcoreinfo_note = alloc_pages_exact(VMCOREINFO_NOTE_SIZE,
						GFP_KERNEL | __GFP_ZERO);
	if (!vmcoreinfo_note) {
		free_page((unsigned long)vmcoreinfo_data);
		vmcoreinfo_data = NULL;
		pr_warn("Memory allocation for vmcoreinfo_note failed\n");
		return -ENOMEM;
	}

	VMCOREINFO_OSRELEASE(init_uts_ns.name.release);
	VMCOREINFO_PAGESIZE(PAGE_SIZE);

	VMCOREINFO_SYMBOL(init_uts_ns);
	VMCOREINFO_SYMBOL(node_online_map);
#ifdef CONFIG_MMU
	VMCOREINFO_SYMBOL_ARRAY(swapper_pg_dir);
#endif
	VMCOREINFO_SYMBOL(_stext);
	VMCOREINFO_SYMBOL(vmap_area_list);

#ifndef CONFIG_NEED_MULTIPLE_NODES
	VMCOREINFO_SYMBOL(mem_map);
	VMCOREINFO_SYMBOL(contig_page_data);
#endif
#ifdef CONFIG_SPARSEMEM
	VMCOREINFO_SYMBOL_ARRAY(mem_section);
	VMCOREINFO_LENGTH(mem_section, NR_SECTION_ROOTS);
	VMCOREINFO_STRUCT_SIZE(mem_section);
	VMCOREINFO_OFFSET(mem_section, section_mem_map);
#endif
	VMCOREINFO_STRUCT_SIZE(page);
	VMCOREINFO_STRUCT_SIZE(pglist_data);
	VMCOREINFO_STRUCT_SIZE(zone);
	VMCOREINFO_STRUCT_SIZE(free_area);
	VMCOREINFO_STRUCT_SIZE(list_head);
	VMCOREINFO_SIZE(nodemask_t);
	VMCOREINFO_OFFSET(page, flags);
	VMCOREINFO_OFFSET(page, _refcount);
	VMCOREINFO_OFFSET(page, mapping);
	VMCOREINFO_OFFSET(page, lru);
	VMCOREINFO_OFFSET(page, _mapcount);
	VMCOREINFO_OFFSET(page, private);
	VMCOREINFO_OFFSET(page, compound_dtor);
	VMCOREINFO_OFFSET(page, compound_order);
	VMCOREINFO_OFFSET(page, compound_head);
	VMCOREINFO_OFFSET(pglist_data, node_zones);
	VMCOREINFO_OFFSET(pglist_data, nr_zones);
#ifdef CONFIG_FLAT_NODE_MEM_MAP
	VMCOREINFO_OFFSET(pglist_data, node_mem_map);
#endif
	VMCOREINFO_OFFSET(pglist_data, node_start_pfn);
	VMCOREINFO_OFFSET(pglist_data, node_spanned_pages);
	VMCOREINFO_OFFSET(pglist_data, node_id);
	VMCOREINFO_OFFSET(zone, free_area);
	VMCOREINFO_OFFSET(zone, vm_stat);
	VMCOREINFO_OFFSET(zone, spanned_pages);
	VMCOREINFO_OFFSET(free_area, free_list);
	VMCOREINFO_OFFSET(list_head, next);
	VMCOREINFO_OFFSET(list_head, prev);
	VMCOREINFO_OFFSET(vmap_area, va_start);
	VMCOREINFO_OFFSET(vmap_area, list);
	VMCOREINFO_LENGTH(zone.free_area, MAX_ORDER);
	log_buf_vmcoreinfo_setup();
	VMCOREINFO_LENGTH(free_area.free_list, MIGRATE_TYPES);
	VMCOREINFO_NUMBER(NR_FREE_PAGES);
	VMCOREINFO_NUMBER(PG_lru);
	VMCOREINFO_NUMBER(PG_private);
	VMCOREINFO_NUMBER(PG_swapcache);
	VMCOREINFO_NUMBER(PG_swapbacked);
	VMCOREINFO_NUMBER(PG_slab);
#ifdef CONFIG_MEMORY_FAILURE
	VMCOREINFO_NUMBER(PG_hwpoison);
#endif
	VMCOREINFO_NUMBER(PG_head_mask);
#define PAGE_BUDDY_MAPCOUNT_VALUE	(~PG_buddy)
	VMCOREINFO_NUMBER(PAGE_BUDDY_MAPCOUNT_VALUE);
#ifdef CONFIG_HUGETLB_PAGE
	VMCOREINFO_NUMBER(HUGETLB_PAGE_DTOR);
#define PAGE_OFFLINE_MAPCOUNT_VALUE	(~PG_offline)
	VMCOREINFO_NUMBER(PAGE_OFFLINE_MAPCOUNT_VALUE);
#endif

	arch_crash_save_vmcoreinfo();
	update_vmcoreinfo_note();

	return 0;
}

subsys_initcall(crash_save_vmcoreinfo_init);
