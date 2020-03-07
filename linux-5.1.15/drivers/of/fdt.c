// SPDX-License-Identifier: GPL-2.0
/*
 * Functions for working with the Flattened Device Tree data format
 *
 * Copyright 2009 Benjamin Herrenschmidt, IBM Corp
 * benh@kernel.crashing.org
 */

#define pr_fmt(fmt)	"OF: fdt: " fmt

#include <linux/crc32.h>
#include <linux/kernel.h>
#include <linux/initrd.h>
#include <linux/memblock.h>
#include <linux/mutex.h>
#include <linux/of.h>
#include <linux/of_fdt.h>
#include <linux/of_reserved_mem.h>
#include <linux/sizes.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/libfdt.h>
#include <linux/debugfs.h>
#include <linux/serial_core.h>
#include <linux/sysfs.h>

#include <asm/setup.h>  /* for COMMAND_LINE_SIZE */
#include <asm/page.h>

#include "of_private.h"

/*
 * of_fdt_limit_memory - limit the number of regions in the /memory node
 * @limit: maximum entries
 *
 * Adjust the flattened device tree to have at most 'limit' number of
 * memory entries in the /memory node. This function may be called
 * any time after initial_boot_param is set.
 */
void of_fdt_limit_memory(int limit)
{
	int memory;
	int len;
	const void *val;
	int nr_address_cells = OF_ROOT_NODE_ADDR_CELLS_DEFAULT;
	int nr_size_cells = OF_ROOT_NODE_SIZE_CELLS_DEFAULT;
	const __be32 *addr_prop;
	const __be32 *size_prop;
	int root_offset;
	int cell_size;

	root_offset = fdt_path_offset(initial_boot_params, "/");
	if (root_offset < 0)
		return;

	addr_prop = fdt_getprop(initial_boot_params, root_offset,
				"#address-cells", NULL);
	if (addr_prop)
		nr_address_cells = fdt32_to_cpu(*addr_prop);

	size_prop = fdt_getprop(initial_boot_params, root_offset,
				"#size-cells", NULL);
	if (size_prop)
		nr_size_cells = fdt32_to_cpu(*size_prop);

	cell_size = sizeof(uint32_t)*(nr_address_cells + nr_size_cells);

	memory = fdt_path_offset(initial_boot_params, "/memory");
	if (memory > 0) {
		val = fdt_getprop(initial_boot_params, memory, "reg", &len);
		if (len > limit*cell_size) {
			len = limit*cell_size;
			pr_debug("Limiting number of entries to %d\n", limit);
			fdt_setprop(initial_boot_params, memory, "reg", val,
					len);
		}
	}
}

/**
 * of_fdt_is_compatible - Return true if given node from the given blob has
 * compat in its compatible list
 * @blob: A device tree blob
 * @node: node to test
 * @compat: compatible string to compare with compatible list.
 *
 * On match, returns a non-zero value with smaller values returned for more
 * specific compatible values.
 */
static int of_fdt_is_compatible(const void *blob,
		      unsigned long node, const char *compat)
{
	const char *cp;
	int cplen;
	unsigned long l, score = 0;

	cp = fdt_getprop(blob, node, "compatible", &cplen);
	if (cp == NULL)
		return 0;
	while (cplen > 0) {
		score++;
		if (of_compat_cmp(cp, compat, strlen(compat)) == 0)
			return score;
		l = strlen(cp) + 1;
		cp += l;
		cplen -= l;
	}

	return 0;
}

/**
 * of_fdt_is_big_endian - Return true if given node needs BE MMIO accesses
 * @blob: A device tree blob
 * @node: node to test
 *
 * Returns true if the node has a "big-endian" property, or if the kernel
 * was compiled for BE *and* the node has a "native-endian" property.
 * Returns false otherwise.
 */
bool of_fdt_is_big_endian(const void *blob, unsigned long node)
{
	if (fdt_getprop(blob, node, "big-endian", NULL))
		return true;
	if (IS_ENABLED(CONFIG_CPU_BIG_ENDIAN) &&
	    fdt_getprop(blob, node, "native-endian", NULL))
		return true;
	return false;
}

/*
	of_fdt_device_is_available()

	: node에서 "status" 속성을 찾는다
	- "status" 속성이 없거나, "ok" or "okay" 값을 가지면 true를 반환
*/
static bool of_fdt_device_is_available(const void *blob, unsigned long node)
{
	const char *status = fdt_getprop(blob, node, "status", NULL);

	if (!status)
		return true;

	if (!strcmp(status, "ok") || !strcmp(status, "okay"))
		return true;

	return false;
}

/**
 * of_fdt_match - Return true if node matches a list of compatible values
 */
int of_fdt_match(const void *blob, unsigned long node,
                 const char *const *compat)
{
	unsigned int tmp, score = 0;

	if (!compat)
		return 0;

	while (*compat) {
		tmp = of_fdt_is_compatible(blob, node, *compat);
		if (tmp && (score == 0 || (tmp < score)))
			score = tmp;
		compat++;
	}

	return score;
}
/*
	unflatten_dt_alloc() : *mem을 align 단위로 round up하고 리턴하며
							입출력 인수 *mem 값은 size만큼 증가시킨다.
*/
static void *unflatten_dt_alloc(void **mem, unsigned long size,
				       unsigned long align)
{
	void *res;

	*mem = PTR_ALIGN(*mem, align);
	res = *mem;
	*mem += size;

	return res;
}

/*
	populate_properties() : 속성을 파싱하여 속성 정보로 변환

	- property 구조체의 크기만큼의 영역을 사용한다.
	- pp->name이 DTB의 속성명을 가리키게 한다.
	- pp->length에 속성 값의 크기를 설정한다.
	- pp->value에 속성 값을 설정한다.
	- 속성들 중 마지막에 현재 속성을 연결한다.
	- 기존 속성 pp->next에 현재 속성을 연결한다.
	
	useage) 
			populate_properties(blob, offset, mem, np, pathp, dryrun);
*/
static void populate_properties(const void *blob,
				int offset,
				void **mem,
				struct device_node *np,
				const char *nodename,
				bool dryrun)
{
	struct property *pp, **pprev = NULL;
	int cur;
	bool has_name = false;

	pprev = &np->properties;
	
	/*
		offset에 있는 노드의 첫 속성부터 마지막 속성까지 루프를 돈다.
	*/
	for (cur = fdt_first_property_offset(blob, offset);
	     cur >= 0;
	     cur = fdt_next_property_offset(blob, cur)) {
		const __be32 *val;
		const char *pname;
		u32 sz;
	
		/*
			속성명을 pname에, 속성 데이터 크기를 sz에 저장하고, 속성 데이터 val를 구하는데
			발견하지 못하면 에러를 호출하고 다음 속성으로 넘어간다.
		*/
		val = fdt_getprop_by_offset(blob, cur, &pname, &sz);
		if (!val) {
			pr_warn("Cannot locate property at 0x%x\n", cur);
			continue;
		}

		/*
			pname이 NULL인 경우에도 에러를 호출하고 다음 속성으로 넘어간다.
		*/
		if (!pname) {
			pr_warn("Cannot find property name at 0x%x\n", cur);
			continue;
		}

		/*
			속성명에 "name"이 있다면 has_name = 1을 설정한다.
			- has_name은 현재 노드 내에서 "name" 속성명이 하나도 발견되지 않으면 추가로
			  "name"이라는 속성명을 만들려고 할 때 사용하는 플래그이다.
			- compact 노드명을 사용하는 DTB 버전 0x10에서는 name 속성이 구성되어 있지 않지만
			  확장 포맷을 구성할 때는 각 노드의 name 속성이 필요하다.
		*/
		if (!strcmp(pname, "name"))
			has_name = true;

		/*
			property 구조체 크기 단위로 property 구조체 크기만큼 사용할 pp 주소를 얻어내고
			mem 주소는 그만큼 증가시킨다.
		*/
		pp = unflatten_dt_alloc(mem, sizeof(struct property),
					__alignof__(struct property));
		/*
			가짜 동작(크기만 알아올 목적)의 경우에는 다음 속성으로 넘어간다.
		*/
		if (dryrun)
			continue;

		/* We accept flattened tree phandles either in
		 * ePAPR-style "phandle" properties, or the
		 * legacy "linux,phandle" properties.  If both
		 * appear and have different values, things
		 * will get weird. Don't do that.
		 */
		/*
			속성명이 "phandle"또는 "linux,phandle"인 경우,
			np->phandle(노드의 phandle)이 처음 설정될 때 속성 데이터 val를 설정
		*/
		if (!strcmp(pname, "phandle") ||
		    !strcmp(pname, "linux,phandle")) {
			if (!np->phandle)
				np->phandle = be32_to_cpup(val);
		}

		/* And we process the "ibm,phandle" property
		 * used in pSeries dynamic device tree
		 * stuff
		 */
		/*
			속성명이 "ibm,phandle"인 경우, np->phandle(노드의 phandle)에 속성 데이터 val 저장
		*/
		if (!strcmp(pname, "ibm,phandle"))
			np->phandle = be32_to_cpup(val);
		/*
			구성할 property 구조체의 name에 속성명(pname)을 가리키게 하고,
			length에는 sz를 설정하고, value에는 속성 데이터를 설정한다.
		*/
		pp->name   = (char *)pname;
		pp->length = sz;
		pp->value  = (__be32 *)val;

		/*
			노드의 첫 속성이 새로 만들어진 속성 구조체를 가리키게 하고,
			pprev에 &pp->next를 설정하여 이후에 추가되는 속성이 계속 다음에 추가될 수 있도록 함
		*/
		*pprev     = pp;
		pprev      = &pp->next;
	}

	/* With version 0x10 we may not have the name property,
	 * recreate it here from the unit name if absent
	 */
	/*
		name property(has_name 플래그가 NULL)가 없다면 다음과 같이 새롭게 구성한다.

		- property구조체 + 속성값 길이(주소를 제외한 compact 노드명 + 1)만큼 영역 사용
		- pp->name이 "name"문자열을 가리키게 함
		- pp->length에 속성 값 길이를 설정
		- pp->value가 property 구조체 다음에 위치한 속성 값을 가리키게 하고,
		  그 위치에 주소를 제외한 compact 노드명을 복사한다.
		- 속성들 중 마지막에 현재 속성을 연결한다.
		- 기존 속성 pp->next에 새로 만든 property 구조체를 연결한다.
	*/

	/*
		DTB 버전 0x10이 name 속성이 없으므로 여기서 name 속성을 만든다.
	*/
	if (!has_name) {
		const char *p = nodename, *ps = p, *pa = NULL;
		int len;

		/*
			*p가 NULL이 아닌 동안 루프를 돌며 *p가 '@'를 만나면 pa에 p를 설정
			*p가 '/'를 만나면 ps에 p+1을 설정
		*/
		while (*p) {
			if ((*p) == '@')
				pa = p;
			else if ((*p) == '/')
				ps = p + 1;
			p++;
		}

		/*
			'/'문자가 '@' 문자 뒤에 온다면, 즉 마지막 '/' 문자열 이후에 주소('@' 문자열 없는)
			없는 노드명인 경우에는 pa = p이다(루프가 끝나서 NULL을 가리킨다)
		*/
		if (pa < ps)
			pa = p;
		/*
			len에는 '@' - '/'를 한 후 1을 더한다.

			예)
				- full path 노드명 : pathp = "/abc/a@1000"
				  len = 2("a"+1);

				- compact 노드명 : pathp = "abc@1000"
				  len = 4("abc" + 1)

				- compact 노드명 : pathp = ""(루트 노드)
				  len = 1("" + 1)
		*/
		len = (pa - ps) + 1;

		/*
			property 구조체 단위로 property 구조체 크기 + len(value값에 대한 문자열 길이 +1)
			만큼 사용할 pp 주소를 얻어내고 mem 주소를 그만큼 증가시킨다.
		*/
		pp = unflatten_dt_alloc(mem, sizeof(struct property) + len,
					__alignof__(struct property));

		/*
			속성명을 "name"으로 하고, length와 value 값을 설정한 후,
			속성을 기존 속성의 뒤(속성이 없으면 노드 밑으로)추가한다.
		*/
		if (!dryrun) {
			pp->name   = "name";
			pp->length = len;
			pp->value  = pp + 1;
			*pprev     = pp;
			pprev      = &pp->next;
			memcpy(pp->value, ps, len - 1);
			((char *)pp->value)[len - 1] = 0;
			pr_debug("fixed up name for %s -> %s\n",
				 nodename, (char *)pp->value);
		}
	}

	if (!dryrun)
		*pprev = NULL;
}

/*
	populate_node() : 노드를 파싱하여 디바이스 노드로 변환한다. 성공 시 true 반환
*/
static bool populate_node(const void *blob,
			  int offset,
			  void **mem,
			  struct device_node *dad,
			  struct device_node **pnp,
			  bool dryrun)
{
	struct device_node *np;
	const char *pathp;
	unsigned int l, allocl;

	/*
		노드명(pathp), 노드명 길이(l), 할당 길이(allocl)를 구한다.
		- 노드명이 null인 경우 출력인자 *pnp에 null을 대입한 후 더 이상 처리하지 않고 false
	*/
	pathp = fdt_get_name(blob, offset, &l);
	if (!pathp) {
		*pnp = NULL;
		return false;
	}

	allocl = ++l;

	/*
		device_node 구조체 크기 단위로 device_node 구조체 + 할당 길이(full path 노드명 길이)
		만큼 사용할 np 주소를 얻어내고 mem주소는 그만큼 증가시킴.
	*/
	np = unflatten_dt_alloc(mem, sizeof(struct device_node) + allocl,
				__alignof__(struct device_node));
	
	/*
		2nd pass인 경우 노드(np)를 초기화하고, 노드명(np->full_name)을 지정한 후
		노드 간의 관계를 연결
	*/
	if (!dryrun) {
		char *fn;
		of_node_init(np);
		np->full_name = fn = ((char *)np) + sizeof(*np);

		memcpy(fn, pathp, l);

		if (dad != NULL) {
			np->parent = dad;
			np->sibling = dad->child;
			dad->child = np;
		}
	}
	
	/*
		속성을 파싱하여 속성 정보로 변환한다. 
		- 속성 이름이 없는 경우 "<NULL>" 문자열을 이름으로 지정한다.
	*/
	populate_properties(blob, offset, mem, np, pathp, dryrun);
	if (!dryrun) {
		np->name = of_get_property(np, "name", NULL);
		if (!np->name)
			np->name = "<NULL>";
	}

	/*
		출력 인자 *pnp에 디바이스 노드(np)를 지정하고 true를 반환한다.
	*/
	*pnp = np;
	return true;
}

/*
	reverse_nodes() : child 노드를 확장 포멧으로 등록할 때 가장 마지막에 등록한 노드가
					  가장 앞에 등록을 했기 때문에 순서가 바뀌어 있다.
					- 따라서 노드를 DTB 순서대로 만들기 위해 각 child 노드를 reverse한다.
*/
static void reverse_nodes(struct device_node *parent)
{
	struct device_node *child, *next;

	/* In-depth first */
	child = parent->child;
	while (child) {
		reverse_nodes(child);

		child = child->sibling;
	}

	/* Reverse the nodes in the child list */
	child = parent->child;
	parent->child = NULL;
	while (child) {
		next = child->sibling;

		child->sibling = parent->child;
		parent->child = child;
		child = next;
	}
}

/**
 * unflatten_dt_nodes - Alloc and populate a device_node from the flat tree
 * @blob: The parent device tree blob
 * @mem: Memory chunk to use for allocating device nodes and properties
 * @dad: Parent struct device_node
 * @nodepp: The device_node tree created by the call
 *
 * It returns the size of unflattened device tree or error code
 */
/*
	unflatten_dt_nodes() : DTB를 device_node, property 구조체 배열로 변환하기
	
	- DTB를 파싱하여 device_node, property 구조체 배열로 변환한다.
*/
static int unflatten_dt_nodes(const void *blob,
			      void *mem,
			      struct device_node *dad,
			      struct device_node **nodepp)
{
	struct device_node *root;
	int offset = 0, depth = 0, initial_depth = 0;
#define FDT_MAX_DEPTH	64
	struct device_node *nps[FDT_MAX_DEPTH];
	/*
		mem이 지정되지 않았으면 dryrun이 true가 된다.
	*/
	void *base = mem;
	bool dryrun = !base;

	/*
		출력인자 nodepp에 null 대입
	*/
	if (nodepp)
		*nodepp = NULL;

	/*
	 * We're unflattening device sub-tree if @dad is valid. There are
	 * possibly multiple nodes in the first level of depth. We need
	 * set @depth to 1 to make fdt_next_node() happy as it bails
	 * immediately when negative @depth is found. Otherwise, the device
	 * nodes except the first one won't be unflattened successfully.
	 */
	/*
		dad가 지정된 경우에 한해 depth와 initial_depth를 1부터 시작
	*/
	if (dad)
		depth = initial_depth = 1;

	root = dad;
	nps[depth] = dad;

	for (offset = 0;
	     offset >= 0 && depth >= initial_depth;
	     offset = fdt_next_node(blob, offset, &depth)) {
		if (WARN_ON_ONCE(depth >= FDT_MAX_DEPTH))
			continue;

		/*
			CONFIG_OF_KOBJ 가 활성화되어 있지 않거나 
			해당 offset의 노드의 status가 "ok"/"okay" 상태가 아닌 경우에는 skip한다.
		*/
		if (!IS_ENABLED(CONFIG_OF_KOBJ) &&
		    !of_fdt_device_is_available(blob, offset))
			continue;

		/*
			노드를 활성화 한다.
			- 실패 시 현재 까지 변환한 사이즈인 mem-base를 반환한다.
		*/
		if (!populate_node(blob, offset, &mem, nps[depth],
				   &nps[depth+1], dryrun))
			return mem - base;
		
		/*
			__unflatten_device_tree()의 2nd pass에서 nodepp에 현재 노드를 지정한다.
			- 단 한번만 지정한다.	
		*/
		if (!dryrun && nodepp && !*nodepp)
			*nodepp = nps[depth+1];
		/*
			2nd pass에서 root가 지정되지 않은 경우 현재 노드를 루트로 지정한다.
		*/
		if (!dryrun && !root)
			root = nps[depth+1];
	}

	/*
		fdt_next_node()에서 노드 파싱에 문제가 있는 경우 에러를 반환한다.
	*/
	if (offset < 0 && offset != -FDT_ERR_NOTFOUND) {
		pr_err("Error %d processing FDT\n", offset);
		return -EINVAL;
	}

	/*
	 * Reverse the child list. Some drivers assumes node order matches .dts
	 * node order
	 */
	/*
		2nd pass인 경우 DTB 순서대로 만들기 위해 각 child 노드를 reverse한다.
	*/
	if (!dryrun)
		reverse_nodes(root);

	/*
		지금까지 변환한 사이즈를 반환한다.
	*/
	return mem - base;
}

/**
 * __unflatten_device_tree - create tree of device_nodes from flat blob
 *
 * unflattens a device-tree, creating the
 * tree of struct device_node. It also fills the "name" and "type"
 * pointers of the nodes so the normal device-tree walking functions
 * can be used.
 * @blob: The blob to expand
 * @dad: Parent device node
 * @mynodes: The device_node tree created by the call
 * @dt_alloc: An allocator that provides a virtual address to memory
 * for the resulting tree
 * @detached: if true set OF_DETACHED on @mynodes
 *
 * Returns NULL on failure or the memory chunk containing the unflattened
 * device tree on success.
 */

/*
	__unflatten_device_tree() : DTB를 확장 포맷으로 변환하기

	- DTB를 파싱하여 확장 포맷으로 변환한 후 of_root 전역 변수가 가리키게 한다.
*/
void *__unflatten_device_tree(const void *blob,
			      struct device_node *dad,
			      struct device_node **mynodes,
			      void *(*dt_alloc)(u64 size, u64 align),
			      bool detached)
{
	int size;
	void *mem;

	pr_debug(" -> unflatten_device_tree()\n");

	if (!blob) {
		pr_debug("No device tree pointer\n");
		return NULL;
	}

	pr_debug("Unflattening device tree:\n");
	pr_debug("magic: %08x\n", fdt_magic(blob));
	pr_debug("size: %08x\n", fdt_totalsize(blob));
	pr_debug("version: %08x\n", fdt_version(blob));

	/*
		DTB의 첫 부분에 위치한 헤더에서 첫 워드를 통해 DTB 데이터 여부를 체크
		- 추가로 지원 가능한 DTB 버전이 0x10 및 0x11인지 확인하여 체크하고
		  다른 경우 출력하고 처리를 하지 않는다.
	*/
	if (fdt_check_header(blob)) {
		pr_err("Invalid device tree blob header\n");
		return NULL;
	}

	/* First pass, scan for size */
	/*
		unflatten_dt_nodes() : 실제 컨버팅 동작을 하지 않고 DTB를 unflatten 할 때 만들어질
		device_node 구조체들과 properties 구조체들의 구성에 필요한 전체 크기의 크기만을 구함
		- 최종 산출된 크기를 워드(4바이트) 단위로 정렬한다.
	*/
	size = unflatten_dt_nodes(blob, NULL, dad, NULL);
	if (size < 0)
		return NULL;

	size = ALIGN(size, 4);
	pr_debug("  size is %d, allocating...\n", size);

	/* Allocate memory for the expanded device tree */
	/*
		인자로 전달받은 dt_alloc 함수를 통해 메모리를 할당받는다.
		- 할당 시의 크기로 위에서 산출한 크기에 추가로 끝부분을 나타내기 위한 
		  4바이트만큼을 추가한다.
		- 정렬 단위는 시스템의 최소 정렬단위가 주어짐, ARM, ARM64는 4바이트이다.
	*/
	mem = dt_alloc(size + 4, __alignof__(struct device_node));
	if (!mem)
		return NULL;

	memset(mem, 0, size);

	/*
		할당된 메모리의 마지막 4바이트에 0xdeadbeef를 저장
		- 경계 침범을 모니터링 하기 위해 사용
	*/
	*(__be32 *)(mem + size) = cpu_to_be32(0xdeadbeef);

	pr_debug("  unflattening %p...\n", mem);

	/* Second pass, do actual unflattening */
	/*
		DTB를 파싱하여 device_node, property 구조체 배열로 변환한다.
	*/
	unflatten_dt_nodes(blob, mem, dad, mynodes);
	/*
		할당된 메모리의 끝에 설치한 경계 침범 값이 오염되었는지 확인하여 경고 출력을 한다.
	*/
	if (be32_to_cpup(mem + size) != 0xdeadbeef)
		pr_warning("End of tree marker overwritten: %08x\n",
			   be32_to_cpup(mem + size));

	if (detached && mynodes) {
		of_node_set_flag(*mynodes, OF_DETACHED);
		pr_debug("unflattened tree is detached\n");
	}

	pr_debug(" <- unflatten_device_tree()\n");
	return mem;
}

static void *kernel_tree_alloc(u64 size, u64 align)
{
	return kzalloc(size, GFP_KERNEL);
}

static DEFINE_MUTEX(of_fdt_unflatten_mutex);

/**
 * of_fdt_unflatten_tree - create tree of device_nodes from flat blob
 * @blob: Flat device tree blob
 * @dad: Parent device node
 * @mynodes: The device tree created by the call
 *
 * unflattens the device-tree passed by the firmware, creating the
 * tree of struct device_node. It also fills the "name" and "type"
 * pointers of the nodes so the normal device-tree walking functions
 * can be used.
 *
 * Returns NULL on failure or the memory chunk containing the unflattened
 * device tree on success.
 */
void *of_fdt_unflatten_tree(const unsigned long *blob,
			    struct device_node *dad,
			    struct device_node **mynodes)
{
	void *mem;

	mutex_lock(&of_fdt_unflatten_mutex);
	mem = __unflatten_device_tree(blob, dad, mynodes, &kernel_tree_alloc,
				      true);
	mutex_unlock(&of_fdt_unflatten_mutex);

	return mem;
}
EXPORT_SYMBOL_GPL(of_fdt_unflatten_tree);

/* Everything below here references initial_boot_params directly. */
int __initdata dt_root_addr_cells;
int __initdata dt_root_size_cells;

void *initial_boot_params;

#ifdef CONFIG_OF_EARLY_FLATTREE

static u32 of_fdt_crc32;

/**
 * res_mem_reserve_reg() - reserve all memory described in 'reg' property
 */
/*
	reserved-memory 노드의 자식 노드에서 속성 'reg'를 memory에 reserve한다. 
*/
static int __init __reserved_mem_reserve_reg(unsigned long node,
					     const char *uname)
{
	int t_len = (dt_root_addr_cells + dt_root_size_cells) * sizeof(__be32);
	phys_addr_t base, size;
	int len;
	const __be32 *prop;
	int nomap, first = 1;

	// 현재 node에서 "reg" 속성 구하기
	prop = of_get_flat_dt_prop(node, "reg", &len);
	if (!prop)
		return -ENOENT;

	// len의 길이 검사
	if (len && len % t_len != 0) {
		pr_err("Reserved memory: invalid reg property in '%s', skipping node.\n",
		       uname);
		return -EINVAL;
	}

	/*
	   reserved-memory 노드의 자식 노드에서 "no-map"에 해당하는 속성이 
	   있으면 -> nomap = 1
	   없으면 -> nomap = 0
	*/
	nomap = of_get_flat_dt_prop(node, "no-map", NULL) != NULL;

	// "reg" 속성 값 읽어서 base, size에 저장
	while (len >= t_len) {
		base = dt_mem_next_cell(dt_root_addr_cells, &prop);
		size = dt_mem_next_cell(dt_root_size_cells, &prop);

		/*
		   size가 있고, 
		   nomap == 1 -> memblock_remove() 수행
		   nomap == 0 -> memblock_reserve() 수행
		*/
		if (size &&
		    early_init_dt_reserve_memory_arch(base, size, nomap) == 0)
			pr_debug("Reserved memory: reserved region for node '%s': base %pa, size %ld MiB\n",
				uname, &base, (unsigned long)size / SZ_1M);
		else
			pr_info("Reserved memory: failed to reserve memory for node '%s': base %pa, size %ld MiB\n",
				uname, &base, (unsigned long)size / SZ_1M);

		len -= t_len;
		if (first) {
			// 전역 배열 reserved_mem[]에 현재 reserved-memory의 정보 저장
			fdt_reserved_mem_save_node(node, uname, base, size);
			first = 0;
		}
	}
	return 0;
}

/**
 * __reserved_mem_check_root() - check if #size-cells, #address-cells provided
 * in /reserved-memory matches the values supported by the current implementation,
 * also check if ranges property has been provided
 */
/*
	__reserved_mem_check_root() 
	
	: "reserved-memory" 노드의 '#size-cells', '#address-cells' 값이
	  dt_root_size_cells, dt_root_addr_cells와 같은 지 비교,
	  'ranges' 속성이 존재하는 지 체크
*/
static int __init __reserved_mem_check_root(unsigned long node)
{
	const __be32 *prop;

	prop = of_get_flat_dt_prop(node, "#size-cells", NULL);
	if (!prop || be32_to_cpup(prop) != dt_root_size_cells)
		return -EINVAL;

	prop = of_get_flat_dt_prop(node, "#address-cells", NULL);
	if (!prop || be32_to_cpup(prop) != dt_root_addr_cells)
		return -EINVAL;

	prop = of_get_flat_dt_prop(node, "ranges", NULL);
	if (!prop)
		return -EINVAL;
	return 0;
}

/**
 * fdt_scan_reserved_mem() - scan a single FDT node for reserved memory
 */
static int __init __fdt_scan_reserved_mem(unsigned long node, const char *uname,
					  int depth, void *data)
{
	static int found;
	int err;

	if (!found && depth == 1 && strcmp(uname, "reserved-memory") == 0) {
		if (__reserved_mem_check_root(node) != 0) {
			pr_err("Reserved memory: unsupported node format, ignoring\n");
			/* break scan */
			return 1;
		}
		found = 1;
		/* scan next node */
		return 0;
	} else if (!found) {
		/* scan next node */
		return 0;
	} else if (found && depth < 2) {
		/* scanning of /reserved-memory has been finished */
		return 1;
	}

	// reserved-memory의 자식 노드일 때만 아래 코드를 실행

	if (!of_fdt_device_is_available(initial_boot_params, node))
		return 0;

	// reg 속성을 찾아서 메모리에 reserve 함
	err = __reserved_mem_reserve_reg(node, uname);
	/*
	   "reg" 속성이 없거나 속성의 길이가 이상하고 "size" 속성이 있다면
		전역 배열 reserved_mem[]에 시작 주소와 크기를 0으로 하고 저장시켜 놓는다.
	*/
	if (err == -ENOENT && of_get_flat_dt_prop(node, "size", NULL))
		fdt_reserved_mem_save_node(node, uname, 0, 0);

	/* scan next node */
	return 0;
}

/**
 * early_init_fdt_scan_reserved_mem() - create reserved memory regions
 *
 * This function grabs memory from early allocator for device exclusive use
 * defined in device tree structures. It should be called by arch specific code
 * once the early allocator (i.e. memblock) has been fully activated.
 */
void __init early_init_fdt_scan_reserved_mem(void)
{
	int n;
	u64 base, size;

	if (!initial_boot_params)
		return;

	/* Process header /memreserve/ fields */
	/*
	   DTB 헤더의 off_mem_rsvmap 필드가 가리키는 memory reserve 블록(바이너리)에서 
	   읽은 메모리들을 reserve 한다
	*/
	for (n = 0; ; n++) {
		fdt_get_mem_rsv(initial_boot_params, n, &base, &size);
		if (!size)
			break;
		early_init_dt_reserve_memory_arch(base, size, 0);
	}

	/* 
		모든 노드를 돌면서 reserved-memory 노드를 메모리에 reserve 한다.
	*/
	of_scan_flat_dt(__fdt_scan_reserved_mem, NULL);
	fdt_init_reserved_mem();
}

/**
 * early_init_fdt_reserve_self() - reserve the memory used by the FDT blob
 */
void __init early_init_fdt_reserve_self(void)
{
	if (!initial_boot_params)
		return;

	/* Reserve the dtb region */
	early_init_dt_reserve_memory_arch(__pa(initial_boot_params),
					  fdt_totalsize(initial_boot_params),
					  0);
}

/**
 * of_scan_flat_dt - scan flattened tree blob and call callback on each.
 * @it: callback function
 * @data: context data pointer
 *
 * This function is used to scan the flattened device-tree, it is
 * used to extract the memory information at boot before we can
 * unflatten the tree
 */
/*
	of_scan_flat_dt() : '/'로 시작하는 노드에 대해 초기화하기
						- 디바이스 토리의 모든 노드를 뒤져 '/'로 시작하는 모든 노드에 대해
						  인자로 받은 함수를 호출하여 그 함수가 요청하는 값을 읽어온 경우 종료
*/

int __init of_scan_flat_dt(int (*it)(unsigned long node,
				     const char *uname, int depth,
				     void *data),
			   void *data)
{
	const void *blob = initial_boot_params;
	const char *pathp;
	int offset, rc = 0, depth = -1;

	if (!blob)
		return 0;
	/*
		디바이스 트리에서 노드만 루프를 돌며 검색하고 원하는 결과(rc=1)값을 읽어온 경우
		루프를 빠져나간다.
	*/
	for (offset = fdt_next_node(blob, -1, &depth);
	     offset >= 0 && depth >= 0 && !rc;
	     offset = fdt_next_node(blob, offset, &depth)) {

		/*
			노드의 이름을 가져와서 '/'로 시작하는 노드인 경우에는 처음 '/'를 제외한 이름을 구함
		*/
		pathp = fdt_get_name(blob, offset, NULL);
		if (*pathp == '/')
			pathp = kbasename(pathp);
		/*
			모든 노드에 대해 인자로 받은 함수(it)를 호출한다.
			- offset : structure 블록 내부에서 현재 순회하고 있는 노드의 오프셋 바이트
			- pathp : 노드명
			- depth : 현재 노드의 depth, 루트 노드가 0부터 시작
			- data : it 함수 호출 시 전달할 데이터
		*/
		rc = it(offset, pathp, depth, data);
	}
	return rc;
}

/**
 * of_scan_flat_dt_subnodes - scan sub-nodes of a node call callback on each.
 * @it: callback function
 * @data: context data pointer
 *
 * This function is used to scan sub-nodes of a node.
 */
int __init of_scan_flat_dt_subnodes(unsigned long parent,
				    int (*it)(unsigned long node,
					      const char *uname,
					      void *data),
				    void *data)
{
	const void *blob = initial_boot_params;
	int node;

	fdt_for_each_subnode(node, blob, parent) {
		const char *pathp;
		int rc;

		pathp = fdt_get_name(blob, node, NULL);
		if (*pathp == '/')
			pathp = kbasename(pathp);
		rc = it(node, pathp, data);
		if (rc)
			return rc;
	}
	return 0;
}

/**
 * of_get_flat_dt_subnode_by_name - get the subnode by given name
 *
 * @node: the parent node
 * @uname: the name of subnode
 * @return offset of the subnode, or -FDT_ERR_NOTFOUND if there is none
 */

int of_get_flat_dt_subnode_by_name(unsigned long node, const char *uname)
{
	return fdt_subnode_offset(initial_boot_params, node, uname);
}

/**
 * of_get_flat_dt_root - find the root node in the flat blob
 */
unsigned long __init of_get_flat_dt_root(void)
{
	return 0;
}

/**
 * of_get_flat_dt_size - Return the total size of the FDT
 */
int __init of_get_flat_dt_size(void)
{
	return fdt_totalsize(initial_boot_params);
}

/**
 * of_get_flat_dt_prop - Given a node in the flat blob, return the property ptr
 *
 * This function can be used within scan_flattened_dt callback to get
 * access to properties
 */
const void *__init of_get_flat_dt_prop(unsigned long node, const char *name,
				       int *size)
{
	return fdt_getprop(initial_boot_params, node, name, size);
}

/**
 * of_flat_dt_is_compatible - Return true if given node has compat in compatible list
 * @node: node to test
 * @compat: compatible string to compare with compatible list.
 */
int __init of_flat_dt_is_compatible(unsigned long node, const char *compat)
{
	return of_fdt_is_compatible(initial_boot_params, node, compat);
}

/**
 * of_flat_dt_match - Return true if node matches a list of compatible values
 */
int __init of_flat_dt_match(unsigned long node, const char *const *compat)
{
	return of_fdt_match(initial_boot_params, node, compat);
}

/**
 * of_get_flat_dt_prop - Given a node in the flat blob, return the phandle
 */
uint32_t __init of_get_flat_dt_phandle(unsigned long node)
{
	return fdt_get_phandle(initial_boot_params, node);
}

struct fdt_scan_status {
	const char *name;
	int namelen;
	int depth;
	int found;
	int (*iterator)(unsigned long node, const char *uname, int depth, void *data);
	void *data;
};

const char * __init of_flat_dt_get_machine_name(void)
{
	const char *name;
	unsigned long dt_root = of_get_flat_dt_root();

	name = of_get_flat_dt_prop(dt_root, "model", NULL);
	if (!name)
		name = of_get_flat_dt_prop(dt_root, "compatible", NULL);
	return name;
}

/**
 * of_flat_dt_match_machine - Iterate match tables to find matching machine.
 *
 * @default_match: A machine specific ptr to return in case of no match.
 * @get_next_compat: callback function to return next compatible match table.
 *
 * Iterate through machine match tables to find the best match for the machine
 * compatible string in the FDT.
 */
const void * __init of_flat_dt_match_machine(const void *default_match,
		const void * (*get_next_compat)(const char * const**))
{
	const void *data = NULL;
	const void *best_data = default_match;
	const char *const *compat;
	unsigned long dt_root;
	unsigned int best_score = ~1, score = 0;

	dt_root = of_get_flat_dt_root();
	while ((data = get_next_compat(&compat))) {
		score = of_flat_dt_match(dt_root, compat);
		if (score > 0 && score < best_score) {
			best_data = data;
			best_score = score;
		}
	}
	if (!best_data) {
		const char *prop;
		int size;

		pr_err("\n unrecognized device tree list:\n[ ");

		prop = of_get_flat_dt_prop(dt_root, "compatible", &size);
		if (prop) {
			while (size > 0) {
				printk("'%s' ", prop);
				size -= strlen(prop) + 1;
				prop += strlen(prop) + 1;
			}
		}
		printk("]\n\n");
		return NULL;
	}

	pr_info("Machine model: %s\n", of_flat_dt_get_machine_name());

	return best_data;
}

#ifdef CONFIG_BLK_DEV_INITRD
static void __early_init_dt_declare_initrd(unsigned long start,
					   unsigned long end)
{
	/* ARM64 would cause a BUG to occur here when CONFIG_DEBUG_VM is
	 * enabled since __va() is called too early. ARM64 does make use
	 * of phys_initrd_start/phys_initrd_size so we can skip this
	 * conversion.
	 */
	if (!IS_ENABLED(CONFIG_ARM64)) {
		initrd_start = (unsigned long)__va(start);
		initrd_end = (unsigned long)__va(end);
		initrd_below_start_ok = 1;
	}
}

/**
 * early_init_dt_check_for_initrd - Decode initrd location from flat tree
 * @node: reference to node containing initrd location ('chosen')
 */
/*
	early_init_dt_check_for_initrd() : initrd 관련 속성을 찾아서 관련 변수 초기화하기
	
		- "linux,initrd-start" 속성 값과 "linux,initrd-end" 속성 값을 찾아
		  전역 변수 initrd_start와 initrd_end에 저장
*/
static void __init early_init_dt_check_for_initrd(unsigned long node)
{
	u64 start, end;
	int len;
	const __be32 *prop;

	pr_debug("Looking for initrd properties... ");
	
	/*
		"linux,initrd_start" 속성 값을 읽어 옴
        */
    prop = of_get_flat_dt_prop(node, "linux,initrd-start", &len);
    if (!prop)
        return;
    start = of_read_number(prop, len/4);

	/*
		"linux,initrd_end" 속성 값을 읽어 옴
	*/
	prop = of_get_flat_dt_prop(node, "linux,initrd-end", &len);
	if (!prop)
		return;
	end = of_read_number(prop, len/4);

	/*
		읽은 2개의 값을 전역 변수 initrd_start와 initrd_end에 저장
	*/
	__early_init_dt_declare_initrd(start, end);
	phys_initrd_start = start;
	phys_initrd_size = end - start;

	pr_debug("initrd_start=0x%llx  initrd_end=0x%llx\n",
		 (unsigned long long)start, (unsigned long long)end);
}
#else
static inline void early_init_dt_check_for_initrd(unsigned long node)
{
}
#endif /* CONFIG_BLK_DEV_INITRD */

#ifdef CONFIG_SERIAL_EARLYCON

int __init early_init_dt_scan_chosen_stdout(void)
{
	int offset;
	const char *p, *q, *options = NULL;
	int l;
	const struct earlycon_id **p_match;
	const void *fdt = initial_boot_params;

	offset = fdt_path_offset(fdt, "/chosen");
	if (offset < 0)
		offset = fdt_path_offset(fdt, "/chosen@0");
	if (offset < 0)
		return -ENOENT;

	p = fdt_getprop(fdt, offset, "stdout-path", &l);
	if (!p)
		p = fdt_getprop(fdt, offset, "linux,stdout-path", &l);
	if (!p || !l)
		return -ENOENT;

	q = strchrnul(p, ':');
	if (*q != '\0')
		options = q + 1;
	l = q - p;

	/* Get the node specified by stdout-path */
	offset = fdt_path_offset_namelen(fdt, p, l);
	if (offset < 0) {
		pr_warn("earlycon: stdout-path %.*s not found\n", l, p);
		return 0;
	}

	for (p_match = __earlycon_table; p_match < __earlycon_table_end;
	     p_match++) {
		const struct earlycon_id *match = *p_match;

		if (!match->compatible[0])
			continue;

		if (fdt_node_check_compatible(fdt, offset, match->compatible))
			continue;

		of_setup_earlycon(match, offset, options);
		return 0;
	}
	return -ENODEV;
}
#endif

/**
 * early_init_dt_scan_root - fetch the top level address and size cells
 */
/*
	early_init_dt_scan_root() : 루트 노드를 스캔하여 "#size-cells" 속성 값과
								 "#address-cells" 속성 값을 읽어와서 전역 dt_root_size_cells 
								및 dt_root_addr_cells에 저장
*/
int __init early_init_dt_scan_root(unsigned long node, const char *uname,
				   int depth, void *data)
{
	const __be32 *prop;

	/*
		노드의 depth가 0이 아닌 경우, 즉 루트 노드가 아닌 경우 빠져나감
	*/
	if (depth != 0)
		return 0;

	dt_root_size_cells = OF_ROOT_NODE_SIZE_CELLS_DEFAULT;
	dt_root_addr_cells = OF_ROOT_NODE_ADDR_CELLS_DEFAULT;

	/*
		"#size-cells" 속성 값을 찾아 전역 변수 dt_root_size_cells에 저장하되, 
		찾지 못한 경우 기본 값 1로 한다. 
		- "#size-cells"는 size를 표현하는 cell의 수를 나타낸다
	*/
	prop = of_get_flat_dt_prop(node, "#size-cells", NULL);
	if (prop)
		dt_root_size_cells = be32_to_cpup(prop);
	pr_debug("dt_root_size_cells = %x\n", dt_root_size_cells);

	/*
		"#address-cells" 속성 값을 찾아 전역 변수 dt_root_addr_cells에 저장하되,
		찾지못한 경우 기본 값 1로 한다.
		- "#address-cells"는 address를 표현하는 cell의 수를 나타낸다.
	*/
	prop = of_get_flat_dt_prop(node, "#address-cells", NULL);
	if (prop)
		dt_root_addr_cells = be32_to_cpup(prop);
	pr_debug("dt_root_addr_cells = %x\n", dt_root_addr_cells);

	/* break now */
	return 1;
}

u64 __init dt_mem_next_cell(int s, const __be32 **cellp)
{
	const __be32 *p = *cellp;

	*cellp = p + s;
	return of_read_number(p, s);
}

/**
 * early_init_dt_scan_memory - Look for and parse memory nodes
 */
/*
	early_init_dt_scan_memory() : memory노드를 스캔해서 memblock에 추가하기

		- memblock : 커널 부트업 시 처음 사용하는 메모리 관리자
		- "memory" 노드를 스캔하여 "reg" 속성 값을 읽어와서 파싱한 물리 메모리 시작 주소 및 
		  크기 정보로 memory memblock에 추가
*/
int __init early_init_dt_scan_memory(unsigned long node, const char *uname,
				     int depth, void *data)
{
	/*
		노드에 대해 device_type 속성을 알아와서 memory 타입이 아닌 경우 그냥 리턴
	*/
	const char *type = of_get_flat_dt_prop(node, "device_type", NULL);
	const __be32 *reg, *endp;
	int l;
	bool hotpluggable;

	/* We are scanning "memory" nodes only */
	if (type == NULL || strcmp(type, "memory") != 0)
		return 0;

	/*
		"linux,usable-memory" 속성 또는 "reg" 속성을 찾아 사용 가능 메모리 크기를 정함
		powerpc 아키텍처에서만 사용하는 속성
	*/
	reg = of_get_flat_dt_prop(node, "linux,usable-memory", &l);
	if (reg == NULL)
		reg = of_get_flat_dt_prop(node, "reg", &l);
	if (reg == NULL)
		return 0;

	endp = reg + (l / sizeof(__be32));

	/*
		"hotpluggable" 속성이 있으면 1, 없으면 0 저장
	*/
	hotpluggable = of_get_flat_dt_prop(node, "hotpluggable", NULL);

	pr_debug("memory scan node %s, reg size %d,\n", uname, l);

	/*
		사용 가능 메모리 크기만큼 reg 값에 있는 메모리 base와 size를 사용하여 계산한 후
		early_init_dt_add_memory_arch()를 호출하여 메모리 블록을 추가한다.
		- 배열인 경우에는 그 수만큼 루프를 돈다.
	*/
	while ((endp - reg) >= (dt_root_addr_cells + dt_root_size_cells)) {
		u64 base, size;

		base = dt_mem_next_cell(dt_root_addr_cells, &reg);
		size = dt_mem_next_cell(dt_root_size_cells, &reg);

		if (size == 0)
			continue;
		pr_debug(" - %llx ,  %llx\n", (unsigned long long)base,
		    (unsigned long long)size);

		/*
			시스템에 존재하는 메모리를 memblock에 추가하기
		*/
		early_init_dt_add_memory_arch(base, size);
		
		/*
			hotplug 메모리의 경우 memblock에 hotplug 표식을 해둔다.
		*/
		if (!hotpluggable)
			continue;

		if (early_init_dt_mark_hotplug_memory_arch(base, size))
			pr_warn("failed to mark hotplug range 0x%llx - 0x%llx\n",
				base, base + size);
	}

	return 0;
}

/*
	early_init_dt_scan_chosen() : /chosen 노드를 스캔하여 initrd, bootargs 처리하기
	
		- /chosen 노드를 스캔하여 "linux,initrd-start" 속성 값과 "linux,initrd-end" 속성 값을
		  읽어와서 전역 initrd_start와 initrd_end에 저장
		- "bootargs" 속성 값을 읽어와 전역 변수 boot_command_line에 저장
*/
int __init early_init_dt_scan_chosen(unsigned long node, const char *uname,
				     int depth, void *data)
{
	int l;
	const char *p;

	pr_debug("search \"chosen\", depth: %d, uname: %s\n", depth, uname);

	/*
		루트 토드의 다음 단계 자식 노드명이 "chosen"이 아니면 이 함수에서 필요한 노드가 아니므로
		대상 노드를 처리하지 않는다.
	*/
	if (depth != 1 || !data ||
	    (strcmp(uname, "chosen") != 0 && strcmp(uname, "chosen@0") != 0))
		return 0;

	/*
		"linux,initrd-start" 속성 값과 "linux,initrd-end" 속성 값을 찾아
		전역 변수 initrd_start와 initrd_end에 저장
	*/
	early_init_dt_check_for_initrd(node);

	/* Retrieve command line */
	/*
		"bootargs" 속성을 찾아 전역 변수 boot_command_line에 저장
	*/
	p = of_get_flat_dt_prop(node, "bootargs", &l);
	if (p != NULL && l > 0)
		strlcpy(data, p, min((int)l, COMMAND_LINE_SIZE));

	/*
	 * CONFIG_CMDLINE is meant to be a default in case nothing else
	 * managed to set the command line, unless CONFIG_CMDLINE_FORCE
	 * is set in which case we override whatever was found earlier.
	 */

	/*
		- CONFIG_CMDLINE 커널 옵션 사용하는 경우 "bootargs" 속성 값이 없다면
		  커널 빌드 시 주어진 디폴트 CONFIG_CMDLINE을 사용
		- CONFIG_CMDLINE_FORCE 커널 옵션도 사용하는 경우 "bootargs" 속성 값의 유무와 상관없이
		  무조건 디폴트 CONFIG_CMDLINE 값을 사용
	*/
#ifdef CONFIG_CMDLINE
#if defined(CONFIG_CMDLINE_EXTEND)
	strlcat(data, " ", COMMAND_LINE_SIZE);
	strlcat(data, CONFIG_CMDLINE, COMMAND_LINE_SIZE);
#elif defined(CONFIG_CMDLINE_FORCE)
	strlcpy(data, CONFIG_CMDLINE, COMMAND_LINE_SIZE);
#else
	/* No arguments from boot loader, use kernel's  cmdl*/
	if (!((char *)data)[0])
		strlcpy(data, CONFIG_CMDLINE, COMMAND_LINE_SIZE);
#endif
#endif /* CONFIG_CMDLINE */

	pr_debug("Command line is: %s\n", (char*)data);

	/* break now */
	return 1;
}

#ifndef MIN_MEMBLOCK_ADDR
#define MIN_MEMBLOCK_ADDR	__pa(PAGE_OFFSET)
#endif
#ifndef MAX_MEMBLOCK_ADDR
#define MAX_MEMBLOCK_ADDR	((phys_addr_t)~0)
#endif

/*
	early_init_dt_add_memory_arch() : 시스템에 존재하는 메모리를 memblock에 추가하기
	
	- 메모리 시작 주소와 크기로 memory memblock에 추가한다.
	- 단, 물리 메모리 범위를 넘어가는 경우 size를 조절한다.
*/
void __init __weak early_init_dt_add_memory_arch(u64 base, u64 size)
{
	/*
		물리 메모리의 하한 주소를 설정한다.
	*/
	const u64 phys_offset = MIN_MEMBLOCK_ADDR;

	/*
		사이즈가 너무 작으면 경고 메세지를 출력하고 함수를 빠져나간다.
        ~PAGE_MASK = PAGE_SIZE - 1
        base & ~PAGE_MASK = base에서 PAGE_SIZE의 offset
        PAGE_SIZE - (base & ~PAGE_MASK) -> 0 ~ PAGE_SIZE -1 까지

        => size가 한 페이지를 넘지 못하는 경우는 return
	*/
	if (size < PAGE_SIZE - (base & ~PAGE_MASK)) {
		pr_warn("Ignoring memory block 0x%llx - 0x%llx\n",
			base, base + size);
		return;
	}

	/*
		시작 주소가 페이지 단위로 정렬되지 않았드면 시작 주소를 페이지 단위로 정렬하고
		그 차이만큼 size를 줄인다. 그런 후 페이지 단위로 내림 정렬한다.

        PAGE_ALIGN(base) : base를 PAGE_SIZE 단위로 round up
	*/
	if (!PAGE_ALIGNED(base)) {
		size -= PAGE_SIZE - (base & ~PAGE_MASK);
		base = PAGE_ALIGN(base);
	}
	size &= PAGE_MASK;

	/*
		시작 주소가 물리 메모리 상한 주소를 초과한다면 더이상 처리하지 않고 함수를 빠져나간다.
	*/
	if (base > MAX_MEMBLOCK_ADDR) {
		pr_warning("Ignoring memory block 0x%llx - 0x%llx\n",
				base, base + size);
		return;
	}

	/*
		끝 주소가 시스템 최대 처리 상한 주소를 초과한다면 초과한 크기만큼 조절한다.
	*/
	if (base + size - 1 > MAX_MEMBLOCK_ADDR) {
		pr_warning("Ignoring memory range 0x%llx - 0x%llx\n",
				((u64)MAX_MEMBLOCK_ADDR) + 1, base + size);
		size = MAX_MEMBLOCK_ADDR - base + 1;
	}

	/*
		끝 주소가 물리 메모리 최소 주소 미만인 경우에는 더 이상 처리하지 않고 함수를 빠져나감
	*/
	if (base + size < phys_offset) {
		pr_warning("Ignoring memory block 0x%llx - 0x%llx\n",
			   base, base + size);
		return;
	}
	/*
		시작 주소가 물리 메모리 최소 주소 미만인 경우에는 
		시작 주소를 물리 메모리 하한 주소로 조정하고, 크기도 그 차이만큼 감소시켜 조정
	*/
	if (base < phys_offset) {
		pr_warning("Ignoring memory range 0x%llx - 0x%llx\n",
			   base, phys_offset);
		size -= phys_offset - base;
		base = phys_offset;
	}
	/*
		memblock_add() 함수를 사용하여 메모리 블록을 추가한다.
	*/
	memblock_add(base, size);
}

int __init __weak early_init_dt_mark_hotplug_memory_arch(u64 base, u64 size)
{
	return memblock_mark_hotplug(base, size);
}

int __init __weak early_init_dt_reserve_memory_arch(phys_addr_t base,
					phys_addr_t size, bool nomap)
{
	if (nomap)
		return memblock_remove(base, size);
	return memblock_reserve(base, size);
}

/*
	early_init_dt_alloc_memory_arch() : align단위로 size만큼의 공간을 memblock으로부터 할당
										그 가상주소를 리턴
*/
static void * __init early_init_dt_alloc_memory_arch(u64 size, u64 align)
{
	void *ptr = memblock_alloc(size, align);

	if (!ptr)
		panic("%s: Failed to allocate %llu bytes align=0x%llx\n",
		      __func__, size, align);

	return ptr;
}

bool __init early_init_dt_verify(void *params)
{
	if (!params)
		return false;

	/* check device tree validity */
	if (fdt_check_header(params))
		return false;

	/* Setup flat device-tree pointer */
	initial_boot_params = params;
	of_fdt_crc32 = crc32_be(~0, initial_boot_params,
				fdt_totalsize(initial_boot_params));
	return true;
}

/*
	early_init_dt_scan_nodes() : 먼저 초기화를 하기 위해 DTB 노드 스캔하기
*/
void __init early_init_dt_scan_nodes(void)
{
	int rc = 0;

	/* Retrieve various information from the /chosen node */
	/*
		 "/chosen" 노드를 스캔하여
		 1) "linux,initrd-start" 속성 값과 "linux,initrd-end" 속성 값을 읽어와서
			전역 initrd_start와 initrd_end에 저장
		 2) "bootargs" 속성 값을 읽어와서 전역 변수 boot_command_line에 저장
	*/
	rc = of_scan_flat_dt(early_init_dt_scan_chosen, boot_command_line);
	if (!rc)
		pr_warn("No chosen node found, continuing without\n");

	/* Initialize {size,address}-cells info */
	/*
		루트 노드를 스캔하여 "#size-cells"속성 값과 "#address-cells" 속성 값을 읽어와서
		전역 변수 dt_root_size_cells와 dt_root_addr_cells에 저장한다
	*/
	of_scan_flat_dt(early_init_dt_scan_root, NULL);

	/* Setup memory, calling early_init_dt_add_memory_arch */
	/*
		"memory"노드를 스캔하여 "reg" 속성 값을 읽어와서 파싱한 물리 메모리 시작 주소 및
		크기 정보로 memory memblock에 추가한다.
	*/
	of_scan_flat_dt(early_init_dt_scan_memory, NULL);
}

bool __init early_init_dt_scan(void *params)
{
	bool status;

	status = early_init_dt_verify(params);
	if (!status)
		return false;

	early_init_dt_scan_nodes();
	return true;
}

/**
 * unflatten_device_tree - create tree of device_nodes from flat blob
 *
 * unflattens the device-tree passed by the firmware, creating the
 * tree of struct device_node. It also fills the "name" and "type"
 * pointers of the nodes so the normal device-tree walking functions
 * can be used.
 */
/*
	unflatten_device_tree() : 디바이스 트리(FDT) -> Expanded 포맷으로 변환
	
	- device_node와 property 구조체를 사용하여 트리 구조로 각 노드와 속성을 연결한다.
	- 기존에 사용하던 DTB 바이너리들도 문자열등을 그대로 사용하므로 삭제되지 않고 유지된다.

*/
void __init unflatten_device_tree(void)
{
	/*
		4바이트 단위의 바이너리로 구성된 DTB를 파싱하여 확장 포맷으로 변환한 후
		of_root 전역 변수가 가리키게 한다.
	*/
	__unflatten_device_tree(initial_boot_params, NULL, &of_root,
				early_init_dt_alloc_memory_arch, false);

	/* Get pointer to "/chosen" and "/aliases" nodes for use everywhere */
	/*
		전역 aliases_lookup리스트에 alias_prop들을 추가한다.
		- 전역 변수 of_aliases가 "/aliases" 노드를 가리키도록 설정
		- 전역 변수 of_chosen이 "/chosen"노드를 가리키도록 설정
	 	- 전역 변수 of_stdout을 "/chosen"노드의 "stdout-path" 속성 값에 대응하는 노드로 설정
	*/
	of_alias_scan(early_init_dt_alloc_memory_arch);

	unittest_unflatten_overlay_base();
}

/**
 * unflatten_and_copy_device_tree - copy and create tree of device_nodes from flat blob
 *
 * Copies and unflattens the device-tree passed by the firmware, creating the
 * tree of struct device_node. It also fills the "name" and "type"
 * pointers of the nodes so the normal device-tree walking functions
 * can be used. This should only be used when the FDT memory has not been
 * reserved such is the case when the FDT is built-in to the kernel init
 * section. If the FDT memory is reserved already then unflatten_device_tree
 * should be used instead.
 */
void __init unflatten_and_copy_device_tree(void)
{
	int size;
	void *dt;

	if (!initial_boot_params) {
		pr_warn("No valid device tree found, continuing without\n");
		return;
	}

	size = fdt_totalsize(initial_boot_params);
	dt = early_init_dt_alloc_memory_arch(size,
					     roundup_pow_of_two(FDT_V17_SIZE));

	if (dt) {
		memcpy(dt, initial_boot_params, size);
		initial_boot_params = dt;
	}
	unflatten_device_tree();
}

#ifdef CONFIG_SYSFS
static ssize_t of_fdt_raw_read(struct file *filp, struct kobject *kobj,
			       struct bin_attribute *bin_attr,
			       char *buf, loff_t off, size_t count)
{
	memcpy(buf, initial_boot_params + off, count);
	return count;
}

static int __init of_fdt_raw_init(void)
{
	static struct bin_attribute of_fdt_raw_attr =
		__BIN_ATTR(fdt, S_IRUSR, of_fdt_raw_read, NULL, 0);

	if (!initial_boot_params)
		return 0;

	if (of_fdt_crc32 != crc32_be(~0, initial_boot_params,
				     fdt_totalsize(initial_boot_params))) {
		pr_warn("not creating '/sys/firmware/fdt': CRC check failed\n");
		return 0;
	}
	of_fdt_raw_attr.size = fdt_totalsize(initial_boot_params);
	return sysfs_create_bin_file(firmware_kobj, &of_fdt_raw_attr);
}
late_initcall(of_fdt_raw_init);
#endif

#endif /* CONFIG_OF_EARLY_FLATTREE */
