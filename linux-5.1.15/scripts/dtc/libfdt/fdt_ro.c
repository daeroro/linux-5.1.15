/*
 * libfdt - Flat Device Tree manipulation
 * Copyright (C) 2006 David Gibson, IBM Corporation.
 *
 * libfdt is dual licensed: you can use it either under the terms of
 * the GPL, or the BSD license, at your option.
 *
 *  a) This library is free software; you can redistribute it and/or
 *     modify it under the terms of the GNU General Public License as
 *     published by the Free Software Foundation; either version 2 of the
 *     License, or (at your option) any later version.
 *
 *     This library is distributed in the hope that it will be useful,
 *     but WITHOUT ANY WARRANTY; without even the implied warranty of
 *     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *     GNU General Public License for more details.
 *
 *     You should have received a copy of the GNU General Public
 *     License along with this library; if not, write to the Free
 *     Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston,
 *     MA 02110-1301 USA
 *
 * Alternatively,
 *
 *  b) Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *     1. Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *     2. Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 *     THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
 *     CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
 *     INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 *     MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 *     DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 *     CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *     SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 *     NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 *     LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 *     HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 *     CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 *     OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 *     EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#include "libfdt_env.h"

#include <fdt.h>
#include <libfdt.h>

#include "libfdt_internal.h"

/*
	fdt_nodename_eq_() : 찾고자 하는 node의 offset, 이름 s, 길이 len에
						일치하는 node가 있는지 확인
*/

static int fdt_nodename_eq_(const void *fdt, int offset,
			    const char *s, int len)
{
	int olen;
	// offset에 해당하는 node의 name을 가리키는 포인터를 p에 저장
	// name의 길이는 olen에 저장
	const char *p = fdt_get_name(fdt, offset, &olen);

	// p가 NULL 이거나
	// olen < len 이면 0을 반환
	if (!p || olen < len)
		/* short match */
		return 0;

	// memcmp()는 p, s를 len만큼 길이로 비교해서 일치하면 0, 
	//											일치하지 않으면 0이 아닌 수를 반환
	if (memcmp(p, s, len) != 0)
		return 0;

	// p의 마지막 문자가 '\0'이면 1을 반환
	if (p[len] == '\0')
		return 1;'
	// '@'문자가 s안에 없거나
	// p의 마지막 문자가 '@'이면 1을 반환
	else if (!memchr(s, '@', len) && (p[len] == '@'))
		return 1;
	else
		return 0;
}


/*
	fdt_get_string() : stroffset에 해당하는 string을 반환하고 길이를 lenp에 저장
*/
const char *fdt_get_string(const void *fdt, int stroffset, int *lenp)
{
	// string block에서 stroffset에 해당하는 offset을 absoffset에 저장
	uint32_t absoffset = stroffset + fdt_off_dt_strings(fdt);
	size_t len;
	int err;
	const char *s, *n;

	// read only인지 확인, 맞으면 0을 반환
	err = fdt_ro_probe_(fdt);
	if (err != 0)
		goto fail;
	
	// 우선 err에 -FDT_ERR_BADOFFSET 값 설정
	err = -FDT_ERR_BADOFFSET;
	// absoffset이 전체 fdt 범위 안에 있는지 확인
	if (absoffset >= fdt_totalsize(fdt))
		goto fail;
	// absoffset 부터 fdt 전체 범위까지의 길이 저장
	len = fdt_totalsize(fdt) - absoffset;

	// magic number 확인
	if (fdt_magic(fdt) == FDT_MAGIC) {
		// stroffset 확인
		if (stroffset < 0)
			goto fail;
		// 버전이 17이상이면 
		if (fdt_version(fdt) >= 17) {
			
			// stroffset이 전체 strings block 크기를 넘어가는지 확인
			if (stroffset >= fdt_size_dt_strings(fdt))
				goto fail;

			// string block 크기 - stroffset < len 
			//			: stroffset이 stirng block 끝 쪽에 위치한다는 의미
			if ((fdt_size_dt_strings(fdt) - stroffset) < len)
				len = fdt_size_dt_strings(fdt) - stroffset;
		}
	// sw magic number이면, stroffset을 음수로 취급하는 것 같음.
	} else if (fdt_magic(fdt) == FDT_SW_MAGIC) {
		if ((stroffset >= 0)
		    || (stroffset < -fdt_size_dt_strings(fdt)))
			goto fail;
		if ((-stroffset) < len)
			len = -stroffset;
	} else {
		err = -FDT_ERR_INTERNAL;
		goto fail;
	}

	// fdt부터 absoffset에 해당하는 문자열을 가리키는 포인터를 s에 저장
	s = (const char *)fdt + absoffset;
	// 문자열 s에서 len 길이만큼 '\0'문자 찾기
	n = memchr(s, '\0', len);
	// n=0, '\0'문자를 찾지 못했으면 에러
	if (!n) {
		/* missing terminating NULL */
		err = -FDT_ERR_TRUNCATED;
		goto fail;
	}
	
	// lenp가 NULL이 아니면, lenp이 가리키는 곳에 n-s, 문자열의 길이 저장하고 s를 반환
	if (lenp)
		*lenp = n - s;
	return s;

fail:
	// 찾지 못했을 경우에는 lenp가 가리키는 곳에 err를 저장하고 NULL을 반환
	if (lenp)
		*lenp = err;
	return NULL;
}

/*
	fdt_string() : string block에서 stroffset에 해당하는 string을 반환
*/
const char *fdt_string(const void *fdt, int stroffset)
{
	return fdt_get_string(fdt, stroffset, NULL);
}

/*
	fdt_string_eq_() : stroffset에 해당하는 문자열과
						 len의 길이를 가지는 문자열 s가 같은지 비교
*/
static int fdt_string_eq_(const void *fdt, int stroffset,
			  const char *s, int len)
{
	int slen;
	// stroffset에 해당하는 string을 반환, slen에 길이 저장
	const char *p = fdt_get_string(fdt, stroffset, &slen);

	// 문자열이 존재하고, 길이가 같고, 내용이 같으면 1을 반환
	return p && (slen == len) && (memcmp(p, s, len) == 0);
}

/*
	fdt_get_max_phandle() : 디바이스 트리에서 phandle이 가장 큰 값을 반환
*/
uint32_t fdt_get_max_phandle(const void *fdt)
{
	uint32_t max_phandle = 0;
	int offset;

	// 처음 node에서 마지막 노드까지 검사
	for (offset = fdt_next_node(fdt, -1, NULL);;
	     offset = fdt_next_node(fdt, offset, NULL)) {
		uint32_t phandle;

		// fdt_nex_node의 값이 -FDT_ERR_NOTFOUND는 현재 node가 FDT_END라는 의미
		if (offset == -FDT_ERR_NOTFOUND)
			return max_phandle;

		// offset이 음수이면 에러
		if (offset < 0)
			return (uint32_t)-1;

		// offset에 해당하는 node에서 phandler을 찾음
		phandle = fdt_get_phandle(fdt, offset);
		// phandler을 찾지못하면 continue;
		if (phandle == (uint32_t)-1)
			continue;
		
		// 가장 큰 값을 max_phandler에 저장
		if (phandle > max_phandle)
			max_phandle = phandle;
	}

	return 0;
}

/*
	fdt_mem_rsv() : n번째에 해당하는 reserve_entry를 반환
*/
static const struct fdt_reserve_entry *fdt_mem_rsv(const void *fdt, int n)
{
	// n번째 reserve_entry의 offset을 저장
	int offset = n * sizeof(struct fdt_reserve_entry);
	// fdt에서 n번째 reserve_entry의 offset을 저장
	int absoffset = fdt_off_mem_rsvmap(fdt) + offset;

	// absoffset의 범위검사
	// absoffset이 reserve blcok 보다 작을 수 없음
	if (absoffset < fdt_off_mem_rsvmap(fdt))
		return NULL;
	// structure block, string block이 없을 때,
	// absoffset이 가질수 있는 최대 범위 검사
	if (absoffset > fdt_totalsize(fdt) - sizeof(struct fdt_reserve_entry))
		return NULL;

	// fdt의 reserve block에서 n번째의 fdt_reserve_entry 반환
	return fdt_mem_rsv_(fdt, n);
}

/*
	fdt_get_mem_rsv() : n번째에 해당하는 fdt_reserve_entry의
						 주소를	address가 가리키는 곳에 저장,
						 크기를 size가 가리키는 곳에 저장
*/
int fdt_get_mem_rsv(const void *fdt, int n, uint64_t *address, uint64_t *size)
{
	// fdt_reserve_entry 구조체 포인터 선언
	const struct fdt_reserve_entry *re;

	FDT_RO_PROBE(fdt);
	// n번째 reserve_entry 구조체 저장
	re = fdt_mem_rsv(fdt, n);
	// re = NULL이면 에러
	if (!re)
		return -FDT_ERR_BADOFFSET;

	// re 구조체의 주소, 크기를 엔디안을 고려해 저장
	*address = fdt64_ld(&re->address);
	*size = fdt64_ld(&re->size);
	return 0;
}

/*
	fdt_num_mem_rsv() : reserve_entry의 개수를 반환
*/
int fdt_num_mem_rsv(const void *fdt)
{
	int i;
	// reserve_entry 구조체 선언
	const struct fdt_reserve_entry *re;

	// i=0 부터 fdt_mem_rsv()가 NULL일 때까지 반복
	for (i = 0; (re = fdt_mem_rsv(fdt, i)) != NULL; i++) {
		if (fdt64_ld(&re->size) == 0)
			return i;
	}
	return -FDT_ERR_TRUNCATED;
}

/*
	nextprop_() : offset부터 PROP tag가 처음 등장할 때를 찾아서 offset을 반환
*/
static int nextprop_(const void *fdt, int offset)
{
	uint32_t tag;
	int nextoffset;

	do {
		// 현재 offset의 다음 tag의 offset을 nextoffset에 저장
		// 현재 offset의 tag를 tag에 저장
		tag = fdt_next_tag(fdt, offset, &nextoffset);

		switch (tag) {
		// 현재 offset의 tag가 END일때,
		// fdt_next_tag() 결과 nextoffset에 저장된 값이 
		case FDT_END:
			// >= 이면, BADSTRUCTURE 에러를 return
			if (nextoffset >= 0)
				return -FDT_ERR_BADSTRUCTURE;
			// < 이면 fdt_next_tag()에서 저장된 에러 값을 return
			else
				return nextoffset;

		// 현재 offset의 tag가 PROP 일때,
		case FDT_PROP:
			return offset;
		}

		// 다음 offset으로 이동
		offset = nextoffset;
	// 모든 tag를 다 검사
	} while (tag == FDT_NOP);

	// 찾지 못했으면 NOTFOUND 에러 return
	return -FDT_ERR_NOTFOUND;
}

/*
	fdt_subnode_offset_namelen() : offset의 자식 노드에서
									 name과 namelen을 가지는 노드의 offset 반환
*/
int fdt_subnode_offset_namelen(const void *fdt, int offset,
			       const char *name, int namelen)
{
	int depth;
	// read only 확인
	FDT_RO_PROBE(fdt);

	// depth = 0 부터시작

	// 현재 offset 부터 fdt_next_node()로 구한 offset이 존재하고,(다음 노드가 존재함)
	// depth가 0 아래로 떨어지지 않을 때까지(부모 노드로 올라가지 않고, 자식 노드에서만 찾겠다)
	
	for (depth = 0; (offset >= 0) && (depth >= 0); offset = fdt_next_node(fdt, offset, &depth))
		// 자식 노드이고, 그 노드의 node name이 name, namelen과 일치할 때
		if ((depth == 1) && fdt_nodename_eq_(fdt, offset, name, namelen))
			// fdt_next_node()에서 구한 다음 node의 offset을 반환
			return offset;

	// for문이 depth<0으로 종료됨
	// depth < 0 이 되었다면 자식 노드에서 name과 namelen에 맞는 노드를 찾지 못한것
	if (depth < 0)
		// NOTFOUND 에러 return
		return -FDT_ERR_NOTFOUND;

	// for문이 offset < 0으로 종료됨
	// fdt_next_node()이 반환한 값이 범위를 넘어갔거나, END일 때,
	// 루트 노드에서 END_NODE를 만났을 때 음수값이 반환됨
	return offset; /* error */
}

/*
	fdt_subnode_offset() : parentoffset의 자식노드에서 name에 일치하는 node를 찾아 offset을 반환
*/
int fdt_subnode_offset(const void *fdt, int parentoffset,
		       const char *name)
{
	return fdt_subnode_offset_namelen(fdt, parentoffset, name, strlen(name));
}

/*
	fdt_path_offset_namelen() : path와 path의 길이인 namelen을 통해서 offset을 찾음
*/
int fdt_path_offset_namelen(const void *fdt, const char *path, int namelen)
{
	// path의 끝을 가리키는 end 포인터 
	const char *end = path + namelen;
	// path의 시작을 가리키는 p 포인터
	const char *p = path;
	int offset = 0;

	// read only 확인
	FDT_RO_PROBE(fdt);

	/* see if we have an alias */
	// path의 시작이 '/'이 아니면 alias가 있을 가능성이 있음
	if (*path != '/') {
		// path에서 path의 길이(end-p) 만큼 '/'를 찾아서 q가 가리키도록 함
		const char *q = memchr(path, '/', end - p);

		// '/'를 찾지 못했다면 q 는 NULL을 반환하므로
		if (!q)
			// path의 끝을 가리키도록 함
			q = end;

		// p의 alias가 있는지 확인
		p = fdt_get_alias_namelen(fdt, p, q - p);
		// alias가 없거나,
		// alias는 있지만  p 이름이 aliases에 없을 때
		if (!p)
			return -FDT_ERR_BADPATH;
		// alias p가 가리키는 path로 offset 반환
		offset = fdt_path_offset(fdt, p);

		// p가 '/' 다음을 가리키도록 함
		p = q;
	}

	// p가 end까지 반복
	while (p < end) {
		const char *q;

		// p 에서 '/' 제거
		while (*p == '/') {
			p++;
			// p 가 끝을 가리키면, 0 반환
			if (p == end)
				return offset;
		}
		// '/'를 찾아 q가 가리키도록 함
		q = memchr(p, '/', end - p);
		// '/'를 찾지 못한 경우에는 path의 끝(end)를 가리키도록 함
		if (! q)
			q = end;

		// offset의 자식노드에서 이름이 p이고, 길이가 q-p인 노드의 offset을 반환
		offset = fdt_subnode_offset_namelen(fdt, offset, p, q-p);
		// 자식노드에서 찾지 못한 경우 에러 return
		if (offset < 0)
			return offset;

		// p를 '/'를 가리키고 있는 q로 업데이트
		p = q;
	}
	
	// path의 마지막 경로까지의 offset을 반환
	return offset;
}

/*
	fdt_path_offset() : path 경로로 offset을 찾아서 반환
*/
int fdt_path_offset(const void *fdt, const char *path)
{
	return fdt_path_offset_namelen(fdt, path, strlen(path));
}

/*
	fdt_get_name() : nodeoffset에 해당하는 이름을 return하고 길이를 len에 저장
*/
const char *fdt_get_name(const void *fdt, int nodeoffset, int *len)
{
	// nodeoffset이 가리키는 노드의 포인터를 반환
	const struct fdt_node_header *nh = fdt_offset_ptr_(fdt, nodeoffset);
	const char *nameptr;
	int err;

	// read only인지 확인
	// nodeoffset가 음수인지, tag size로 정렬되어 있는지, BEGIN_NODE를 가리키고 있는지 확인
	if (((err = fdt_ro_probe_(fdt)) != 0)
	    || ((err = fdt_check_node_offset_(fdt, nodeoffset)) < 0))
			goto fail;

	// nameptr가 노드 이름을 가리키게 함
	nameptr = nh->name;

	// 버전 확인
	if (fdt_version(fdt) < 0x10) {
		/*
		 * For old FDT versions, match the naming conventions of V16:
		 * give only the leaf name (after all /). The actual tree
		 * contents are loosely checked.
		 */
		const char *leaf;
		// nameptr 오른쪽 끝에서 부터 '/'를 찾아서 leaf가 가리키도록 함
		leaf = strrchr(nameptr, '/');
		// '/'를 찾지 못했다면 에러
		if (leaf == NULL) {
			err = -FDT_ERR_BADSTRUCTURE;
			goto fail;
		}
		// nameptr이 '/' 다음을 가리키도록 함
		nameptr = leaf+1;
	}

	// len이 NULL이 아니면
	// nameptr의 길이를 저장
	if (len)
		*len = strlen(nameptr);
	// nameptr을 return
	return nameptr;

// nodeoffset 이상하거나, '/'를 찾지 못했을 때
 fail:
	// len이 존재하면, err를 저장
	if (len)
		*len = err;
	// NULL 반환
	return NULL;
}

/*
	fdt_first_property_offset() : nodeoffset이 가리키는 노드에서 첫번째 property offset을 반환
*/
int fdt_first_property_offset(const void *fdt, int nodeoffset)
{
	int offset;

	// nodeoffset이 음수인지, 정렬이 잘 되어 있는지, BEGIN_NODE를 가리키고 있는지 확인
	if ((offset = fdt_check_node_offset_(fdt, nodeoffset)) < 0)
		return offset;

	// offset으로 부터 첫번째 PROP를 찾아서 offset 반환
	return nextprop_(fdt, offset);
}

/*
	fdt_next_property_offset() : offset 다음의 property offset을 반환
*/
int fdt_next_property_offset(const void *fdt, int offset)
{
	// offset이 음수인지, 정렬이 잘 되어있는지, PROP을 가리키고 있는지 확인
	if ((offset = fdt_check_prop_offset_(fdt, offset)) < 0)
		return offset;

	// offset으로 부터 다음 PROP을 찾아서 offset 반환
	return nextprop_(fdt, offset);
}

/*
	fdt_get_property_by_offset_() : offset이 가라키는 PROP의 fdt_property 구조체를 반환
									lenp가 가리키는 곳에 len변수 저장
*/
static const struct fdt_property *fdt_get_property_by_offset_(const void *fdt,
						              int offset,
						              int *lenp)
{
	int err;
	// fdt_property 구조체를 가리키는 prop 포인터 선언
	const struct fdt_property *prop;

	// offset이 음수인지, 정렬이 되어있는지, PROP을 가리키고 있는지 확인
	if ((err = fdt_check_prop_offset_(fdt, offset)) < 0) {
		// lenp가 NULL이 아니면, 에러를 저장하고 NULL 리턴
		if (lenp)
			*lenp = err;
		return NULL;
	}

	// structure block에서 offset 만큼의 오프셋을 가지는 포인터 반환
	prop = fdt_offset_ptr_(fdt, offset);

	// lenp가 NULL이 아니면, 엔디안을 고려하여 fdt_property 구조체의 len을 저장
	if (lenp)
		*lenp = fdt32_ld(&prop->len);

	// fdt_property 구조체를 가리키는 포인터 반환
	return prop;
}

/*
	fdt_get_property_by_offset() : structure block에서 offset이 가리키는 곳의
									property를 가리키는 fdt_property 구조체 반환
*/
const struct fdt_property *fdt_get_property_by_offset(const void *fdt,
						      int offset,
						      int *lenp)
{
	/* Prior to version 16, properties may need realignment
	 * and this API does not work. fdt_getprop_*() will, however. */

	// 16버전 이전에서는 이 함수를 사용하지 않고, fdt_getprop_() 함수를 사용
	if (fdt_version(fdt) < 0x10) {
		if (lenp)
			*lenp = -FDT_ERR_BADVERSION;
		return NULL;
	}
	
	// fdt_get_property_by_offset_() 함수 호출
	return fdt_get_property_by_offset_(fdt, offset, lenp);
}

/*
	fdt_get_property_namelen_() : offset이 가리키는 노드에서 name, namelen과 일치하는 property를 									찾아서 fdt_property 구조체를 포인터를 반환
								-lenp가 가리키는 곳에는 property를 찾지못했을 때 에러 저장
								-poffset에는 찾은 property의 offset을 저장
*/
static const struct fdt_property *fdt_get_property_namelen_(const void *fdt,
						            int offset,
						            const char *name,
						            int namelen,
							    int *lenp,
							    int *poffset)
{
	// offset이 가리키는 노드의 첫번째 property 부터
	// offset 다음 property 가 존재할 때까지 반복
	for (offset = fdt_first_property_offset(fdt, offset);
	     (offset >= 0);
	     (offset = fdt_next_property_offset(fdt, offset))) {
		const struct fdt_property *prop;

		// offset이 음수인지, 정렬이 잘 되어있는지, PROP을 가리키고 있는지 확인
		if (!(prop = fdt_get_property_by_offset_(fdt, offset, lenp))) {
			offset = -FDT_ERR_INTERNAL;
			break;
		}
		
		// prop->nameoff을 통해 구해진 이름과 name, namelen에 일치하는 지 확인
		if (fdt_string_eq_(fdt, fdt32_ld(&prop->nameoff),
				   name, namelen)) {
			// poffset이 NULL이 아니면, offset 값을 저장
			if (poffset)
				*poffset = offset;
			// fdt_property를 가리키는 prop 리턴
			return prop;
		}
	}

	// offset이 가리키는 노드내에서 name, namelen에 해당하는 property를 찾지 못했을때,
	// 에러를 lenp에 저장하고, NULL을 반환
	if (lenp)
		*lenp = offset;
	return NULL;
}

/*
	fdt_get_property_namelen() : offset이 가리키는 노드에서 name, namelen을 이용해 
								property를 찾아 fdt_property 구조체를 반환
*/
const struct fdt_property *fdt_get_property_namelen(const void *fdt,
						    int offset,
						    const char *name,
						    int namelen, int *lenp)
{
	/* Prior to version 16, properties may need realignment
	 * and this API does not work. fdt_getprop_*() will, however. */
	// 이 함수는 16버전 아래에서 사용할 수 없음
	// fdt_getprop_()을 사용해야함.
	if (fdt_version(fdt) < 0x10) {
		if (lenp)
			*lenp = -FDT_ERR_BADVERSION;
		return NULL;
	}
	
	// fdt_get_property_namelen_() 함수 호출
	return fdt_get_property_namelen_(fdt, offset, name, namelen, lenp, NULL);
}

/*
	fdt_get_property() : fdt_get_property_namelen 래퍼 함수, 
						name의 길이를 strlen(name)으로 구함
*/
const struct fdt_property *fdt_get_property(const void *fdt,
					    int nodeoffset,
					    const char *name, int *lenp)
{
	return fdt_get_property_namelen(fdt, nodeoffset, name,
					strlen(name), lenp);
}

/*
	fdt_getprop_namelen() : nodeoffset에 해당하는 노드에서 name, namelen에 일치하는
						 fdt_property가 가지고 있는 data를 반환
*/
const void *fdt_getprop_namelen(const void *fdt, int nodeoffset,
				const char *name, int namelen, int *lenp)
{
	int poffset;
	const struct fdt_property *prop;

	// nodeoffset에 해당하는 노드에서 name, namelen과 일치하는 fdt_property 구조체를 반환
	prop = fdt_get_property_namelen_(fdt, nodeoffset, name, namelen, lenp,
					 &poffset);
	// name, namelen에 일치하는 fdt_property 구조체를 찾지 못한 경우, NULL 반환
	if (!prop)
		return NULL;

	/* Handle realignment */
	// fdt버전이 16아래이고
	// 찾은 fdt_property 구조체가 8 바이트 단위로 정렬되어 있고
	// prop->len 이 8보다 크면 prop->data + 4를 반환
	if (fdt_version(fdt) < 0x10 && (poffset + sizeof(*prop)) % 8 &&
	    fdt32_ld(&prop->len) >= 8)
		return prop->data + 4;

	// prop->data를 반환
	return prop->data;
}

/*
	fdt_getprop_by_offset() : 주어진 offset으로 fdt_property 구조체에 저장된 data를 반환
								namep는 fdt_property 이름을 가리킴
								lenp가 가리키는 곳에 fdt_property 구조체의 len변수 저장
*/
const void *fdt_getprop_by_offset(const void *fdt, int offset,
				  const char **namep, int *lenp)
{
	// fdt_property 구조체 포인터 선언
	const struct fdt_property *prop;

	// offset가 가리키는 fdt_property 구조체를 반환
	prop = fdt_get_property_by_offset_(fdt, offset, lenp);
	// offset이 가리키는 fdt_property 구조체가 존재하지 않으면
	if (!prop)
		return NULL;
	// namep가 존재하면
	if (namep) {
		const char *name;
		int namelen;
		// prop->nameoff에 해당하는 이름을 반환하고 길이를 namelen에 저장
		name = fdt_get_string(fdt, fdt32_ld(&prop->nameoff),
				      &namelen);
		// offset에 해당하는 name을 찾지 못했을 경우
		if (!name) {
			// lenp가 존재하면, lenp가 가리키는 곳에 fdt_get_string()에서 넘어온 에러를 반환
			if (lenp)
				*lenp = namelen;
			// 찾지 못할 경우 NULL 반환
			return NULL;
		}
		// namep가 name을 가리키도록 함.
		*namep = name;
	}

	/* Handle realignment */
	// fdt 버전이 16 아래이고, 8바이트 단위로 정렬되어 있고, prop->len이 8을 넘을 때
	if (fdt_version(fdt) < 0x10 && (offset + sizeof(*prop)) % 8 &&
	    fdt32_ld(&prop->len) >= 8)
		// data를 반환할 때, 4바이트 떨어진 곳을 반환
		return prop->data + 4;
	// data를 반환
	return prop->data;
}
/*
	fdt_getprop() : nodeoffset에 해당하는 노드에서,
					 name과 일치하는 fdt_property 구조체의 data를 반환
					lenp에는 fdt_property 구조체의 len을 저장
*/
const void *fdt_getprop(const void *fdt, int nodeoffset,
			const char *name, int *lenp)
{
	return fdt_getprop_namelen(fdt, nodeoffset, name, strlen(name), lenp);
}

/*
	fdt_get_phandle() : nodeoffset에 해당하는 노드의 phandle을 반환
*/
uint32_t fdt_get_phandle(const void *fdt, int nodeoffset)
{
	const fdt32_t *php;
	int len;

	/* FIXME: This is a bit sub-optimal, since we potentially scan
	 * over all the properties twice. */
	// nodeoffset이 가리키는 노드에서 "phandle"에 일치하는 fdt_property 구조체 data 반환
	// len에는 fdt_property 구조체의 len 반환
	php = fdt_getprop(fdt, nodeoffset, "phandle", &len);
	// php가 존재하지 않거나, len과 php가 가리키는 data의 길이가 일치하지 않을 때,
	if (!php || (len != sizeof(*php))) {
		// "linux, phandle"로 다시 한번 찾음
		php = fdt_getprop(fdt, nodeoffset, "linux,phandle", &len);
		// 다시 찾아도 없는 경우에는 0을 반환
		if (!php || (len != sizeof(*php)))
			return 0;
	}

	// 노드에서 "phandle"이나 "linux,phandle"을 찾은 경우에는
	// 엔디안에 맞춰 포인터 반환
	return fdt32_ld(php);
}

/*
	fdt_get_alias_namelen() : name, namelen에 해당하는 alias가 있으면
							그 fdt_property 구조체의 data를 가리키는 포인터 반환
*/
const char *fdt_get_alias_namelen(const void *fdt,
				  const char *name, int namelen)
{
	int aliasoffset;

	// "/aliases"로 offset을 구함
	aliasoffset = fdt_path_offset(fdt, "/aliases");
	// "/aliases"가 없을 때, NULL 리턴
	if (aliasoffset < 0)
		return NULL;

	// aliasoffset에 해당하는 노드에서 name과 namelen으로 PROP를 찾아서 data를 반환
	return fdt_getprop_namelen(fdt, aliasoffset, name, namelen, NULL);
}

/*
	fdt_get_alias() : name에 해당하는 alias가 있으면
					 그 fdt_property의 data를 가리키는 포인터 반환
*/
const char *fdt_get_alias(const void *fdt, const char *name)
{
	// fdt_get_alias_namelen() 함수 호출, name, strlen(name)을 인자로
	return fdt_get_alias_namelen(fdt, name, strlen(name));
}

/*
	fdt_get_path() : nodeoffset에 해당하는 노드의 full path를 buf에 저장,
												 buf의 길이를 buflen에 저장
*/
int fdt_get_path(const void *fdt, int nodeoffset, char *buf, int buflen)
{
	// buf에서 경로가 깊이를 나타내는 pdepth
	// buf에서 다음에 경로를 저장할 인덱스를 나타내는 p
	int pdepth = 0, p = 0;
	// 노드를 순회하면서 노드의 오프셋을 저장할 offset
	// 노드를 순회하면서 노드의 깊이를 저장 depth
	int offset, depth, namelen;
	const char *name;
	
	// read only 인지 확인
	FDT_RO_PROBE(fdt);

	// buflen가 2보다 작으면 (buf에 '\0'문자만 저장 가능하므로) 에러
	if (buflen < 2)
		return -FDT_ERR_NOSPACE;

	// offset, depth가 0부터
	// fdt_next_node()에서 반환한 offset이 0보다 크거나 같고, nodeoffset보다 작거나 같을 때
	// -> 다음 node가 존재하고, 그 노드가 경로를 찾으려는 nodeoffset보다 작거나 같을 때까지
	// fdt_next_node()를 수행해서 offset, depth를 업데이트 한다.
	// -> 다음 노드가 있으면 offset값이 그 노드를 가리키고,
	//		자식 노드가 있으면, depth 증가. 형제 노드가 있으면, depth 유지
	for (offset = 0, depth = 0;
	     (offset >= 0) && (offset <= nodeoffset);
	     offset = fdt_next_node(fdt, offset, &depth)) {
		// 노드를 순회하다보면 해당 노드의 형제/자식 노드에 찾는 노드가 없으면,
		// 부모 노드로 올라가는 경우가 있음
		// -> 노드 순회 시 사용하는 depth가 부모 노드로 올라가면서 감소하여, 
		// 	  buf에 저장된 경로의 깊이를 나타내는 pdepth가 depth보다 커질 수 있음
		while (pdepth > depth) {
			do {
				// p가 가리키는 인덱스가 '/' 다음을 가리킬 때까지 감소시킴
				p--;
			} while (buf[p-1] != '/');
			// buf에 저장된 경로의 깊이를 하나 줄임
			pdepth--;
		}

		// depth가 pdepth보다 작거나 같은 경우
		if (pdepth >= depth) {
			// 현재 offset의 노드의 이름을 반환, namelen은 이름의 길이를 저장
			name = fdt_get_name(fdt, offset, &namelen);
			// 에러일 경우 NULL 반환, namelen에 에러 이유 저장
			if (!name)
				return namelen;
			// 현재 offset의 노드의 이름을 성공적으로 반환했을 때,
			// 저장할 버퍼의 공간이 충분하면
			if ((p + namelen + 1) <= buflen) {
				// buf+p 위치에 name을 namelen 만큼 복사
				memcpy(buf + p, name, namelen);
				// buf에서 현재 위치를 가리키는 p를 namelen만큼 이동시킴
				p += namelen;
				// 경로를 표시하기 위해 '/'를 추가하고 p를 하나 증가시킴
				buf[p++] = '/';
				// 경로의 깊이를 표시하는 pdepth 하나 증가
				pdepth++;
			}
		}

		// 현재 offset과 nodeoffset이 같으면, 
		if (offset == nodeoffset) {
			// 
			if (pdepth < (depth + 1))
				return -FDT_ERR_NOSPACE;
			// p가 2이상이면 루트 노드 이외의 경로가 존재하는 것이므로
			if (p > 1) /* special case so that root path is "/", not "" */
				// 위에서 삽입했던 '/'문자 제거
				p--;
			// 문자열을 표시하기 위해 '/0'을 삽입
			buf[p] = '\0';
			// 성공 시 0 반환
			return 0;
		}
	}

	// 끝까지 노드를 순회해도 찾을 수 없는 경우
	// fdt_next_node()에서 반환하는 에러값에 따라 처리
	if ((offset == -FDT_ERR_NOTFOUND) || (offset >= 0))
		return -FDT_ERR_BADOFFSET;
	else if (offset == -FDT_ERR_BADOFFSET)
		return -FDT_ERR_BADSTRUCTURE;
	
	return offset; /* error from fdt_next_node() */
}

/*
	fdt_supernode_atdepth_offset() : nodeoffset의 조상 노드 중,
									 supernodedepth와 일치하는 노드의 offset을 반환
*/
int fdt_supernode_atdepth_offset(const void *fdt, int nodeoffset,
				 int supernodedepth, int *nodedepth)
{
	// 노드를 순회하면서, 그 노드의 오프셋과 깊이를 offset, depth에 저장
	int offset, depth;
	// supernodeoffset
	int supernodeoffset = -FDT_ERR_INTERNAL;

	FDT_RO_PROBE(fdt);

	// 루트 노드의 depth가 0이므로 supernodedepth는 0보다 작을 수 없음
	if (supernodedepth < 0)
		return -FDT_ERR_NOTFOUND;

	// offset, depth가 0부터 -> 처음 노드 부터 찾겠다
	// offset이 존재하고, nodeoffset 까지 찾음
	// fdt_next_node()로 offset, depth 업데이트
	for (offset = 0, depth = 0;
	     (offset >= 0) && (offset <= nodeoffset);
	     offset = fdt_next_node(fdt, offset, &depth)) {
		// depth가 찾는 supernodepeth와 일치하면
		if (depth == supernodedepth)
			// supernodeoffset을 offset으로 갱신
			supernodeoffset = offset;

		// offset이 nodeoffset과 같으면 처음 부터 nodeoffset의 조상을 다 찾은 것임
		if (offset == nodeoffset) {
			// nodedepth가 NULL이 아니면, nodedepth가 가리키는 곳에 depth 저장
			if (nodedepth)
				*nodedepth = depth;

			// supernodedepth가 depth보다 크면 supernodedepth에 해당하는 노드를 찾지 못한 것
			if (supernodedepth > depth)
				return -FDT_ERR_NOTFOUND;
			// supernodedepth가 depth보다 작거나 같으면 성공, supernodeoffset을 반환
			else
				return supernodeoffset;
		}
	}

	// supernodedepth에 해당하는 노드를 찾지 못한 경우,
	// fdt_next_node()함수의 반환값에 따라 에러 처리
	if ((offset == -FDT_ERR_NOTFOUND) || (offset >= 0))
		return -FDT_ERR_BADOFFSET;
	else if (offset == -FDT_ERR_BADOFFSET)
		return -FDT_ERR_BADSTRUCTURE;

	return offset; /* error from fdt_next_node() */
}

/*
	fdt_node_depth() : nodeoffset에 해당하는 노드의 depth를 반환
*/
int fdt_node_depth(const void *fdt, int nodeoffset)
{
	int nodedepth;
	int err;
	
	// fdt_supernode_atdepth_offset() 함수는
	// 처음 노드에서 nodeoffset까지 노드를 순회하면서 supernodedepth(현재 0)에 
	// 해당하는 깊이가 있는 노드를 찾고, nodeoffset의 깊이를 nodedepth에 저장하는데,
	// supernodedepth가 현재 0이므로 함수의 반환값은 0에 해당하는 오프셋이 되어야함
	err = fdt_supernode_atdepth_offset(fdt, nodeoffset, 0, &nodedepth);
	// err=0 은 루트 노드의 depth(0)인 경우 -> 0을 출력
	// err<0은 함수에서 에러가 발생한 경우 -> 에러 메세지 출력
	if (err)
		return (err < 0) ? err : -FDT_ERR_INTERNAL;
	// nodeoffset에 해당하는 nodedepth를 반환
	return nodedepth;
}

/*
	fdt_parent_offset() : nodeoffset에 해당하는 노드의 부모 노드의 오프셋을 반환
*/
int fdt_parent_offset(const void *fdt, int nodeoffset)
{
	// nodeoffset에 해당하는 노드의 깊이를 nodedepth에 저장
	int nodedepth = fdt_node_depth(fdt, nodeoffset);

	// nodedepth가 음수이면, 에러난 것
	if (nodedepth < 0)
		return nodedepth;
	// nodedepth가 0보다 크거나 같으면, nodeoffset에 해당하는 nodedepth를 찾았다는 의미
	// -> nodeodepth보다 하나 작은 부모 노드의 깊이로 fdt_supernode_atdepth_offset() 함수 호출
	return fdt_supernode_atdepth_offset(fdt, nodeoffset, nodedepth - 1, NULL);
}
/*
	fdt_node_offset_by_prop_value() : startoffset에 해당하는 노드에서 시작하여
										propname, propval, proplen과 일치하는
										 property value를 가진 fdt_property 구조체의 오프셋 반환
*/
int fdt_node_offset_by_prop_value(const void *fdt, int startoffset,
				  const char *propname,
				  const void *propval, int proplen)
{
	// 찾은 offset 저장
	int offset;
	
	const void *val;
	int len;

	FDT_RO_PROBE(fdt);

	/* FIXME: The algorithm here is pretty horrible: we scan each
	 * property of a node in fdt_getprop(), then if that didn't
	 * find what we want, we scan over them again making our way
	 * to the next node.  Still it's the easiest to implement
	 * approach; performance can come later. */

	// fdt_next_node() 함수로 startoffset 다음 노드 부터 시작
	// offset이 존재할 때까지
	// fdt_next_node() 함수로 offset 업데이트
	for (offset = fdt_next_node(fdt, startoffset, NULL);
	     offset >= 0;
	     offset = fdt_next_node(fdt, offset, NULL)) {
		// offset에 해당하는 노드에서 propname과 일치하는 fdt_property 구조체의 data를 반환
		// len에는 fdt_property 구조체의 len(data의 길이)를 저장
		val = fdt_getprop(fdt, offset, propname, &len);
		// val가 NULL이 아니고, len이 찾는 proplen과 같고,
		// val에 저장된 문자열과 propval가 일치하면 -> offset을 반환
		if (val && (len == proplen)
		    && (memcmp(val, propval, len) == 0))
			return offset;
	}

	// startoffset부터 모든 노드를 찾아도
	// propname, propval, proplen과 일치하는 구조체를 찾지 못한 경우
	// -> fdt_next_node()로 부터의 에러 반환
	return offset; /* error from fdt_next_node() */
}

int fdt_node_offset_by_phandle(const void *fdt, uint32_t phandle)
{
	int offset;

	if ((phandle == 0) || (phandle == -1))
		return -FDT_ERR_BADPHANDLE;

	FDT_RO_PROBE(fdt);

	/* FIXME: The algorithm here is pretty horrible: we
	 * potentially scan each property of a node in
	 * fdt_get_phandle(), then if that didn't find what
	 * we want, we scan over them again making our way to the next
	 * node.  Still it's the easiest to implement approach;
	 * performance can come later. */
	for (offset = fdt_next_node(fdt, -1, NULL);
	     offset >= 0;
	     offset = fdt_next_node(fdt, offset, NULL)) {
		if (fdt_get_phandle(fdt, offset) == phandle)
			return offset;
	}

	return offset; /* error from fdt_next_node() */
}

int fdt_stringlist_contains(const char *strlist, int listlen, const char *str)
{
	int len = strlen(str);
	const char *p;

	while (listlen >= len) {
		if (memcmp(str, strlist, len+1) == 0)
			return 1;
		p = memchr(strlist, '\0', listlen);
		if (!p)
			return 0; /* malformed strlist.. */
		listlen -= (p-strlist) + 1;
		strlist = p + 1;
	}
	return 0;
}

int fdt_stringlist_count(const void *fdt, int nodeoffset, const char *property)
{
	const char *list, *end;
	int length, count = 0;

	list = fdt_getprop(fdt, nodeoffset, property, &length);
	if (!list)
		return length;

	end = list + length;

	while (list < end) {
		length = strnlen(list, end - list) + 1;

		/* Abort if the last string isn't properly NUL-terminated. */
		if (list + length > end)
			return -FDT_ERR_BADVALUE;

		list += length;
		count++;
	}

	return count;
}

int fdt_stringlist_search(const void *fdt, int nodeoffset, const char *property,
			  const char *string)
{
	int length, len, idx = 0;
	const char *list, *end;

	list = fdt_getprop(fdt, nodeoffset, property, &length);
	if (!list)
		return length;

	len = strlen(string) + 1;
	end = list + length;

	while (list < end) {
		length = strnlen(list, end - list) + 1;

		/* Abort if the last string isn't properly NUL-terminated. */
		if (list + length > end)
			return -FDT_ERR_BADVALUE;

		if (length == len && memcmp(list, string, length) == 0)
			return idx;

		list += length;
		idx++;
	}

	return -FDT_ERR_NOTFOUND;
}

const char *fdt_stringlist_get(const void *fdt, int nodeoffset,
			       const char *property, int idx,
			       int *lenp)
{
	const char *list, *end;
	int length;

	list = fdt_getprop(fdt, nodeoffset, property, &length);
	if (!list) {
		if (lenp)
			*lenp = length;

		return NULL;
	}

	end = list + length;

	while (list < end) {
		length = strnlen(list, end - list) + 1;

		/* Abort if the last string isn't properly NUL-terminated. */
		if (list + length > end) {
			if (lenp)
				*lenp = -FDT_ERR_BADVALUE;

			return NULL;
		}

		if (idx == 0) {
			if (lenp)
				*lenp = length - 1;

			return list;
		}

		list += length;
		idx--;
	}

	if (lenp)
		*lenp = -FDT_ERR_NOTFOUND;

	return NULL;
}

int fdt_node_check_compatible(const void *fdt, int nodeoffset,
			      const char *compatible)
{
	const void *prop;
	int len;

	prop = fdt_getprop(fdt, nodeoffset, "compatible", &len);
	if (!prop)
		return len;

	return !fdt_stringlist_contains(prop, len, compatible);
}

int fdt_node_offset_by_compatible(const void *fdt, int startoffset,
				  const char *compatible)
{
	int offset, err;

	FDT_RO_PROBE(fdt);

	/* FIXME: The algorithm here is pretty horrible: we scan each
	 * property of a node in fdt_node_check_compatible(), then if
	 * that didn't find what we want, we scan over them again
	 * making our way to the next node.  Still it's the easiest to
	 * implement approach; performance can come later. */
	for (offset = fdt_next_node(fdt, startoffset, NULL);
	     offset >= 0;
	     offset = fdt_next_node(fdt, offset, NULL)) {
		err = fdt_node_check_compatible(fdt, offset, compatible);
		if ((err < 0) && (err != -FDT_ERR_NOTFOUND))
			return err;
		else if (err == 0)
			return offset;
	}

	return offset; /* error from fdt_next_node() */
}

int fdt_check_full(const void *fdt, size_t bufsize)
{
	int err;
	int num_memrsv;
	int offset, nextoffset = 0;
	uint32_t tag;
	unsigned depth = 0;
	const void *prop;
	const char *propname;

	if (bufsize < FDT_V1_SIZE)
		return -FDT_ERR_TRUNCATED;
	err = fdt_check_header(fdt);
	if (err != 0)
		return err;
	if (bufsize < fdt_totalsize(fdt))
		return -FDT_ERR_TRUNCATED;

	num_memrsv = fdt_num_mem_rsv(fdt);
	if (num_memrsv < 0)
		return num_memrsv;

	while (1) {
		offset = nextoffset;
		tag = fdt_next_tag(fdt, offset, &nextoffset);

		if (nextoffset < 0)
			return nextoffset;

		switch (tag) {
		case FDT_NOP:
			break;

		case FDT_END:
			if (depth != 0)
				return -FDT_ERR_BADSTRUCTURE;
			return 0;

		case FDT_BEGIN_NODE:
			depth++;
			if (depth > INT_MAX)
				return -FDT_ERR_BADSTRUCTURE;
			break;

		case FDT_END_NODE:
			if (depth == 0)
				return -FDT_ERR_BADSTRUCTURE;
			depth--;
			break;

		case FDT_PROP:
			prop = fdt_getprop_by_offset(fdt, offset, &propname, &err);
			if (!prop)
				return err;
			break;

		default:
			return -FDT_ERR_INTERNAL;
		}
	}
}
