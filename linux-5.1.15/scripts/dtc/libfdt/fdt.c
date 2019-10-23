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
 * Minimal sanity check for a read-only tree. fdt_ro_probe_() checks
 * that the given buffer contains what appears to be a flattened
 * device tree with sane information in its header.
 */
/*
	fdt_ro_probe_() : read only인지 확인하는 함수
*/
int fdt_ro_probe_(const void *fdt)
{
	//magic_number 확인, FDT_MAGIC = 0xd00dfeed
	if (fdt_magic(fdt) == FDT_MAGIC) {
		/* Complete tree */
		// 버전 확인
		// FDT_FIRST_SUPPORTED_VERSION = 0x02
		if (fdt_version(fdt) < FDT_FIRST_SUPPORTED_VERSION)
			return -FDT_ERR_BADVERSION;
		// FDT_LAST_SUPPORTED_VERSION = 0x11
		if (fdt_last_comp_version(fdt) > FDT_LAST_SUPPORTED_VERSION)
			return -FDT_ERR_BADVERSION;

	// FDT_SW_MAGIC = (~FDT_MAGIC)
	// magic number를 확인해서 FDT_SW_MAGIC이면 struct 사이즈를 확인함
	} else if (fdt_magic(fdt) == FDT_SW_MAGIC) {
		/* Unfinished sequential-write blob */
		if (fdt_size_dt_struct(fdt) == 0)
			return -FDT_ERR_BADSTATE;

	// magic number가 맞지 않으면 에러 return
	} else {
		return -FDT_ERR_BADMAGIC;
	}

	return 0;
}

/*
	check_off_() : offset이 DTB의 header와 끝 사이에 있는 것인지 확인
*/

static int check_off_(uint32_t hdrsize, uint32_t totalsize, uint32_t off)
{
	return (off >= hdrsize) && (off <= totalsize);
}

/*
	check_block_() : block의 base, base+size가 DTB의 header~ DTB의 끝 사이에 있는지 확인
*/
static int check_block_(uint32_t hdrsize, uint32_t totalsize,
			uint32_t base, uint32_t size)
{
	// base가 DTB의 header~끝의 범위를 벗어난 경우
	if (!check_off_(hdrsize, totalsize, base))
		return 0; /* block start out of bounds */

	// size < 0 인 경우
	if ((base + size) < base)
		return 0; /* overflow */

	// block이 범위를 범어난 경우
	if (!check_off_(hdrsize, totalsize, base + size))
		return 0; /* block end out of bounds */
	return 1;
}

/*
	fdt_header_size_() : 버전에 따른 header 사이즈를 return
*/
size_t fdt_header_size_(uint32_t version)
{
	if (version <= 1)
		return FDT_V1_SIZE;
	else if (version <= 2)
		return FDT_V2_SIZE;
	else if (version <= 3)
		return FDT_V3_SIZE;
	else if (version <= 16)
		return FDT_V16_SIZE;
	else
		return FDT_V17_SIZE;
}

/*
	fdt_check_header() : header 구조체에 정의되어 있는 정보들
						 (magic number, header size, version, totalsize, reserve block 크기, 
						  structure block 크기, string block 크기)을 확인함.
*/

int fdt_check_header(const void *fdt)
{
	size_t hdrsize;

	// magic number 확인
	if (fdt_magic(fdt) != FDT_MAGIC)
		return -FDT_ERR_BADMAGIC;

	// header size 저장
	hdrsize = fdt_header_size(fdt);

	// version 확인
	// 현재 버전과 호환될 수 있는 버전도 확인
	if ((fdt_version(fdt) < FDT_FIRST_SUPPORTED_VERSION)
	    || (fdt_last_comp_version(fdt) > FDT_LAST_SUPPORTED_VERSION))
		return -FDT_ERR_BADVERSION;
	if (fdt_version(fdt) < fdt_last_comp_version(fdt))
		return -FDT_ERR_BADVERSION;

	// fdt의 전체 크기확인
	if ((fdt_totalsize(fdt) < hdrsize)
	    || (fdt_totalsize(fdt) > INT_MAX))
		return -FDT_ERR_TRUNCATED;

	/* Bounds check memrsv block */
	if (!check_off_(hdrsize, fdt_totalsize(fdt), fdt_off_mem_rsvmap(fdt)))
		return -FDT_ERR_TRUNCATED;

	/* Bounds check structure block */
	if (fdt_version(fdt) < 17) {
		if (!check_off_(hdrsize, fdt_totalsize(fdt),
				fdt_off_dt_struct(fdt)))
			return -FDT_ERR_TRUNCATED;
	} else {
		if (!check_block_(hdrsize, fdt_totalsize(fdt),
				  fdt_off_dt_struct(fdt),
				  fdt_size_dt_struct(fdt)))
			return -FDT_ERR_TRUNCATED;
	}

	/* Bounds check strings block */
	if (!check_block_(hdrsize, fdt_totalsize(fdt),
			  fdt_off_dt_strings(fdt), fdt_size_dt_strings(fdt)))
		return -FDT_ERR_TRUNCATED;

	return 0;
}

/*
	fdt_offset_ptr() : structure에서 offset만큼 거리에 있는 node의 포인터를 구함
*/
const void *fdt_offset_ptr(const void *fdt, int offset, unsigned int len)
{
	// offset은 structure에서부터 찾는 node까지의 offset을 의미
	// absoffset는 찾는 node의 offset을 의미
	unsigned absoffset = offset + fdt_off_dt_struct(fdt);

	// 범위 검사
	// structure offset이 음수인지, len가 음수인지, 전체 fdt 사이즈를 넘는 지
	if ((absoffset < offset)
	    || ((absoffset + len) < absoffset)
	    || (absoffset + len) > fdt_totalsize(fdt))
		return NULL;

	// 17버전 이후에는 header에 structure block의 사이즈를 나타내는 size_dt_struct가 추가됨
	// 범위 검사
    // len이 음수 인지, node의 크기가 structure의 사이즈를 넘는지
	if (fdt_version(fdt) >= 0x11)
		if (((offset + len) < offset)
		    || ((offset + len) > fdt_size_dt_struct(fdt)))
			return NULL;
	
	// 찾는 structure node을 가리키는 포인터 반환
	return fdt_offset_ptr_(fdt, offset);
}

/*
	fdt_next_tag() : nextoffset에 현재 startoffset이 가리키는 tag의 다음 tag를 저장하고
					 현재 tag에 저장된 값을 반환
*/
uint32_t fdt_next_tag(const void *fdt, int startoffset, int *nextoffset)
{
	const fdt32_t *tagp, *lenp;
	uint32_t tag;
	int offset = startoffset;
	const char *p;

	// 일단 err로 설정
	*nextoffset = -FDT_ERR_TRUNCATED;
	// structure에서 offset(startoffset)만큼 떨어진 곳에 있는 node의 포인터를 저장
	tagp = fdt_offset_ptr(fdt, offset, FDT_TAGSIZE);
	
	// NULL이면 node가 범위를 벗어난 것임
	if (!tagp)
		return FDT_END; /* premature end */
	// 엔디안에 맞게 tagp에 저장되어 있는 값을 가져옴.
	tag = fdt32_to_cpu(*tagp);
	// FDT_TAGSIZE = 4
	// tag의 끝을 나타내는 offset이 됨
	offset += FDT_TAGSIZE;

	*nextoffset = -FDT_ERR_BADSTRUCTURE;
	// 현재 tag가 BEGIN_NODE, PROP, END, END_NODE, NOP인지에 따라 
	// 다음 tag를 구하는 연산을 함
	switch (tag) {
	case FDT_BEGIN_NODE:
		// 현재 tag가 BEGIN_NODE이면 다음 tag를 구하기 위해서는 name을 건너뛰어야함
		/* skip name */

		// '\0'을 만날때 까지 offset을 1씩 더하면서 검사
		do {
			p = fdt_offset_ptr(fdt, offset++, 1);
		} while (p && (*p != '\0'));
		// p가 NULL이면 범위를 벗어난 것
		if (!p)
			return FDT_END; /* premature end */
		break;

	case FDT_PROP:
		// 현재 tag가 PROP이면 다음 tag구하려면 value length, name offset, value를 건너뛰어야 함
		// lenp에 현재 tag의 value length를 가리키는 포인터 저장
		lenp = fdt_offset_ptr(fdt, offset, sizeof(*lenp));

		if (!lenp)
			return FDT_END; /* premature end */
		/* skip-name offset, length and value */

		// fdt_property는 tag, len, nameoff로 이루어짐 -> 12byte
		// FDT_TAGSIZE = 4
		// fdt32_to_cpu(*lenp) : 현재 tag의 value length

		// offset += (tag, len, nameoff) - tag size + value length
		// 따라서 다음 tag offset를 나타내는 offset이 됨
		offset += sizeof(struct fdt_property) - FDT_TAGSIZE
			+ fdt32_to_cpu(*lenp);

		// 15버전 이하이고, value length가 8이상,
		// tag, value length, name off이 8단위로 정렬되있지 않으면 offset에 4를 더함

		// value가 8이상이면 공간을 더 마련해주기 위해서 하는 것 같음...
		if (fdt_version(fdt) < 0x10 && fdt32_to_cpu(*lenp) >= 8 &&
		    ((offset - fdt32_to_cpu(*lenp)) % 8) != 0)
			offset += 4;
		break;
	// tag가 FDT_END, END_NODE, NOP일 때는 다음 tag를 구하지 않음
	case FDT_END:
	case FDT_END_NODE:
	case FDT_NOP:
		break;

	default:
		return FDT_END;
	}

	// startoffset에서 부터 offset - startoffset 만큼 크기를 가질 수 있는지 범위검사
	if (!fdt_offset_ptr(fdt, startoffset, offset - startoffset))
		return FDT_END; /* premature end */

	// tag size(4)로 offset을 정렬하여 nextoffset에 저장
	*nextoffset = FDT_TAGALIGN(offset);
	return tag;
}

/*
	fdt_check_node_offset() : offset이 음수인지, tag size단위로 정렬되어있는 지, 
								BEGIN_NODE를 가리키고 있는지 확인
*/
int fdt_check_node_offset_(const void *fdt, int offset)
{
	if ((offset < 0) || (offset % FDT_TAGSIZE)
	    || (fdt_next_tag(fdt, offset, &offset) != FDT_BEGIN_NODE))
		return -FDT_ERR_BADOFFSET;

	return offset;
}

/*
	fdt_check_prop_offset() : offset이 음수인지, tag size단위로 정렬되어 있는 지,
								PROP을 가리키고 있는지 확인
*/
int fdt_check_prop_offset_(const void *fdt, int offset)
{
	if ((offset < 0) || (offset % FDT_TAGSIZE)
	    || (fdt_next_tag(fdt, offset, &offset) != FDT_PROP))
		return -FDT_ERR_BADOFFSET;

	return offset;
}

/*
	fdt_next_node() : 현재 offset의 depth를 가지고 tag단위로 확인
					  다음 node의 offset을 반환
*/
int fdt_next_node(const void *fdt, int offset, int *depth)
{
	int nextoffset = 0;
	uint32_t tag;

	// 현재 offset을 범위, 정렬, BEGIN_NODE를 가리키고 있는지 검사
	if (offset >= 0)
		if ((nextoffset = fdt_check_node_offset_(fdt, offset)) < 0)
			return nextoffset;
			

	do {
		offset = nextoffset;
		// 현재 offset의 tag를 tag에 저장,
		// 다음 tag의 offset을 nextoffset에 저장
		tag = fdt_next_tag(fdt, offset, &nextoffset);

		switch (tag) {
		//현재 tag가 PROP, NOP이면 신경 안씀
		case FDT_PROP:
		case FDT_NOP:
			break;
		
		// 현재 tag가 BEGIN_NODE 이면, depth가 NULL이 아니면 depth를 증가시킴
		// 현재 tag가 BEGIN_NODE 이면 do_while 문을 빠져나감
		case FDT_BEGIN_NODE:
			if (depth)
				(*depth)++;
			break;
		
		// 현재 tag가 END_NODE이면, 
		case FDT_END_NODE:
			// depth < 0 이면 루트 노드를 벗어난 것이므로
			// fdt_next_tag()에서 nextoffset에 에러 값이 저장되어 있을 것이으로 에러 반환
			if (depth && ((--(*depth)) < 0))
				return nextoffset;
			break;
		
		// 현재 tag가 END이면, 다음 node가 존재 하지 않으므로
		case FDT_END:
			// nextoffset >= 0 이면 다음 tag가 존재한다는 의미이므로 에러
			// fdt_next_tag에서 nextoffset이 -FDT_ERR_TRUNCATED이면 범위를 벗어난 것
			if ((nextoffset >= 0)
			    || ((nextoffset == -FDT_ERR_TRUNCATED) && !depth))
				return -FDT_ERR_NOTFOUND;
			else
				return nextoffset;
		}
	//현재 tag가 BEGIN_NODE 일 때까지 반복
	} while (tag != FDT_BEGIN_NODE);

	// BEGIN_NODE 일때의 offset 반환
	return offset;
}

/*
	fdt_first_subnode() : 현재 offset이 가리키는 tag로 부터 다음 첫번째 자식 node를 찾음
							자식 노드가 없으면 err
*/
int fdt_first_subnode(const void *fdt, int offset)
{
	int depth = 0;
	
	// 현재 offset이 가리키는 tag로 부터 depth = 0을 가지고 다음 노드를 찾음
	offset = fdt_next_node(fdt, offset, &depth);
	// offset < 0 이면 err
	// depth가 1이 아니면, 자식 node가 아님
	if (offset < 0 || depth != 1)
		return -FDT_ERR_NOTFOUND;

	return offset;
}

/*
	fdt_next_subnode() : 현재 offset이 가리키는 node의 형제 node를 찾음
*/
int fdt_next_subnode(const void *fdt, int offset)
{
	int depth = 1;

	/*
	 * With respect to the parent, the depth of the next subnode will be
	 * the same as the last.
	 */

	// 자식 node가 존재하면 depth 증가
	// 부모 node로 올라가면 depth 감소

	do {
		// 다음 node의 offset을 구해서 offset에 저장
		offset = fdt_next_node(fdt, offset, &depth);
		// offset < 0이면 다음 node가 없다는 의미
		// depth < 1 이면 부모 node로 올라간 것, 형제 node가 없다는 의미
		if (offset < 0 || depth < 1)
			return -FDT_ERR_NOTFOUND;

	// 자식 node가 존재하는 경우에는 계속 다음 node를 찾는 것을 반복
	} while (depth > 1);

	return offset;
}

/*
	fdt_find_string_() : string block에서 s를 찾아서 존재하면 포인터 반환, 
													존재하지 않으면 NULL 반환
*/
const char *fdt_find_string_(const char *strtab, int tabsize, const char *s)
{
	// NULL 문자를 포함한 s길이 저장
	int len = strlen(s) + 1;
	// string block의 마지막에서 s의 길이만큼을 뺀 곳까지의 포인터 저장
	const char *last = strtab + tabsize - len;
	const char *p;

	// string block의 시작부터 last까지 한문자씩 옮겨가며 s와 비교하여 포인터 반환
	for (p = strtab; p <= last; p++)
		if (memcmp(p, s, len) == 0)
			return p;
	return NULL;
}

/*
	fdt_move() : fdt 전체를 buf에 복사
*/
int fdt_move(const void *fdt, void *buf, int bufsize)
{
	// fdt가 read only인지 확인
	FDT_RO_PROBE(fdt);

	// buffer 사이즈가 fdt의 전체 크기보다 작으면 err
	if (fdt_totalsize(fdt) > bufsize)
		return -FDT_ERR_NOSPACE;

	// fdt에서 buf로 fdt_totalsize(fdt) 만큼 복사
	memmove(buf, fdt, fdt_totalsize(fdt));
	return 0;
}
