/* Minimal kernel-side types for probe.c: the integer typedefs the libbpf
 * helper headers expect and the two map types the program uses. Kept by
 * hand instead of a generated vmlinux.h (plan #96, decision 4); the
 * struct pt_regs the program reads is defined in probe.c per target. */
#ifndef PII_SHIELD_TYPES_H
#define PII_SHIELD_TYPES_H

typedef unsigned char __u8;
typedef short int __s16;
typedef short unsigned int __u16;
typedef int __s32;
typedef unsigned int __u32;
typedef long long int __s64;
typedef long long unsigned int __u64;
typedef __u16 __le16;
typedef __u16 __be16;
typedef __u32 __be32;
typedef __u64 __be64;
typedef __u32 __wsum;

enum bpf_map_type_used {
	BPF_MAP_TYPE_PERCPU_ARRAY = 6,
	BPF_MAP_TYPE_RINGBUF = 27,
};

#include "bpf_helpers.h"

#endif
