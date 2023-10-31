#include<stdio.h>
#include<string.h>
#include <stdlib.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <sys/queue.h>
#include <math.h>
#include <stdbool.h>
/*
#include "./headers/rte_ether.h"
#include <headers/rte_ip.h>
#include <headers/rte_tcp.h>
#include <headers/rte_udp.h>
#include <headers/rte_vxlan.h>*/


#define	_CTYPE_H	1
#include <features.h>
#include <bits/types.h>
#include "ctype.h"
#define _GNU_SOURCE
#include <sched.h>
#pragma pack(1) 
unsigned char outer_header[]={0x08,0x00, 0x27, 0xf2, 0x1d, 0x8c, 0x08, 0x00, 0x27, 0xae, 0x4d, 0x62, 0x08, 0x00, 0x45, 0x00, 
	0x00, 0x4e, 0xd9, 0x98, 0x40, 0x00, 0x40, 0x11, 0x6f, 0x9e, 0xc0, 0xa8, 0x38, 0x0b, 0xc0, 0xa8, 0x38, 0x0c, 0x9b, 0xf4, 0x12, 0xb5, 0x00, 0x3a, 0x00, 0x00, 0x08, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x7b, 0x00};

unsigned char inner_header[]={0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xba, 0x09, 0x2b, 0x6e, 0xf8, 0xbe, 0x08, 0x06,
	0x08,0x00,0x4c,0x8a,0x0d,0x3d,0x00,0x01,0xa3,0x8c,0x7c,0x57,
	0x00,0x00,0x00,0x00,0xb5,0x80,0x0a,0x00,0x00,0x00,0x00,0x00,0x10,0x11,0x12,0x13,
	0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,0x20,0x21,0x22,0x23,
	0x24,0x25,0x26,0x27,0x28,0x29,0x2a,0x2b,0x2c,0x2d,0x2e,0x2f,0x30,0x31,0x32,0x33,
	0x34,0x35,0x36,0x37} ;

/**
 * Mask of bits used to determine the status of RX IP checksum.
 * - RTE_MBUF_F_RX_IP_CKSUM_UNKNOWN: no information about the RX IP checksum
 * - RTE_MBUF_F_RX_IP_CKSUM_BAD: the IP checksum in the packet is wrong
 * - RTE_MBUF_F_RX_IP_CKSUM_GOOD: the IP checksum in the packet is valid
 * - RTE_MBUF_F_RX_IP_CKSUM_NONE: the IP checksum is not correct in the packet
 *   data, but the integrity of the IP header is verified.
 */
#define RTE_MBUF_F_RX_IP_CKSUM_MASK ((1ULL << 4) | (1ULL << 7))

#define RTE_MBUF_F_RX_IP_CKSUM_UNKNOWN 0
#define RTE_MBUF_F_RX_IP_CKSUM_BAD     (1ULL << 4)
#define RTE_MBUF_F_RX_IP_CKSUM_GOOD    (1ULL << 7)
#define RTE_MBUF_F_RX_IP_CKSUM_NONE    ((1ULL << 4) | (1ULL << 7))

/**
 * Mask of bits used to determine the status of RX L4 checksum.
 * - RTE_MBUF_F_RX_L4_CKSUM_UNKNOWN: no information about the RX L4 checksum
 * - RTE_MBUF_F_RX_L4_CKSUM_BAD: the L4 checksum in the packet is wrong
 * - RTE_MBUF_F_RX_L4_CKSUM_GOOD: the L4 checksum in the packet is valid
 * - RTE_MBUF_F_RX_L4_CKSUM_NONE: the L4 checksum is not correct in the packet
 *   data, but the integrity of the L4 data is verified.
 */
#define RTE_MBUF_F_RX_L4_CKSUM_MASK ((1ULL << 3) | (1ULL << 8))

#define RTE_MBUF_F_RX_L4_CKSUM_UNKNOWN 0
#define RTE_MBUF_F_RX_L4_CKSUM_BAD     (1ULL << 3)
#define RTE_MBUF_F_RX_L4_CKSUM_GOOD    (1ULL << 8)
#define RTE_MBUF_F_RX_L4_CKSUM_NONE    ((1ULL << 3) | (1ULL << 8))

struct outer_ether
{
	unsigned char outer_dmac[6];
	unsigned char outer_smac[6];
	uint16_t outer_ethertype;
};

struct outer_ip{
	uint8_t outer_ip_version : 4;
	uint8_t outer_ip_ihl : 4;
	uint8_t outer_ip_d_sf;
	uint16_t outer_ip_len;
	uint16_t outer_ip_iden;
	uint16_t outer__ip_flags;
	uint8_t outer_ip_ttl;
	uint8_t outer_ip_proto;
	uint16_t outer_ip_csum;
	uint32_t outer_ip_saddr;
	uint32_t outer_ip_daddr;

};     

struct outer_udp{
	u_int16_t udp_source_port;
	u_int16_t udp_dest_port;
	u_int16_t udp_length; 
	u_int16_t checksum;
};

struct vxlan_hdr
{
	u_int16_t vxlan_flags;
	u_int16_t vxlan_group_policy_id; 
	u_int32_t vxlan_VNI:24; 
	u_int8_t vxlan_reserved; 
};

struct inner_ether
{
	unsigned char inner_dmac[6];
	unsigned char inner_smac[6];
	uint16_t inner_ethertype;
};

struct icmp_hdr{
	u_int8_t type;
	u_int8_t code; 
	u_int16_t checksum; 
	u_int16_t identifier; 
	u_int16_t seq_numbr; 
	unsigned char time_stamp[8]; 
	unsigned char data[48];   
};

struct  encap_pkt
{
	struct outer_ether outer_ether1;
	struct outer_ip outer_ip1; 
	struct outer_udp outer_udp1;
	struct vxlan_hdr vxlan_hdr1; 
	struct inner_ether inner_ether1; 
	struct imcp_hdr; 
};

/**
 * encap_vxlan_pkt() encapsulated the vxlan packet with the 
 * original packet
 * @param *encap_pkt_info 
 *     The packet to be encapsulated
 * @result
 * Encapsulated packet.            
 */
int encap_vxln_pkt(struct encap_pkt *encap_pkt_info)
{
	unsigned char temp_buff[148];
	memcpy(temp_buff,outer_header,sizeof(outer_header));
	memcpy(temp_buff+sizeof(outer_header),inner_header,sizeof(inner_header));
	memcpy(encap_pkt_info,temp_buff,sizeof(encap_pkt_info)); 
}
/*
 * decap_vxlan_pkt() decapsulated the encapsulated packet and 
 * provides the original packet. 
 */
unsigned char *decap_vxlan_pkt(struct encap_pkt *encap_pkt_2, unsigned char *orginal_buff){
	unsigned char temp_buff[148]; 
	memcpy(temp_buff,encap_pkt_2,sizeof(encap_pkt_2));
	memcpy(orginal_buff,temp_buff+50,62);
}

typedef struct a{
	int ele1; 
};
typedef struct b{
	struct a  eleb_1; 
};

typedef struct c
{
	union check
	{ 
		struct {
			int ele1; 
		}a;
	};

};

struct logical_port{
	uint32_t mac_port; 
	uint32_t PINs; 
	uint32_t lpbk_port; 
};
/*
struct MVP {
	bool mvp_port_indicator[3] = {0,0,0}; 
	logical_port dst_port;  
}; */ 
/*
// 3 parts involved in Output Logical Port Generations: 
1) Match Action setting a logical Port 
2) VLAN logical port filtering 
3) Adding Promiscuous Ports */
/*
void logical_port_gen(struct MVP obj1, struct logical_port logical_port1){

	if (obj1.mvp_port_indicator[0] == true){
		logical_port1.mac_port = 0xffffffff; 
	}
	else if (obj1.mvp_port_indicator[1] == true){
		logical_port1.lpbk_port = 0xffffffff; 
	}
	else {
		logical_port1.PINs = 0xffffffff; 
	}
}
*/
/**
 * show_mem_rep() shows the number to stored in memory location. 
 * It will show whether the device under test is saving the number 
 * in little endian or big endian.
 * @param *start
 *   Starting address of the hex number
 * @param n
 *  The number for which the memory map has to be shown.   
 */
void show_mem_rep(char *start, int n)
{
	int i;
	for (i = 0; i < n; i++)
		printf(" %.2x", start[i]);
	printf("\n");
}
int initi (struct a *obj1){
	obj1->ele1=10; 
}

/**
 * setBitNumber() sets the MSB of a number  
 * @param n 
 *  n represents, the number for which MSB has to be found. 
 * @return
 *  The MSB of the number.   
 */
int setBitNumber(int n)
{
	// Below steps set bits after
	// MSB (including MSB)

	// Suppose n is 273 (binary
	// is 100010001). It does following
	// 100010001 | 010001000 = 110011001
	n |= n >> 1;

	// This makes sure 4 bits
	// (From MSB and including MSB)
	// are set. It does following
	// 110011001 | 001100110 = 111111111
	n |= n >> 2;

	n |= n >> 4;
	n |= n >> 8;
	n |= n >> 16;

	// Increment n by 1 so that
	// there is only one set bit
	// which is just before original
	// MSB. n now becomes 1000000000
	n = n + 1;

	// Return original MSB after shifting.
	// n now becomes 100000000
	return (n >> 1);
}

struct rte_config{
	int ele1; 
};

static struct rte_config rte_config;

/*
 * rte_eal_get_configuration returns the address of rte_config object of struct rte_config  
 */
	struct rte_config *
rte_eal_get_configuration(void)
{
	return &rte_config;
}
/**
 * rte_eal_init_alert() prints the error msg to console and set error status, 
 * open a file and writes the msg to the file. first fprintf is used to 
 * print content in stdout console. Second, fprintf is used to print 
 * content in file instead of stdout console.
 * @param *msg 
 * @param *mp
 *  msg to be printed to stdout and store on sample.txt. 
 *
 */
static void rte_eal_init_alert(const char *msg)
{

	fprintf(stderr, "EAL: FATAL: %s\n", msg);  
	FILE *fptr = fopen("sample.txt", "w");
	fprintf(fptr, "EAL: FATAL: %s\n", msg);  
	printf("EAL: FATAL: %s\n", msg); 
}

#define __CPU_MASK_TYPE 	__SYSCALL_ULONG_TYPE
typedef __CPU_MASK_TYPE __cpu_mask;

/* Size definition for CPU sets.  */
#define __CPU_SETSIZE	1024
#define __NCPUBITS	(8 * sizeof (__cpu_mask))
/* Data structure to describe CPU mask.  */
/*typedef struct
  {
  __cpu_mask __bits[__CPU_SETSIZE / __NCPUBITS];
  } cpu_set_t;*/

#ifndef CPU_SETSIZE
#define CPU_SETSIZE 5
#endif

#define _BITS_PER_SET (sizeof(long long) * 8)
#define _BIT_SET_MASK (_BITS_PER_SET - 1)

#define _NUM_SETS(b) (((b) + _BIT_SET_MASK) / _BITS_PER_SET)

typedef struct _rte_cpuset_s {
	long long _bits[_NUM_SETS(CPU_SETSIZE)];
} rte_cpuset_t;
/**
 * Structure storing internal configuration (per-lcore)
 */
struct lcore_config {
	//	pthread_t thread_id;       /**< pthread identifier */
	//	int pipe_main2worker[2];   /**< communication pipe with main */
	//	int pipe_worker2main[2];   /**< communication pipe with main */

	//	lcore_function_t * volatile f; /**< function to call */
	//	void * volatile arg;       /**< argument of function */
	//	volatile int ret;          /**< return value of function */

	//	volatile enum rte_lcore_state_t state; /**< lcore state */
	unsigned int socket_id;    /**< physical socket id for this lcore */
	unsigned int core_id;      /**< core number on socket for this lcore */
	int core_index;            /**< relative index, starting from 0 */
	uint8_t core_role;         /**< role of core eg: OFF, RTE, SERVICE */

	rte_cpuset_t cpuset;       /**< cpu set which the lcore affinity to */
};

//extern struct lcore_config lcore_config[5];
struct lcore_config lcore_config[5];

struct lcore_map {
	uint8_t socket_id;
	uint8_t core_id;
};
struct cpu_map {
	unsigned int lcore_count;
	unsigned int socket_count;
	unsigned int cpu_count;
	struct lcore_map lcores[5];
	//	struct socket_map sockets[RTE_MAX_NUMA_NODES];
	//	GROUP_AFFINITY cpus[CPU_SETSIZE];
};

static struct cpu_map cpu_map;

	unsigned
eal_cpu_socket_id(unsigned int lcore_id)
{
	return cpu_map.lcores[lcore_id].socket_id;
}

	int
eal_cpu_detected(unsigned int lcore_id)
{
	return lcore_id < cpu_map.lcore_count;
}

/*
 * Parse /sys/devices/system/cpu to get the number of physical and logical 
 * processors on the machine. The function will fill the cpu_info 
 * structure. 
 */
	int
rte_eal_cpu_init(void)
{
	unsigned int socket_id, prev_socket_id;
	unsigned lcore_id =0;
	int RTE_MAX_LCORE = 5; 
	unsigned count = 0;
	int lcore_to_socket_id[RTE_MAX_LCORE];

	/*
	 * Parse the maximum set of logical cores, detect the subset of running
	 * ones and enable them by default.
	 */
	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
		lcore_config[lcore_id].core_index = count;

		/* init cpuset for per lcore config */
		//CPU_ZERO(&lcore_config[lcore_id].cpuset);
		socket_id = eal_cpu_socket_id(lcore_id);
		printf("sock_id : %d \n", socket_id ); 
		lcore_to_socket_id[lcore_id] = socket_id;
		if (eal_cpu_detected(lcore_id) == 0) {
			//	config->lcore_role[lcore_id] = ROLE_OFF;
			lcore_config[lcore_id].core_index = -1;
			printf("true \n"); 
			continue;
		}
		/* By default, lcore 1:1 map to cpu id */
		//CPU_SET(lcore_id, &lcore_config[lcore_id].cpuset);

	}
}

#define	TAILQ_FOREACH(var, head, field)					\
	for ((var) = ((head)->tqh_first);				\
			(var);							\
			(var) = ((var)->field.tqe_next))


struct entry {
	int data; 
	TAILQ_ENTRY(entry) entries; 
};
TAILQ_HEAD (tailhead, entry); 

/* These macros are compatible with bundled sys/queue.h. */
#define RTE_TAILQ_HEAD(name, type) \
	struct name { \
		struct type *tqh_first; \
		struct type **tqh_last; \
	}
#define RTE_TAILQ_ENTRY(type) \
	struct { \
		struct type *tqe_next; \
		struct type **tqe_prev; \
	}
#define RTE_TAILQ_FOREACH(var, head, field) \
	for ((var) = RTE_TAILQ_FIRST((head)); \
			(var); \
			(var) = RTE_TAILQ_NEXT((var), field))
#define RTE_TAILQ_FIRST(head) ((head)->tqh_first)
#define RTE_TAILQ_NEXT(elm, field) ((elm)->field.tqe_next)
#define RTE_STAILQ_HEAD(name, type) \
	struct name { \
		struct type *stqh_first; \
		struct type **stqh_last; \
	}
#define RTE_STAILQ_ENTRY(type) \
	struct { \
		struct type *stqe_next; \
	}


struct rte_bus {
	RTE_TAILQ_ENTRY(rte_bus) next; /**< Next bus object in linked list */
	const char *name;            /**< Name of the bus */
	//	rte_bus_scan_t scan;         /**< Scan for devices attached to bus */
	//	rte_bus_probe_t probe;       /**< Probe devices on bus */
	//	rte_bus_find_device_t find_device; /**< Find a device on the bus */
	//	rte_bus_plug_t plug;         /**< Probe single device for drivers */
	//	rte_bus_unplug_t unplug;     /**< Remove single device from driver */
	//	rte_bus_parse_t parse;       /**< Parse a device name */
	//	rte_bus_devargs_parse_t devargs_parse; /**< Parse bus devargs */
	//	rte_dev_dma_map_t dma_map;   /**< DMA map for device in the bus */
	//	rte_dev_dma_unmap_t dma_unmap; /**< DMA unmap for device in the bus */
	//	struct rte_bus_conf conf;    /**< Bus configuration */
	//	rte_bus_get_iommu_class_t get_iommu_class; /**< Get iommu class */
	//	rte_dev_iterate_t dev_iterate; /**< Device iterator. */
	//	rte_bus_hot_unplug_handler_t hot_unplug_handler;
	/**< handle hot-unplug failure on the bus */
	//	rte_bus_sigbus_handler_t sigbus_handler;
	/**< handle sigbus error on the bus */
	//	rte_bus_cleanup_t cleanup;   /**< Cleanup devices on bus */
};

struct rte_bus_aux {
	RTE_TAILQ_ENTRY(rte_bus) next; /**< Next bus object in linked list */
	const char *name;            /**< Name of the bus */
	const char *scan;           /**< Scan for devices attached to bus */
};

#define RTE_PRIORITY_LOG 101
#define RTE_PRIORITY_BUS 110
#define RTE_PRIORITY_CLASS 120
#define RTE_PRIORITY_FIRST 65534
#define RTE_PRIORITY_LAST 65535

#define RTE_PRIO(prio) \
	RTE_PRIORITY_ ## prio

/**
 * Run function before main() with high priority.
 *
 * @param func
 *   Constructor function.
 * @param prio
 *   Priority number must be above 100.
 *   Lowest number is the first to run.
 */
//#ifndef RTE_INIT_PRIO /* Allow to override from EAL */
//#define RTE_INIT_PRIO(func, prio) \
//static void __attribute__((constructor(RTE_PRIO(prio)), used)) func(void)
//#endif
//RTE_INIT_PRIO(businitfn_ ##nm, BUS) \

	void
rte_bus_register(struct rte_bus *bus)
{
	//	RTE_VERIFY(bus);
	//	RTE_VERIFY(rte_bus_name(bus) && strlen(rte_bus_name(bus)));
	/* A bus should mandatorily have the scan implemented */
	//	RTE_VERIFY(bus->scan);
	//	RTE_VERIFY(bus->probe);
	//	RTE_VERIFY(bus->find_device);
	/* Buses supporting driver plug also require unplug. */
	//	RTE_VERIFY(!bus->plug || bus->unplug);

	//	TAILQ_INSERT_TAIL(&rte_bus_list, bus, next);
	//	RTE_LOG(DEBUG, EAL, "Registered [%s] bus.\n", rte_bus_name(bus));
}

#define RTE_REGISTER_BUS(nm, bus) \
{\
	(bus).name = RTE_STR(nm);\
	rte_bus_register(&bus); \
}

RTE_TAILQ_HEAD(rte_bus_list, rte_bus);

#define DBNIC_DRIVER_NAME net_dbnic

/** Number of elements in the array. */
#define	RTE_DIM(a)	(sizeof (a) / sizeof ((a)[0]))

/*********** Macros for calculating min and max **********/

/**
 * Macro to return the minimum of two numbers
 */
#define RTE_MIN(a, b) \
	__extension__ ({ \
			typeof (a) _a = (a); \
			typeof (b) _b = (b); \
			_a < _b ? _a : _b; \
			})

/**
 * Macro to return the maximum of two numbers
 */
#define RTE_MAX(a, b) \
	__extension__ ({ \
			typeof (a) _a = (a); \
			typeof (b) _b = (b); \
			_a > _b ? _a : _b; \
			})

/* Amount of data bytes in minimal inline data segment. */
#define MLX5_DSEG_MIN_INLINE_SIZE 12u

/* Amount of data bytes in minimal inline eth segment. */
#define MLX5_ESEG_MIN_INLINE_SIZE 18u
#define MLX5_WSEG_SIZE 16u
/* Amount of data bytes after eth data segment. */
#define MLX5_ESEG_EXTRA_DATA_SIZE 32u

/**
 * Force a structure to be packed
 */
#define __rte_packed __attribute__((__packed__))
/**
 * Force alignment
 */
#define __rte_aligned(a) __attribute__((__aligned__(a)))

/* WQE Control segment. */
struct mlx5_wqe_cseg {
	uint32_t opcode;
	uint32_t sq_ds;
	uint32_t flags;
	uint32_t misc;
} __rte_packed __rte_aligned(MLX5_WSEG_SIZE);    // 16 bytes

/* Header of data segment. Minimal size Data Segment */
struct mlx5_wqe_dseg {
	uint32_t bcount;
	union {
		uint8_t inline_data[MLX5_DSEG_MIN_INLINE_SIZE];
		struct {
			uint32_t lkey;
			uint64_t pbuf;
		} __rte_packed;
	};
} __rte_packed;

/* Subset of struct WQE Ethernet Segment. */
struct mlx5_wqe_eseg {
	union {
		struct {
			uint32_t swp_offs;
			uint8_t	cs_flags;
			uint8_t	swp_flags;
			uint16_t mss;
			uint32_t metadata;
			uint16_t inline_hdr_sz;
			union {
				uint16_t inline_data;
				uint16_t vlan_tag;
			};
		} __rte_packed;
		struct {
			uint32_t offsets;
			uint32_t flags;
			uint32_t flow_metadata;
			uint32_t inline_hdr;
		} __rte_packed;
	};
} __rte_packed;

/* The title WQEBB, header of WQE. */
struct mlx5_wqe {
	union {
		struct mlx5_wqe_cseg cseg; // 16 
		uint32_t ctrl[4]; 
	};
	struct mlx5_wqe_eseg eseg; // 16
	union {
		struct mlx5_wqe_dseg dseg[2]; // 32 
		uint8_t data[MLX5_ESEG_EXTRA_DATA_SIZE];
	};
} __rte_packed;

/* The title WQEBB, header of WQE. */
struct mlx5w {
	struct mlx5_wqe_cseg cseg;
	uint32_t ctrl[4];	
	struct mlx5_wqe_eseg eseg;
	struct mlx5_wqe_dseg dseg[2];
	uint8_t data[MLX5_ESEG_EXTRA_DATA_SIZE];
} __rte_packed;


/* WQE Segment sizes in bytes. */
#define MLX5_WSEG_SIZE 16u
#define MLX5_WQE_CSEG_SIZE sizeof(struct mlx5_wqe_cseg)
#define MLX5_WQE_DSEG_SIZE sizeof(struct mlx5_wqe_dseg)
#define MLX5_WQE_ESEG_SIZE sizeof(struct mlx5_wqe_eseg)
/* WQE/WQEBB size in bytes. */
#define MLX5_WQE_SIZE sizeof(struct mlx5_wqe)
/*
 * Default packet length threshold to be inlined with
 * ordinary SEND. Inlining saves the MR key search
 * and extra PCIe data fetch transaction, but eats the
 * CPU cycles.
 */
#define MLX5_SEND_DEF_INLINE_LEN (5U * MLX5_WQE_SIZE + \
		MLX5_ESEG_MIN_INLINE_SIZE - \
		MLX5_WQE_CSEG_SIZE - \
		MLX5_WQE_ESEG_SIZE - \
		MLX5_WQE_DSEG_SIZE)
/*
 * Max size of a WQE session.
 * Absolute maximum size is 63 (MLX5_DSEG_MAX) segments,
 * the WQE size field in Control Segment is 6 bits wide.
 */
#define MLX5_WQE_SIZE_MAX (60 * MLX5_WSEG_SIZE)


/**
 * Searches the input parameter for the least significant set bit
 * (starting from zero).
 * If a least significant 1 bit is found, its bit index is returned.
 * If the content of the input parameter is zero, then the content of the return
 * value is undefined.
 * @param v
 *     input parameter, should not be zero.
 * @return
 *     least significant set bit in the input parameter.
 */
	static inline uint32_t
rte_bsf32(uint32_t v)
{
	return (uint32_t)__builtin_ctz(v);
}

/**
 * add a byte-value offset to a pointer
 */
#define RTE_PTR_ADD(ptr, x) ((void*)((uintptr_t)(ptr) + (x)))

/**
 * subtract a byte-value offset from a pointer
 */
#define RTE_PTR_SUB(ptr, x) ((void *)((uintptr_t)(ptr) - (x)))

/**
 * get the difference between two pointer values, i.e. how far apart
 * in bytes are the locations they point two. It is assumed that
 * ptr1 is greater than ptr2.
 */
#define RTE_PTR_DIFF(ptr1, ptr2) ((uintptr_t)(ptr1) - (uintptr_t)(ptr2))

/**
 * Combines 32b inputs most significant set bits into the least
 * significant bits to construct a value with the same MSBs as x
 * but all 1's under it.
 *
 * @param x
 *    The integer whose MSBs need to be combined with its LSBs
 * @return
 *    The combined value.
 */
	static inline uint32_t
rte_combine32ms1b(uint32_t x)
{
	x |= x >> 1;
	x |= x >> 2;
	x |= x >> 4;
	x |= x >> 8;
	x |= x >> 16;

	return x;
}

/**
 * Combines 64b inputs most significant set bits into the least
 * significant bits to construct a value with the same MSBs as x
 * but all 1's under it.
 *
 * @param v
 *    The integer whose MSBs need to be combined with its LSBs
 * @return
 *    The combined value.
 */
	static inline uint64_t
rte_combine64ms1b(uint64_t v)
{
	v |= v >> 1;
	v |= v >> 2;
	v |= v >> 4;
	v |= v >> 8;
	v |= v >> 16;
	v |= v >> 32;

	return v;
}


/*

   uint64_t
   rte_str_to_size(const char *str)
   {
   char *endptr;
   unsigned long long size;

   while (isspace((int)*str))
   str++;
   if (*str == '-')
   return 0;

   errno = 0;
   size = strtoull(str, &endptr, 0);
   if (errno)
   return 0;

   if (*endptr == ' ')
   endptr++; /* allow 1 space gap */

//	switch (*endptr) {
//	case 'G': case 'g':
//		size *= 1024; /* fall-through */
//	case 'M': case 'm':
//		size *= 1024; /* fall-through */
//	case 'K': case 'k':
//		size *= 1024; /* fall-through */
//	default:
//		break;
//	}
//	return size;
//}*/


#define RTE_ETHER_ADDR_LEN  6 /**< Length of Ethernet address. */
#define RTE_ETHER_TYPE_LEN  2 /**< Length of Ethernet type field. */
#define RTE_ETHER_CRC_LEN   4 /**< Length of Ethernet CRC. */
#define RTE_ETHER_HDR_LEN   \
	(RTE_ETHER_ADDR_LEN * 2 + \
	 RTE_ETHER_TYPE_LEN) /**< Length of Ethernet header. */
#define RTE_ETHER_MIN_LEN   64    /**< Minimum frame len, including CRC. */
#define RTE_ETHER_MAX_LEN   1518  /**< Maximum frame len, including CRC. */
#define RTE_ETHER_MTU       \
	(RTE_ETHER_MAX_LEN - RTE_ETHER_HDR_LEN - \
	 RTE_ETHER_CRC_LEN) /**< Ethernet MTU. */

#define RTE_VLAN_HLEN       4  /**< VLAN (IEEE 802.1Q) header length. */
/** Maximum VLAN frame length (excluding QinQ), including CRC. */
#define RTE_ETHER_MAX_VLAN_FRAME_LEN \
	(RTE_ETHER_MAX_LEN + RTE_VLAN_HLEN)

#define RTE_ETHER_MAX_JUMBO_FRAME_LEN \
	0x3F00 /**< Maximum Jumbo frame length, including CRC. */

#define RTE_ETHER_MAX_VLAN_ID  4095 /**< Maximum VLAN ID. */

#define RTE_ETHER_MIN_MTU 68 /**< Minimum MTU for IPv4 packets, see RFC 791. */

typedef uint16_t rte_be16_t; /**< 16-bit big-endian value. */
typedef uint32_t rte_be32_t; /**< 32-bit big-endian value. */
typedef uint64_t rte_be64_t; /**< 64-bit big-endian value. */
typedef uint16_t rte_le16_t; /**< 16-bit little-endian value. */
typedef uint32_t rte_le32_t; /**< 32-bit little-endian value. */
typedef uint64_t rte_le64_t; /**< 64-bit little-endian value. */


struct rte_ether_addr {
	uint8_t addr_bytes[RTE_ETHER_ADDR_LEN]; /**< Addr bytes in tx order */
} __rte_aligned(2);

struct rte_ether_hdr {
	struct rte_ether_addr dst_addr; /**< Destination address. */
	struct rte_ether_addr src_addr; /**< Source address. */
	rte_be16_t ether_type; /**< Frame type. */
} __rte_aligned(2);

/**
 * Ethernet VLAN Header.
 * Contains the 16-bit VLAN Tag Control Identifier and the Ethernet type
 * of the encapsulated frame.
 */
struct rte_vlan_hdr {
	rte_be16_t vlan_tci;  /**< Priority (3) + CFI (1) + Identifier Code (12) */
	rte_be16_t eth_proto; /**< Ethernet type of encapsulated frame. */
} __rte_packed;

/**
 * IPv6 Header
 */
struct rte_ipv6_hdr {
	rte_be32_t vtc_flow;	/**< IP version, traffic class & flow label. */
	rte_be16_t payload_len;	/**< IP payload size, including ext. headers */
	uint8_t  proto;		/**< Protocol, next header. */
	uint8_t  hop_limits;	/**< Hop limits. */
	uint8_t  src_addr[16];	/**< IP address of source host. */
	uint8_t  dst_addr[16];	/**< IP address of destination host(s). */
} __rte_packed;

/**
 * TCP Header
 */
struct rte_tcp_hdr {
	rte_be16_t src_port; /**< TCP source port. */
	rte_be16_t dst_port; /**< TCP destination port. */
	rte_be32_t sent_seq; /**< TX data sequence number. */
	rte_be32_t recv_ack; /**< RX data acknowledgment sequence number. */
	uint8_t  data_off;   /**< Data offset. */
	uint8_t  tcp_flags;  /**< TCP flags */
	rte_be16_t rx_win;   /**< RX flow control window. */
	rte_be16_t cksum;    /**< TCP checksum. */
	rte_be16_t tcp_urp;  /**< TCP urgent pointer, if any. */
} __rte_packed;

/**
 * UDP Header
 */
struct rte_udp_hdr {
	rte_be16_t src_port;    /**< UDP source port. */
	rte_be16_t dst_port;    /**< UDP destination port. */
	rte_be16_t dgram_len;   /**< UDP datagram length */
	rte_be16_t dgram_cksum; /**< UDP datagram checksum */
} __rte_packed;

/**
 * VXLAN protocol header.
 * Contains the 8-bit flag, 24-bit VXLAN Network Identifier and
 * Reserved fields (24 bits and 8 bits)
 */
struct rte_vxlan_hdr {
	rte_be32_t vx_flags; /**< flag (8) + Reserved (24). */
	rte_be32_t vx_vni;   /**< VNI (24) + Reserved (8). */
} __rte_packed;


/* Inline data size required by NICs. */
#define MLX5_INLINE_HSIZE_NONE 0
#define MLX5_INLINE_HSIZE_L2 (sizeof(struct rte_ether_hdr) + \
		sizeof(struct rte_vlan_hdr))
#define MLX5_INLINE_HSIZE_L3 (MLX5_INLINE_HSIZE_L2 + \
		sizeof(struct rte_ipv6_hdr))
#define MLX5_INLINE_HSIZE_L4 (MLX5_INLINE_HSIZE_L3 + \
		sizeof(struct rte_tcp_hdr))
#define MLX5_INLINE_HSIZE_INNER_L2 (MLX5_INLINE_HSIZE_L3 + \
		sizeof(struct rte_udp_hdr) + \
		sizeof(struct rte_vxlan_hdr) + \
		sizeof(struct rte_ether_hdr) + \
		sizeof(struct rte_vlan_hdr))
#define MLX5_INLINE_HSIZE_INNER_L3 (MLX5_INLINE_HSIZE_INNER_L2 + \
		sizeof(struct rte_ipv6_hdr))
#define MLX5_INLINE_HSIZE_INNER_L4 (MLX5_INLINE_HSIZE_INNER_L3 + \
		sizeof(struct rte_tcp_hdr))

#define debug_print(fmt, ...) \
	do { if (1) fprintf(stderr, "%s:%d:%s(): " fmt, __FILE__, \
			__LINE__, __func__, __VA_ARGS__); } while (0)

// ................... APC ............//
#define MAX_ACTION_PAGES 15
#define APC_PAGE_MAX_INST 4

/* Local Defines/Enums/Structures */
typedef enum
{
	ISA_OPCODE_NOP=0,
	ISA_OPCODE_WRITE,
	ISA_OPCODE_WRITE_DOUBLE,
	ISA_OPCODE_WRITE_META,
	ISA_OPCODE_INSERT,
	ISA_OPCODE_REMOVE,
	ISA_OPCODE_SET_PINS,
	ISA_OPCODE_ADD,
	ISA_OPCODE_SUBTRACT,
	ISA_OPCODE_COUNT,
	ISA_OPCODE_MOVE_TO_META,
	ISA_OPCODE_MOVE_TO_HEADER,
	ISA_OPCODE_ADD_META,
	ISA_OPCODE_SUBTRACT_META,
	ISA_OPCODE_INSERT_MULTIPLE,
	ISA_OPCODE_ENCAP,
	ISA_OPCODE_DECAP,
	ISA_OPCODE_RSS,
	ISA_OPCODE_DROP,
	ISA_OPCODE_RECIRCULATE,
	ISA_OPCODE_EXTENSION,
	ISA_OPCODE_EXTENSION_DOUBLE,
	ISA_OPCODE_RESERVED
} isa_instruction_opcode_t;

typedef struct __attribute__ ((packed)) 
{
	isa_instruction_opcode_t    opcode:8;
	uint8_t                     header_id;
	uint8_t                     offset:6;
	uint16_t                    operand_2:10;
	uint32_t                    operand_1;
	uint32_t                    operand_0;
	uint32_t                    operand_3;    
} action_instruction_t;

typedef struct __attribute__ ((packed)) 
{
	isa_instruction_opcode_t    opcode:8;
	uint16_t                    encapPtid[4];
	uint8_t                     encapheaderoffset[4];
	uint8_t                     encaptptidlength:5;
	uint8_t                     encap_header_offset_length:3;
	uint8_t                     length;
	uint8_t                     operands[109];
} encap_instruction_t;

typedef struct __attribute__ ((packed))
{
	action_instruction_t            instruction[APC_PAGE_MAX_INST];
} action_program_page_t ;

typedef struct __attribute__ ((packed))
{
	encap_instruction_t             instruction;
} encap_instruction_page_t;

typedef struct __attribute__ ((packed)) 
{
	uint8_t count; //  count = MAX_ACTION_PAGES; 
	action_program_page_t pages[];
} action_pages_t;

//....................................

#define A 
int fun()
{
#ifndef A 
#ifndef B 

#else
printf("Case B is executed \n"); 
#endif
#else 
printf("Case A is executed \n"); 
#endif
}
/**
 * Checking whether int fun(); (decleration) means different in C and C++ as found: 
 *In C means “a function with any number and type of argument.” 
 * This prevents type-checking, so in C++ it means 
 * “a function with no arguments.”
*/
int func2();

int func2(int a, int b) {
	
	return 0; 
}

#define MLX5_SRTCM_XBS_MAX (0xFF * (1ULL << 0x1F))
#define MLX5_SRTCM_XIR_MAX (8 * (1ULL << 30) * 0xFF)

enum mlx5_parse_graph_node_len_mode {
	MLX5_GRAPH_NODE_LEN_FIXED = 0x0,
	MLX5_GRAPH_NODE_LEN_FIELD = 0x1,
	MLX5_GRAPH_NODE_LEN_BITMASK = 0x2,
};


/**
 * Get the uint32_t value for a specified bit set.
 *
 * @param nr
 *   The bit number in range of 0 to 31.
 */
#define RTE_BIT32(nr) (UINT32_C(1) << (nr))


int main(){
	//.......  This logic implements encap/decap to the specified location ...................
	unsigned char original_pkt[62]; 
	struct encap_pkt encap_pkt1;
	bool check=true;

	encap_vxln_pkt(&encap_pkt1);

	decap_vxlan_pkt(&encap_pkt1,original_pkt); 

	printf("\n Decapsulated Packet information \n"); 
	for (int i = 0; i < sizeof(original_pkt); i++)
	{
		printf("%x ",original_pkt[i]);
	}    
	printf("\n \n"); 

	struct a obja1; 
	initi(&obja1);
	printf("obja1 %d \n",obja1.ele1); 

	struct b obj1;
	obj1.eleb_1.ele1=20; 
	printf("objb1 value %d \n", obj1.eleb_1.ele1); 
	uint64_t mask; 
	uint8_t operand_2 = 0xff;  // 1100 0000 //  1110 0000 // 1111 0000  
	if (operand_2 & 0x80){  // 0001 0000// 
		printf("Ist byte is on \n"); 
	}
	if (operand_2 & 0x40){
		printf("2nd byte is on \n"); 
	}
	if (operand_2 & 0x20){
		printf("3rd byte is on \n"); 
	}
	if (operand_2 & 0x10){
		printf("4th byte is on \n"); 
	}

	mask = ((operand_2 & 0x80) ? 0xFF : 0x00) | ((operand_2 & 0x40) ? 0xFF : 0x00) | ((operand_2 & 0x20) ? 0xFF : 0x00) | 
		(operand_2 & 0x01) ? 0xFF : 0x00 | (operand_2 & 0x08) ? 0xFF : 0x00 |  (operand_2 & 0x04) ? 0xFF : 0x00 | 
		(operand_2 & 0x02) ? 0xFF : 0x00 |  (operand_2 & 0x01) ? 0xFF : 0x00 ;  // mask=0xFF FF FF FF FF FF FF FF; 

	printf ("mask0: %lx \n", mask);  

	/*
	 * This logic implements a check to see if the under testing device 
	 * is in little endian or in big endian.
	 */

	uint32_t i = 0;
	uint8_t ttl=64;
	i=ttl;
	printf("i %d \n", i); 
	char *c = (char *) &i;
	if (*c)
		printf ("Little endian %d \n",i); //64 0 0 0 
	else
		printf ("Big endian %d \n",i); // 0  0 0 64 
	uint64_t value = 0xaa00eeeebbbbbbbb; 
	printf ("value : %lx \n", value);  

	int b = 0x01234567;                  
	/*
	 * If DUT is in little endian, prints: 67 45 23 01; in big endian: 01 23 45 67  
	 */ 
	show_mem_rep((char *)&b, sizeof(b));

	// Below steps set bits after
	// MSB (including MSB)
	int n = 9;  // 1001 , it will result in 8 
	printf("MSB %x \n ", setBitNumber(n)); 

	printf ("1ULL: %d ", 1ULL << 16); 
	printf ("1ULL: %d ", 1ULL << 12); 
	printf ("1ULL: %d ", 1ULL << 11); 

	printf ("1ULL: %d ", 1ULL << 17); 


	struct rte_config *rte_conf = rte_eal_get_configuration();
	rte_conf->ele1 = 100; 
	printf("\n rte_conf-> ele1 value %d \n ",rte_conf->ele1); 

	rte_eal_init_alert("unsupported cpu type.");

	/*
	 * strrchr() sets the string after the provided charector, 
	 * explore string.h in details. 
	 */    
	const char *p;
	p = strrchr("http://www.dreambigsemi.com", '/');
	printf("String after |/| is - |%s|\n", p);

	if (rte_eal_cpu_init() < 0) {
		rte_eal_init_alert("Cannot detect lcores.");
		//rte_errno = ENOTSUP;
		return -1;
	}
	struct entry *n1, *n2, *n3, *np; 
	struct tailhead head; 
	TAILQ_INIT(&head);
	n1 = (struct entry *) malloc(sizeof(struct entry));  
	TAILQ_INSERT_HEAD(&head,n1,entries); 
	n2 = (struct entry *) malloc (sizeof(struct entry)) ; 
	TAILQ_INSERT_AFTER(&head, n1, n2, entries);
	n3 = (struct entry *) malloc (sizeof (struct entry)); 
	TAILQ_INSERT_BEFORE(n2,n3, entries); 
	i=0; 
	TAILQ_FOREACH(np, &head, entries)
		np->data =i++; 

	TAILQ_FOREACH_REVERSE(np, &head, tailhead,entries)
		printf("%i\n", np->data);

	n1 = TAILQ_FIRST(&head);
	while (n1 != NULL) {
		n2 = TAILQ_NEXT(n1, entries);
		free(n1);
		n1 = n2;
	}
	TAILQ_INIT(&head);

	struct rte_bus *m1, *m2, *m3, *mn;
	struct rte_bus_list bus_list; 
	TAILQ_INIT(&bus_list);
	m1 = (struct rte_bus *) malloc (sizeof(struct rte_bus*));  
	TAILQ_INSERT_HEAD(&bus_list, m1, next);
	m2 = (struct rte_bus *) malloc (sizeof(struct rte_bus*));  
	TAILQ_INSERT_AFTER(&bus_list, m1, m2, next);
	m3 = (struct rte_bus *) malloc (sizeof(struct rte_bus*));  
	TAILQ_INSERT_BEFORE(m2,m3, next); 

	RTE_TAILQ_FOREACH(mn,&bus_list,next)
		mn->name ="Appollo";

	RTE_TAILQ_FOREACH(mn,&bus_list,next)
		printf("%s\n", mn->name);

	unsigned int inlen;
	uint16_t nb_max;
	inlen = MLX5_SEND_DEF_INLINE_LEN; 
	nb_max = (MLX5_WQE_SIZE_MAX +
			MLX5_ESEG_MIN_INLINE_SIZE -
			MLX5_WQE_CSEG_SIZE -
			MLX5_WQE_ESEG_SIZE -
			MLX5_WQE_DSEG_SIZE -
			inlen) / MLX5_WSEG_SIZE;
	printf("MLX5_DSEG_MIN_INLINE_SIZE %d",MLX5_DSEG_MIN_INLINE_SIZE); 


	printf ("\n \n \n Max allowed number of segments per whole packet %d, \n For TSO packet this is the total number of data descriptors allowed by device \n", nb_max);  



	printf("\n MLX5_WQE_SIZE %d \n MLX5_WQE_SIZE_MAX (Max size of a WQE session) %d \n MLX5_ESEG_MIN_INLINE_SIZE %d \n MLX5_WQE_CSEG_SIZE %d \n MLX5_WQE_ESEG_SIZE  %d \n LX5_WQE_DSEG_SIZE %d \n", 
			MLX5_WQE_SIZE, 
			MLX5_WQE_SIZE_MAX,
			MLX5_ESEG_MIN_INLINE_SIZE,
			MLX5_WQE_CSEG_SIZE,
			MLX5_WQE_ESEG_SIZE, 
			MLX5_WQE_DSEG_SIZE);

	printf (" \n Default packet length threshold to be inlined with ordinary SEND %d \n \n", MLX5_SEND_DEF_INLINE_LEN); 
	uint32_t rte_bus_pci_status; 
	uint32_t rte_bus_auxiliry_status;
	uint32_t bus_status,index,*ptr;  
	ptr = &rte_bus_auxiliry_status;  
	rte_bus_pci_status = inlen; 
	rte_bus_auxiliry_status = nb_max; 
	bus_status = RTE_MAX(rte_bus_pci_status,rte_bus_auxiliry_status); 
	index = rte_bsf32(32768); // 1000 0000 0000 0000 // bit index 15 
	printf ("bus_status : %d , index : %d, add a value %d, sub %d, value %d and rte_combine %d \n", bus_status, index,
			RTE_PTR_ADD(*ptr, 1), RTE_PTR_SUB(*ptr,1),8, rte_combine32ms1b(8)); 

	printf("\n \n MLX5_INLINE_HSIZE_NONE :%d, \n MLX5_INLINE_HSIZE_L2 %d,\n MLX5_INLINE_HSIZE_L3: %d, \n MLX5_INLINE_HSIZE_L4 : %d, \n  MLX5_INLINE_HSIZE_INNER_L2 : %d \n  MLX5_INLINE_HSIZE_INNER_L2 : %d \n MLX5_INLINE_HSIZE_INNER_L4 : %d \n \n , ", 
			MLX5_INLINE_HSIZE_NONE, MLX5_INLINE_HSIZE_L2, MLX5_INLINE_HSIZE_L3, MLX5_INLINE_HSIZE_L4, MLX5_INLINE_HSIZE_INNER_L2, MLX5_INLINE_HSIZE_INNER_L3, MLX5_INLINE_HSIZE_INNER_L4); 

	printf("charc %c, %c sizeof(mlx5w) %d  sizeof(mlx5_wqe) %d \n", 3["a"], 3["axycbw"],sizeof(struct mlx5w),sizeof(struct mlx5_wqe)); 
	printf("\n\n\n");

	int x = 10, y = 2, z; 

	if (x > y)
	{  

		debug_print("x (%d) > y (%d)\n", x, y);
		debug_print("x (%d) > y (%d)\n", x, y);
	}
	else
		z = x-y;

	int array [5] = {1,3,5,7,9}; 
	int *ptr_arr;
	ptr_arr = array;

	printf("\n\n Pointer to array:  %d \n", *ptr_arr);  

	int row = 5, column = 3; 
	int *mat; 
	mat= (int *)malloc(row * column * sizeof(int)); 

	for (i = 0; i< 5; i++){
		for (int j = 0; j < 3; j++)
		{
			*(mat + i * column + j) = i + j; 
		}

	}
	for (i = 0; i< 5; i++){
		for (int j = 0; j < 3; j++)
		{
			printf(" %d",*(mat + i * column + j)); 
		}
		printf("\n"); 
	}

	int arr2[2] = {10, 20};
	int *ptr2[2];  // Array of two pointers
	int **ptr3; 

	ptr2[0] = &arr2[0];  // Assigning the address of arr[0] to ptr[0]
	ptr2[1] = &arr2[1];  // Assigning the address of arr[1] to ptr[1]
	ptr3 = &ptr2[0]; 

	printf("Value at arr[0]: %d\n", *ptr2[0]);
	printf("Value at arr[1]: %d\n", *ptr2[1]);
	printf("Value at arr[1]: %d\n", **ptr3);

	action_pages_t *action_pages = (action_pages_t *)malloc(sizeof(action_pages_t) + sizeof(action_program_page_t) * MAX_ACTION_PAGES);
	action_pages->count = 0;

	action_program_page_t *inst_program = (action_program_page_t *)&action_pages->pages[0];
	encap_instruction_page_t *inst_program_encap = (encap_instruction_page_t *)&action_pages->pages[0];

	printf("\n size of action_pages_t %d \n",sizeof(action_pages));
	printf("\n size of action program page %d \n",sizeof(action_program_page_t)); 
	printf("\n size of encap_instrction_page_t :%d \n", sizeof(encap_instruction_page_t)); 
	printf("\n size of encap/action program page : %d \n", (sizeof(encap_instruction_page_t)/sizeof(action_program_page_t)));

	printf("MLX5_SRTCM_XBS_MAX %llx \n", MLX5_SRTCM_XBS_MAX);
	printf("MLX5_SRTCM_XIR_MAX %llx \n", MLX5_SRTCM_XIR_MAX);

	if (!(21 & RTE_BIT32(MLX5_GRAPH_NODE_LEN_FIXED))){
		printf("Condition true RTE_BIT32 : %d \n",RTE_BIT32(MLX5_GRAPH_NODE_LEN_FIXED));
	}


	
	func2(1,2);
	 
	fun(); 

	return 0; 
}

