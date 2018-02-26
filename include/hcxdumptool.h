#define MACSTAESSIDLISTZEMAX 256


#define TIME_INTERVAL 5

#define LASTWPASTAT_NONE		0b00000000
#define LASTWPASTAT_AUTHENTICATE	0b00000001
#define LASTWPASTAT_ASSOCIATE		0b00000010
#define LASTWPASTAT_ACKNOWLEDGE		0b00000100
#define LASTWPASTAT_M1			0b00001000

/*===========================================================================*/
struct arg_s
{
 uint32_t	waittime;
} __attribute__((__packed__));
typedef struct arg_s arg_t;
/*===========================================================================*/
struct networklist_s
{
 long int	tv_sec;
 uint8_t	status;
 uint8_t	mac_sta[6];
 uint8_t	mac_ap[6];
 uint8_t	essid_len;
 uint8_t	essid[32];
};
typedef struct networklist_s networklist_t;
#define	NETWORKLIST_SIZE (sizeof(networklist_t))

static int sort_networklist_by_time(const void *a, const void *b)
{
const networklist_t *ia = (const networklist_t *)a;
const networklist_t *ib = (const networklist_t *)b;
return ia->tv_sec < ib->tv_sec;
}
/*===========================================================================*/
struct maclist_s
{
 long int	tv_sec;
 uint8_t	status;
 uint8_t	mac_ap[6];
};
typedef struct maclist_s maclist_t;
#define	MACLIST_SIZE (sizeof(maclist_t))

static int sort_maclist_by_time(const void *a, const void *b)
{
const maclist_t *ia = (const maclist_t *)a;
const maclist_t *ib = (const maclist_t *)b;
return ia->tv_sec < ib->tv_sec;
}
/*===========================================================================*/
struct macessidlist_s
{
 long int	tv_sec;
 uint8_t	mac_ap[6];
 uint8_t	essid_len;
 uint8_t	essid[32];
};
typedef struct macessidlist_s macessidlist_t;
#define	MACESSIDLIST_SIZE (sizeof(macessidlist_t))

static int sort_macessidlist_by_time(const void *a, const void *b)
{
const macessidlist_t *ia = (const macessidlist_t *)a;
const macessidlist_t *ib = (const macessidlist_t *)b;
return ia->tv_sec < ib->tv_sec;
}
/*===========================================================================*/
