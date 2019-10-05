#define ETH_ALEN 6 
#define u8 __u8
#define u16 __u16
#define u32 __u32
#define u64 __u64
#include <stddef.h>
#include <net/ethernet.h>
#include <endian.h>


struct ieee80211_frame
{
    //struct frame_control fc;
    u16 fc;                 /**< 802.11 Frame Control field */
    u16 duration;           /**< Microseconds to reserve link */
    u8 addr1[ETH_ALEN];     /**< Address 1 (immediate receiver) */
    u8 addr2[ETH_ALEN];     /**< Address 2 (immediate sender) */
    u8 addr3[ETH_ALEN];     /**< Address 3 (often "forward to") */
    u16 seq;                /**< 802.11 Sequence Control field */
    u8 data[0];             /**< Beginning of frame data */
};

struct ieee80211_rts
{
    u16 fc;                 /**< 802.11 Frame Control field */
    u16 duration;           /**< Microseconds to reserve link */
    u8 addr1[ETH_ALEN];     /**< Address 1 (immediate receiver) */
    u8 addr2[ETH_ALEN];     /**< Address 2 (immediate sender) */
};

struct ieee80211_cts_or_ack
{
    u16 fc;                 /**< 802.11 Frame Control field */
    u16 duration;           /**< Microseconds to reserve link */
    u8 addr1[ETH_ALEN];     /**< Address 1 (immediate receiver) */
} __attribute__((packed));

struct ieee80211_ie_header {
    u8 id;                  /**< Information element ID */
    u8 len;                 /**< Information element length */
};

struct ieee80211_ie_ssid {
    u8 id;                  /**< SSID ID: 0 */
    u8 len;                 /**< SSID length */
    char ssid[0];           /**< SSID data, not NUL-terminated */
};

struct ieee80211_ie_rates {
    u8 id;                  /**< Rates ID: 1 or 50 */
    u8 len;                 /**< Number of rates */
    u8 rates[0];            /**< Rates data, one rate per byte */
};

struct ieee80211_ie_ds_param {
    u8 id;                  /**< DS parameter ID: 3 */
    u8 len;                 /**< DS parameter length: 1 */
    u8 current_channel;     /**< Current channel number, 1-14 */
};

struct ieee80211_ie_country_ext_triplet {
    u8 reg_ext_id;          /**< Regulatory extension ID */
    u8 reg_class_id;        /**< Regulatory class ID */
    u8 coverage_class;      /**< Coverage class */
};

struct ieee80211_ie_country_band_triplet {
    u8 first_channel;       /**< Channel number for first channel in band */
    u8 nr_channels;         /**< Number of contiguous channels in band */
    u8 max_txpower;         /**< Maximum TX power in dBm */
};

union ieee80211_ie_country_triplet {
    /** Differentiator between band and ext triplets */
    u8 first;

    /** Information about a band of channels */
    struct ieee80211_ie_country_band_triplet band;

    /** Regulatory extension information */
    struct ieee80211_ie_country_ext_triplet ext;
};

struct ieee80211_ie_country {
    u8 id;                  /**< Country information ID: 7 */
    u8 len;                 /**< Country information length: varies */
    char name[2];           /**< ISO Alpha2 country code */
    char in_out;            /**< 'I' for indoor, 'O' for outdoor */

    /** List of regulatory triplets */
    union ieee80211_ie_country_triplet triplet[0];
};

struct ieee80211_ie_request {
    u8 id;                  /**< Request ID: 10 */
    u8 len;                 /**< Number of IEs requested */
    u8 request[0];          /**< List of IEs requested */
};

struct ieee80211_ie_challenge_text {
    u8 id;                  /**< Challenge Text ID: 16 */
    u8 len;                 /**< Challenge Text length: usually 128 */
    u8 challenge_text[0];   /**< Challenge Text data */
};

struct ieee80211_ie_power_constraint {
    u8 id;                  /**< Power Constraint ID: 52 */
    u8 len;                 /**< Power Constraint length: 1 */
    u8 power_constraint;    /**< Decrease in allowed TX power, dBm */
};

struct ieee80211_ie_power_capab {
    u8 id;                  /**< Power Capability ID: 33 */
    u8 len;                 /**< Power Capability length: 2 */
    u8 min_txpower;         /**< Minimum possible TX power, dBm */
    u8 max_txpower;         /**< Maximum possible TX power, dBm */
};

struct ieee80211_ie_channels_channel_band {
    u8 first_channel;       /**< Channel number of first channel in band */
    u8 nr_channels;         /**< Number of channels in band */
};

struct ieee80211_ie_channels {
    u8 id;                  /**< Channels ID: 36 */
    u8 len;                 /**< Channels length: 2 */

    /** List of (start, length) channel bands we can use */
    struct ieee80211_ie_channels_channel_band channels[0];
};

struct ieee80211_ie_erp_info {
    u8 id;                  /**< ERP Information ID: 42 */
    u8 len;                 /**< ERP Information length: 1 */
    u8 erp_info;            /**< ERP flags */
};

struct ieee80211_ie_vendor {
    u8 id;                  /**< Vendor-specific ID: 221 */
    u8 len;                 /**< Vendor-specific length: variable */
    u32 oui;                /**< OUI and vendor-specific type byte */
    u8 data[0];             /**< Vendor-specific data */
};

struct ieee80211_ie_rsn {
    u8 id;                          /** Information element ID */        
    u8 len;                         /** Information element length */        
    u16 version;                    /** RSN information element version */        
    u32 group_cipher;               /** Cipher ID for the cipher used in multicast/broadcast frames */        
    u16 pairwise_count;             /** Number of unicast ciphers supported */        
    u32 pairwise_cipher[1];         /** List of cipher IDs for supported unicast frame ciphers */        
    u16 akm_count;                  /** Number of authentication types supported */        
    u32 akm_list[1];                /** List of authentication type IDs for supported types */        
    u16 rsn_capab;                  /** Security capabilities field (RSN only) */        
    u16 pmkid_count;                /** Number of PMKIDs included (present only in association frames) */        
    u8 pmkid_list[0];               /** List of PMKIDs included, each a 16-byte SHA1 hash */
};

union ieee80211_ie{
    /** Generic and simple information element info */
    struct {
        u8 id;          /**< Information element ID */
        u8 len;         /**< Information element data length */
        union {
            //struct ieee80211_ie_ssid ssid;
            char ssid[0];   /**< SSID text */
            u8 rates[0];    /**< Rates data */
            u8 request[0];  /**< Request list */
            u8 challenge_text[0]; /**< Challenge text data */
            u8 power_constraint; /**< Power constraint, dBm */
            u8 erp_info;    /**< ERP information flags */
            /** List of channels */
            struct ieee80211_ie_channels_channel_band channels[0];
        };
    };    
    struct ieee80211_ie_ds_param ds_param;              /** DS parameter set */
    struct ieee80211_ie_country country;                /** Country information */
    struct ieee80211_ie_power_capab power_capab;        /** Power capability */
    struct ieee80211_ie_rsn rsn;                        /** Security information */
    struct ieee80211_ie_vendor vendor;                  /** Vendor-specific */
};

/** Beacon or probe response frame data */
struct ieee80211_beacon_or_probe_resp{       
    u64 timestamp;                          /** 802.11 TSFT value at frame send */        
    u16 beacon_interval;                    /** Interval at which beacons are sent, in units of 1024 us */        
    u16 capability;                         /** Capability flags */        
    union ieee80211_ie info_element[0];     /** List of information elements */
};