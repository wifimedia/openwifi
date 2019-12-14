#ifndef __CAPWAP_ELEMENT_80211_SUPPORTEDRATES_HEADER__
#define __CAPWAP_ELEMENT_80211_SUPPORTEDRATES_HEADER__

#define CAPWAP_ELEMENT_80211_SUPPORTEDRATES_VENDOR		0
#define CAPWAP_ELEMENT_80211_SUPPORTEDRATES_TYPE		1040
#define CAPWAP_ELEMENT_80211_SUPPORTEDRATES			(struct capwap_message_element_id){ .vendor = CAPWAP_ELEMENT_80211_SUPPORTEDRATES_VENDOR, .type = CAPWAP_ELEMENT_80211_SUPPORTEDRATES_TYPE }


#define CAPWAP_SUPPORTEDRATES_MINLENGTH			2
#define CAPWAP_SUPPORTEDRATES_MAXLENGTH			8

struct capwap_80211_supportedrates_element {
	uint8_t radioid;
	uint8_t supportedratescount;
	uint8_t supportedrates[CAPWAP_SUPPORTEDRATES_MAXLENGTH];
};

extern const struct capwap_message_elements_ops capwap_element_80211_supportedrates_ops;

#endif /* __CAPWAP_ELEMENT_80211_SUPPORTEDRATES_HEADER__ */
