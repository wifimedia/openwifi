#ifndef __CAPWAP_ELEMENT_WTPFALLBACK_HEADER__
#define __CAPWAP_ELEMENT_WTPFALLBACK_HEADER__

#define CAPWAP_ELEMENT_WTPFALLBACK_VENDOR			0
#define CAPWAP_ELEMENT_WTPFALLBACK_TYPE			40
#define CAPWAP_ELEMENT_WTPFALLBACK				(struct capwap_message_element_id){ .vendor = CAPWAP_ELEMENT_WTPFALLBACK_VENDOR, .type = CAPWAP_ELEMENT_WTPFALLBACK_TYPE }


#define CAPWAP_WTP_FALLBACK_ENABLED			1
#define CAPWAP_WTP_FALLBACK_DISABLED		2

struct capwap_wtpfallback_element {
	uint8_t mode;
};

extern const struct capwap_message_elements_ops capwap_element_wtpfallback_ops;

#endif /* __CAPWAP_ELEMENT_WTPFALLBACK_HEADER__ */
