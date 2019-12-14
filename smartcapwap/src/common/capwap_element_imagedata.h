#ifndef __CAPWAP_ELEMENT_IMAGE_DATA_HEADER__
#define __CAPWAP_ELEMENT_IMAGE_DATA_HEADER__

#define CAPWAP_ELEMENT_IMAGEDATA_VENDOR					0
#define CAPWAP_ELEMENT_IMAGEDATA_TYPE					24
#define CAPWAP_ELEMENT_IMAGEDATA						(struct capwap_message_element_id){ .vendor = CAPWAP_ELEMENT_IMAGEDATA_VENDOR, .type = CAPWAP_ELEMENT_IMAGEDATA_TYPE }


#define CAPWAP_IMAGEDATA_TYPE_DATA_IS_INCLUDED		1
#define CAPWAP_IMAGEDATA_TYPE_DATA_EOF				2
#define CAPWAP_IMAGEDATA_TYPE_ERROR					5

#define CAPWAP_IMAGEDATA_DATA_MAX_LENGTH			1024

struct capwap_imagedata_element {
	uint8_t type;
	uint16_t length;
	uint8_t* data;
};

extern const struct capwap_message_elements_ops capwap_element_imagedata_ops;

#endif /* __CAPWAP_ELEMENT_IMAGE_DATA_HEADER__ */
