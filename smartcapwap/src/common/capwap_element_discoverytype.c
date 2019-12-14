#include "capwap.h"
#include "capwap_element.h"

/********************************************************************

 0
 0 1 2 3 4 5 6 7
+-+-+-+-+-+-+-+-+
| Discovery Type|
+-+-+-+-+-+-+-+-+

Type:   20 for Discovery Type

Length:   1

********************************************************************/

/* */
static void capwap_discoverytype_element_create(void* data, capwap_message_elements_handle handle, struct capwap_write_message_elements_ops* func) {
	struct capwap_discoverytype_element* element = (struct capwap_discoverytype_element*)data;

	ASSERT(data != NULL);
	ASSERT((element->type == CAPWAP_DISCOVERYTYPE_TYPE_UNKNOWN) || (element->type == CAPWAP_DISCOVERYTYPE_TYPE_STATIC) ||
		(element->type == CAPWAP_DISCOVERYTYPE_TYPE_DHCP) || (element->type == CAPWAP_DISCOVERYTYPE_TYPE_DNS) ||
		(element->type == CAPWAP_DISCOVERYTYPE_TYPE_ACREFERRAL));

	/* */
	func->write_u8(handle, element->type);
}

/* */
static void* capwap_discoverytype_element_clone(void* data) {
	ASSERT(data != NULL);

	return capwap_clone(data, sizeof(struct capwap_discoverytype_element));
}

/* */
static void capwap_discoverytype_element_free(void* data) {
	ASSERT(data != NULL);
	
	capwap_free(data);
}

/* */
static void* capwap_discoverytype_element_parsing(capwap_message_elements_handle handle, struct capwap_read_message_elements_ops* func) {
	struct capwap_discoverytype_element* data;

	ASSERT(handle != NULL);
	ASSERT(func != NULL);

	if (func->read_ready(handle) != 1) {
		log_printf(LOG_DEBUG, "Invalid Discovery Type element: underbuffer");
		return NULL;
	}

	/* Retrieve data */
	data = (struct capwap_discoverytype_element*)capwap_alloc(sizeof(struct capwap_discoverytype_element));
	func->read_u8(handle, &data->type);
	if ((data->type != CAPWAP_DISCOVERYTYPE_TYPE_UNKNOWN) && (data->type != CAPWAP_DISCOVERYTYPE_TYPE_STATIC) &&
		(data->type != CAPWAP_DISCOVERYTYPE_TYPE_DHCP) && (data->type != CAPWAP_DISCOVERYTYPE_TYPE_DNS) &&
		(data->type != CAPWAP_DISCOVERYTYPE_TYPE_ACREFERRAL)) {
		capwap_discoverytype_element_free((void*)data);
		log_printf(LOG_DEBUG, "Invalid Discovery Type element: invalid type");
		return NULL;
	}

	return data;
}

/* */
const struct capwap_message_elements_ops capwap_element_discoverytype_ops = {
	.category = CAPWAP_MESSAGE_ELEMENT_SINGLE,
	.create = capwap_discoverytype_element_create,
	.parse = capwap_discoverytype_element_parsing,
	.clone = capwap_discoverytype_element_clone,
	.free = capwap_discoverytype_element_free
};
