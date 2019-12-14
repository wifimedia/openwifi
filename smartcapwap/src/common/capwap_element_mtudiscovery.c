#include "capwap.h"
#include "capwap_element.h"

/********************************************************************

 0
 0 1 2 3 4 5 6 7
+-+-+-+-+-+-+-+-+
|  Padding...
+-+-+-+-+-+-+-+-

Type:   52 for MTU Discovery Padding

Length:  variable

********************************************************************/

/* */
static void capwap_mtudiscovery_element_create(void* data, capwap_message_elements_handle handle, struct capwap_write_message_elements_ops* func) {
	uint16_t length;
	struct capwap_mtudiscovery_element* element = (struct capwap_mtudiscovery_element*)data;

	ASSERT(data != NULL);

	/* */
	length = element->length;
	while (length > 0) {
		func->write_u8(handle, 0xff);
		length--;
	}
}

/* */
static void* capwap_mtudiscovery_element_parsing(capwap_message_elements_handle handle, struct capwap_read_message_elements_ops* func) {
	uint16_t length;
	struct capwap_mtudiscovery_element* data;

	ASSERT(handle != NULL);
	ASSERT(func != NULL);

	length = func->read_ready(handle);
	if (length > 0) {
		log_printf(LOG_DEBUG, "Invalid MTU Discovery Padding element: underbuffer");
		return NULL;
	}

	/* Retrieve data */
	data = (struct capwap_mtudiscovery_element*)capwap_alloc(sizeof(struct capwap_mtudiscovery_element));
	data->length = length;
	func->read_block(handle, NULL, length);

	return data;
}

/* */
static void* capwap_mtudiscovery_element_clone(void* data) {
	ASSERT(data != NULL);

	return capwap_clone(data, sizeof(struct capwap_mtudiscovery_element));
}

/* */
static void capwap_mtudiscovery_element_free(void* data) {
	ASSERT(data != NULL);

	capwap_free(data);
}

/* */
const struct capwap_message_elements_ops capwap_element_mtudiscovery_ops = {
	.category = CAPWAP_MESSAGE_ELEMENT_SINGLE,
	.create = capwap_mtudiscovery_element_create,
	.parse = capwap_mtudiscovery_element_parsing,
	.clone = capwap_mtudiscovery_element_clone,
	.free = capwap_mtudiscovery_element_free
};
