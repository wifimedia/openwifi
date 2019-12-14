#include "capwap.h"
#include "capwap_element.h"

/********************************************************************

 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           Timestamp                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Type:   6 for AC Timestamp

Length:   4

********************************************************************/

/* */
static void capwap_actimestamp_element_create(void* data, capwap_message_elements_handle handle, struct capwap_write_message_elements_ops* func) {
	struct capwap_actimestamp_element* element = (struct capwap_actimestamp_element*)data;

	ASSERT(data != NULL);

	/* */
	func->write_u32(handle, element->timestamp);
}

/* */
static void* capwap_actimestamp_element_parsing(capwap_message_elements_handle handle, struct capwap_read_message_elements_ops* func) {
	struct capwap_actimestamp_element* data;

	ASSERT(handle != NULL);
	ASSERT(func != NULL);

	if (func->read_ready(handle) != 4) {
		log_printf(LOG_DEBUG, "Invalid AC Timestamp element: underbuffer");
		return NULL;
	}

	/* Retrieve data */
	data = (struct capwap_actimestamp_element*)capwap_alloc(sizeof(struct capwap_actimestamp_element));
	func->read_u32(handle, &data->timestamp);

	return data;
}

/* */
static void* capwap_actimestamp_element_clone(void* data) {
	ASSERT(data != NULL);

	return capwap_clone(data, sizeof(struct capwap_actimestamp_element));
}

/* */
static void capwap_actimestamp_element_free(void* data) {
	ASSERT(data != NULL);
	
	capwap_free(data);
}

/* */
const struct capwap_message_elements_ops capwap_element_actimestamp_ops = {
	.category = CAPWAP_MESSAGE_ELEMENT_SINGLE,
	.create = capwap_actimestamp_element_create,
	.parse = capwap_actimestamp_element_parsing,
	.clone = capwap_actimestamp_element_clone,
	.free = capwap_actimestamp_element_free
};
