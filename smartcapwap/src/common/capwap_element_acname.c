#include "capwap.h"
#include "capwap_element.h"

/********************************************************************

 0
 0 1 2 3 4 5 6 7
+-+-+-+-+-+-+-+-+
|   Name ...
+-+-+-+-+-+-+-+-+

Type:   4 for AC Name

Length:   >= 1

********************************************************************/

/* */
static void capwap_acname_element_create(void* data, capwap_message_elements_handle handle, struct capwap_write_message_elements_ops* func) {
	struct capwap_acname_element* element = (struct capwap_acname_element*)data;

	ASSERT(data != NULL);
	ASSERT(element->name != NULL);

	func->write_block(handle, element->name, strlen((char*)element->name));
}

/* */
static void* capwap_acname_element_parsing(capwap_message_elements_handle handle, struct capwap_read_message_elements_ops* func) {
	unsigned short length;
	struct capwap_acname_element* data;

	ASSERT(handle != NULL);
	ASSERT(func != NULL);

	length = func->read_ready(handle);
	if ((length < 1) || (length > CAPWAP_ACNAME_MAXLENGTH)) {
		log_printf(LOG_DEBUG, "Invalid AC Name element: underbuffer");
		return NULL;
	}

	/* Retrieve data */
	data = (struct capwap_acname_element*)capwap_alloc(sizeof(struct capwap_acname_element));
	data->name = (uint8_t*)capwap_alloc(length + 1);
	func->read_block(handle, data->name, length);
	data->name[length] = 0;

	return data;
}

/* */
static void* capwap_acname_element_clone(void* data) {
	struct capwap_acname_element* cloneelement;

	ASSERT(data != NULL);

	cloneelement = capwap_clone(data, sizeof(struct capwap_acname_element));
	if (cloneelement->name) {
		cloneelement->name = (uint8_t*)capwap_duplicate_string((char*)((struct capwap_acname_element*)data)->name);
	}

	return cloneelement;
}

/* */
static void capwap_acname_element_free(void* data) {
	struct capwap_acname_element* element = (struct capwap_acname_element*)data;

	ASSERT(data != NULL);

	if (element->name) {
		capwap_free(element->name);
	}

	capwap_free(data);
}

/* */
const struct capwap_message_elements_ops capwap_element_acname_ops = {
	.category = CAPWAP_MESSAGE_ELEMENT_SINGLE,
	.create = capwap_acname_element_create,
	.parse = capwap_acname_element_parsing,
	.clone = capwap_acname_element_clone,
	.free = capwap_acname_element_free
};
