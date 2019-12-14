#include "capwap.h"
#include "capwap_element.h"

/********************************************************************

 0                   1                   2
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Radio ID    |Num Of Entries |     Length    | MAC Address...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Type:   15 for Decryption Error Report

Length:   >= 9

********************************************************************/

/* */
static void capwap_decrypterrorreport_element_create(void* data, capwap_message_elements_handle handle, struct capwap_write_message_elements_ops* func) {
	struct capwap_decrypterrorreport_element* element = (struct capwap_decrypterrorreport_element*)data;

	ASSERT(data != NULL);
	ASSERT(IS_VALID_RADIOID(element->radioid));
	ASSERT(element->entry > 0);
	ASSERT(IS_VALID_MACADDRESS_LENGTH(element->length));

	func->write_u8(handle, element->radioid);
	func->write_u8(handle, element->entry);
	func->write_u8(handle, element->length);
	func->write_block(handle, element->address, element->entry * element->length);
}

/* */
static void* capwap_decrypterrorreport_element_clone(void* data) {
	struct capwap_decrypterrorreport_element* cloneelement;

	ASSERT(data != NULL);

	cloneelement = capwap_clone(data, sizeof(struct capwap_decrypterrorreport_element));
	if (cloneelement->entry > 0) {
		cloneelement->address = capwap_clone(((struct capwap_decrypterrorreport_element*)data)->address, cloneelement->entry * cloneelement->length);
	}

	return cloneelement;
}

/* */
static void capwap_decrypterrorreport_element_free(void* data) {
	struct capwap_decrypterrorreport_element* element = (struct capwap_decrypterrorreport_element*)data;

	ASSERT(data != NULL);

	if (element->address) {
		capwap_free(element->address);
	}

	capwap_free(data);
}

/* */
static void* capwap_decrypterrorreport_element_parsing(capwap_message_elements_handle handle, struct capwap_read_message_elements_ops* func) {
	unsigned short length;
	struct capwap_decrypterrorreport_element* data;

	ASSERT(handle != NULL);
	ASSERT(func != NULL);

	length = func->read_ready(handle);
	if (length < 9) {
		log_printf(LOG_DEBUG, "Invalid Decryption Error Report element: underbuffer");
		return NULL;
	}

	length -= 3;

	/* */
	data = (struct capwap_decrypterrorreport_element*)capwap_alloc(sizeof(struct capwap_decrypterrorreport_element));
	memset(data, 0, sizeof(struct capwap_decrypterrorreport_element));

	/* Retrieve data */
	func->read_u8(handle, &data->radioid);
	func->read_u8(handle, &data->entry);
	func->read_u8(handle, &data->length);

	if (!IS_VALID_RADIOID(data->radioid)) {
		capwap_decrypterrorreport_element_free((void*)data);
		log_printf(LOG_DEBUG, "Invalid Decryption Error Report element: invalid radioid");
		return NULL;
	} else if (!data->entry) {
		capwap_decrypterrorreport_element_free((void*)data);
		log_printf(LOG_DEBUG, "Invalid Decryption Error Report element: invalid entry");
		return NULL;
	} else if (!IS_VALID_MACADDRESS_LENGTH(data->length)) {
		capwap_decrypterrorreport_element_free((void*)data);
		log_printf(LOG_DEBUG, "Invalid Decryption Error Report element: invalid length");
		return NULL;
	}

	if (length != (data->entry * data->length)) {
		capwap_decrypterrorreport_element_free((void*)data);
		log_printf(LOG_DEBUG, "Invalid Decryption Error Report element: invalid total length");
		return NULL;
	}

	data->address = (uint8_t*)capwap_alloc(length);
	func->read_block(handle, data->address, length);

	return data;
}

/* */
const struct capwap_message_elements_ops capwap_element_decrypterrorreport_ops = {
	.category = CAPWAP_MESSAGE_ELEMENT_SINGLE,
	.create = capwap_decrypterrorreport_element_create,
	.parse = capwap_decrypterrorreport_element_parsing,
	.clone = capwap_decrypterrorreport_element_clone,
	.free = capwap_decrypterrorreport_element_free
};
