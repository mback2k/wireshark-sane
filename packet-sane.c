/* packet-sane.c
 *
 * Copyright (C) 2013, Marc Hoersken, <info@marc-hoersken.de>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <string.h>
#include <glib.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/emem.h>
#include <epan/conversation.h>

#define PROTO_TAG_SANE						"SANE"
#define TCP_PORT_SANE						6566

#define SANE_NET_INIT						0
#define SANE_NET_GET_DEVICES				1
#define SANE_NET_OPEN						2
#define SANE_NET_CLOSE						3
#define SANE_NET_GET_OPTION_DESCRIPTORS		4
#define SANE_NET_CONTROL_OPTION				5
#define SANE_NET_GET_PARAMETERS				6
#define SANE_NET_START						7
#define SANE_NET_CANCEL						8
#define SANE_NET_AUTHORIZE					9
#define SANE_NET_EXIT						10

#define SANE_STATUS_GOOD					0
#define SANE_STATUS_UNSUPPORTED				1
#define SANE_STATUS_CANCELLED				2
#define SANE_STATUS_DEVICE_BUSY				3
#define SANE_STATUS_INVAL					4
#define SANE_STATUS_EOF						5
#define SANE_STATUS_JAMMED					6
#define SANE_STATUS_NO_DOCS					7
#define SANE_STATUS_COVER_OPEN				8
#define SANE_STATUS_IO_ERROR				9
#define SANE_STATUS_NO_MEM					10
#define SANE_STATUS_ACCESS_DENIED			11

#define SANE_TYPE_BOOL						0
#define	SANE_TYPE_INT						1
#define SANE_TYPE_FIXED						2
#define SANE_TYPE_STRING					3
#define SANE_TYPE_BUTTON					4
#define SANE_TYPE_GROUP						5

#define SANE_UNIT_NONE						0
#define SANE_UNIT_PIXEL						1
#define SANE_UNIT_BIT						2
#define SANE_UNIT_MM						3
#define SANE_UNIT_DPI						4
#define SANE_UNIT_PERCENT					5
#define SANE_UNIT_MICROSECOND				6

#define SANE_CONSTRAINT_NONE				0
#define SANE_CONSTRAINT_RANGE				1
#define SANE_CONSTRAINT_WORD_LIST			2
#define SANE_CONSTRAINT_STRING_LIST			3

#define SANE_ACTION_GET_VALUE				0
#define SANE_ACTION_SET_VALUE				1
#define SANE_ACTION_SET_AUTO				2

#define SANE_FRAME_GRAY						0
#define SANE_FRAME_RGB						1
#define SANE_FRAME_RED						2
#define SANE_FRAME_GREEN					3
#define SANE_FRAME_BLUE						4

static const value_string CodeNames[] = {
	{ SANE_NET_INIT,					"SANE_NET_INIT"						},
	{ SANE_NET_GET_DEVICES,				"SANE_NET_GET_DEVICES"				},
	{ SANE_NET_OPEN,					"SANE_NET_OPEN"						},
	{ SANE_NET_CLOSE,					"SANE_NET_CLOSE"					},
	{ SANE_NET_GET_OPTION_DESCRIPTORS,	"SANE_NET_GET_OPTION_DESCRIPTORS"	},
	{ SANE_NET_CONTROL_OPTION,			"SANE_NET_CONTROL_OPTION"			},
	{ SANE_NET_GET_PARAMETERS,			"SANE_NET_GET_PARAMETERS"			},
	{ SANE_NET_START,					"SANE_NET_START"					},
	{ SANE_NET_CANCEL,					"SANE_NET_CANCEL"					},
	{ SANE_NET_AUTHORIZE,				"SANE_NET_AUTHORIZE"				},
	{ SANE_NET_EXIT,					"SANE_NET_EXIT"						},

	{ 0,								NULL								}
};

static const value_string StatusNames[] = {
	{ SANE_STATUS_GOOD,					"SANE_STATUS_GOOD"					},
	{ SANE_STATUS_UNSUPPORTED,			"SANE_STATUS_UNSUPPORTED"			},
	{ SANE_STATUS_CANCELLED,			"SANE_STATUS_CANCELLED"				},
	{ SANE_STATUS_DEVICE_BUSY,			"SANE_STATUS_DEVICE_BUSY"			},
	{ SANE_STATUS_INVAL,				"SANE_STATUS_INVAL"					},
	{ SANE_STATUS_EOF,					"SANE_STATUS_EOF"					},
	{ SANE_STATUS_JAMMED,				"SANE_STATUS_JAMMED"				},
	{ SANE_STATUS_NO_DOCS,				"SANE_STATUS_NO_DOCS"				},
	{ SANE_STATUS_COVER_OPEN,			"SANE_STATUS_COVER_OPEN"			},
	{ SANE_STATUS_IO_ERROR,				"SANE_STATUS_IO_ERROR"				},
	{ SANE_STATUS_NO_MEM,				"SANE_STATUS_NO_MEM"				},
	{ SANE_STATUS_ACCESS_DENIED,		"SANE_STATUS_ACCESS_DENIED"			},

	{ 0,								NULL								}
};

static const value_string TypeNames[] = {
	{ SANE_TYPE_BOOL,					"SANE_TYPE_BOOL"					},
	{ SANE_TYPE_INT,					"SANE_TYPE_INT"						},
	{ SANE_TYPE_FIXED,					"SANE_TYPE_FIXED"					},
	{ SANE_TYPE_STRING,					"SANE_TYPE_STRING"					},
	{ SANE_TYPE_BUTTON,					"SANE_TYPE_BUTTON"					},
	{ SANE_TYPE_GROUP,					"SANE_TYPE_GROUP"					},

	{ 0,								NULL								}
};

static const value_string UnitNames[] = {
	{ SANE_UNIT_NONE,					"SANE_UNIT_NONE"					},
	{ SANE_UNIT_PIXEL,					"SANE_UNIT_PIXEL"					},
	{ SANE_UNIT_BIT,					"SANE_UNIT_BIT"						},
	{ SANE_UNIT_MM,						"SANE_UNIT_MM"						},
	{ SANE_UNIT_DPI,					"SANE_UNIT_DPI"						},
	{ SANE_UNIT_PERCENT,				"SANE_UNIT_PERCENT"					},
	{ SANE_UNIT_MICROSECOND,			"SANE_UNIT_MICROSECOND"				},

	{ 0,								NULL								}
};

static const value_string ConstraintNames[] = {
	{ SANE_CONSTRAINT_NONE,				"SANE_CONSTRAINT_NONE"				},
	{ SANE_CONSTRAINT_RANGE,			"SANE_CONSTRAINT_RANGE"				},
	{ SANE_CONSTRAINT_WORD_LIST,		"SANE_CONSTRAINT_WORD_LIST"			},
	{ SANE_CONSTRAINT_STRING_LIST,		"SANE_CONSTRAINT_STRING_LIST"		},

	{ 0,								NULL								}
};

static const value_string ActionNames[] = {
	{ SANE_ACTION_GET_VALUE,			"SANE_ACTION_GET_VALUE"				},
	{ SANE_ACTION_SET_VALUE,			"SANE_ACTION_SET_VALUE"				},
	{ SANE_ACTION_SET_AUTO,				"SANE_ACTION_SET_AUTO"				},

	{ 0,								NULL								}
};

static const value_string FrameNames[] = {
	{ SANE_FRAME_GRAY,					"SANE_FRAME_GRAY"					},
	{ SANE_FRAME_RGB,					"SANE_FRAME_RGB"					},
	{ SANE_FRAME_RED,					"SANE_FRAME_RED"					},
	{ SANE_FRAME_GREEN,					"SANE_FRAME_GREEN"					},
	{ SANE_FRAME_BLUE,					"SANE_FRAME_BLUE"					},

	{ 0,								NULL								}
};

/* Wireshark ID of the SANE protocol */
static int proto_sane = -1;

/* The following hf_* variables are used to hold the Wireshark IDs of
* our header fields; they are filled out when we call
* proto_register_field_array() in proto_register_sane()
*/

/** Defining the protocol */
static gint hf_sane_rpc_code = -1;
static gint hf_sane_rpc_status = -1;
static gint hf_sane_net_version_code = -1;
static gint hf_sane_net_version_code_major = -1;
static gint hf_sane_net_version_code_minor = -1;
static gint hf_sane_net_version_code_build = -1;
static gint hf_sane_net_user_name = -1;
static gint hf_sane_net_device = -1;
static gint hf_sane_net_device_name = -1;
static gint hf_sane_net_device_vendor = -1;
static gint hf_sane_net_device_model = -1;
static gint hf_sane_net_device_type = -1;
static gint hf_sane_net_handle = -1;
static gint hf_sane_net_resource = -1;
static gint hf_sane_net_username = -1;
static gint hf_sane_net_password = -1;
static gint hf_sane_net_dummy = -1;
static gint hf_sane_net_num_options = -1;
static gint hf_sane_net_option = -1;
static gint hf_sane_net_option_name = -1;
static gint hf_sane_net_option_title = -1;
static gint hf_sane_net_option_desc = -1;
static gint hf_sane_net_option_type = -1;
static gint hf_sane_net_option_unit = -1;
static gint hf_sane_net_option_size = -1;
static gint hf_sane_net_option_cap = -1;
static gint hf_sane_net_option_constraint_type = -1;
static gint hf_sane_net_option_constraint_range = -1;
static gint hf_sane_net_option_constraint_range_min = -1;
static gint hf_sane_net_option_constraint_range_max = -1;
static gint hf_sane_net_option_constraint_range_quant = -1;
static gint hf_sane_net_option_constraint_word_list = -1;
static gint hf_sane_net_option_constraint_word_list_item = -1;
static gint hf_sane_net_option_constraint_string_list = -1;
static gint hf_sane_net_option_constraint_string_list_item = -1;
static gint hf_sane_net_option_num = -1;
static gint hf_sane_net_action = -1;
static gint hf_sane_net_value_type = -1;
static gint hf_sane_net_value_size = -1;
static gint hf_sane_net_value = -1;
static gint hf_sane_net_info = -1;
static gint hf_sane_net_port = -1;
static gint hf_sane_net_byte_order = -1;
static gint hf_sane_net_parameters = -1;
static gint hf_sane_net_parameters_format = -1;
static gint hf_sane_net_parameters_last_frame = -1;
static gint hf_sane_net_parameters_bytes_per_line = -1;
static gint hf_sane_net_parameters_pixels_per_line = -1;
static gint hf_sane_net_parameters_lines = -1;
static gint hf_sane_net_parameters_depth = -1;

/* These are the ids of the subtrees that we may be creating */
static gint ett_sane = -1;


static gboolean check_remaining_length(packet_info *pinfo, guint initial_offset, guint offset, guint length, int need)
{
	int have = length - offset;

	if (need > have) {
		pinfo->desegment_offset = initial_offset;
		pinfo->desegment_len = need - have;
		return FALSE;
	}

	return TRUE;
}

static guint dissect_sane_rpc_request(packet_info *pinfo, proto_tree *sane_tree, tvbuff_t *tvb, guint offset, guint length)
{
	guint remember_initial_offset = offset;
	conversation_t *conversation = NULL;
	proto_item *sane_sub_item = NULL;
	proto_tree *sane_sub_tree = NULL;
	GQueue *frame_rpc_queue = NULL;
	guint *frame_rpc = NULL;
	guint rpc = 0;
	guint len = 0;

	if (check_remaining_length(pinfo, remember_initial_offset, offset, length, 4)) {
		rpc = tvb_get_ntohl(tvb, offset);
		proto_tree_add_item(sane_tree, hf_sane_rpc_code, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
	} else
		return offset;

	switch (rpc) {
		case SANE_NET_INIT:
			if (check_remaining_length(pinfo, remember_initial_offset, offset, length, 8)) {
				sane_sub_item = proto_tree_add_item(sane_tree, hf_sane_net_version_code, tvb, offset, 4, ENC_BIG_ENDIAN);
				if (sane_sub_item) {
					sane_sub_tree = proto_item_add_subtree(sane_sub_item, ett_sane);
					proto_tree_add_item(sane_sub_tree, hf_sane_net_version_code_major, tvb, offset + 0, 1, ENC_BIG_ENDIAN);
					proto_tree_add_item(sane_sub_tree, hf_sane_net_version_code_minor, tvb, offset + 1, 1, ENC_BIG_ENDIAN);
					proto_tree_add_item(sane_sub_tree, hf_sane_net_version_code_build, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
				}
				offset += 4;
			} else
				return offset;

			if (check_remaining_length(pinfo, remember_initial_offset, offset, length, 4)) {
				len = tvb_get_ntohl(tvb, offset);
				offset += 4;
			} else
				return offset;

			if (check_remaining_length(pinfo, remember_initial_offset, offset, length, len)) {
				proto_tree_add_item(sane_tree, hf_sane_net_user_name, tvb, offset, len, ENC_UTF_8);
				offset += len;
			} else
				return offset;
		break;

		case SANE_NET_OPEN:
			if (check_remaining_length(pinfo, remember_initial_offset, offset, length, 4)) {
				len = tvb_get_ntohl(tvb, offset);
				offset += 4;
			} else
				return offset;

			if (check_remaining_length(pinfo, remember_initial_offset, offset, length, len)) {
				proto_tree_add_item(sane_tree, hf_sane_net_device_name, tvb, offset, len, ENC_UTF_8);
				offset += len;
			} else
				return offset;
		break;

		case SANE_NET_CONTROL_OPTION:
			if (check_remaining_length(pinfo, remember_initial_offset, offset, length, 24)) {
				proto_tree_add_item(sane_tree, hf_sane_net_handle, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
			} else
				return offset;

			if (check_remaining_length(pinfo, remember_initial_offset, offset, length, 20)) {
				proto_tree_add_item(sane_tree, hf_sane_net_option_num, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
			} else
				return offset;

			if (check_remaining_length(pinfo, remember_initial_offset, offset, length, 16)) {
				proto_tree_add_item(sane_tree, hf_sane_net_action, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
			} else
				return offset;

			if (check_remaining_length(pinfo, remember_initial_offset, offset, length, 12)) {
				proto_tree_add_item(sane_tree, hf_sane_net_value_type, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
			} else
				return offset;

			if (check_remaining_length(pinfo, remember_initial_offset, offset, length, 8)) {
				len = tvb_get_ntohl(tvb, offset);
				proto_tree_add_item(sane_tree, hf_sane_net_value_size, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
			} else
				return offset;

			offset += 4; /* TODO: element_count? */

			if (check_remaining_length(pinfo, remember_initial_offset, offset, length, len)) {
				proto_tree_add_item(sane_tree, hf_sane_net_value, tvb, offset, len, ENC_NA);
				offset += len;
			} else
				return offset;
		break;

		case SANE_NET_AUTHORIZE:
			if (check_remaining_length(pinfo, remember_initial_offset, offset, length, 12)) {
				len = tvb_get_ntohl(tvb, offset);
				offset += 4;
			} else
				return offset;

			if (check_remaining_length(pinfo, remember_initial_offset, offset, length, len)) {
				proto_tree_add_item(sane_tree, hf_sane_net_resource, tvb, offset, len, ENC_UTF_8);
				offset += len;
			} else
				return offset;
			
			if (check_remaining_length(pinfo, remember_initial_offset, offset, length, 8)) {
				len = tvb_get_ntohl(tvb, offset);
				offset += 4;
			} else
				return offset;

			if (check_remaining_length(pinfo, remember_initial_offset, offset, length, len)) {
				proto_tree_add_item(sane_tree, hf_sane_net_username, tvb, offset, len, ENC_UTF_8);
				offset += len;
			} else
				return offset;
			
			if (check_remaining_length(pinfo, remember_initial_offset, offset, length, 4)) {
				len = tvb_get_ntohl(tvb, offset);
				offset += 4;
			} else
				return offset;

			if (check_remaining_length(pinfo, remember_initial_offset, offset, length, len)) {
				proto_tree_add_item(sane_tree, hf_sane_net_password, tvb, offset, len, ENC_UTF_8);
				offset += len;
			} else
				return offset;
		break;

		case SANE_NET_CLOSE:
		case SANE_NET_GET_OPTION_DESCRIPTORS:
		case SANE_NET_GET_PARAMETERS:
		case SANE_NET_START:
		case SANE_NET_CANCEL:
			if (check_remaining_length(pinfo, remember_initial_offset, offset, length, 4)) {
				proto_tree_add_item(sane_tree, hf_sane_net_handle, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
			} else
				return offset;
		break;
	}

	if (!pinfo->fd->flags.visited) {
		conversation = find_or_create_conversation(pinfo);
		if (conversation) {
			frame_rpc_queue = (GQueue*) conversation_get_proto_data(conversation, proto_sane);
			if (!frame_rpc_queue) {
				frame_rpc_queue = (GQueue*) se_alloc(sizeof(GQueue));
				if (frame_rpc_queue) {
					g_queue_init(frame_rpc_queue);
					conversation_add_proto_data(conversation, proto_sane, frame_rpc_queue);
				}
			}
			if (frame_rpc_queue) {
				frame_rpc = (guint*) se_alloc(sizeof(guint));
				if (frame_rpc) {
					*frame_rpc = rpc;
					g_queue_push_tail(frame_rpc_queue, frame_rpc);
				}
			}
		}
	}

	return offset;
}

static guint dissect_sane_rpc_response(packet_info *pinfo, proto_tree *sane_tree, tvbuff_t *tvb, guint offset, guint length)
{
	guint remember_initial_offset = offset;
	conversation_t *conversation = NULL;
	proto_item *sane_subsub_item = NULL;
	proto_tree *sane_subsub_tree = NULL;
	proto_item *sane_sub_item = NULL;
	proto_tree *sane_sub_tree = NULL;
	GQueue *packet_rpc_queue = NULL;
	GQueue *frame_rpc_queue = NULL;
	guint *packet_rpc = NULL;
	guint *frame_rpc = NULL;
	guint sub_idx = 0;
	guint sub_cnt = 0;
	guint idx = 0;
	guint cnt = 0;
	guint rpc = 0;
	guint len = 0;

	conversation = find_or_create_conversation(pinfo);
	if (conversation) {
		frame_rpc_queue = (GQueue*) conversation_get_proto_data(conversation, proto_sane);
	}

	packet_rpc_queue = (GQueue*) p_get_proto_data(pinfo->fd, proto_sane, 0);
	if (!packet_rpc_queue) {
		packet_rpc_queue = (GQueue*) se_alloc(sizeof(GQueue));
		if (packet_rpc_queue) {
			g_queue_init(packet_rpc_queue);
			p_add_proto_data(pinfo->fd, proto_sane, 0, packet_rpc_queue);
		}
	}

	if (packet_rpc_queue) {
		packet_rpc = (guint*) g_queue_peek_head(packet_rpc_queue);
		if (!packet_rpc) {
			if (frame_rpc_queue) {
				frame_rpc = (guint*) g_queue_peek_head(frame_rpc_queue);
				if (frame_rpc) {
					g_queue_push_tail(packet_rpc_queue, frame_rpc);
					packet_rpc = frame_rpc;
				}
			}
		}
	}

	if (!packet_rpc)
		return offset;

	rpc = *packet_rpc;

	switch (rpc) {
		case SANE_NET_INIT:
			if (check_remaining_length(pinfo, remember_initial_offset, offset, length, 8)) {
				proto_tree_add_item(sane_tree, hf_sane_rpc_status, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
			} else
				return offset;

			if (check_remaining_length(pinfo, remember_initial_offset, offset, length, 4)) {
				sane_sub_item = proto_tree_add_item(sane_tree, hf_sane_net_version_code, tvb, offset, 4, ENC_BIG_ENDIAN);
				if (sane_sub_item) {
					sane_sub_tree = proto_item_add_subtree(sane_sub_item, ett_sane);
					proto_tree_add_item(sane_sub_tree, hf_sane_net_version_code_major, tvb, offset + 0, 1, ENC_BIG_ENDIAN);
					proto_tree_add_item(sane_sub_tree, hf_sane_net_version_code_minor, tvb, offset + 1, 1, ENC_BIG_ENDIAN);
					proto_tree_add_item(sane_sub_tree, hf_sane_net_version_code_build, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
				}
				offset += 4;
			} else
				return offset;
		break;

		case SANE_NET_GET_DEVICES:
			if (check_remaining_length(pinfo, remember_initial_offset, offset, length, 8)) {
				proto_tree_add_item(sane_tree, hf_sane_rpc_status, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
			} else
				return offset;

			if (check_remaining_length(pinfo, remember_initial_offset, offset, length, 4)) {
				cnt = tvb_get_ntohl(tvb, offset);
				offset += 4;
			} else
				return offset;

			for (idx = 0; idx < cnt; idx++) {
				if (check_remaining_length(pinfo, remember_initial_offset, offset, length, 4)) {
					len = tvb_get_ntohl(tvb, offset);
					offset += 4;
				} else
					return offset;

				if (len) /* null-pointer check */
					continue;

				if (!check_remaining_length(pinfo, remember_initial_offset, offset, length, 16))
					return offset;

				sane_sub_item = proto_tree_add_item(sane_tree, hf_sane_net_device, tvb, offset, -1, ENC_NA);
				if (sane_sub_item) {
					sane_sub_tree = proto_item_add_subtree(sane_sub_item, ett_sane);

					if (check_remaining_length(pinfo, remember_initial_offset, offset, length, 16)) {
						len = tvb_get_ntohl(tvb, offset);
						offset += 4;
					} else
						return offset;

					if (check_remaining_length(pinfo, remember_initial_offset, offset, length, len)) {
						proto_tree_add_item(sane_sub_tree, hf_sane_net_device_name, tvb, offset, len, ENC_UTF_8);
						offset += len;
					} else
						return offset;

					if (check_remaining_length(pinfo, remember_initial_offset, offset, length, 12)) {
						len = tvb_get_ntohl(tvb, offset);
						offset += 4;
					} else
						return offset;

					if (check_remaining_length(pinfo, remember_initial_offset, offset, length, len)) {
						proto_tree_add_item(sane_sub_tree, hf_sane_net_device_vendor, tvb, offset, len, ENC_UTF_8);
						offset += len;
					} else
						return offset;

					if (check_remaining_length(pinfo, remember_initial_offset, offset, length, 8)) {
						len = tvb_get_ntohl(tvb, offset);
						offset += 4;
					} else
						return offset;

					if (check_remaining_length(pinfo, remember_initial_offset, offset, length, len)) {
						proto_tree_add_item(sane_sub_tree, hf_sane_net_device_model, tvb, offset, len, ENC_UTF_8);
						offset += len;
					} else
						return offset;

					if (check_remaining_length(pinfo, remember_initial_offset, offset, length, 4)) {
						len = tvb_get_ntohl(tvb, offset);
						offset += 4;
					} else
						return offset;

					if (check_remaining_length(pinfo, remember_initial_offset, offset, length, len)) {
						proto_tree_add_item(sane_sub_tree, hf_sane_net_device_type, tvb, offset, len, ENC_UTF_8);
						offset += len;
					} else
						return offset;

					proto_item_set_end(sane_sub_item, tvb, offset);
				}
			}
		break;

		case SANE_NET_OPEN:
			if (check_remaining_length(pinfo, remember_initial_offset, offset, length, 12)) {
				proto_tree_add_item(sane_tree, hf_sane_rpc_status, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
			} else
				return offset;

			if (check_remaining_length(pinfo, remember_initial_offset, offset, length, 8)) {
				proto_tree_add_item(sane_tree, hf_sane_net_handle, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
			} else
				return offset;

			if (check_remaining_length(pinfo, remember_initial_offset, offset, length, 4)) {
				len = tvb_get_ntohl(tvb, offset);
				offset += 4;
			} else
				return offset;

			if (check_remaining_length(pinfo, remember_initial_offset, offset, length, len)) {
				proto_tree_add_item(sane_tree, hf_sane_net_resource, tvb, offset, len, ENC_UTF_8);
				offset += len;
			} else
				return offset;
		break;

		case SANE_NET_GET_OPTION_DESCRIPTORS:
			if (check_remaining_length(pinfo, remember_initial_offset, offset, length, 4)) {
				cnt = tvb_get_ntohl(tvb, offset);
				proto_tree_add_item(sane_tree, hf_sane_net_num_options, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
			} else
				return offset;

			for (idx = 0; idx < cnt; idx++) {
				if (check_remaining_length(pinfo, remember_initial_offset, offset, length, 4)) {
					len = tvb_get_ntohl(tvb, offset);
					offset += 4;
				} else
					return offset;

				if (len) /* null-pointer check */
					continue;

				if (!check_remaining_length(pinfo, remember_initial_offset, offset, length, 32))
					return offset;

				sane_sub_item = proto_tree_add_item(sane_tree, hf_sane_net_option, tvb, offset, -1, ENC_NA);
				if (sane_sub_item) {
					sane_sub_tree = proto_item_add_subtree(sane_sub_item, ett_sane);

					if (check_remaining_length(pinfo, remember_initial_offset, offset, length, 32)) {
						len = tvb_get_ntohl(tvb, offset);
						offset += 4;
					} else
						return offset;

					if (check_remaining_length(pinfo, remember_initial_offset, offset, length, len)) {
						proto_tree_add_item(sane_sub_tree, hf_sane_net_option_name, tvb, offset, len, ENC_UTF_8);
						offset += len;
					} else
						return offset;

					if (check_remaining_length(pinfo, remember_initial_offset, offset, length, 28)) {
						len = tvb_get_ntohl(tvb, offset);
						offset += 4;
					} else
						return offset;

					if (check_remaining_length(pinfo, remember_initial_offset, offset, length, len)) {
						proto_tree_add_item(sane_sub_tree, hf_sane_net_option_title, tvb, offset, len, ENC_UTF_8);
						offset += len;
					} else
						return offset;

					if (check_remaining_length(pinfo, remember_initial_offset, offset, length, 24)) {
						len = tvb_get_ntohl(tvb, offset);
						offset += 4;
					} else
						return offset;

					if (check_remaining_length(pinfo, remember_initial_offset, offset, length, len)) {
						proto_tree_add_item(sane_sub_tree, hf_sane_net_option_desc, tvb, offset, len, ENC_UTF_8);
						offset += len;
					} else
						return offset;

					if (check_remaining_length(pinfo, remember_initial_offset, offset, length, 20)) {
						proto_tree_add_item(sane_sub_tree, hf_sane_net_option_type, tvb, offset, 4, ENC_BIG_ENDIAN);
						offset += 4;
					} else
						return offset;

					if (check_remaining_length(pinfo, remember_initial_offset, offset, length, 16)) {
						proto_tree_add_item(sane_sub_tree, hf_sane_net_option_unit, tvb, offset, 4, ENC_BIG_ENDIAN);
						offset += 4;
					} else
						return offset;

					if (check_remaining_length(pinfo, remember_initial_offset, offset, length, 12)) {
						proto_tree_add_item(sane_sub_tree, hf_sane_net_option_size, tvb, offset, 4, ENC_BIG_ENDIAN);
						offset += 4;
					} else
						return offset;

					if (check_remaining_length(pinfo, remember_initial_offset, offset, length, 8)) {
						proto_tree_add_item(sane_sub_tree, hf_sane_net_option_cap, tvb, offset, 4, ENC_BIG_ENDIAN);
						offset += 4;
					} else
						return offset;

					if (check_remaining_length(pinfo, remember_initial_offset, offset, length, 4)) {
						len = tvb_get_ntohl(tvb, offset);
						proto_tree_add_item(sane_sub_tree, hf_sane_net_option_constraint_type, tvb, offset, 4, ENC_BIG_ENDIAN);
						offset += 4;
					} else
						return offset;

					switch (len) {
						case SANE_CONSTRAINT_NONE:
							/* nothing to do here */
						break;

						case SANE_CONSTRAINT_RANGE:
							if (check_remaining_length(pinfo, remember_initial_offset, offset, length, 4)) {
								len = tvb_get_ntohl(tvb, offset);
								offset += 4;
							} else
								return offset;

							if (len) /* null-pointer check */
								break;

							if (!check_remaining_length(pinfo, remember_initial_offset, offset, length, 4 * 3))
								return offset;

							sane_subsub_item = proto_tree_add_item(sane_sub_tree, hf_sane_net_option_constraint_range, tvb, offset, 4 * 3, ENC_NA);
							if (sane_sub_item) {
								sane_subsub_tree = proto_item_add_subtree(sane_subsub_item, ett_sane);

								proto_tree_add_item(sane_subsub_tree, hf_sane_net_option_constraint_range_min, tvb, offset, 4, ENC_BIG_ENDIAN);
								offset += 4;

								proto_tree_add_item(sane_subsub_tree, hf_sane_net_option_constraint_range_max, tvb, offset, 4, ENC_BIG_ENDIAN);
								offset += 4;

								proto_tree_add_item(sane_subsub_tree, hf_sane_net_option_constraint_range_quant, tvb, offset, 4, ENC_BIG_ENDIAN);
								offset += 4;

								proto_item_set_end(sane_subsub_item, tvb, offset);
							}
						break;

						case SANE_CONSTRAINT_WORD_LIST:
							if (check_remaining_length(pinfo, remember_initial_offset, offset, length, 4)) {
								sub_cnt = tvb_get_ntohl(tvb, offset);
								sane_subsub_item = proto_tree_add_item(sane_sub_tree, hf_sane_net_option_constraint_word_list, tvb, offset, 4, ENC_BIG_ENDIAN);
								offset += 4;
							} else
								return offset;

							if (sane_subsub_item) {
								sane_subsub_tree = proto_item_add_subtree(sane_subsub_item, ett_sane);

								for (sub_idx = 0; sub_idx < sub_cnt; sub_idx++) {
									if (check_remaining_length(pinfo, remember_initial_offset, offset, length, 4)) {
										proto_tree_add_item(sane_subsub_tree, hf_sane_net_option_constraint_word_list_item, tvb, offset, 4, ENC_BIG_ENDIAN);
										offset += 4;
									} else
										return offset;
								}
							}
						break;

						case SANE_CONSTRAINT_STRING_LIST:
							if (check_remaining_length(pinfo, remember_initial_offset, offset, length, 4)) {
								sub_cnt = tvb_get_ntohl(tvb, offset);
								sane_subsub_item = proto_tree_add_item(sane_sub_tree, hf_sane_net_option_constraint_string_list, tvb, offset, 4, ENC_BIG_ENDIAN);
								offset += 4;
							} else
								return offset;

							if (sane_sub_item) {
								sane_subsub_tree = proto_item_add_subtree(sane_subsub_item, ett_sane);

								for (sub_idx = 0; sub_idx < sub_cnt; sub_idx++) {
									if (check_remaining_length(pinfo, remember_initial_offset, offset, length, 4)) {
										len = tvb_get_ntohl(tvb, offset);
										offset += 4;
									} else
										return offset;

									if (check_remaining_length(pinfo, remember_initial_offset, offset, length, len)) {
										proto_tree_add_item(sane_subsub_tree, hf_sane_net_option_constraint_string_list_item, tvb, offset, len, ENC_UTF_8);
										offset += len;
									} else
										return offset;
								}
							}
						break;
					}

					proto_item_set_end(sane_sub_item, tvb, offset);
				}
			}
		break;

		case SANE_NET_CONTROL_OPTION:
			if (check_remaining_length(pinfo, remember_initial_offset, offset, length, 24)) {
				proto_tree_add_item(sane_tree, hf_sane_rpc_status, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
			} else
				return offset;

			if (check_remaining_length(pinfo, remember_initial_offset, offset, length, 20)) {
				proto_tree_add_item(sane_tree, hf_sane_net_info, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
			} else
				return offset;

			if (check_remaining_length(pinfo, remember_initial_offset, offset, length, 16)) {
				proto_tree_add_item(sane_tree, hf_sane_net_value_type, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
			} else
				return offset;

			if (check_remaining_length(pinfo, remember_initial_offset, offset, length, 12)) {
				len = tvb_get_ntohl(tvb, offset);
				proto_tree_add_item(sane_tree, hf_sane_net_value_size, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
			} else
				return offset;

			offset += 4; /* TODO: element_count? */

			if (check_remaining_length(pinfo, remember_initial_offset, offset, length, len)) {
				proto_tree_add_item(sane_tree, hf_sane_net_value, tvb, offset, len, ENC_NA);
				offset += len;
			} else
				return offset;

			if (check_remaining_length(pinfo, remember_initial_offset, offset, length, 4)) {
				len = tvb_get_ntohl(tvb, offset);
				offset += 4;
			} else
				return offset;

			if (check_remaining_length(pinfo, remember_initial_offset, offset, length, len)) {
				proto_tree_add_item(sane_tree, hf_sane_net_resource, tvb, offset, len, ENC_UTF_8);
				offset += len;
			} else
				return offset;
		break;

		case SANE_NET_GET_PARAMETERS:
			if (check_remaining_length(pinfo, remember_initial_offset, offset, length, 4 + (4 * 6))) {
				proto_tree_add_item(sane_tree, hf_sane_rpc_status, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
			} else
				return offset;

			if (!check_remaining_length(pinfo, remember_initial_offset, offset, length, 4 * 6))
				return offset;

			sane_sub_item = proto_tree_add_item(sane_tree, hf_sane_net_parameters, tvb, offset, 4 * 6, ENC_NA);
			if (sane_sub_item) {
				sane_sub_tree = proto_item_add_subtree(sane_sub_item, ett_sane);

				proto_tree_add_item(sane_sub_tree, hf_sane_net_parameters_format, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;

				proto_tree_add_item(sane_sub_tree, hf_sane_net_parameters_last_frame, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;

				proto_tree_add_item(sane_sub_tree, hf_sane_net_parameters_bytes_per_line, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;

				proto_tree_add_item(sane_sub_tree, hf_sane_net_parameters_pixels_per_line, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;

				proto_tree_add_item(sane_sub_tree, hf_sane_net_parameters_lines, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;

				proto_tree_add_item(sane_sub_tree, hf_sane_net_parameters_depth, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;

				proto_item_set_end(sane_sub_item, tvb, offset);
			}
		break;

		case SANE_NET_START:
			if (check_remaining_length(pinfo, remember_initial_offset, offset, length, 16)) {
				proto_tree_add_item(sane_tree, hf_sane_rpc_status, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
			} else
				return offset;

			if (check_remaining_length(pinfo, remember_initial_offset, offset, length, 12)) {
				proto_tree_add_item(sane_tree, hf_sane_net_port, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
			} else
				return offset;

			if (check_remaining_length(pinfo, remember_initial_offset, offset, length, 8)) {
				proto_tree_add_item(sane_tree, hf_sane_net_byte_order, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
			} else
				return offset;

			if (check_remaining_length(pinfo, remember_initial_offset, offset, length, 4)) {
				len = tvb_get_ntohl(tvb, offset);
				offset += 4;
			} else
				return offset;

			if (check_remaining_length(pinfo, remember_initial_offset, offset, length, len)) {
				proto_tree_add_item(sane_tree, hf_sane_net_resource, tvb, offset, len, ENC_UTF_8);
				offset += len;
			} else
				return offset;
		break;

		case SANE_NET_CLOSE:
		case SANE_NET_CANCEL:
		case SANE_NET_AUTHORIZE:
			if (check_remaining_length(pinfo, remember_initial_offset, offset, length, 4)) {
				proto_tree_add_item(sane_tree, hf_sane_net_dummy, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
			} else
				return offset;
		break;
	}

	if (packet_rpc_queue) {
		packet_rpc = (guint*) g_queue_pop_head(packet_rpc_queue);
		if (packet_rpc) {
			g_queue_push_tail(packet_rpc_queue, packet_rpc);
		}
	}

	if (!pinfo->fd->flags.visited && frame_rpc_queue) {
		frame_rpc = (guint*) g_queue_pop_head(frame_rpc_queue);
	}

	return offset;
}

static void dissect_sane(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item *sane_item = NULL;
	proto_tree *sane_tree = NULL;
	gboolean request = pinfo->match_port == pinfo->destport || TCP_PORT_SANE == pinfo->destport;
	guint offset = 0;
	guint length = tvb_length(tvb);

	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, PROTO_TAG_SANE);

	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_clear(pinfo->cinfo, COL_INFO);
		col_add_fstr(pinfo->cinfo, COL_INFO, "%d > %d - %s %s",
			pinfo->srcport,
			pinfo->destport,
			request ? "Request" : "Response",
			request && length >= 4 ? val_to_str(tvb_get_ntohl(tvb, offset), CodeNames, "RPC Code: 0x%08x") : ""
		);
	}

	if (tree) { /* we are being asked for details */
		sane_item = proto_tree_add_item(tree, proto_sane, tvb, 0, -1, FALSE);
		sane_tree = proto_item_add_subtree(sane_item, ett_sane);
	}

	if (request)
		offset = dissect_sane_rpc_request(pinfo, sane_tree, tvb, offset, length);
	else
		offset = dissect_sane_rpc_response(pinfo, sane_tree, tvb, offset, length);
}

void proto_register_sane(void)
{
	/* A header field is something you can search/filter on.
	* 
	* We create a structure to register our fields. It consists of an
	* array of hf_register_info structures, each of which are of the format
	* {&(field id), {name, abbrev, type, display, strings, bitmask, blurb, HFILL}}.
	*/
	static hf_register_info hf[] = {
		{ &hf_sane_rpc_code,
			{ "RPC Code", "sane.rpc.code", FT_UINT32, BASE_DEC, VALS(CodeNames), 0x0, "RPC Code", HFILL }
		},
		{ &hf_sane_rpc_status,
			{ "RPC Status", "sane.rpc.status", FT_UINT32, BASE_DEC, VALS(StatusNames), 0x0, "RPC Status", HFILL }
		},
		{ &hf_sane_net_version_code,
			{ "Version Code", "sane.net.version_code", FT_UINT32, BASE_HEX, NULL, 0x0, "Version Code", HFILL }
		},
		{ &hf_sane_net_version_code_major,
			{ "Major", "sane.net.version_code.major", FT_UINT8, BASE_DEC, NULL, 0x0, "Major", HFILL }
		},
		{ &hf_sane_net_version_code_minor,
			{ "Minor", "sane.net.version_code.minor", FT_UINT8, BASE_DEC, NULL, 0x0, "Minor", HFILL }
		},
		{ &hf_sane_net_version_code_build,
			{ "Build", "sane.net.version_code.build", FT_UINT16, BASE_DEC, NULL, 0x0, "Build", HFILL }
		},
		{ &hf_sane_net_user_name,
			{ "User Name", "sane.net.user_name", FT_STRING, BASE_NONE, NULL, 0x0, "User Name", HFILL }
		},
		{ &hf_sane_net_device,
			{ "Device", "sane.net.device", FT_NONE, BASE_NONE, NULL, 0x0, "Device", HFILL }
		},
		{ &hf_sane_net_device_name,
			{ "Device Name", "sane.net.device.name", FT_STRING, BASE_NONE, NULL, 0x0, "Device Name", HFILL }
		},
		{ &hf_sane_net_device_vendor,
			{ "Device Vendor", "sane.net.device.vendor", FT_STRING, BASE_NONE, NULL, 0x0, "Device Vendor", HFILL }
		},
		{ &hf_sane_net_device_model,
			{ "Device Model", "sane.net.device.model", FT_STRING, BASE_NONE, NULL, 0x0, "Device Model", HFILL }
		},
		{ &hf_sane_net_device_type,
			{ "Device Type", "sane.net.device.type", FT_STRING, BASE_NONE, NULL, 0x0, "Device Type", HFILL }
		},
		{ &hf_sane_net_handle,
			{ "Handle", "sane.net.handle", FT_UINT32, BASE_HEX, NULL, 0x0, "Handle", HFILL }
		},
		{ &hf_sane_net_resource,
			{ "Resource", "sane.net.resource", FT_STRING, BASE_NONE, NULL, 0x0, "Resource", HFILL }
		},
		{ &hf_sane_net_username,
			{ "Username", "sane.net.username", FT_STRING, BASE_NONE, NULL, 0x0, "Username", HFILL }
		},
		{ &hf_sane_net_password,
			{ "Password", "sane.net.password", FT_STRING, BASE_NONE, NULL, 0x0, "Password", HFILL }
		},
		{ &hf_sane_net_dummy,
			{ "Dummy", "sane.net.dummy", FT_UINT32, BASE_HEX, NULL, 0x0, "Dummy", HFILL }
		},
		{ &hf_sane_net_num_options,
			{ "Number of Options", "sane.net.num_options", FT_UINT32, BASE_DEC, NULL, 0x0, "Number of Options", HFILL }
		},
		{ &hf_sane_net_option,
			{ "Option", "sane.net.option", FT_NONE, BASE_NONE, NULL, 0x0, "Option", HFILL }
		},
		{ &hf_sane_net_option_name,
			{ "Name", "sane.net.option.name", FT_STRING, BASE_NONE, NULL, 0x0, "Option Name", HFILL }
		},
		{ &hf_sane_net_option_title,
			{ "Title", "sane.net.option.title", FT_STRING, BASE_NONE, NULL, 0x0, "Option Title", HFILL }
		},
		{ &hf_sane_net_option_desc,
			{ "Description", "sane.net.option.desc", FT_STRING, BASE_NONE, NULL, 0x0, "Option Description", HFILL }
		},
		{ &hf_sane_net_option_type,
			{ "Type", "sane.net.option.type", FT_UINT32, BASE_DEC, VALS(TypeNames), 0x0, "Option Type", HFILL }
		},
		{ &hf_sane_net_option_unit,
			{ "Unit", "sane.net.option.unit", FT_UINT32, BASE_DEC, VALS(UnitNames), 0x0, "Option Unit", HFILL }
		},
		{ &hf_sane_net_option_size,
			{ "Size", "sane.net.option.size", FT_UINT32, BASE_DEC, NULL, 0x0, "Option Size", HFILL }
		},
		{ &hf_sane_net_option_cap,
			{ "Capabilities", "sane.net.option.cap", FT_UINT32, BASE_HEX, NULL, 0x0, "Option Capabilities", HFILL }
		},
		{ &hf_sane_net_option_constraint_type,
			{ "Constraint Type", "sane.net.option.constraint_type", FT_UINT32, BASE_DEC, VALS(ConstraintNames), 0x0, "Option Capabilities", HFILL }
		},
		{ &hf_sane_net_option_constraint_range,
			{ "Range", "sane.net.option.constraint.range", FT_NONE, BASE_NONE, NULL, 0x0, "Range", HFILL }
		},
		{ &hf_sane_net_option_constraint_range_max,
			{ "Max", "sane.net.option.constraint.range.max", FT_UINT32, BASE_HEX, NULL, 0x0, "Max", HFILL }
		},
		{ &hf_sane_net_option_constraint_range_min,
			{ "Min", "sane.net.option.constraint.range.min", FT_UINT32, BASE_HEX, NULL, 0x0, "Min", HFILL }
		},
		{ &hf_sane_net_option_constraint_range_quant,
			{ "Quant", "sane.net.option.constraint.range.quant", FT_UINT32, BASE_HEX, NULL, 0x0, "Quant", HFILL }
		},
		{ &hf_sane_net_option_constraint_word_list,
			{ "Word List", "sane.net.option.constraint.word_list", FT_UINT32, BASE_DEC, NULL, 0x0, "Word List", HFILL }
		},
		{ &hf_sane_net_option_constraint_word_list_item,
			{ "Item", "sane.net.option.constraint.word_list.item", FT_UINT32, BASE_HEX, NULL, 0x0, "Item", HFILL }
		},
		{ &hf_sane_net_option_constraint_string_list,
			{ "String List", "sane.net.option.constraint.string_list", FT_UINT32, BASE_DEC, NULL, 0x0, "String List", HFILL }
		},
		{ &hf_sane_net_option_constraint_string_list_item,
			{ "Item", "sane.net.option.constraint.string_list.item", FT_STRING, BASE_NONE, NULL, 0x0, "Item", HFILL }
		},
		{ &hf_sane_net_option_num,
			{ "Option", "sane.net.option_num", FT_UINT32, BASE_DEC, NULL, 0x0, "Option", HFILL }
		},
		{ &hf_sane_net_action,
			{ "Action", "sane.net.action", FT_UINT32, BASE_DEC, VALS(ActionNames), 0x0, "Action", HFILL }
		},
		{ &hf_sane_net_value_type,
			{ "Value Type", "sane.net.value_type", FT_UINT32, BASE_DEC, VALS(TypeNames), 0x0, "Value Type", HFILL }
		},
		{ &hf_sane_net_value_size,
			{ "Value Size", "sane.net.value_size", FT_UINT32, BASE_DEC, NULL, 0x0, "Value Size", HFILL }
		},
		{ &hf_sane_net_value,
			{ "Value", "sane.net.value", FT_BYTES, BASE_NONE, NULL, 0x0, "Value", HFILL }
		},
		{ &hf_sane_net_info,
			{ "Info", "sane.net.info", FT_UINT32, BASE_HEX, NULL, 0x0, "Info", HFILL }
		},
		{ &hf_sane_net_port,
			{ "Port", "sane.net.port", FT_UINT32, BASE_DEC, NULL, 0x0, "Port", HFILL }
		},
		{ &hf_sane_net_byte_order,
			{ "Byte Order", "sane.net.byte_order", FT_UINT32, BASE_HEX, NULL, 0x0, "Byte Order", HFILL }
		},
		{ &hf_sane_net_parameters,
			{ "Parameters", "sane.net.parameters", FT_NONE, BASE_NONE, NULL, 0x0, "Parameters", HFILL }
		},
		{ &hf_sane_net_parameters_format,
			{ "Format", "sane.net.parameters.format", FT_UINT32, BASE_DEC, VALS(FrameNames), 0x0, "Format", HFILL }
		},
		{ &hf_sane_net_parameters_last_frame,
			{ "Last Frame", "sane.net.parameters.last_frame", FT_BOOLEAN, BASE_NONE, NULL, 0x0, "Last Frame", HFILL }
		},
		{ &hf_sane_net_parameters_bytes_per_line,
			{ "Bytes per Line", "sane.net.parameters.bytes_per_line", FT_UINT32, BASE_DEC, NULL, 0x0, "Bytes per Line", HFILL }
		},
		{ &hf_sane_net_parameters_pixels_per_line,
			{ "Pixels per Line", "sane.net.parameters.pixels_per_line", FT_UINT32, BASE_DEC, NULL, 0x0, "Pixels per Line", HFILL }
		},
		{ &hf_sane_net_parameters_lines,
			{ "Lines", "sane.net.parameters.lines", FT_UINT32, BASE_DEC, NULL, 0x0, "Lines", HFILL }
		},
		{ &hf_sane_net_parameters_depth,
			{ "Depth", "sane.net.parameters.depth", FT_UINT32, BASE_DEC, NULL, 0x0, "Depth", HFILL }
		}
	};
	static gint *ett[] = {
		&ett_sane
	};

	proto_sane = proto_register_protocol("SANE Protocol", PROTO_TAG_SANE, "sane");
	proto_register_field_array(proto_sane, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	register_dissector("sane", dissect_sane, proto_sane);
}

void proto_reg_handoff_sane(void)
{
	static int sane_initialized = FALSE;
	static dissector_handle_t sane_handle;

	if (!sane_initialized) {
		sane_handle = create_dissector_handle(dissect_sane, proto_sane);
		sane_initialized = TRUE;
	} else {
		dissector_delete_uint("tcp.port", TCP_PORT_SANE, sane_handle);
	}

	dissector_add_uint("tcp.port", TCP_PORT_SANE, sane_handle);
}
