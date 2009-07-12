/*
 * EAP peer configuration data
 * Copyright (c) 2003-2008, Jouni Malinen <j@w1.fi>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Alternatively, this software may be distributed under the terms of BSD
 * license.
 *
 * See README and COPYING for more details.
 */

#ifndef EAP_CONFIG_H
#define EAP_CONFIG_H

/**
 * struct eap_peer_config - EAP peer configuration/credentials
 */

typedef struct eap_peer_config {
	u8 *identity;
	size_t identity_len;

	u8 *password;
	size_t password_len;
} eap_peer_config_t;

#endif /* EAP_CONFIG_H */
