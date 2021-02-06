/*
 * Copyright (C) 2020 Semihalf
 * Author: Lukasz Bartosik <lukasz.bartosik@semihalf.com>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifdef CONFIG_NETMAP_DSA

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "libnetmap.h"

#define MAX_TOKENS 7
#define MAX_NAME_LEN 32
#define MAX_LINE_LEN 80
#define DSA_MAX_PROFILES 32
#define TAG_TYPE_STR "tag-type"
#define TAG_DSA_TYPE_STR "dsa"
#define BIND_MODE_ALL "all"
#define BIND_MODE_HOST "host"
#define BIND_MODE_HW "hw"
#define BIND_MODE_ANNOT_ALL "*"
#define BIND_MODE_ANNOT_HOST "^"
#define BIND_MODE_ANNOT_HW ""
#define TAG_EDSA_TYPE_STR "edsa"
#define DSA_CFG_FILE_NAME "dsa.cfg"
#define NETMAP_IF_PREFIX "netmap:"

typedef struct dsa_port_cfg {
	char profile_name[MAX_NAME_LEN];
	char name[NETMAP_REQ_IFNAMSIZ];
	char cpu_port_name[NETMAP_REQ_IFNAMSIZ];
	uint8_t bind_mode;
	uint8_t port_num;
	uint16_t vlan_id;
	uint8_t vlan_pri;
	uint8_t is_tagged;
} dsa_port_cfg_t;

typedef struct dsa_cfg {
	dsa_port_cfg_t dsa_ports[DSA_MAX_PROFILES];
	struct nmport_d *nm_cpu_port;
	uint8_t nb_ports;
	uint8_t tag_type;
} dsa_cfg_t;

static dsa_cfg_t dsa_cfg;

static char *
trim(char *str)
{
	int i, len;
	char *ptr;

	if (!str)
		return NULL;

	len = strlen(str);
	if (!len)
		return str;

	ptr = str + len - 1;
	for (i = 0; i < len; i++, ptr--)
		if (!isspace(*ptr))
			break;
	*(ptr + 1) = '\0';

	len = strlen(str);
	for (i = 0; i < len; i++, str++)
		if (!isspace(*str))
			break;
	return str;
}

static char *
to_lower(char *str)
{
	int i;

	for (i = 0; str[i]; i++)
		str[i] = tolower(str[i]);

	return str;
}

static char *
bind_mode_to_str(uint8_t bind_mode)
{
	switch (bind_mode) {
	case NR_REG_NIC_SW:
		return BIND_MODE_ALL;
	case NR_REG_ALL_NIC:
		return BIND_MODE_HW;
	case NR_REG_SW:
		return BIND_MODE_HOST;
	default:
		return "n/a";
	}
}

static char *
bind_mode_to_annot(uint8_t bind_mode)
{
	switch (bind_mode) {
	case NR_REG_NIC_SW:
		return BIND_MODE_ANNOT_ALL;
	case NR_REG_ALL_NIC:
		return BIND_MODE_ANNOT_HW;
	case NR_REG_SW:
		return BIND_MODE_ANNOT_HOST;
	default:
		return BIND_MODE_ANNOT_HW;
	}
}

static int
dsa_config_read(char *cfg_file_name)
{
	struct nmctx *ctx = nmctx_get();
	int val, nb_tokens, nb_ports;
	char line_buf[MAX_LINE_LEN];
	char *token, *line = NULL;
	char *tokens[MAX_TOKENS];
	dsa_port_cfg_t *ports;
	size_t size = 0;
	FILE *cfg_file;

	if (!cfg_file_name)
		return -EINVAL;

	cfg_file = fopen(cfg_file_name, "r");
	if (!cfg_file) {
		nmctx_ferror(ctx, "File \"%s\" does not exist\n",
		             cfg_file_name);
		return -EINVAL;
	}

	ports = dsa_cfg.dsa_ports;
	nb_ports = dsa_cfg.nb_ports;
	dsa_cfg.tag_type = TAG_DSA_TYPE;

next_line:
	while (getline(&line, &size, cfg_file) != -1) {
		strncpy(line_buf, line, MAX_LINE_LEN);
		line_buf[MAX_LINE_LEN - 1] = '\0';

		nb_tokens = 0;
		token = trim(strtok(line, " \t\n"));
		if (!token || !strlen(token))
			continue;

		do {
			if (*token == '#' || *token == '\0')
				goto next_line;
			if (nb_tokens >= MAX_TOKENS)
				goto invalid_line;

			tokens[nb_tokens++] = token;
			token = trim(strtok(NULL, " \t\n"));
		} while (token);

		if (nb_ports >= DSA_MAX_PROFILES) {
			nmctx_ferror(ctx,
			             "Error number of profiles exceeds "
			             "max supported %d",
			             DSA_MAX_PROFILES);
			goto error;
		}

		switch (nb_tokens) {
		case 7:
			/* get vlan identifier */
			val = strtol(tokens[5], NULL, 10);
			if (val < 0 || val > MAX_VLAN_ID) {
				nmctx_ferror(ctx,
				             "Vlan identifier '%d' is out of "
				             "range [0, %d)",
				             val, MAX_VLAN_ID);
				goto error;
			}
			ports[nb_ports].vlan_id = val;

			/* get vlan priority */
			val = strtol(tokens[6], NULL, 10);
			if (val < 0 || val > MAX_VLAN_PRIO) {
				nmctx_ferror(ctx,
				             "Vlan priority '%d' is out of "
				             "range [0, %d)",
				             val, MAX_VLAN_PRIO);
				goto error;
			}
			ports[nb_ports].vlan_pri = val;
			ports[nb_ports].is_tagged = 1;
			/* intentional fallthrough */

		case 5:
			/* get profile name */
			strncpy(ports[nb_ports].profile_name, tokens[0],
			        MAX_NAME_LEN);
			ports[nb_ports].profile_name[MAX_NAME_LEN - 1] = '\0';

			/* get slave port name */
			strncpy(ports[nb_ports].name, tokens[1],
			        NETMAP_REQ_IFNAMSIZ);
			ports[nb_ports].name[NETMAP_REQ_IFNAMSIZ - 1] = '\0';

			/* get slave port number */
			val = strtol(tokens[2], NULL, 10);
			if (val < 0 || val > DSA_MAX_PORTS) {
				nmctx_ferror(ctx,
				             "Port number '%d' is out of range "
				             "[0, %d)",
				             val, DSA_MAX_PORTS);
				goto error;
			}
			ports[nb_ports].port_num = val;

			/* get bind mode */
			tokens[3] = to_lower(tokens[3]);
			if (!strcmp(tokens[3], BIND_MODE_ALL))
				ports[nb_ports].bind_mode = NR_REG_NIC_SW;
			else if (!strcmp(tokens[3], BIND_MODE_HW))
				ports[nb_ports].bind_mode = NR_REG_ALL_NIC;
			else if (!strcmp(tokens[3], BIND_MODE_HOST))
				ports[nb_ports].bind_mode = NR_REG_SW;
			else {
				nmctx_ferror(ctx,
				             "Invalid bind mode '%s'. "
				             "Supported bind modes are: hw, "
				             "host, all.",
				             tokens[3]);
				goto error;
			}

			/* get cpu port name */
			strncpy(ports[nb_ports].cpu_port_name, tokens[4], NETMAP_REQ_IFNAMSIZ);
			ports[nb_ports].cpu_port_name[NETMAP_REQ_IFNAMSIZ - 1] = '\0';

			nb_ports++;
			break;

		case 2:
			if (strcmp(tokens[0], TAG_TYPE_STR))
				goto invalid_line;

			/* get tag type */
			if (!strcmp(tokens[1], TAG_DSA_TYPE_STR))
				dsa_cfg.tag_type = TAG_DSA_TYPE;
			else if (!strcmp(tokens[1], TAG_EDSA_TYPE_STR))
				dsa_cfg.tag_type = TAG_EDSA_TYPE;
			else {
				nmctx_ferror(ctx, "Unsupported tag-type '%s'\n",
				             tokens[1]);
				goto error;
			}
			break;

		default:
			goto invalid_line;
		}
	}

	dsa_cfg.nb_ports = nb_ports;
	free(line);
	return 0;

invalid_line:
	nmctx_ferror(ctx, "Invalid line \"%s\" in config file \"%s\"\n",
	             line_buf, cfg_file_name);
error:
	free(line);
	return -EINVAL;
}

static int
dsa_config_validate(void)
{
	struct nmctx *ctx = nmctx_get();
	dsa_port_cfg_t *ports;
	int i, j;

	if (!dsa_cfg.nb_ports) {
		nmctx_ferror(ctx, "Error no ports configured\n");
		return -EINVAL;
	}

	ports = dsa_cfg.dsa_ports;
	for (i = 0; i < dsa_cfg.nb_ports; i++) {
		for (j = 0; j < dsa_cfg.nb_ports; j++) {

			if (i == j)
				continue;

			if (!strcmp(ports[i].profile_name, ports[j].profile_name)) {
				nmctx_ferror(ctx, "Error duplicate profile name '%s'\n",
					     ports[i].profile_name);
				return -EINVAL;
			}

			if (strcmp(ports[i].cpu_port_name, ports[j].cpu_port_name)) {
				nmctx_ferror(ctx, "Error only single cpu port is supported\n");
				return -EINVAL;
			}
		}
	}

	return 0;
}

static int
dsa_cpu_port_open(void)
{
	char cpu_if_name[2 * NETMAP_REQ_IFNAMSIZ];

	snprintf(cpu_if_name, 2 * NETMAP_REQ_IFNAMSIZ, "%s%s", NETMAP_IF_PREFIX,
	         dsa_cfg.dsa_ports[0].cpu_port_name);

	dsa_cfg.nm_cpu_port = nmport_open(cpu_if_name);
	if (dsa_cfg.nm_cpu_port)
		return 0;
	return 1;
}

int
nmdsa_find_port_cfg(struct nmport_d *d, const char *iface, char *dsa_iface_buf,
                    uint16_t buf_len)
{
	char *fmt, name[2 * NETMAP_REQ_IFNAMSIZ];
	struct nmctx *ctx = nmctx_get();
	dsa_port_cfg_t *ports;
	int i;

	ports = dsa_cfg.dsa_ports;
	for (i = 0; i < dsa_cfg.nb_ports; i++) {
		snprintf(name, 2 * NETMAP_REQ_IFNAMSIZ, "%s%s", DSA_IF_PREFIX,
		         ports[i].profile_name);

		if (strcmp(iface, name))
			continue;

		fmt = ports[i].is_tagged ? "dsa:%s#%s%%%d+%d%s<%d>%d"
		                         : "dsa:%s#%s%%%d+%d%s";
		snprintf(dsa_iface_buf, buf_len, fmt, ports[i].name,
		         ports[i].cpu_port_name, ports[i].port_num,
		         dsa_cfg.tag_type,
		         bind_mode_to_annot(ports[i].bind_mode),
		         ports[i].vlan_id, ports[i].vlan_pri);
		return 1;
	}

	nmctx_ferror(ctx, "Error DSA port '%s' is not configured\n", iface);
	nmdsa_config_print();
	return 0;
}

void
nmdsa_config_print(void)
{
	dsa_port_cfg_t *ports;
	int i;

	ports = dsa_cfg.dsa_ports;
	printf("======== DSA ports configuration ========\n");
	printf("Tag type: %s\n\n", dsa_cfg.tag_type == TAG_DSA_TYPE
	                                   ? TAG_DSA_TYPE_STR
	                                   : TAG_EDSA_TYPE_STR);

	printf("Profile name \tPort name \tPort number \tBind mode "
	       "\tCpu port name \tVlan id \tVlan pri\n");
	for (i = 0; i < dsa_cfg.nb_ports; i++) {

		if (ports[i].is_tagged)
			printf("%-16s %-8s \t%-4d \t\t%-7s \t%-4s \t\t%-4d "
			       "\t\t%-4d\n",
			       ports[i].profile_name, ports[i].name,
			       ports[i].port_num,
			       bind_mode_to_str(ports[i].bind_mode),
			       ports[i].cpu_port_name, ports[i].vlan_id,
			       ports[i].vlan_pri);
		else
			printf("%-16s %-8s \t%-4d \t\t%-7s \t%-4s \t\t%-4s "
			       "\t\t%-4s\n",
			       ports[i].profile_name, ports[i].name,
			       ports[i].port_num,
			       bind_mode_to_str(ports[i].bind_mode),
			       ports[i].cpu_port_name, "--", "--");
	}
	printf("=========================================\n");
}

int
nmdsa_init(void)
{
	int ret;

	/* read DSA configuration from a file */
	ret = dsa_config_read(DSA_CFG_FILE_NAME);
	if (ret)
		return ret;

	/* validate DSA configuration */
	ret = dsa_config_validate();
	if (ret) {
		nmdsa_config_print();
		return ret;
	}

	/* open DSA cpu port */
	ret = dsa_cpu_port_open();
	if (ret)
		return ret;

	return 0;
}

void
nmdsa_fini(void)
{
	/* close DSA cpu port */
	nmport_close(dsa_cfg.nm_cpu_port);
}

#endif /* CONFIG_NETMAP_DSA */
