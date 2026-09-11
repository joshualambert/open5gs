/*
 * Copyright (C) 2019-2024 by Sukchan Lee <acetcom@gmail.com>
 *
 * This file is part of Open5GS.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include "context.h"
#include "gtp-path.h"
#include "pfcp-path.h"

static smf_context_t self;
static ogs_diam_config_t g_diam_conf;

int __smf_log_domain;
int __gsm_log_domain;

static OGS_POOL(smf_gtp_node_pool, smf_gtp_node_t);
static OGS_POOL(smf_ue_pool, smf_ue_t);
static OGS_POOL(smf_bearer_pool, smf_bearer_t);
static OGS_POOL(smf_pf_pool, smf_pf_t);

static OGS_POOL(smf_sess_pool, smf_sess_t);
static OGS_POOL(smf_n4_seid_pool, ogs_pool_id_t);

static int context_initialized = 0;

/* Locally administered, unicast: 02:00:00:00:01:01 */
static const uint8_t smf_ra_default_link_layer_address[6] = {
    0x02, 0x00, 0x00, 0x00, 0x01, 0x01
};

static int num_of_smf_sess = 0;

static void stats_add_smf_session(void);
static void stats_remove_smf_session(smf_sess_t *sess);

int smf_ctf_config_init(smf_ctf_config_t *ctf_config)
{
    ctf_config->enabled = SMF_CTF_ENABLED_AUTO;
    return OGS_OK;
}

/* Shall Gy session be used according to policy and state? 1: yes, 0: no, -1: reject */
int smf_use_gy_iface(void)
{
    switch (smf_self()->ctf_config.enabled) {
    case SMF_CTF_ENABLED_AUTO:
        return ogs_diam_is_relay_or_app_advertised(
                OGS_DIAM_GY_APPLICATION_ID) ? 1 : 0;
    case SMF_CTF_ENABLED_YES:
        return ogs_diam_is_relay_or_app_advertised(
                OGS_DIAM_GY_APPLICATION_ID) ? 1 : -1;
    case SMF_CTF_ENABLED_NO:
        return 0;
    default:
        return -1;
    }
}

void smf_context_init(void)
{
    ogs_assert(context_initialized == 0);

    /* Initial FreeDiameter Config */
    memset(&g_diam_conf, 0, sizeof(ogs_diam_config_t));

    /* Initialize SMF context */
    memset(&self, 0, sizeof(smf_context_t));
    smf_ctf_config_init(&self.ctf_config);
    self.diam_config = &g_diam_conf;

    ogs_log_install_domain(&__ogs_ngap_domain, "ngap", ogs_core()->log.level);
    ogs_log_install_domain(&__ogs_nas_domain, "nas", ogs_core()->log.level);
    ogs_log_install_domain(&__ogs_diam_domain, "diam", ogs_core()->log.level);
    ogs_log_install_domain(&__smf_log_domain, "smf", ogs_core()->log.level);
    ogs_log_install_domain(&__gsm_log_domain, "gsm", ogs_core()->log.level);

    ogs_pool_init(&smf_gtp_node_pool, ogs_app()->pool.nf);
    ogs_pool_init(&smf_ue_pool, ogs_global_conf()->max.ue);
    ogs_pool_init(&smf_bearer_pool, ogs_app()->pool.bearer);
    ogs_pool_init(&smf_pf_pool,
            ogs_app()->pool.bearer * OGS_MAX_NUM_OF_FLOW_IN_BEARER);

    ogs_pool_init(&smf_sess_pool, ogs_app()->pool.sess);
    ogs_pool_init(&smf_n4_seid_pool, ogs_app()->pool.sess);
    ogs_pool_random_id_generate(&smf_n4_seid_pool);

    self.supi_hash = ogs_hash_make();
    ogs_assert(self.supi_hash);
    self.imsi_hash = ogs_hash_make();
    ogs_assert(self.imsi_hash);
    self.smf_n4_seid_hash = ogs_hash_make();
    ogs_assert(self.smf_n4_seid_hash);
    self.ipv4_hash = ogs_hash_make();
    ogs_assert(self.ipv4_hash);
    self.ipv6_hash = ogs_hash_make();
    ogs_assert(self.ipv6_hash);
    self.ipv6_pd_hash = ogs_hash_make();
    ogs_assert(self.ipv6_pd_hash);
    self.n1n2message_hash = ogs_hash_make();
    ogs_assert(self.n1n2message_hash);

    /* DHCPv6 prefix delegation defaults; T1/T2 are derived from the
     * preferred lifetime by smf_dhcpv6_config_finalize() unless set */
    self.dhcpv6.preferred_lifetime = SMF_DHCPV6_DEFAULT_PREFERRED_LIFETIME;
    self.dhcpv6.valid_lifetime = SMF_DHCPV6_DEFAULT_VALID_LIFETIME;
    self.dhcpv6.rapid_commit = true;
    self.dhcpv6.sticky = true;
    self.dhcpv6.information_refresh_time =
        SMF_DHCPV6_DEFAULT_INFORMATION_REFRESH_TIME;

    /* Router Advertisement defaults (DESIGN.md section 5.9) */
    self.router_advertisement.other_config = SMF_RA_OTHER_CONFIG_AUTO;
    self.router_advertisement.on_link = false;
    self.router_advertisement.rdnss = true;
    self.router_advertisement.source_link_layer_address = true;
    memcpy(self.router_advertisement.link_layer_address,
            smf_ra_default_link_layer_address,
            sizeof(self.router_advertisement.link_layer_address));
    self.router_advertisement.router_lifetime =
        SMF_RA_DEFAULT_ROUTER_LIFETIME;

    context_initialized = 1;
}

void smf_context_final(void)
{
    int i;

    ogs_gtp_node_t *gnode = NULL, *next_gnode = NULL;
    ogs_assert(context_initialized == 1);

    smf_ue_remove_all();

    ogs_assert(self.supi_hash);
    ogs_hash_destroy(self.supi_hash);
    ogs_assert(self.imsi_hash);
    ogs_hash_destroy(self.imsi_hash);
    ogs_assert(self.smf_n4_seid_hash);
    ogs_hash_destroy(self.smf_n4_seid_hash);
    ogs_assert(self.ipv4_hash);
    ogs_hash_destroy(self.ipv4_hash);
    ogs_assert(self.ipv6_hash);
    ogs_hash_destroy(self.ipv6_hash);
    ogs_assert(self.ipv6_pd_hash);
    ogs_hash_destroy(self.ipv6_pd_hash);
    ogs_assert(self.n1n2message_hash);
    ogs_hash_destroy(self.n1n2message_hash);

    ogs_pool_final(&smf_ue_pool);
    ogs_pool_final(&smf_bearer_pool);
    ogs_pool_final(&smf_pf_pool);

    ogs_pool_final(&smf_sess_pool);
    ogs_pool_final(&smf_n4_seid_pool);

    ogs_list_for_each_entry_safe(&self.sgw_s5c_list, next_gnode, gnode, node) {
        smf_gtp_node_t *smf_gnode = gnode->data_ptr;
        ogs_assert(smf_gnode);
        smf_gtp_node_free(smf_gnode);
        ogs_gtp_node_remove(&self.sgw_s5c_list, gnode);
    }

    for (i = 0; i < self.num_of_p_cscf; i++)
        ogs_free(self.p_cscf[i]);
    for (i = 0; i < self.num_of_p_cscf6; i++)
        ogs_free(self.p_cscf6[i]);

    ogs_pool_final(&smf_gtp_node_pool);

    context_initialized = 0;
}

smf_context_t *smf_self(void)
{
    return &self;
}

static int smf_context_prepare(void)
{
    self.diam_config->cnf_port = DIAMETER_PORT;
    self.diam_config->cnf_port_tls = DIAMETER_SECURE_PORT;

    return OGS_OK;
}

static int smf_context_validation(void)
{
    ogs_sbi_nf_instance_t *nf_instance = NULL;
    ogs_sbi_nf_info_t *nf_info = NULL;

    nf_instance = ogs_sbi_self()->nf_instance;
    ogs_assert(nf_instance);

    if (self.dns[0] == NULL && self.dns6[0] == NULL) {
        ogs_error("No smf.dns in '%s'", ogs_app()->file);
        return OGS_ERROR;
    }
    if (ogs_list_first(&ogs_gtp_self()->gtpu_list) == NULL) {
        ogs_error("No smf.gtpu.address in '%s'", ogs_app()->file);
        return OGS_ERROR;
    }
    if (ogs_list_first(&ogs_pfcp_self()->subnet_list) == NULL) {
        ogs_error("No smf.session.subnet: in '%s'", ogs_app()->file);
        return OGS_ERROR;
    }

    ogs_list_for_each(&nf_instance->nf_info_list, nf_info) {
        int i;
        ogs_sbi_smf_info_t *smf_info = &nf_info->smf;
        ogs_assert(smf_info);

        if (smf_info->num_of_slice == 0) {
            ogs_error("CHECK CONFIGURATION: No S-NSSAI in smfInfo");
            return OGS_ERROR;
        }

        for (i = 0; i < smf_info->num_of_slice; i++) {
            if (smf_info->slice[i].num_of_dnn == 0) {
                ogs_error("CHECK CONFIGURATION: No DNN in SST[%d] SD[0x%x]",
                            smf_info->slice[i].s_nssai.sst,
                            smf_info->slice[i].s_nssai.sd.v);
                return OGS_ERROR;
            }
        }
        for (i = 0; i < smf_info->num_of_nr_tai_range; i++) {
            if (smf_info->nr_tai_range[i].num_of_tac_range == 0) {
                ogs_error("CHECK CONFIGURATION: No TacRange in "
                        "MCC[%d] MNC[0x%x]",
                    ogs_plmn_id_mcc(&smf_info->nr_tai[i].plmn_id),
                    ogs_plmn_id_mnc(&smf_info->nr_tai[i].plmn_id));
                return OGS_ERROR;
            }
        }
    }

    if (self.security_indication.integrity_protection_indication ||
        self.security_indication.confidentiality_protection_indication) {
        if (!self.security_indication.integrity_protection_indication ||
            !self.security_indication.confidentiality_protection_indication) {
            ogs_error("Invalid security_indication [%s,%s]",
                self.security_indication.integrity_protection_indication ?
                self.security_indication.integrity_protection_indication :
                "No integrity_protection_indication",
                self.security_indication.confidentiality_protection_indication ?
                self.security_indication.confidentiality_protection_indication :
                "No confidentiality_protection_indication");
            return OGS_ERROR;
        }
        if (smf_integrity_protection_indication_value2enum(
            self.security_indication.integrity_protection_indication) < 0) {
            ogs_error("Invalid integrity_protection_indication [%s]",
                self.security_indication.integrity_protection_indication);
            return OGS_ERROR;
        }
        if (smf_confidentiality_protection_indication_value2enum(
            self.security_indication.
            confidentiality_protection_indication) < 0) {
            ogs_error("Invalid confidentiality_protection_indication [%s]",
                self.security_indication.confidentiality_protection_indication);
            return OGS_ERROR;
        }
    }

    if (self.security_indication.maximum_integrity_protected_data_rate_uplink) {
        NGAP_IntegrityProtectionIndication_t integrityProtectionIndication;
        if (smf_maximum_integrity_protected_data_rate_uplink_value2enum(
                self.security_indication.
                    maximum_integrity_protected_data_rate_uplink) < 0) {
            ogs_error("Invalid "
                "maximum_integrity_protected_data_rate_uplink [%s]",
                self.security_indication.
                    maximum_integrity_protected_data_rate_uplink);
            return OGS_ERROR;
        }
        integrityProtectionIndication =
            smf_integrity_protection_indication_value2enum(
                self.security_indication.integrity_protection_indication);
        if (integrityProtectionIndication ==
                NGAP_IntegrityProtectionIndication_required ||
            integrityProtectionIndication ==
                NGAP_IntegrityProtectionIndication_preferred) {
        } else {
            ogs_error("Invalid security_indication [%s:UL-%s]",
                self.security_indication.integrity_protection_indication ?
                self.security_indication.integrity_protection_indication :
                "No integrity_protection_indication",
                self.security_indication.
                    maximum_integrity_protected_data_rate_uplink ?
                self.security_indication.
                    maximum_integrity_protected_data_rate_uplink :
                "No integrity_protection_indication");
            return OGS_ERROR;
        }
    }

    if (self.security_indication.maximum_integrity_protected_data_rate_downlink) {
        if (smf_maximum_integrity_protected_data_rate_downlink_value2enum(
                self.security_indication.
                    maximum_integrity_protected_data_rate_downlink) < 0) {
            ogs_error("Invalid "
                "maximum_integrity_protected_data_rate_downlink [%s]",
                self.security_indication.
                    maximum_integrity_protected_data_rate_downlink);
            return OGS_ERROR;
        }
        if (!self.security_indication.
                maximum_integrity_protected_data_rate_uplink) {
            ogs_error("No maximum_integrity_protected_data_rate_uplink");
            return OGS_ERROR;
        }
    }

    return OGS_OK;
}

/*
 * DHCPv6 server DUID from smf.yaml: hexadecimal octets, ':' separators
 * allowed, 3..130 octets (RFC 8415 section 11).
 */
static int smf_dhcpv6_parse_duid(const char *v, ogs_dhcpv6_duid_t *duid)
{
    char hex[OGS_DHCPV6_MAX_DUID_LEN * 2 + 1];
    int n = 0, len;

    ogs_assert(v);
    ogs_assert(duid);

    for (; *v; v++) {
        if (*v == ':')
            continue;
        if (n >= (int)sizeof(hex) - 1) {
            ogs_error("DHCPv6 DUID longer than %d octets",
                    OGS_DHCPV6_MAX_DUID_LEN);
            return OGS_ERROR;
        }
        hex[n++] = *v;
    }
    hex[n] = 0;

    len = n / 2;
    if (n % 2 || len < OGS_DHCPV6_MIN_DUID_LEN ||
        len > OGS_DHCPV6_MAX_DUID_LEN) {
        ogs_error("DHCPv6 DUID must be %d..%d hexadecimal octets [%s]",
                OGS_DHCPV6_MIN_DUID_LEN, OGS_DHCPV6_MAX_DUID_LEN, hex);
        return OGS_ERROR;
    }
    if (ogs_ascii_to_hex_checked(hex, n, duid->data, len) != OGS_OK) {
        ogs_error("DHCPv6 DUID is not hexadecimal [%s]", hex);
        return OGS_ERROR;
    }
    duid->len = len;

    return OGS_OK;
}

/*
 * Default server DUID: DUID-UUID (RFC 6355, type 4) whose UUID is the first
 * 16 octets of SHA-256("open5gs-smf-dhcpv6-duid:" + <first configured PFCP
 * server address>), with the RFC 4122 version (5) and variant bits set.
 * The PFCP address is part of the static configuration, so the DUID is
 * stable across restarts without storing anything.
 */
static void smf_dhcpv6_default_duid(ogs_dhcpv6_duid_t *duid)
{
    ogs_socknode_t *node = NULL;
    char addr[OGS_ADDRSTRLEN];
    char seed[OGS_ADDRSTRLEN + 32];
    uint8_t digest[OGS_SHA256_DIGEST_SIZE];

    ogs_assert(duid);

    node = ogs_list_first(&ogs_pfcp_self()->pfcp_list);
    if (!node)
        node = ogs_list_first(&ogs_pfcp_self()->pfcp_list6);

    ogs_snprintf(seed, sizeof(seed), "open5gs-smf-dhcpv6-duid:%s",
            (node && node->addr) ? OGS_ADDR(node->addr, addr) : "");
    ogs_sha256((const uint8_t *)seed, strlen(seed), digest);

    duid->len = 2 + 16;
    duid->data[0] = 0x00;
    duid->data[1] = 0x04;                 /* DUID-UUID */
    memcpy(duid->data + 2, digest, 16);
    duid->data[2 + 6] = (duid->data[2 + 6] & 0x0f) | 0x50;  /* version 5 */
    duid->data[2 + 8] = (duid->data[2 + 8] & 0x3f) | 0x80;  /* RFC 4122 */
}

/* Apply DHCPv6 defaults that depend on other keys and reject nonsense */
static int smf_dhcpv6_config_finalize(bool t1_set, bool t2_set)
{
    char hex[OGS_DHCPV6_MAX_DUID_LEN * 2 + 1];

    if (!self.dhcpv6.duid.len)
        smf_dhcpv6_default_duid(&self.dhcpv6.duid);

    if (self.dhcpv6.preferred_lifetime == 0) {
        ogs_error("dhcpv6.preferred_lifetime must be greater than 0");
        return OGS_ERROR;
    }
    if (self.dhcpv6.valid_lifetime < self.dhcpv6.preferred_lifetime) {
        ogs_error("dhcpv6.valid_lifetime[%u] must not be less than "
                "dhcpv6.preferred_lifetime[%u]",
                self.dhcpv6.valid_lifetime, self.dhcpv6.preferred_lifetime);
        return OGS_ERROR;
    }

    /* RFC 8415 section 21.21: T1 = 0.5 and T2 = 0.8 of the shortest
     * preferred lifetime are recommended */
    if (!t1_set)
        self.dhcpv6.t1 = self.dhcpv6.preferred_lifetime / 2;
    if (!t2_set)
        self.dhcpv6.t2 = self.dhcpv6.preferred_lifetime / 5 * 4;

    /* 0 means "the client decides" and is exempt from the ordering rule */
    if (self.dhcpv6.t1 && self.dhcpv6.t2 && self.dhcpv6.t1 > self.dhcpv6.t2) {
        ogs_error("dhcpv6.t1[%u] must not be greater than dhcpv6.t2[%u]",
                self.dhcpv6.t1, self.dhcpv6.t2);
        return OGS_ERROR;
    }
    if (self.dhcpv6.t1 > self.dhcpv6.valid_lifetime ||
        self.dhcpv6.t2 > self.dhcpv6.valid_lifetime) {
        ogs_error("dhcpv6.t1[%u]/t2[%u] must not exceed "
                "dhcpv6.valid_lifetime[%u]",
                self.dhcpv6.t1, self.dhcpv6.t2, self.dhcpv6.valid_lifetime);
        return OGS_ERROR;
    }

    ogs_info("DHCPv6 server DUID[%s] lifetimes[%u/%u] T1/T2[%u/%u] "
            "rapid_commit[%d] preference[%u] binding_policy[%s] "
            "information_refresh_time[%u]",
            (char *)ogs_hex_to_ascii(self.dhcpv6.duid.data,
                self.dhcpv6.duid.len, hex, sizeof(hex)),
            self.dhcpv6.preferred_lifetime, self.dhcpv6.valid_lifetime,
            self.dhcpv6.t1, self.dhcpv6.t2,
            self.dhcpv6.rapid_commit, self.dhcpv6.preference,
            self.dhcpv6.sticky ? "sticky" : "replace",
            self.dhcpv6.information_refresh_time);

    ogs_info("Router Advertisement other_config[%s] on_link[%d] rdnss[%d] "
            "source_link_layer_address[%d] "
            "link_layer_address[%02x:%02x:%02x:%02x:%02x:%02x] "
            "router_lifetime[%u]",
            self.router_advertisement.other_config ==
                SMF_RA_OTHER_CONFIG_AUTO ? "auto" :
            self.router_advertisement.other_config ==
                SMF_RA_OTHER_CONFIG_TRUE ? "true" : "false",
            self.router_advertisement.on_link,
            self.router_advertisement.rdnss,
            self.router_advertisement.source_link_layer_address,
            self.router_advertisement.link_layer_address[0],
            self.router_advertisement.link_layer_address[1],
            self.router_advertisement.link_layer_address[2],
            self.router_advertisement.link_layer_address[3],
            self.router_advertisement.link_layer_address[4],
            self.router_advertisement.link_layer_address[5],
            self.router_advertisement.router_lifetime);

    return OGS_OK;
}

/*
 * router_advertisement.link_layer_address: six hexadecimal octets separated
 * by ':' or '-'. The address is a made-up MAC for the virtual gateway; the
 * locally administered bit (RFC 7042) should be set and the group bit must
 * not be (a multicast address can never be a link-layer source).
 */
static int smf_ra_parse_link_layer_address(const char *v, uint8_t *mac)
{
    unsigned n = 0;
    const char *p = NULL;

    ogs_assert(v);
    ogs_assert(mac);

    for (p = v; *p; ) {
        char *end = NULL;
        unsigned long octet;

        if (n >= 6 || !isxdigit((unsigned char)p[0]) ||
            !isxdigit((unsigned char)p[1]))
            goto invalid;
        octet = strtoul(p, &end, 16);
        if (end != p + 2 || octet > 0xff)
            goto invalid;
        mac[n++] = (uint8_t)octet;
        p = end;
        if (*p == ':' || *p == '-') {
            if (!p[1])
                goto invalid;
            p++;
        } else if (*p) {
            goto invalid;
        }
    }
    if (n != 6)
        goto invalid;

    if (mac[0] & 0x01) {
        ogs_error("router_advertisement.link_layer_address [%s] is a "
                "group (multicast) address", v);
        return OGS_ERROR;
    }
    if (!(mac[0] & 0x02))
        ogs_warn("router_advertisement.link_layer_address [%s] does not "
                "have the locally administered bit set", v);

    return OGS_OK;

invalid:
    ogs_error("router_advertisement.link_layer_address [%s] must be six "
            "hexadecimal octets separated by ':' or '-'", v);
    return OGS_ERROR;
}

/* router_advertisement.other_config: auto | true | false */
static int smf_ra_parse_other_config(const char *v, int *out)
{
    ogs_assert(out);

    if (!v || !strcasecmp(v, "auto"))
        *out = SMF_RA_OTHER_CONFIG_AUTO;
    else if (!strcasecmp(v, "true") || !strcasecmp(v, "yes") ||
             !strcmp(v, "1"))
        *out = SMF_RA_OTHER_CONFIG_TRUE;
    else if (!strcasecmp(v, "false") || !strcasecmp(v, "no") ||
             !strcmp(v, "0"))
        *out = SMF_RA_OTHER_CONFIG_FALSE;
    else {
        ogs_error("router_advertisement.other_config [%s] must be "
                "auto, true or false", v);
        return OGS_ERROR;
    }

    return OGS_OK;
}

/* Parse an unsigned 32-bit scalar; false when the value is not a number */
static bool smf_yaml_iter_uint32(ogs_yaml_iter_t *iter, uint32_t *out)
{
    const char *v = ogs_yaml_iter_value(iter);
    char *end = NULL;
    unsigned long n;

    if (!v || !*v)
        return false;
    n = strtoul(v, &end, 10);
    if (*end || n > UINT32_MAX)
        return false;
    *out = (uint32_t)n;

    return true;
}

int smf_context_parse_config(void)
{
    bool dhcpv6_t1_set = false, dhcpv6_t2_set = false;
    int rv;
    yaml_document_t *document = NULL;
    ogs_yaml_iter_t root_iter;
    int idx = 0;

    document = ogs_app()->document;
    ogs_assert(document);

    rv = smf_context_prepare();
    if (rv != OGS_OK) return rv;

    ogs_yaml_iter_init(&root_iter, document);
    while (ogs_yaml_iter_next(&root_iter)) {
        const char *root_key = ogs_yaml_iter_key(&root_iter);
        ogs_assert(root_key);
        if ((!strcmp(root_key, "smf")) &&
            (idx++ == ogs_app()->config_section_id)) {
            ogs_yaml_iter_t smf_iter;
            ogs_yaml_iter_recurse(&root_iter, &smf_iter);
            while (ogs_yaml_iter_next(&smf_iter)) {
                const char *smf_key = ogs_yaml_iter_key(&smf_iter);
                ogs_assert(smf_key);
                if (!strcmp(smf_key, "freeDiameter")) {
                    yaml_node_t *node =
                        yaml_document_get_node(document, smf_iter.pair->value);
                    ogs_assert(node);
                    if (node->type == YAML_SCALAR_NODE) {
                        self.diam_conf_path = ogs_yaml_iter_value(&smf_iter);
                    } else if (node->type == YAML_MAPPING_NODE) {
                        ogs_yaml_iter_t fd_iter;
                        ogs_yaml_iter_recurse(&smf_iter, &fd_iter);

                        while (ogs_yaml_iter_next(&fd_iter)) {
                            const char *fd_key = ogs_yaml_iter_key(&fd_iter);
                            ogs_assert(fd_key);
                            if (!strcmp(fd_key, "identity")) {
                                self.diam_config->cnf_diamid =
                                    ogs_yaml_iter_value(&fd_iter);
                            } else if (!strcmp(fd_key, "realm")) {
                                self.diam_config->cnf_diamrlm =
                                    ogs_yaml_iter_value(&fd_iter);
                            } else if (!strcmp(fd_key, "port")) {
                                const char *v = ogs_yaml_iter_value(&fd_iter);
                                if (v) self.diam_config->cnf_port = atoi(v);
                            } else if (!strcmp(fd_key, "sec_port")) {
                                const char *v = ogs_yaml_iter_value(&fd_iter);
                                if (v) self.diam_config->cnf_port_tls = atoi(v);
                            } else if (!strcmp(fd_key, "listen_on")) {
                                self.diam_config->cnf_addr =
                                    ogs_yaml_iter_value(&fd_iter);
                            } else if (!strcmp(fd_key, "no_fwd")) {
                                self.diam_config->cnf_flags.no_fwd =
                                    ogs_yaml_iter_bool(&fd_iter);
                            } else if (!strcmp(fd_key, "load_extension")) {
                                ogs_yaml_iter_t ext_array, ext_iter;
                                ogs_yaml_iter_recurse(&fd_iter, &ext_array);
                                do {
                                    const char *module = NULL;
                                    const char *conf = NULL;

                                    if (ogs_yaml_iter_type(&ext_array) ==
                                        YAML_MAPPING_NODE) {
                                        memcpy(&ext_iter, &ext_array,
                                                sizeof(ogs_yaml_iter_t));
                                    } else if (ogs_yaml_iter_type(&ext_array) ==
                                        YAML_SEQUENCE_NODE) {
                                        if (!ogs_yaml_iter_next(&ext_array))
                                            break;
                                        ogs_yaml_iter_recurse(
                                                &ext_array, &ext_iter);
                                    } else if (ogs_yaml_iter_type(&ext_array) ==
                                        YAML_SCALAR_NODE) {
                                        break;
                                    } else
                                        ogs_assert_if_reached();

                                    while (ogs_yaml_iter_next(&ext_iter)) {
                                        const char *ext_key =
                                            ogs_yaml_iter_key(&ext_iter);
                                        ogs_assert(ext_key);
                                        if (!strcmp(ext_key, "module")) {
                                            module = ogs_yaml_iter_value(
                                                    &ext_iter);
                                        } else if (!strcmp(ext_key, "conf")) {
                                            conf = ogs_yaml_iter_value(
                                                    &ext_iter);
                                        } else
                                            ogs_warn("unknown key `%s`",
                                                    ext_key);
                                    }

                                    if (module) {
                                        self.diam_config->
                                            ext[self.diam_config->num_of_ext].
                                                module = module;
                                        self.diam_config->
                                            ext[self.diam_config->num_of_ext].
                                                conf = conf;
                                        self.diam_config->num_of_ext++;
                                    }
                                } while (ogs_yaml_iter_type(&ext_array) ==
                                        YAML_SEQUENCE_NODE);
                            } else if (!strcmp(fd_key, "connect")) {
                                ogs_yaml_iter_t conn_array, conn_iter;
                                ogs_yaml_iter_recurse(&fd_iter, &conn_array);
                                do {
                                    const char *identity = NULL;
                                    const char *addr = NULL;
                                    uint16_t port = 0;
                                    int tc_timer = 0;

                                    if (ogs_yaml_iter_type(&conn_array) ==
                                        YAML_MAPPING_NODE) {
                                        memcpy(&conn_iter, &conn_array,
                                                sizeof(ogs_yaml_iter_t));
                                    } else if (ogs_yaml_iter_type(
                                        &conn_array) == YAML_SEQUENCE_NODE) {
                                        if (!ogs_yaml_iter_next(&conn_array))
                                            break;
                                        ogs_yaml_iter_recurse(&conn_array,
                                                &conn_iter);
                                    } else if (ogs_yaml_iter_type(
                                            &conn_array) == YAML_SCALAR_NODE) {
                                        break;
                                    } else
                                        ogs_assert_if_reached();

                                    while (ogs_yaml_iter_next(&conn_iter)) {
                                        const char *conn_key =
                                            ogs_yaml_iter_key(&conn_iter);
                                        ogs_assert(conn_key);
                                        if (!strcmp(conn_key, "identity")) {
                                            identity =
                                                ogs_yaml_iter_value(&conn_iter);
                                        } else if (!strcmp(conn_key,
                                                    "address")) {
                                            addr =
                                                ogs_yaml_iter_value(&conn_iter);
                                        } else if (!strcmp(conn_key, "port")) {
                                            const char *v =
                                                ogs_yaml_iter_value(&conn_iter);
                                            if (v) port = atoi(v);
                                        } else if (!strcmp(conn_key, "tc_timer")) {
                                            const char *v =
                                                ogs_yaml_iter_value(&conn_iter);
                                            if (v) tc_timer = atoi(v);
                                        } else
                                            ogs_warn("unknown key `%s`",
                                                    conn_key);
                                    }

                                    if (identity && addr) {
                                        self.diam_config->
                                            conn[self.diam_config->num_of_conn].
                                                identity = identity;
                                        self.diam_config->
                                            conn[self.diam_config->num_of_conn].
                                                addr = addr;
                                        self.diam_config->
                                            conn[self.diam_config->num_of_conn].
                                                port = port;
                                        self.diam_config->
                                            conn[self.diam_config->num_of_conn].
                                                tc_timer = tc_timer;
                                        self.diam_config->num_of_conn++;
                                    }
                                } while (ogs_yaml_iter_type(&conn_array) ==
                                        YAML_SEQUENCE_NODE);
                            } else if (!strcmp(fd_key, "tc_timer")) {
                                const char *v = ogs_yaml_iter_value(&fd_iter);
                                if (v) self.diam_config->cnf_timer_tc = atoi(v);
                            } else
                                ogs_warn("unknown key `%s`", fd_key);
                        }
                    }
                } else if (!strcmp(smf_key, "ctf")) {
                    ogs_yaml_iter_t ctf_iter;
                    yaml_node_t *node =
                        yaml_document_get_node(document, smf_iter.pair->value);
                    ogs_assert(node);
                    ogs_assert(node->type == YAML_MAPPING_NODE);
                    ogs_yaml_iter_recurse(&smf_iter, &ctf_iter);
                    while (ogs_yaml_iter_next(&ctf_iter)) {
                        const char *ctf_key = ogs_yaml_iter_key(&ctf_iter);
                        ogs_assert(ctf_key);
                        if (!strcmp(ctf_key, "enabled")) {
                            yaml_node_t *ctf_node = yaml_document_get_node(
                                    document, ctf_iter.pair->value);
                            ogs_assert(ctf_node->type == YAML_SCALAR_NODE);
                            const char* enabled =
                                ogs_yaml_iter_value(&ctf_iter);
                            if (!strcmp(enabled, "auto"))
                                self.ctf_config.enabled = SMF_CTF_ENABLED_AUTO;
                            else if (!strcmp(enabled, "yes"))
                                self.ctf_config.enabled = SMF_CTF_ENABLED_YES;
                            else if (!strcmp(enabled, "no"))
                                self.ctf_config.enabled = SMF_CTF_ENABLED_NO;
                            else
                                ogs_warn("unknown 'enabled' value `%s`",
                                        enabled);
                        } else
                            ogs_warn("unknown key `%s`", ctf_key);
                    }
                } else if (!strcmp(smf_key, "gtpc")) {
                    /* handle config in gtp library */
                } else if (!strcmp(smf_key, "gtpu")) {
                    /* handle config in gtp library */
                } else if (!strcmp(smf_key, "dns")) {
                    ogs_yaml_iter_t dns_iter;
                    ogs_yaml_iter_recurse(&smf_iter, &dns_iter);
                    ogs_assert(ogs_yaml_iter_type(&dns_iter) !=
                        YAML_MAPPING_NODE);

                    do {
                        const char *v = NULL;

                        if (ogs_yaml_iter_type(&dns_iter) ==
                                YAML_SEQUENCE_NODE) {
                            if (!ogs_yaml_iter_next(&dns_iter))
                                break;
                        }

                        v = ogs_yaml_iter_value(&dns_iter);
                        if (v && strlen(v)) {
                            ogs_ipsubnet_t ipsub;
                            rv = ogs_ipsubnet(&ipsub, v, NULL);
                            ogs_assert(rv == OGS_OK);

                            if (ipsub.family == AF_INET) {
                                if (self.dns[0] && self.dns[1])
                                    ogs_warn("Ignore DNS : %s", v);
                                else if (self.dns[0]) self.dns[1] = v;
                                else self.dns[0] = v;
                            }
                            else if (ipsub.family == AF_INET6) {
                                if (self.dns6[0] && self.dns6[1])
                                    ogs_warn("Ignore DNS : %s", v);
                                else if (self.dns6[0]) self.dns6[1] = v;
                                else self.dns6[0] = v;
                            } else
                                ogs_warn("Ignore DNS : %s", v);
                        }

                    } while (ogs_yaml_iter_type(&dns_iter) ==
                                YAML_SEQUENCE_NODE);
                } else if (!strcmp(smf_key, "mtu")) {
                    ogs_assert(ogs_yaml_iter_type(&smf_iter) !=
                            YAML_SCALAR_NODE);
                    self.mtu = atoi(ogs_yaml_iter_value(&smf_iter));
                    ogs_assert(self.mtu);
                } else if (!strcmp(smf_key, "dhcpv6")) {
                    ogs_yaml_iter_t dhcpv6_iter;
                    ogs_yaml_iter_recurse(&smf_iter, &dhcpv6_iter);
                    while (ogs_yaml_iter_next(&dhcpv6_iter)) {
                        const char *dhcpv6_key =
                            ogs_yaml_iter_key(&dhcpv6_iter);
                        const char *v = ogs_yaml_iter_value(&dhcpv6_iter);
                        uint32_t n = 0;
                        ogs_assert(dhcpv6_key);
                        if (!strcmp(dhcpv6_key, "duid")) {
                            if (!v || smf_dhcpv6_parse_duid(
                                        v, &self.dhcpv6.duid) != OGS_OK)
                                return OGS_ERROR;
                        } else if (!strcmp(dhcpv6_key,
                                    "preferred_lifetime")) {
                            if (!smf_yaml_iter_uint32(&dhcpv6_iter, &n)) {
                                ogs_error("Invalid dhcpv6.%s", dhcpv6_key);
                                return OGS_ERROR;
                            }
                            self.dhcpv6.preferred_lifetime = n;
                        } else if (!strcmp(dhcpv6_key, "valid_lifetime")) {
                            if (!smf_yaml_iter_uint32(&dhcpv6_iter, &n)) {
                                ogs_error("Invalid dhcpv6.%s", dhcpv6_key);
                                return OGS_ERROR;
                            }
                            self.dhcpv6.valid_lifetime = n;
                        } else if (!strcmp(dhcpv6_key, "t1")) {
                            if (!smf_yaml_iter_uint32(&dhcpv6_iter, &n)) {
                                ogs_error("Invalid dhcpv6.%s", dhcpv6_key);
                                return OGS_ERROR;
                            }
                            self.dhcpv6.t1 = n;
                            dhcpv6_t1_set = true;
                        } else if (!strcmp(dhcpv6_key, "t2")) {
                            if (!smf_yaml_iter_uint32(&dhcpv6_iter, &n)) {
                                ogs_error("Invalid dhcpv6.%s", dhcpv6_key);
                                return OGS_ERROR;
                            }
                            self.dhcpv6.t2 = n;
                            dhcpv6_t2_set = true;
                        } else if (!strcmp(dhcpv6_key, "rapid_commit")) {
                            self.dhcpv6.rapid_commit =
                                ogs_yaml_iter_bool(&dhcpv6_iter);
                        } else if (!strcmp(dhcpv6_key, "preference")) {
                            if (!smf_yaml_iter_uint32(&dhcpv6_iter, &n) ||
                                n > UINT8_MAX) {
                                ogs_error("Invalid dhcpv6.%s (0..255)",
                                        dhcpv6_key);
                                return OGS_ERROR;
                            }
                            self.dhcpv6.preference = n;
                        } else if (!strcmp(dhcpv6_key, "binding_policy")) {
                            if (v && !strcasecmp(v, "sticky"))
                                self.dhcpv6.sticky = true;
                            else if (v && !strcasecmp(v, "replace"))
                                self.dhcpv6.sticky = false;
                            else {
                                ogs_error("Invalid dhcpv6.%s [%s] "
                                        "(sticky|replace)",
                                        dhcpv6_key, v ? v : "");
                                return OGS_ERROR;
                            }
                        } else if (!strcmp(dhcpv6_key,
                                    "information_refresh_time")) {
                            /* RFC 8415 section 21.23: IRT_MINIMUM 600 s */
                            if (!smf_yaml_iter_uint32(&dhcpv6_iter, &n) ||
                                n < SMF_DHCPV6_MIN_INFORMATION_REFRESH_TIME) {
                                ogs_error("Invalid dhcpv6.%s (>= %u)",
                                    dhcpv6_key,
                                    SMF_DHCPV6_MIN_INFORMATION_REFRESH_TIME);
                                return OGS_ERROR;
                            }
                            self.dhcpv6.information_refresh_time = n;
                        } else
                            ogs_warn("unknown key `%s`", dhcpv6_key);
                    }
                } else if (!strcmp(smf_key, "router_advertisement")) {
                    ogs_yaml_iter_t ra_iter;
                    ogs_yaml_iter_recurse(&smf_iter, &ra_iter);
                    while (ogs_yaml_iter_next(&ra_iter)) {
                        const char *ra_key = ogs_yaml_iter_key(&ra_iter);
                        const char *v = ogs_yaml_iter_value(&ra_iter);
                        uint32_t n = 0;
                        ogs_assert(ra_key);
                        if (!strcmp(ra_key, "other_config")) {
                            if (smf_ra_parse_other_config(v,
                                    &self.router_advertisement.other_config)
                                    != OGS_OK)
                                return OGS_ERROR;
                        } else if (!strcmp(ra_key, "on_link")) {
                            self.router_advertisement.on_link =
                                ogs_yaml_iter_bool(&ra_iter);
                        } else if (!strcmp(ra_key, "rdnss")) {
                            self.router_advertisement.rdnss =
                                ogs_yaml_iter_bool(&ra_iter);
                        } else if (!strcmp(ra_key,
                                    "source_link_layer_address")) {
                            self.router_advertisement.
                                source_link_layer_address =
                                    ogs_yaml_iter_bool(&ra_iter);
                        } else if (!strcmp(ra_key, "link_layer_address")) {
                            if (!v || smf_ra_parse_link_layer_address(v,
                                    self.router_advertisement.
                                        link_layer_address) != OGS_OK)
                                return OGS_ERROR;
                        } else if (!strcmp(ra_key, "router_lifetime")) {
                            /* RFC 4861 section 4.2: 16 bits, 0 = not a
                             * default router */
                            if (!smf_yaml_iter_uint32(&ra_iter, &n) ||
                                n > UINT16_MAX) {
                                ogs_error("Invalid router_advertisement.%s "
                                        "(0..65535)", ra_key);
                                return OGS_ERROR;
                            }
                            self.router_advertisement.router_lifetime = n;
                        } else
                            ogs_warn("unknown key `%s`", ra_key);
                    }
                } else if (!strcmp(smf_key, "p-cscf")) {
                    ogs_yaml_iter_t p_cscf_iter;
                    ogs_yaml_iter_recurse(&smf_iter, &p_cscf_iter);
                    ogs_assert(ogs_yaml_iter_type(&p_cscf_iter) !=
                            YAML_MAPPING_NODE);

                    self.num_of_p_cscf = 0;
                    self.num_of_p_cscf6 = 0;
                    do {
                        const char *v = NULL;
                        ogs_sockaddr_t *resolved_list = NULL;
                        ogs_sockaddr_t *cur = NULL;
                        char buf[OGS_ADDRSTRLEN];
                        int res;

                        if (ogs_yaml_iter_type(&p_cscf_iter) ==
                                YAML_SEQUENCE_NODE) {
                            if (!ogs_yaml_iter_next(&p_cscf_iter))
                                break;
                        }
                        v = ogs_yaml_iter_value(&p_cscf_iter);
                        if (!v) {
                            ogs_error("No value for P-CSCF in configuration");
                            continue;
                        }

                        /* Use the new API to resolve IP or FQDN
                         * into one or more addresses */
                        res = ogs_sockaddr_from_ip_or_fqdn(
                                &resolved_list, AF_UNSPEC, v, 0);
                        if (res != OGS_OK || !resolved_list) {
                            ogs_error("Failed to resolve P-CSCF address: %s",
                                    v);
                            continue; /* Skip this entry and move to the next */
                        }

                        /* Iterate through all resolved addresses
                         * and store them */
                        for (cur = resolved_list; cur; cur = cur->next) {
                            if (cur->ogs_sa_family == AF_INET) {
                                if (self.num_of_p_cscf < MAX_NUM_OF_P_CSCF) {
                                    self.p_cscf[self.num_of_p_cscf++] =
                                        ogs_ipstrdup(cur);
                                } else {
                                    ogs_warn("Ignore P-CSCF IPv4 "
                                            "(max %d reached): %s",
                                             MAX_NUM_OF_P_CSCF,
                                             OGS_ADDR(cur, buf));
                                }
                            } else if (cur->ogs_sa_family == AF_INET6) {
                                if (self.num_of_p_cscf6 < MAX_NUM_OF_P_CSCF) {
                                    self.p_cscf6[self.num_of_p_cscf6++] =
                                        ogs_ipstrdup(cur);
                                } else {
                                    ogs_warn("Ignore P-CSCF IPv6 "
                                            "(max %d reached): %s",
                                             MAX_NUM_OF_P_CSCF,
                                             OGS_ADDR(cur, buf));
                                }
                            }
                        }
                        /* free the linked list */
                        ogs_freeaddrinfo(resolved_list);

                    } while (ogs_yaml_iter_type(&p_cscf_iter) ==
                            YAML_SEQUENCE_NODE);

                } else if (!strcmp(smf_key, "info")) {
                    ogs_sbi_nf_instance_t *nf_instance = NULL;

                    ogs_yaml_iter_t info_array, info_iter;
                    ogs_yaml_iter_recurse(&smf_iter, &info_array);

                    nf_instance = ogs_sbi_self()->nf_instance;
                    ogs_assert(nf_instance);

                    do {
                        ogs_sbi_nf_info_t *nf_info = NULL;
                        ogs_sbi_smf_info_t *smf_info = NULL;

                        if (ogs_yaml_iter_type(&info_array) ==
                                YAML_MAPPING_NODE) {
                            memcpy(&info_iter, &info_array,
                                    sizeof(ogs_yaml_iter_t));
                        } else if (ogs_yaml_iter_type(&info_array) ==
                                    YAML_SEQUENCE_NODE) {
                            if (!ogs_yaml_iter_next(&info_array))
                                break;
                            ogs_yaml_iter_recurse(&info_array, &info_iter);
                        } else if (ogs_yaml_iter_type(&info_array) ==
                                    YAML_SCALAR_NODE) {
                            break;
                        } else
                            ogs_assert_if_reached();

                        nf_info = ogs_sbi_nf_info_add(
                                    &nf_instance->nf_info_list,
                                        OpenAPI_nf_type_SMF);
                        ogs_assert(nf_info);

                        smf_info = &nf_info->smf;
                        ogs_assert(smf_info);

                        while (ogs_yaml_iter_next(&info_iter)) {
                            const char *info_key =
                                ogs_yaml_iter_key(&info_iter);
                            ogs_assert(info_key);
                            if (!strcmp(info_key, "s_nssai")) {
                                int num_of_slice = 0;

                                ogs_yaml_iter_t s_nssai_array, s_nssai_iter;
                                ogs_yaml_iter_recurse(&info_iter,
                                        &s_nssai_array);
                                do {
                                    ogs_s_nssai_t *s_nssai = NULL;
                                    const char *sst = NULL, *sd = NULL;
                                    int num_of_dnn = 0;
                                    const char *dnn[OGS_MAX_NUM_OF_DNN];

                                    ogs_assert(num_of_slice <
                                            OGS_MAX_NUM_OF_SLICE);
                                    s_nssai = &smf_info->slice[num_of_slice].
                                            s_nssai;
                                    ogs_assert(s_nssai);

                                    if (ogs_yaml_iter_type(&s_nssai_array) ==
                                            YAML_MAPPING_NODE) {
                                        memcpy(&s_nssai_iter, &s_nssai_array,
                                                sizeof(ogs_yaml_iter_t));
                                    } else if (ogs_yaml_iter_type(
                                                &s_nssai_array) ==
                                                YAML_SEQUENCE_NODE) {
                                        if (!ogs_yaml_iter_next(&s_nssai_array))
                                            break;
                                        ogs_yaml_iter_recurse(&s_nssai_array,
                                                &s_nssai_iter);
                                    } else if (ogs_yaml_iter_type(
                                                &s_nssai_array) ==
                                                    YAML_SCALAR_NODE) {
                                        break;
                                    } else
                                        ogs_assert_if_reached();

                                    while (ogs_yaml_iter_next(&s_nssai_iter)) {
                                        const char *s_nssai_key =
                                            ogs_yaml_iter_key(&s_nssai_iter);
                                        ogs_assert(s_nssai_key);
                                        if (!strcmp(s_nssai_key, "sst")) {
                                            sst = ogs_yaml_iter_value(
                                                    &s_nssai_iter);
                                        } else if (!strcmp(s_nssai_key, "sd")) {
                                            sd = ogs_yaml_iter_value(
                                                    &s_nssai_iter);
                                        } else if (!strcmp(s_nssai_key,
                                                    "dnn")) {
                                            ogs_yaml_iter_t dnn_iter;
                                            ogs_yaml_iter_recurse(&s_nssai_iter,
                                                    &dnn_iter);
                                            ogs_assert(ogs_yaml_iter_type(
                                                        &dnn_iter) !=
                                                        YAML_MAPPING_NODE);

                                            do {
                                                const char *v = NULL;

                                                if (ogs_yaml_iter_type(
                                                        &dnn_iter) ==
                                                        YAML_SEQUENCE_NODE) {
                                                    if (!ogs_yaml_iter_next(
                                                                &dnn_iter))
                                                        break;
                                                }

                                                v = ogs_yaml_iter_value(
                                                        &dnn_iter);
                                                if (v) {
                                                    ogs_assert(num_of_dnn <
                                                            OGS_MAX_NUM_OF_DNN);
                                                    dnn[num_of_dnn++] = v;
                                                }
                                            } while (ogs_yaml_iter_type(
                                                        &dnn_iter) ==
                                                        YAML_SEQUENCE_NODE);
                                        }
                                    }

                                    if (sst) {
                                        int i;

                                        s_nssai->sst = atoi(sst);
                                        if (sd)
                                            s_nssai->sd =
                                                ogs_uint24_from_string_hexadecimal(
                                                        (char*)sd);
                                        else
                                            s_nssai->sd.v =
                                                OGS_S_NSSAI_NO_SD_VALUE;

                                        ogs_assert(num_of_dnn <
                                                OGS_MAX_NUM_OF_DNN);

                                        for (i = 0; i < num_of_dnn; i++) {
                                            smf_info->slice[num_of_slice].
                                                dnn[i] = ogs_strdup(dnn[i]);
                                            ogs_assert(
                                                smf_info->slice[num_of_slice].
                                                    dnn[i]);
                                        }

                                        smf_info->slice[num_of_slice].
                                            num_of_dnn = num_of_dnn;

                                        num_of_slice++;
                                    }
                                } while (ogs_yaml_iter_type(&s_nssai_array) ==
                                        YAML_SEQUENCE_NODE);

                                smf_info->num_of_slice = num_of_slice;

                            } else if (!strcmp(info_key, "tai")) {
                                int num_of_nr_tai = 0;
                                int num_of_nr_tai_range = 0;

                                ogs_yaml_iter_t tai_array, tai_iter;
                                ogs_yaml_iter_recurse(&info_iter, &tai_array);
                                do {
                                    const char *mcc = NULL, *mnc = NULL;
                                    int num_of_tac = 0;
                                    ogs_uint24_t start[OGS_MAX_NUM_OF_TAI];
                                    ogs_uint24_t end[OGS_MAX_NUM_OF_TAI];

                                    if (ogs_yaml_iter_type(&tai_array) ==
                                            YAML_MAPPING_NODE) {
                                        memcpy(&tai_iter, &tai_array,
                                                sizeof(ogs_yaml_iter_t));
                                    } else if (ogs_yaml_iter_type(&tai_array) ==
                                            YAML_SEQUENCE_NODE) {
                                        if (!ogs_yaml_iter_next(&tai_array))
                                            break;
                                        ogs_yaml_iter_recurse(&tai_array,
                                                &tai_iter);
                                    } else if (ogs_yaml_iter_type(&tai_array) ==
                                            YAML_SCALAR_NODE) {
                                        break;
                                    } else
                                        ogs_assert_if_reached();

                                    while (ogs_yaml_iter_next(&tai_iter)) {
                                        const char *tai_key =
                                            ogs_yaml_iter_key(&tai_iter);
                                        ogs_assert(tai_key);
                                        if (!strcmp(tai_key, "plmn_id")) {
                                            ogs_yaml_iter_t plmn_id_iter;

                                            ogs_yaml_iter_recurse(
                                                    &tai_iter, &plmn_id_iter);
                                            while (ogs_yaml_iter_next(
                                                        &plmn_id_iter)) {
                                                const char *plmn_id_key =
                                                    ogs_yaml_iter_key(
                                                            &plmn_id_iter);
                                                ogs_assert(plmn_id_key);
                                                if (!strcmp(plmn_id_key,
                                                            "mcc")) {
                                                    mcc = ogs_yaml_iter_value(
                                                            &plmn_id_iter);
                                                } else if (!strcmp(plmn_id_key,
                                                            "mnc")) {
                                                    mnc = ogs_yaml_iter_value(
                                                            &plmn_id_iter);
                                                }
                                            }
                                        } else if (!strcmp(tai_key, "tac")) {
                                            ogs_yaml_iter_t tac_iter;
                                            ogs_yaml_iter_recurse(&tai_iter,
                                                    &tac_iter);
                                            ogs_assert(ogs_yaml_iter_type(
                                                    &tac_iter) !=
                                                        YAML_MAPPING_NODE);
                                            do {
                                                char *v = NULL;
                                                char *low = NULL, *high = NULL;

                                                if (ogs_yaml_iter_type(
                                                        &tac_iter) ==
                                                        YAML_SEQUENCE_NODE) {
                                                    if (!ogs_yaml_iter_next(
                                                                &tac_iter))
                                                        break;
                                                }

                                                v = (char *)ogs_yaml_iter_value(
                                                            &tac_iter);
                                                if (v) {
                                                    low = strsep(&v, "-");
                                                    if (low && strlen(low) == 0)
                                                        low = NULL;

                                                    high = v;
                                                    if (high &&
                                                            strlen(high) == 0)
                                                        high = NULL;

                                                    if (low) {
                                                        ogs_assert(num_of_tac <
                                                            OGS_MAX_NUM_OF_TAI);
                                                        start[num_of_tac].v =
                                                            atoi(low);
                                                        if (high) {
                                                            end[num_of_tac].v =
                                                                atoi(high);
                                                            if (end[num_of_tac].
                                                                    v <
                                                                start[
                                                                    num_of_tac].
                                                                    v)
                                                                ogs_error(
                                                                "Invalid TAI "
                                                                "range: LOW:%s,"
                                                                "HIGH:%s",
                                                                    low, high);
                                                            else
                                                                num_of_tac++;
                                                        } else {
                                                            end[num_of_tac].v =
                                                                start[
                                                                num_of_tac].v;
                                                            num_of_tac++;
                                                        }
                                                    }
                                                }
                                            } while (
                                                ogs_yaml_iter_type(&tac_iter) ==
                                                    YAML_SEQUENCE_NODE);

                                        } else
                                            ogs_warn("unknown key `%s`",
                                                    tai_key);
                                    }

                                    if (mcc && mnc && num_of_tac) {
                                        int tac, num_of_tac_range = 0;
                                        for (tac = 0; tac < num_of_tac; tac++) {
                                            ogs_assert(end[tac].v >=
                                                    start[tac].v);
                                            if (start[tac].v == end[tac].v) {
                                                ogs_assert(num_of_nr_tai <
                                                        OGS_MAX_NUM_OF_TAI);
                                                ogs_plmn_id_build(
                                                    &smf_info->nr_tai[
                                                        num_of_nr_tai].plmn_id,
                                                    atoi(mcc), atoi(mnc),
                                                    strlen(mnc));
                                                smf_info->nr_tai[num_of_nr_tai].
                                                    tac.v = start[tac].v;
                                                num_of_nr_tai++;
                                            } else if (start[tac].v <
                                                    end[tac].v) {
                                                ogs_assert(num_of_nr_tai_range <
                                                        OGS_MAX_NUM_OF_TAI);
                                                ogs_assert(num_of_tac_range <
                                                        OGS_MAX_NUM_OF_TAI);
                                                smf_info->nr_tai_range[
                                                    num_of_nr_tai_range].
                                                    start[num_of_tac_range].v =
                                                        start[tac].v;
                                                smf_info->nr_tai_range[
                                                    num_of_nr_tai_range].
                                                    end[num_of_tac_range].v =
                                                    end[tac].v;
                                                num_of_tac_range++;
                                            }
                                        }
                                        if (num_of_tac_range) {
                                            ogs_plmn_id_build(
                                                &smf_info->nr_tai_range[
                                                num_of_nr_tai_range].plmn_id,
                                                atoi(mcc), atoi(mnc),
                                                strlen(mnc));
                                            smf_info->nr_tai_range[
                                                num_of_nr_tai_range].
                                                num_of_tac_range =
                                                num_of_tac_range;
                                            num_of_nr_tai_range++;
                                        }
                                    } else {
                                        ogs_warn("Ignore tai : mcc(%p), "
                                                "mnc(%p), num_of_tac(%d)",
                                                mcc, mnc, num_of_tac);
                                    }
                                } while (ogs_yaml_iter_type(&tai_array) ==
                                        YAML_SEQUENCE_NODE);

                                smf_info->num_of_nr_tai = num_of_nr_tai;
                                smf_info->num_of_nr_tai_range =
                                    num_of_nr_tai_range;
                            } else
                                ogs_warn("unknown key `%s`", info_key);
                        }
                    } while (ogs_yaml_iter_type(&info_array) ==
                            YAML_SEQUENCE_NODE);

                } else if (!strcmp(smf_key, "security_indication")) {
                    ogs_yaml_iter_t security_indication_iter;
                    ogs_yaml_iter_recurse(
                            &smf_iter, &security_indication_iter);
                    while (ogs_yaml_iter_next(&security_indication_iter)) {
                        const char *security_indication_key =
                            ogs_yaml_iter_key(&security_indication_iter);
                        ogs_assert(security_indication_key);
                        if (!strcmp(security_indication_key,
                            "integrity_protection_indication")) {
                            self.security_indication.
                                integrity_protection_indication =
                                    ogs_yaml_iter_value(
                                        &security_indication_iter);
                        } else if (!strcmp(security_indication_key,
                            "confidentiality_protection_indication")) {
                            self.security_indication.
                                confidentiality_protection_indication =
                                    ogs_yaml_iter_value(
                                            &security_indication_iter);
                        } else if (!strcmp(security_indication_key,
                            "maximum_integrity_protected_data_rate_uplink")) {
                            self.security_indication.
                                maximum_integrity_protected_data_rate_uplink =
                                    ogs_yaml_iter_value(
                                            &security_indication_iter);
                        } else if (!strcmp(security_indication_key,
                            "maximum_integrity_protected_data_rate_downlink")) {
                            self.security_indication.
                                maximum_integrity_protected_data_rate_downlink =
                                    ogs_yaml_iter_value(
                                            &security_indication_iter);
                        }
                    }
                } else if (!strcmp(smf_key, "pfcp")) {
                    /* handle config in pfcp library */
                } else if (!strcmp(smf_key, "upf")) {
                    /* handle config in pfcp library */
                } else if (!strcmp(smf_key, "session")) {
                    /* handle config in pfcp library */
                } else if (!strcmp(smf_key, "default")) {
                    /* handle config in sbi library */
                } else if (!strcmp(smf_key, "sbi")) {
                    /* handle config in sbi library */
                } else if (!strcmp(smf_key, "nrf")) {
                    /* handle config in sbi library */
                } else if (!strcmp(smf_key, "scp")) {
                    /* handle config in sbi library */
                } else if (!strcmp(smf_key, "service_name")) {
                    /* handle config in sbi library */
                } else if (!strcmp(smf_key, "discovery")) {
                    /* handle config in sbi library */
                } else if (!strcmp(smf_key, "metrics")) {
                    /* handle config in metrics library */
                } else
                    ogs_warn("unknown key `%s`", smf_key);
            }
        }
    }

    rv = smf_context_validation();
    if (rv != OGS_OK) return rv;

    rv = smf_dhcpv6_config_finalize(dhcpv6_t1_set, dhcpv6_t2_set);
    if (rv != OGS_OK) return rv;

    return OGS_OK;
}

smf_gtp_node_t *smf_gtp_node_new(ogs_gtp_node_t *gnode)
{
    smf_gtp_node_t *smf_gnode = NULL;
    char addr[OGS_ADDRSTRLEN];

    ogs_pool_alloc(&smf_gtp_node_pool, &smf_gnode);
    if (!smf_gnode) {
        ogs_error("ogs_pool_alloc() failed");
        return NULL;
    }
    memset(smf_gnode, 0, sizeof(smf_gtp_node_t));

    addr[0] = '\0';
    ogs_assert(gnode->sa_list);
    ogs_inet_ntop(&gnode->sa_list[0].sa, addr, sizeof(addr));
    ogs_assert(smf_metrics_init_inst_gtp_node(smf_gnode->metrics, addr)
        == OGS_OK);

    smf_gnode->gnode = gnode;
    gnode->data_ptr = smf_gnode; /* Set backpointer */
    return smf_gnode;
}

void smf_gtp_node_free(smf_gtp_node_t *smf_gnode)
{
    ogs_assert(smf_gnode);
    if (smf_gnode->gnode)
        smf_gnode->gnode->data_ptr = NULL; /* Drop backpointer */
    smf_metrics_free_inst_gtp_node(smf_gnode->metrics);
    ogs_pool_free(&smf_gtp_node_pool, smf_gnode);
}

static smf_ue_t *smf_ue_add(void)
{
    smf_ue_t *smf_ue = NULL;

    ogs_pool_id_calloc(&smf_ue_pool, &smf_ue);
    if (!smf_ue) {
        ogs_error("Maximum number of smf_ue[%lld] reached",
                    (long long)ogs_global_conf()->max.ue);
        return NULL;
    }

    ogs_list_init(&smf_ue->sess_list);

    ogs_list_add(&self.smf_ue_list, smf_ue);

    smf_metrics_inst_global_inc(SMF_METR_GLOB_GAUGE_UES_ACTIVE);
    ogs_info("[Added] Number of SMF-UEs is now %d",
            ogs_list_count(&self.smf_ue_list));
    return smf_ue;
}

/*
 * Set and index SUPI in one place.  Callers decide which smf_ue_t to
 * use; this helper prevents a hash entry owned by another UE from being
 * overwritten by ogs_hash_set().
 */
static int smf_ue_set_supi(smf_ue_t *smf_ue, const char *supi)
{
    smf_ue_t *indexed_smf_ue = NULL;

    ogs_assert(smf_ue);

    if (!supi) {
        ogs_error("No SUPI");
        return OGS_ERROR;
    }
    if (strlen(supi) == 0) {
        ogs_error("Empty SUPI");
        return OGS_ERROR;
    }

    if (smf_ue->supi) {
        if (strcmp(smf_ue->supi, supi) != 0) {
            ogs_fatal("SUPI mismatch [%s:%s]", smf_ue->supi, supi);
            ogs_assert_if_reached();
            return OGS_ERROR;
        }
        return OGS_OK;
    }

    indexed_smf_ue = smf_ue_find_by_supi((char *)supi);
    if (indexed_smf_ue && indexed_smf_ue != smf_ue) {
        ogs_fatal("SUPI[%s] already indexed", supi);
        ogs_assert_if_reached();
        return OGS_ERROR;
    }

    smf_ue->supi = ogs_strdup(supi);
    ogs_assert(smf_ue->supi);

    ogs_hash_set(self.supi_hash,
            smf_ue->supi, strlen(smf_ue->supi), smf_ue);

    return OGS_OK;
}

/*
 * Set and index IMSI in one place.  Convert first to a temporary buffer
 * so an existing hash key is not modified before mismatch detection.
 */
static int smf_ue_set_imsi_bcd(smf_ue_t *smf_ue, const char *imsi_bcd)
{
    smf_ue_t *indexed_smf_ue = NULL;
    uint8_t imsi[OGS_MAX_IMSI_LEN];
    int imsi_len = 0;

    ogs_assert(smf_ue);
    ogs_assert(imsi_bcd);

    if (ogs_imsi_bcd_is_valid(imsi_bcd) == false) {
        ogs_error("ogs_imsi_bcd_is_valid() failed [%s]", imsi_bcd);
        return OGS_ERROR;
    }

    memset(imsi, 0, sizeof(imsi));
    ogs_bcd_to_buffer(imsi_bcd, imsi, &imsi_len);
    ogs_assert(imsi_len > 0);
    ogs_assert(imsi_len <= OGS_MAX_IMSI_LEN);

    if (smf_ue->imsi_len) {
        if (smf_ue->imsi_len != imsi_len ||
            memcmp(smf_ue->imsi, imsi, imsi_len) != 0) {
            ogs_fatal("IMSI mismatch [%s:%s]",
                    smf_ue->imsi_bcd, imsi_bcd);
            ogs_assert_if_reached();
            return OGS_ERROR;
        }
        return OGS_OK;
    }

    indexed_smf_ue = smf_ue_find_by_imsi(imsi, imsi_len);
    if (indexed_smf_ue && indexed_smf_ue != smf_ue) {
        ogs_fatal("IMSI[%s] already indexed", imsi_bcd);
        ogs_assert_if_reached();
        return OGS_ERROR;
    }

    smf_ue->imsi_len = imsi_len;
    memcpy(smf_ue->imsi, imsi, smf_ue->imsi_len);
    ogs_cpystrn(smf_ue->imsi_bcd, imsi_bcd, OGS_MAX_IMSI_BCD_LEN+1);

    ogs_hash_set(self.imsi_hash,
            smf_ue->imsi, smf_ue->imsi_len, smf_ue);

    return OGS_OK;
}

/*
 * The EPC path receives raw BCD bytes.  Convert them to the canonical
 * decimal IMSI string used by the SUPI path.
 */
static int smf_ue_set_imsi(smf_ue_t *smf_ue, uint8_t *imsi, int imsi_len)
{
    char imsi_bcd[OGS_MAX_IMSI_BCD_LEN+1];

    ogs_assert(smf_ue);
    ogs_assert(imsi);
    ogs_assert(imsi_len);

    if (imsi_len > OGS_MAX_IMSI_LEN) {
        ogs_error("Invalid IMSI length [%d]", imsi_len);
        return OGS_ERROR;
    }

    memset(imsi_bcd, 0, sizeof(imsi_bcd));
    ogs_buffer_to_bcd(imsi, imsi_len, imsi_bcd);

    if (smf_ue_set_imsi_bcd(smf_ue, imsi_bcd) != OGS_OK) {
        ogs_error("smf_ue_set_imsi_bcd() failed [%s]", imsi_bcd);
        return OGS_ERROR;
    }

    return OGS_OK;
}

smf_ue_t *smf_ue_add_by_supi(char *supi)
{
    smf_ue_t *smf_ue = NULL;
    char imsi_bcd[OGS_MAX_IMSI_BCD_LEN+1];
    uint8_t imsi[OGS_MAX_IMSI_LEN];
    int imsi_len = 0;
    bool created = false;
    bool imsi_supi = false;

    if (!supi) {
        ogs_error("No SUPI");
        return NULL;
    }
    if (strlen(supi) == 0) {
        ogs_error("Empty SUPI");
        return NULL;
    }

    memset(imsi_bcd, 0, sizeof(imsi_bcd));
    memset(imsi, 0, sizeof(imsi));

    if (ogs_supi_to_imsi_bcd(supi, imsi_bcd, &imsi_supi) != OGS_OK) {
        ogs_error("ogs_supi_to_imsi_bcd() failed [%s]", supi);
        return NULL;
    }

    /* First use the native SBI key. */
    smf_ue = smf_ue_find_by_supi(supi);

    /* If this is an IMSI SUPI, try the EPC IMSI key as an alias. */
    if (!smf_ue && imsi_supi == true) {
        ogs_bcd_to_buffer(imsi_bcd, imsi, &imsi_len);
        smf_ue = smf_ue_find_by_imsi(imsi, imsi_len);
    }

    if (!smf_ue) {
        smf_ue = smf_ue_add();
        if (!smf_ue) {
            ogs_error("smf_ue_add_by_supi() failed");
            return NULL;
        }
        created = true;
    }

    if (smf_ue_set_supi(smf_ue, supi) != OGS_OK) {
        ogs_error("smf_ue_set_supi() failed [%s]", supi);
        goto error;
    }

    if (imsi_supi == true &&
        smf_ue_set_imsi_bcd(smf_ue, imsi_bcd) != OGS_OK) {
        ogs_error("smf_ue_set_imsi_bcd() failed [%s:%s]",
                supi, imsi_bcd);
        goto error;
    }

    return smf_ue;

error:
    if (created == true)
        smf_ue_remove(smf_ue);
    return NULL;
}

smf_ue_t *smf_ue_add_by_imsi(uint8_t *imsi, int imsi_len)
{
    smf_ue_t *smf_ue = NULL;
    char imsi_bcd[OGS_MAX_IMSI_BCD_LEN+1];
    char *supi = NULL;
    bool created = false;

    ogs_assert(imsi);
    ogs_assert(imsi_len);

    if (imsi_len > OGS_MAX_IMSI_LEN) {
        ogs_error("Invalid IMSI length [%d]", imsi_len);
        return NULL;
    }

    memset(imsi_bcd, 0, sizeof(imsi_bcd));
    ogs_buffer_to_bcd(imsi, imsi_len, imsi_bcd);
    if (ogs_imsi_bcd_is_valid(imsi_bcd) == false) {
        ogs_error("ogs_imsi_bcd_is_valid() failed [%s]", imsi_bcd);
        return NULL;
    }

    supi = ogs_msprintf("%s-%s", OGS_ID_SUPI_TYPE_IMSI, imsi_bcd);
    ogs_assert(supi);

    /* First use the native EPC key. */
    smf_ue = smf_ue_find_by_imsi(imsi, imsi_len);

    /* Then try the canonical IMSI SUPI used by the SBI path. */
    if (!smf_ue)
        smf_ue = smf_ue_find_by_supi(supi);

    if (!smf_ue) {
        smf_ue = smf_ue_add();
        if (!smf_ue) {
            ogs_error("smf_ue_add() failed");
            goto error;
        }
        created = true;
    }

    if (smf_ue_set_imsi(smf_ue, imsi, imsi_len) != OGS_OK) {
        ogs_error("smf_ue_set_imsi() failed [%s]", imsi_bcd);
        goto error;
    }

    if (smf_ue_set_supi(smf_ue, supi) != OGS_OK) {
        ogs_error("smf_ue_set_supi() failed [%s]", supi);
        goto error;
    }

    ogs_free(supi);
    return smf_ue;

error:
    if (supi)
        ogs_free(supi);
    if (created == true)
        smf_ue_remove(smf_ue);
    return NULL;
}

void smf_ue_remove(smf_ue_t *smf_ue)
{
    ogs_assert(smf_ue);

    ogs_list_remove(&self.smf_ue_list, smf_ue);

    smf_sess_remove_all(smf_ue);

    if (smf_ue->supi) {
        ogs_hash_set(self.supi_hash, smf_ue->supi, strlen(smf_ue->supi), NULL);
        ogs_free(smf_ue->supi);
    }

    if (smf_ue->gpsi)
        ogs_free(smf_ue->gpsi);

    if (smf_ue->imsi_len) {
        ogs_hash_set(self.imsi_hash, smf_ue->imsi, smf_ue->imsi_len, NULL);
    }

    ogs_pool_id_free(&smf_ue_pool, smf_ue);

    smf_metrics_inst_global_dec(SMF_METR_GLOB_GAUGE_UES_ACTIVE);
    ogs_info("[Removed] Number of SMF-UEs is now %d",
            ogs_list_count(&self.smf_ue_list));
}

void smf_ue_remove_all(void)
{
    smf_ue_t *smf_ue = NULL, *next = NULL;;

    ogs_list_for_each_safe(&self.smf_ue_list, next, smf_ue)
        smf_ue_remove(smf_ue);
}

smf_ue_t *smf_ue_find_by_supi(char *supi)
{
    size_t supi_len;

    if (!supi) {
        ogs_error("No SUPI");
        return NULL;
    }

    supi_len = strlen(supi);
    if (supi_len == 0) {
        ogs_error("Empty SUPI");
        return NULL;
    }

    return (smf_ue_t *)ogs_hash_get(self.supi_hash, supi, supi_len);
}

smf_ue_t *smf_ue_find_by_imsi(uint8_t *imsi, int imsi_len)
{
    ogs_assert(imsi);
    ogs_assert(imsi_len);
    return (smf_ue_t *)ogs_hash_get(self.imsi_hash, imsi, imsi_len);
}

static bool compare_ue_info(ogs_pfcp_node_t *node, smf_sess_t *sess)
{
    int i;

    ogs_assert(node);
    ogs_assert(sess);
    ogs_assert(sess->session.name);

    for (i = 0; i < node->num_of_dnn; i++)
        if (ogs_strcasecmp(node->dnn[i], sess->session.name) == 0) return true;

    for (i = 0; i < node->num_of_e_cell_id; i++)
        if (sess->gtp_rat_type == OGS_GTP2_RAT_TYPE_EUTRAN &&
                node->e_cell_id[i] == sess->e_cgi.cell_id) return true;

    for (i = 0; i < node->num_of_nr_cell_id; i++)
        if (node->nr_cell_id[i] == sess->nr_cgi.cell_id) return true;

    for (i = 0; i < node->num_of_tac; i++)
        if ((sess->gtp_rat_type == OGS_GTP2_RAT_TYPE_EUTRAN &&
                node->tac[i] == sess->e_tai.tac) ||
            (node->tac[i] == sess->nr_tai.tac.v)) return true;

    return false;
}

static ogs_pfcp_node_t *selected_upf_node(
        ogs_pfcp_node_t *current, smf_sess_t *sess)
{
    ogs_pfcp_node_t *next, *node;

    ogs_assert(current);
    ogs_assert(sess);

    /* continue search from current position */
    next = ogs_list_next(current);
    for (node = next; node; node = ogs_list_next(node)) {
        if (OGS_FSM_CHECK(&node->sm, smf_pfcp_state_associated) &&
            compare_ue_info(node, sess) == true) return node;
    }
    /* cyclic search from top to current position */
    for (node = ogs_list_first(&ogs_pfcp_self()->pfcp_peer_list);
            node != next; node = ogs_list_next(node)) {
        if (OGS_FSM_CHECK(&node->sm, smf_pfcp_state_associated) &&
            compare_ue_info(node, sess) == true) return node;
    }

    if (ogs_global_conf()->parameter.no_pfcp_rr_select == 0) {
        /* continue search from current position */
        next = ogs_list_next(current);
        for (node = next; node; node = ogs_list_next(node)) {
            if (OGS_FSM_CHECK(&node->sm, smf_pfcp_state_associated))
                return node;
        }
        /* cyclic search from top to current position */
        for (node = ogs_list_first(&ogs_pfcp_self()->pfcp_peer_list);
                node != next; node = ogs_list_next(node)) {
            if (OGS_FSM_CHECK(&node->sm, smf_pfcp_state_associated))
                return node;
        }
    }

    ogs_error("No UPFs are PFCP associated that are suited to RR");
    return ogs_list_first(&ogs_pfcp_self()->pfcp_peer_list);
}

void smf_sess_select_upf(smf_sess_t *sess)
{
    ogs_assert(sess);

    /*
     * When used for the first time, if last node is set,
     * the search is performed from the first UPF in a round-robin manner.
     */
    if (ogs_pfcp_self()->pfcp_node == NULL)
        ogs_pfcp_self()->pfcp_node =
            ogs_list_last(&ogs_pfcp_self()->pfcp_peer_list);

    if (ogs_pfcp_self()->pfcp_node) {
        /* setup GTP session with selected UPF */
        ogs_pfcp_self()->pfcp_node =
            selected_upf_node(ogs_pfcp_self()->pfcp_node, sess);
        ogs_assert(ogs_pfcp_self()->pfcp_node);
        OGS_SETUP_PFCP_NODE(sess, ogs_pfcp_self()->pfcp_node);
        ogs_debug("UE using UPF on IP %s",
                ogs_sockaddr_to_string_static(
                    ogs_pfcp_self()->pfcp_node->addr_list));
    } else {
        ogs_error("No suitable UPF found for session");
        ogs_assert(sess->pfcp_node == NULL);
    }
}

smf_sess_t *smf_sess_add_by_apn(smf_ue_t *smf_ue, char *apn, uint8_t rat_type)
{
    smf_event_t e;

    smf_sess_t *sess = NULL;

    ogs_assert(smf_ue);
    ogs_assert(apn);

    ogs_pool_id_calloc(&smf_sess_pool, &sess);
    if (!sess) {
        ogs_error("Maximum number of session[%lld] reached",
                    (long long)ogs_app()->pool.sess);
        return NULL;
    }

    ogs_pfcp_pool_init(&sess->pfcp);
    smf_qfi_pool_init(sess);
    smf_pf_precedence_pool_init(sess);

    sess->index = ogs_pool_index(&smf_sess_pool, sess);
    ogs_assert(sess->index > 0 && sess->index <= ogs_app()->pool.sess);

    /* Set TEID & SEID */
    ogs_pool_alloc(&smf_n4_seid_pool, &sess->smf_n4_seid_node);
    ogs_assert(sess->smf_n4_seid_node);

    sess->smf_n4_teid = *(sess->smf_n4_seid_node);
    sess->smf_n4_seid = *(sess->smf_n4_seid_node);

    ogs_hash_set(self.smf_n4_seid_hash, &sess->smf_n4_seid,
            sizeof(sess->smf_n4_seid), sess);

    /* Set Charging ID */
    sess->charging.id = sess->index;

    /* Create BAR in PFCP Session */
    ogs_pfcp_bar_new(&sess->pfcp);

    /* Set APN */
    sess->session.name = ogs_strdup(apn);
    ogs_assert(sess->session.name);

    /* Set RAT-Type */
    sess->gtp_rat_type = rat_type;
    ogs_assert(sess->gtp_rat_type);

    /* Set EPC */
    sess->epc = true;

    memset(&e, 0, sizeof(e));
    e.sess_id = sess->id;
    ogs_fsm_init(&sess->sm, smf_gsm_state_initial, smf_gsm_state_final, &e);

    sess->smf_ue_id = smf_ue->id;

    ogs_list_add(&smf_ue->sess_list, sess);

    stats_add_smf_session();

    return sess;
}

smf_sess_t *smf_sess_add_by_gtp1_message(ogs_gtp1_message_t *message)
{
    smf_ue_t *smf_ue = NULL;
    smf_sess_t *sess = NULL;
    char apn[OGS_MAX_APN_LEN+1];

    ogs_gtp1_create_pdp_context_request_t *req = &message->create_pdp_context_request;

    if (req->imsi.presence == 0) {
        ogs_error("No IMSI");
        return NULL;
    }
    if (req->tunnel_endpoint_identifier_data_i.presence == 0) {
        ogs_error("No Tunnel Endpoint Identifier Data I");
        return NULL;
    }
    if (req->nsapi.presence == 0) {
        ogs_error("No NSAPI");
        return NULL;
    }
    if (req->access_point_name.presence == 0) {
        ogs_error("No APN");
        return NULL;
    } else {
        if (ogs_fqdn_parse(apn, req->access_point_name.data,
            ogs_min(req->access_point_name.len, OGS_MAX_APN_LEN)) <= 0) {
            ogs_error("Invalid APN");
            return NULL;
        }
    }

    if (req->sgsn_address_for_signalling.presence == 0) {
        ogs_error("No SGSN Address for signalling");
        return NULL;
    }
    if (req->sgsn_address_for_user_traffic.presence == 0) {
        ogs_error("No SGSN Address for user traffic");
        return NULL;
    }
    if (req->quality_of_service_profile.presence == 0) {
        ogs_error("No QoS Profile");
        return NULL;
    }
    if (req->rat_type.presence == 0) {
        ogs_error("No RAT Type");
        return NULL;
    }

    ogs_trace("smf_sess_add_by_message() [APN:%s]", apn);

    /*
     * 7.3.1 in 3GPP TS 29.060 Release 16
     *
     * If a new Create PDP Context Request is incoming on TEID 0 for an already
     * active PDP context, this Create PDP Context Request must be considered
     * related to a new session. The existing PDP context shall be torn down
     * locally, and the associated PDP contexts deleted locally, before the new
     * session is created.
     */

    smf_ue = smf_ue_find_by_imsi(req->imsi.data, req->imsi.len);
    if (!smf_ue) {
        smf_ue = smf_ue_add_by_imsi(req->imsi.data, req->imsi.len);
        if (!smf_ue)
            return NULL;
    }

    sess = smf_sess_find_by_apn(smf_ue, apn, req->rat_type.u8);
    if (sess) {
        ogs_warn("OLD Session Will Release [IMSI:%s,APN:%s]",
                smf_ue->imsi_bcd, sess->session.name);
        smf_sess_remove(sess);
    }

    sess = smf_sess_add_by_apn(smf_ue, apn, req->rat_type.u8);
    sess->gtp.version = 1;
    smf_metrics_inst_global_inc(SMF_METR_GLOB_GAUGE_GTP1_PDPCTXS_ACTIVE);
    return sess;
}

smf_sess_t *smf_sess_add_by_gtp2_message(ogs_gtp2_message_t *message)
{
    smf_ue_t *smf_ue = NULL;
    smf_sess_t *sess = NULL;
    char apn[OGS_MAX_APN_LEN+1];

    ogs_gtp2_create_session_request_t *req = &message->create_session_request;

    if (req->imsi.presence == 0) {
        ogs_error("No IMSI");
        return NULL;
    }
    if (req->access_point_name.presence == 0) {
        ogs_error("No APN");
        return NULL;
    } else {
        if (ogs_fqdn_parse(apn, req->access_point_name.data,
            ogs_min(req->access_point_name.len, OGS_MAX_APN_LEN)) <= 0) {
            ogs_error("Invalid APN");
            return NULL;
        }
    }
    if (req->rat_type.presence == 0) {
        ogs_error("No RAT Type");
        return NULL;
    }

    ogs_trace("smf_sess_add_by_message() [APN:%s]", apn);

    /*
     * 7.2.1 in 3GPP TS 29.274 Release 15
     *
     * If the new Create Session Request received by the SMF collides with
     * an existing PDN connection context (the existing PDN connection context
     * is identified with the triplet [IMSI, EPS Bearer ID, Interface type],
     * where applicable Interface type here is S2a TWAN GTP-C interface or
     * S2b ePDG GTP-C interface or S5/S8 SGW GTP-C interface, and where IMSI
     * shall be replaced by TAC and SNR part of ME Identity for emergency
     * attached UE without UICC or authenticated IMSI), this Create Session
     * Request shall be treated as a request for a new session. Before creating
     * the new session, the SMF should delete:
     *
     * - the existing PDN connection context, if the Create Session Request
     *   collides with the default bearer of an existing PDN connection context;
     * - the existing dedicated bearer context, if the Create Session Request
     *   collides with a dedicated bearer of an existing PDN connection context.
     */

    smf_ue = smf_ue_find_by_imsi(req->imsi.data, req->imsi.len);
    if (!smf_ue) {
        smf_ue = smf_ue_add_by_imsi(req->imsi.data, req->imsi.len);
        if (!smf_ue)
            return NULL;
    }

    sess = smf_sess_find_by_apn(smf_ue, apn, req->rat_type.u8);
    if (sess) {
        ogs_info("OLD Session Will Release [IMSI:%s,APN:%s]",
                smf_ue->imsi_bcd, sess->session.name);
        smf_sess_remove(sess);
    }

    sess = smf_sess_add_by_apn(smf_ue, apn, req->rat_type.u8);
    sess->gtp.version = 2;
    smf_metrics_inst_global_inc(SMF_METR_GLOB_GAUGE_GTP2_SESSIONS_ACTIVE);
    return sess;
}

smf_sess_t *smf_sess_add_by_psi(smf_ue_t *smf_ue, uint8_t psi)
{
    smf_event_t e;

    smf_sess_t *sess = NULL;

    ogs_assert(smf_ue);
    ogs_assert(psi != OGS_NAS_PDU_SESSION_IDENTITY_UNASSIGNED);

    ogs_pool_id_calloc(&smf_sess_pool, &sess);
    if (!sess) {
        ogs_error("Maximum number of session[%lld] reached",
            (long long)ogs_app()->pool.sess);
        return NULL;
    }

    /* SBI Features */
    OGS_SBI_FEATURES_SET(sess->smpolicycontrol_features,
            OGS_SBI_NPCF_SMPOLICYCONTROL_DN_AUTHORIZATION);

    ogs_pfcp_pool_init(&sess->pfcp);
    smf_qfi_pool_init(sess);
    smf_pf_precedence_pool_init(sess);

    sess->index = ogs_pool_index(&smf_sess_pool, sess);
    ogs_assert(sess->index > 0 && sess->index <= ogs_app()->pool.sess);

    /* Set TEID & SEID */
    ogs_pool_alloc(&smf_n4_seid_pool, &sess->smf_n4_seid_node);
    ogs_assert(sess->smf_n4_seid_node);

    sess->smf_n4_teid = *(sess->smf_n4_seid_node);
    sess->smf_n4_seid = *(sess->smf_n4_seid_node);

    ogs_hash_set(self.smf_n4_seid_hash, &sess->smf_n4_seid,
            sizeof(sess->smf_n4_seid), sess);

    /* Set SmContextRef in 5GC */
    sess->sm_context_ref = ogs_msprintf("%d", sess->index);
    ogs_assert(sess->sm_context_ref);

    /* Set PduSessionRef in 5GC */
    sess->pdu_session_ref = ogs_msprintf("%d", sess->index);
    ogs_assert(sess->pdu_session_ref);

    /* Create BAR in PFCP Session */
    ogs_pfcp_bar_new(&sess->pfcp);

    /* Set PSI */
    sess->psi = psi;

    /* Set S-NSSAI */
    sess->s_nssai.sst = 0;
    sess->s_nssai.sd.v = OGS_S_NSSAI_NO_SD_VALUE;
    sess->mapped_hplmn.sst = 0;
    sess->mapped_hplmn.sd.v = OGS_S_NSSAI_NO_SD_VALUE;

    /* Set Charging Id */
    sess->charging.id = sess->index;

    memset(&e, 0, sizeof(e));
    e.sess_id = sess->id;
    ogs_fsm_init(&sess->sm, smf_gsm_state_initial, smf_gsm_state_final, &e);

    sess->smf_ue_id = smf_ue->id;

    ogs_list_add(&smf_ue->sess_list, sess);

    smf_metrics_inst_global_inc(SMF_METR_GLOB_GAUGE_PFCP_SESSIONS_ACTIVE);
    stats_add_smf_session();

    return sess;
}

smf_sess_t *smf_sess_add_by_sm_context(ogs_sbi_message_t *message)
{
    smf_ue_t *smf_ue = NULL;
    smf_sess_t *sess = NULL;

    OpenAPI_sm_context_create_data_t *SmContextCreateData = NULL;

    ogs_assert(message);
    SmContextCreateData = message->SmContextCreateData;
    if (!SmContextCreateData) {
        ogs_error("No SmContextCreateData");
        return NULL;
    }

    if (!SmContextCreateData->supi) {
        ogs_error("No SUPI");
        return NULL;
    }
    if (strlen(SmContextCreateData->supi) == 0) {
        ogs_error("Empty SUPI");
        return NULL;
    }

    if (SmContextCreateData->is_pdu_session_id == false) {
        ogs_error("No PDU session identitiy");
        return NULL;
    }

    if (ogs_pdu_session_id_is_valid(
            SmContextCreateData->pdu_session_id) == false) {
        ogs_error("Invalid PDU session identity [%d]",
                SmContextCreateData->pdu_session_id);
        return NULL;
    }

    smf_ue = smf_ue_find_by_supi(SmContextCreateData->supi);
    if (!smf_ue) {
        smf_ue = smf_ue_add_by_supi(SmContextCreateData->supi);
        if (!smf_ue) {
            ogs_error("smf_ue_add_by_supi() failed");
            return NULL;
        }
    }

    sess = smf_sess_find_by_psi(smf_ue, SmContextCreateData->pdu_session_id);
    if (sess) {
        ogs_warn("OLD Session Will Release [SUPI:%s,PDU Session identity:%d]",
                SmContextCreateData->supi, SmContextCreateData->pdu_session_id);
        smf_metrics_inst_by_slice_add(&sess->serving_plmn_id, &sess->s_nssai,
                SMF_METR_GAUGE_SM_SESSIONNBR, -1);
        smf_sess_remove(sess);
    }

    sess = smf_sess_add_by_psi(smf_ue, SmContextCreateData->pdu_session_id);

    return sess;
}

smf_sess_t *smf_sess_add_by_pdu_session(ogs_sbi_message_t *message)
{
    smf_ue_t *smf_ue = NULL;
    smf_sess_t *sess = NULL;

    OpenAPI_pdu_session_create_data_t *PduSessionCreateData = NULL;

    ogs_assert(message);
    PduSessionCreateData = message->PduSessionCreateData;
    if (!PduSessionCreateData) {
        ogs_error("No PduSessionCreateData");
        return NULL;
    }

    if (!PduSessionCreateData->supi) {
        ogs_error("No SUPI");
        return NULL;
    }
    if (strlen(PduSessionCreateData->supi) == 0) {
        ogs_error("Empty SUPI");
        return NULL;
    }

    if (PduSessionCreateData->is_pdu_session_id == false) {
        ogs_error("No PDU session identitiy");
        return NULL;
    }

    if (ogs_pdu_session_id_is_valid(
            PduSessionCreateData->pdu_session_id) == false) {
        ogs_error("Invalid PDU session identity [%d]",
                PduSessionCreateData->pdu_session_id);
        return NULL;
    }

    smf_ue = smf_ue_find_by_supi(PduSessionCreateData->supi);
    if (!smf_ue) {
        smf_ue = smf_ue_add_by_supi(PduSessionCreateData->supi);
        if (!smf_ue) {
            ogs_error("smf_ue_add_by_supi() failed");
            return NULL;
        }
    }

    sess = smf_sess_find_by_psi(smf_ue, PduSessionCreateData->pdu_session_id);
    if (sess) {
        ogs_warn("OLD Session Will Release [SUPI:%s,PDU Session identity:%d]",
                PduSessionCreateData->supi,
                PduSessionCreateData->pdu_session_id);
        smf_metrics_inst_by_slice_add(&sess->serving_plmn_id, &sess->s_nssai,
                SMF_METR_GAUGE_SM_SESSIONNBR, -1);
        smf_sess_remove(sess);
    }

    sess = smf_sess_add_by_psi(smf_ue, PduSessionCreateData->pdu_session_id);

    return sess;
}

uint8_t smf_sess_ipv6_prefixlen(smf_sess_t *sess)
{
    ogs_assert(sess);

    if (!sess->ipv6)
        return 0;

    return ogs_pfcp_ue_ip_prefixlen(sess->ipv6);
}

/* Network prefix of `addr6` masked to `prefixlen` (< 64) + length octet */
static void ipv6_pd_key(uint8_t *key, const uint32_t *addr6, uint8_t prefixlen)
{
    uint64_t prefix;

    ogs_assert(key);
    ogs_assert(addr6);
    ogs_assert(prefixlen > 0 && prefixlen < OGS_IPV6_DEFAULT_PREFIX_LEN);

    memcpy(&prefix, addr6, sizeof(prefix));
    prefix = be64toh(prefix) & ~((UINT64_C(1) << (64 - prefixlen)) - 1);
    prefix = htobe64(prefix);
    memcpy(key, &prefix, sizeof(prefix));
    key[sizeof(prefix)] = prefixlen;
}

/* Forget the session's IPv6 link prefix, its delegated block and the
 * DHCPv6 binding that was tied to them. Entries are only removed when they
 * still point to this session: with conflicting static addresses (logged
 * by sess_ipv6_hash_set()) a later session may own them by now. */
static void sess_ipv6_hash_unset(smf_sess_t *sess)
{
    ogs_assert(sess);
    ogs_assert(sess->ipv6);

    if (ogs_hash_get(self.ipv6_hash,
                sess->ipv6->addr, OGS_IPV6_DEFAULT_PREFIX_LEN >> 3) == sess)
        ogs_hash_set(self.ipv6_hash,
                sess->ipv6->addr, OGS_IPV6_DEFAULT_PREFIX_LEN >> 3, NULL);
    if (ogs_pfcp_ue_ip_prefixlen(sess->ipv6) < OGS_IPV6_DEFAULT_PREFIX_LEN &&
        ogs_hash_get(self.ipv6_pd_hash,
                sess->ipv6_pd_key, sizeof(sess->ipv6_pd_key)) == sess)
        ogs_hash_set(self.ipv6_pd_hash,
                sess->ipv6_pd_key, sizeof(sess->ipv6_pd_key), NULL);

    memset(&sess->dhcpv6, 0, sizeof(sess->dhcpv6));
}

/* Register the session's IPv6 link prefix and, with prefix delegation,
 * its whole block. A previous DHCPv6 binding never survives this. */
static void sess_ipv6_hash_set(smf_sess_t *sess)
{
    smf_sess_t *other = NULL;
    uint8_t prefixlen;
    char buf[OGS_ADDRSTRLEN];

    ogs_assert(sess);
    ogs_assert(sess->ipv6);

    other = ogs_hash_get(self.ipv6_hash,
            sess->ipv6->addr, OGS_IPV6_DEFAULT_PREFIX_LEN >> 3);
    if (other && other != sess)
        ogs_error("IPv6 prefix %s/64 (static[%d]) is already in use by "
                "another session; check the static UE addresses and the "
                "dynamic range", OGS_INET6_NTOP(sess->ipv6->addr, buf),
                sess->ipv6->static_ip);
    ogs_hash_set(self.ipv6_hash,
            sess->ipv6->addr, OGS_IPV6_DEFAULT_PREFIX_LEN >> 3, sess);

    prefixlen = ogs_pfcp_ue_ip_prefixlen(sess->ipv6);
    if (prefixlen < OGS_IPV6_DEFAULT_PREFIX_LEN) {
        ipv6_pd_key(sess->ipv6_pd_key, sess->ipv6->addr, prefixlen);
        other = ogs_hash_get(self.ipv6_pd_hash,
                sess->ipv6_pd_key, sizeof(sess->ipv6_pd_key));
        if (other && other != sess)
            ogs_error("IPv6 block %s/%d (static[%d]) is already in use by "
                    "another session", OGS_INET6_NTOP(sess->ipv6->addr, buf),
                    prefixlen, sess->ipv6->static_ip);
        ogs_hash_set(self.ipv6_pd_hash,
                sess->ipv6_pd_key, sizeof(sess->ipv6_pd_key), sess);
    }

    memset(&sess->dhcpv6, 0, sizeof(sess->dhcpv6));
}

uint8_t smf_sess_set_ue_ip(smf_sess_t *sess)
{
    ogs_pfcp_subnet_t *subnet6 = NULL;
    smf_ue_t *smf_ue = NULL;

    uint8_t cause_value = OGS_PFCP_CAUSE_REQUEST_ACCEPTED;

    ogs_assert(sess);
    smf_ue = smf_ue_find_by_id(sess->smf_ue_id);
    ogs_assert(smf_ue);

    if (sess->session.session_type == OGS_PDU_SESSION_TYPE_IPV4V6) {

        /*
         * This is the case when the HSS is set to IPv4v6 and
         * the UE requests IPv4v6.
         *
         * At this time, it was changed to operate normally
         * even when SMF has no IPv4 or IPv6 subnet.
         *
         * If there is no IPv6 subnet, only IPv4 IP address is assigned.
         * If there is no IPv4 subnet, only IPv6 IP address is assigned.
         * If there are IPv4/IPv6 subnet, IPv4/IPv6 IP address are assigned.
         */

        ogs_pfcp_subnet_t *subnet = NULL;
        ogs_pfcp_subnet_t *subnet6 = NULL;

        uint8_t zero6[OGS_IPV6_LEN];

        ogs_assert(sess->session.name);
        memset(zero6, 0, sizeof zero6);

        /*
         * A family is available when a dynamic pool of the DNN has a free
         * entry, or when the subscriber has a static address that some
         * subnet of the DNN contains (including `static: true` subnets,
         * which have no pool). The static address itself is resolved by
         * containment in ogs_pfcp_ue_ip_alloc() (DESIGN.md 5.3, 5.5).
         */
        if (sess->session.ue_ip.addr)
            subnet = ogs_pfcp_find_subnet_by_addr(AF_INET,
                    sess->session.name, (uint8_t *)&sess->session.ue_ip.addr);
        else
            subnet = ogs_pfcp_find_subnet_by_dnn(AF_INET, sess->session.name);
        if (memcmp(sess->session.ue_ip.addr6, zero6, OGS_IPV6_LEN) != 0)
            subnet6 = ogs_pfcp_find_subnet_by_addr(AF_INET6,
                    sess->session.name, sess->session.ue_ip.addr6);
        else
            subnet6 = ogs_pfcp_find_subnet_by_dnn(AF_INET6, sess->session.name);

        if (subnet != NULL && subnet6 == NULL) {
            sess->session.session_type = OGS_PDU_SESSION_TYPE_IPV4;
            ogs_error("[%s] No IPv6 subnet or set to /63 or /64, "
                    "only IPv4 assigned", sess->session.name);
        } else if (subnet == NULL && subnet6 != NULL) {
            sess->session.session_type = OGS_PDU_SESSION_TYPE_IPV6;
            ogs_error("[%s] No IPv4 subnet or set to /31 or /32, "
                    "only IPv6 assigned", sess->session.name);
        }
    }

    sess->paa.session_type = sess->session.session_type;
    ogs_assert(sess->session.session_type);

    if (sess->ipv4) {
        ogs_hash_set(smf_self()->ipv4_hash,
                sess->ipv4->addr, OGS_IPV4_LEN, NULL);
        ogs_pfcp_ue_ip_free(sess->ipv4);
        sess->ipv4 = NULL;
    }
    if (sess->ipv6) {
        sess_ipv6_hash_unset(sess);
        ogs_pfcp_ue_ip_free(sess->ipv6);
        sess->ipv6 = NULL;
    }

    if (sess->session.session_type == OGS_PDU_SESSION_TYPE_IPV4) {
        sess->ipv4 = ogs_pfcp_ue_ip_alloc(&cause_value, AF_INET,
                sess->session.name, (uint8_t *)&sess->session.ue_ip.addr);
        if (!sess->ipv4) {
            ogs_error("ogs_pfcp_ue_ip_alloc() failed[%d]", cause_value);
            return cause_value;
        }
        sess->paa.addr = sess->ipv4->addr[0];
        ogs_hash_set(smf_self()->ipv4_hash,
                sess->ipv4->addr, OGS_IPV4_LEN, sess);
    } else if (sess->session.session_type == OGS_PDU_SESSION_TYPE_IPV6) {
        sess->ipv6 = ogs_pfcp_ue_ip_alloc(&cause_value, AF_INET6,
                sess->session.name, sess->session.ue_ip.addr6);
        if (!sess->ipv6) {
            ogs_error("ogs_pfcp_ue_ip_alloc() failed[%d]", cause_value);
            return cause_value;
        }

        subnet6 = sess->ipv6->subnet;
        ogs_assert(subnet6);

        sess->paa.len = OGS_IPV6_DEFAULT_PREFIX_LEN;
        memcpy(sess->paa.addr6, sess->ipv6->addr, OGS_IPV6_LEN);
        sess_ipv6_hash_set(sess);
    } else if (sess->session.session_type == OGS_PDU_SESSION_TYPE_IPV4V6) {
        sess->ipv4 = ogs_pfcp_ue_ip_alloc(&cause_value, AF_INET,
                sess->session.name, (uint8_t *)&sess->session.ue_ip.addr);
        if (!sess->ipv4) {
            ogs_error("ogs_pfcp_ue_ip_alloc() failed[%d]", cause_value);
            return cause_value;
        }
        sess->ipv6 = ogs_pfcp_ue_ip_alloc(&cause_value, AF_INET6,
                sess->session.name, sess->session.ue_ip.addr6);
        if (!sess->ipv6) {
            ogs_error("ogs_pfcp_ue_ip_alloc() failed[%d]", cause_value);
            ogs_assert(cause_value != OGS_PFCP_CAUSE_REQUEST_ACCEPTED);
            if (sess->ipv4) {
                ogs_hash_set(smf_self()->ipv4_hash,
                        sess->ipv4->addr, OGS_IPV4_LEN, NULL);
                ogs_pfcp_ue_ip_free(sess->ipv4);
                sess->ipv4 = NULL;
            }
            return cause_value;
        }

        subnet6 = sess->ipv6->subnet;
        ogs_assert(subnet6);

        sess->paa.both.addr = sess->ipv4->addr[0];
        sess->paa.both.len = OGS_IPV6_DEFAULT_PREFIX_LEN;
        memcpy(sess->paa.both.addr6, sess->ipv6->addr, OGS_IPV6_LEN);
        ogs_hash_set(smf_self()->ipv4_hash,
                sess->ipv4->addr, OGS_IPV4_LEN, sess);
        sess_ipv6_hash_set(sess);
    } else {
        ogs_fatal("Invalid sess->session.session_type[%d]",
                sess->session.session_type);
        ogs_assert_if_reached();
    }

    return cause_value;
}

void smf_sess_set_paging_n1n2message_location(
        smf_sess_t *sess, char *n1n2message_location)
{
    ogs_assert(sess);
    ogs_assert(n1n2message_location);

    if (sess->paging.n1n2message_location) {
        ogs_hash_set(self.n1n2message_hash,
                sess->paging.n1n2message_location,
                strlen(sess->paging.n1n2message_location),
                NULL);
        ogs_free(sess->paging.n1n2message_location);
    }

    sess->paging.n1n2message_location = ogs_strdup(n1n2message_location);
    ogs_assert(sess->paging.n1n2message_location);

    ogs_hash_set(self.n1n2message_hash,
            sess->paging.n1n2message_location,
            strlen(sess->paging.n1n2message_location),
            sess);
}

int smf_sess_pdr_set_ue_ip_addr(smf_sess_t *sess, ogs_pfcp_pdr_t *pdr)
{
    uint8_t prefixlen;

    ogs_assert(sess);
    ogs_assert(pdr);

    if (ogs_pfcp_paa_to_ue_ip_addr(&sess->paa,
                &pdr->ue_ip_addr, &pdr->ue_ip_addr_len) != OGS_OK)
        return OGS_ERROR;

    /* TS 29.244 8.2.62: IPv6D + IPv6 Prefix Delegation Bits tell the UPF
     * that the whole block, not only the link /64, belongs to the UE */
    prefixlen = smf_sess_ipv6_prefixlen(sess);
    if (pdr->ue_ip_addr.ipv6 &&
        prefixlen && prefixlen < OGS_IPV6_DEFAULT_PREFIX_LEN)
        return ogs_pfcp_ue_ip_addr_set_ipv6_prefixlen(
                &pdr->ue_ip_addr, &pdr->ue_ip_addr_len, prefixlen);

    return OGS_OK;
}

/*
 * Neighbour Discovery filters for the SMF link-local address L (fixed for
 * the lifetime of the process, known once smf_gtp_open() has run):
 *   permit out 58 from <solicited-node(L)>/128 to assigned
 *   permit out 58 from <L>/128 to assigned
 * Built on first use. In TS 29.212 flow descriptions "from" is the remote
 * side of the "out" (uplink) direction, i.e. the packet destination.
 */
static const char *smf_nd_flow_description(int index)
{
    static char description[2][96];
    static bool built = false;
    uint8_t link_local[OGS_IPV6_LEN], solicited[OGS_IPV6_LEN];
    char buf[OGS_ADDRSTRLEN];

    ogs_assert(index >= 0 && index < (int)OGS_ARRAY_SIZE(description));

    if (!built) {
        smf_gtp_link_local_addr(link_local);

        /* RFC 4291 section 2.7.1: ff02::1:ffXX:XXXX, low 24 bits of L */
        memset(solicited, 0, sizeof(solicited));
        solicited[0] = 0xff;
        solicited[1] = 0x02;
        solicited[11] = 0x01;
        solicited[12] = 0xff;
        memcpy(solicited + 13, link_local + 13, 3);

        ogs_snprintf(description[0], sizeof(description[0]),
                "permit out 58 from %s/128 to assigned",
                OGS_INET6_NTOP(solicited, buf));
        ogs_snprintf(description[1], sizeof(description[1]),
                "permit out 58 from %s/128 to assigned",
                OGS_INET6_NTOP(link_local, buf));
        built = true;

        ogs_info("UP2CP Neighbour Discovery filters [%s] [%s]",
                description[0], description[1]);
    }

    return description[index];
}

void smf_sess_set_up2cp_flow_description(smf_sess_t *sess)
{
    ogs_pfcp_pdr_t *up2cp_pdr = NULL;
    const char *description[] = {
        /* ICMPv6 Router Solicitation */
        "permit out 58 from ff02::2/128 to assigned",
        /*
         * DHCPv6 from the UE to the server (RFC 8415). A conformant client
         * multicasts to All_DHCP_Relay_Agents_and_Servers (ff02::1:2), but
         * because we never send OPTION_UNICAST a client may also unicast a
         * Renew/Release to the server address; RFC 8415 section 18.4
         * requires the server to answer such a message with UseMulticast.
         * Matching every uplink packet with destination port 547 (the SMF
         * is the only DHCPv6 server the UE can reach) covers both cases.
         */
        "permit out 17 from any 547 to assigned",
        /*
         * ICMPv6 Neighbour Solicitation for the gateway (RFC 4861): to the
         * solicited-node multicast address of the SMF link-local (address
         * resolution) and to the link-local itself (NUD probes).
         */
        smf_nd_flow_description(0),
        smf_nd_flow_description(1),
    };
    size_t i;

    ogs_assert(sess);
    up2cp_pdr = sess->up2cp_pdr;
    ogs_assert(up2cp_pdr);

    /* The UP2CP PDR carries nothing but these fixed filters */
    ogs_assert(up2cp_pdr->num_of_flow + (int)OGS_ARRAY_SIZE(description) <=
            OGS_MAX_NUM_OF_FLOW_IN_PDR);

    for (i = 0; i < OGS_ARRAY_SIZE(description); i++) {
        up2cp_pdr->flow[up2cp_pdr->num_of_flow].fd = 1;
        up2cp_pdr->flow[up2cp_pdr->num_of_flow].description =
            (char *)description[i];
        up2cp_pdr->num_of_flow++;
    }
}

void smf_sess_remove(smf_sess_t *sess)
{
    int i;
    smf_ue_t *smf_ue = NULL;
    smf_event_t e;

    char buf1[OGS_ADDRSTRLEN];
    char buf2[OGS_ADDRSTRLEN];

    ogs_assert(sess);
    smf_ue = smf_ue_find_by_id(sess->smf_ue_id);
    ogs_assert(smf_ue);

    ogs_info("Removed Session: UE IMSI:[%s] DNN:[%s:%d] IPv4:[%s] IPv6:[%s]",
            smf_ue->supi ? smf_ue->supi : smf_ue->imsi_bcd,
            sess->session.name, sess->psi,
            sess->ipv4 ? OGS_INET_NTOP(&sess->ipv4->addr, buf1) : "",
            sess->ipv6 ? OGS_INET6_NTOP(&sess->ipv6->addr, buf2) : "");

    ogs_list_remove(&smf_ue->sess_list, sess);

    memset(&e, 0, sizeof(e));
    e.sess_id = sess->id;
    ogs_fsm_fini(&sess->sm, &e);

    OGS_TLV_CLEAR_DATA(&sess->gtp.ue_pco);
    OGS_TLV_CLEAR_DATA(&sess->gtp.ue_apco);
    OGS_TLV_CLEAR_DATA(&sess->gtp.ue_epco);
    OGS_TLV_CLEAR_DATA(&sess->gtp.user_location_information);
    OGS_TLV_CLEAR_DATA(&sess->gtp.ue_timezone);
    OGS_TLV_CLEAR_DATA(&sess->gtp.charging_characteristics);
    OGS_TLV_CLEAR_DATA(&sess->gtp.v1.qos);

    OGS_NAS_CLEAR_DATA(&sess->nas.ue_epco);

    for (i = 0; i < sess->policy.num_of_pcc_rule; i++)
        OGS_PCC_RULE_FREE(&sess->policy.pcc_rule[i]);
    sess->policy.num_of_pcc_rule = 0;

    ogs_hash_set(self.smf_n4_seid_hash, &sess->smf_n4_seid,
            sizeof(sess->smf_n4_seid), NULL);

    if (sess->ipv4) {
        ogs_hash_set(self.ipv4_hash, sess->ipv4->addr, OGS_IPV4_LEN, NULL);
        ogs_pfcp_ue_ip_free(sess->ipv4);
    }
    if (sess->ipv6) {
        sess_ipv6_hash_unset(sess);
        ogs_pfcp_ue_ip_free(sess->ipv6);
    }

    if (sess->paging.n1n2message_location) {
        ogs_hash_set(self.n1n2message_hash,
                sess->paging.n1n2message_location,
                strlen(sess->paging.n1n2message_location),
                NULL);
        ogs_free(sess->paging.n1n2message_location);
    }

    if (sess->sm_context_ref)
        ogs_free(sess->sm_context_ref);
    if (sess->sm_context_status_uri)
        ogs_free(sess->sm_context_status_uri);
    if (sess->namf.client)
        ogs_sbi_client_remove(sess->namf.client);

    CLEAR_PDU_SESSION(sess);
    if (sess->pdu_session.client)
        ogs_sbi_client_remove(sess->pdu_session.client);

    PCF_SM_POLICY_CLEAR(sess);
    if (sess->policy_association.client)
        ogs_sbi_client_remove(sess->policy_association.client);

    UDM_SDM_CLEAR(sess);
    if (sess->data_change_subscription.client)
        ogs_sbi_client_remove(sess->data_change_subscription.client);

    if (sess->gx_sid)
        ogs_free(sess->gx_sid);
    if (sess->gy_sid)
        ogs_free(sess->gy_sid);
    if (sess->s6b_sid)
        ogs_free(sess->s6b_sid);

    if (sess->session.name)
        ogs_free(sess->session.name);
    if (sess->full_dnn)
        ogs_free(sess->full_dnn);

    if (sess->session.ipv4_framed_routes) {
        for (i = 0; i < OGS_MAX_NUM_OF_FRAMED_ROUTES_IN_PDI; i++) {
            if (!sess->session.ipv4_framed_routes[i])
                break;
            ogs_free(sess->session.ipv4_framed_routes[i]);
        }
        ogs_free(sess->session.ipv4_framed_routes);
    }
    if (sess->session.ipv6_framed_routes) {
        for (i = 0; i < OGS_MAX_NUM_OF_FRAMED_ROUTES_IN_PDI; i++) {
            if (!sess->session.ipv6_framed_routes[i])
                break;
            ogs_free(sess->session.ipv6_framed_routes[i]);
        }
        ogs_free(sess->session.ipv6_framed_routes);
    }

    if (sess->handover.local_dl_addr)
        ogs_freeaddrinfo(sess->handover.local_dl_addr);
    if (sess->handover.local_dl_addr6)
        ogs_freeaddrinfo(sess->handover.local_dl_addr6);

    if (sess->local_dl_addr)
        ogs_freeaddrinfo(sess->local_dl_addr);
    if (sess->local_dl_addr6)
        ogs_freeaddrinfo(sess->local_dl_addr6);
    if (sess->local_ul_addr)
        ogs_freeaddrinfo(sess->local_ul_addr);
    if (sess->local_ul_addr6)
        ogs_freeaddrinfo(sess->local_ul_addr6);

    if (sess->pcf_id)
        ogs_free(sess->pcf_id);
    if (sess->amf_nf_id)
        ogs_free(sess->amf_nf_id);

    /* H-SMF */
    if (sess->h_smf_uri)
        ogs_free(sess->h_smf_uri);
    if (sess->h_smf_id)
        ogs_free(sess->h_smf_id);
    if (sess->h_smf.client)
        ogs_sbi_client_remove(sess->h_smf.client);
    if (sess->vsmf_pdu_session_uri)
        ogs_free(sess->vsmf_pdu_session_uri);
    if (sess->v_smf.client)
        ogs_sbi_client_remove(sess->v_smf.client);

    if (sess->n1SmBufFromUe)
        ogs_pkbuf_free(sess->n1SmBufFromUe);

    OGS_NAS_CLEAR_DATA(&sess->h_smf_extended_protocol_configuration_options);
    sess->h_smf_gsm_cause = 0;

    CLEAR_QOS_FLOWS_SETUP_LIST(sess->h_smf_qos_flows_setup_list);
    CLEAR_QOS_FLOWS_ADD_MOD_REQUEST_LIST(
            sess->h_smf_qos_flows_add_mod_request_list);
    CLEAR_QOS_FLOWS_REL_REQUEST_LIST(sess->h_smf_qos_flows_rel_request_list);

    if (sess->pending_modification_xact)
        ogs_sbi_xact_remove(sess->pending_modification_xact);

    /* Free SBI object memory */
    ogs_sbi_object_free(&sess->sbi);

    if (sess->aaa_server_identifier.name)
        ogs_free(sess->aaa_server_identifier.name);
    if (sess->aaa_server_identifier.realm)
        ogs_free(sess->aaa_server_identifier.realm);

    smf_bearer_remove_all(sess);

    ogs_assert(sess->pfcp.bar);
    ogs_pfcp_bar_delete(sess->pfcp.bar);

    smf_sess_delete_cp_up_data_forwarding(sess);

    ogs_pfcp_pool_final(&sess->pfcp);
    smf_qfi_pool_final(sess);
    smf_pf_precedence_pool_final(sess);

    switch (sess->gtp.version) {
    case 1:
        smf_metrics_inst_global_dec(SMF_METR_GLOB_GAUGE_GTP1_PDPCTXS_ACTIVE);
        break;
    case 2:
        smf_metrics_inst_global_dec(SMF_METR_GLOB_GAUGE_GTP2_SESSIONS_ACTIVE);
        break;
    }
    smf_metrics_inst_global_dec(SMF_METR_GLOB_GAUGE_PFCP_SESSIONS_ACTIVE);
    stats_remove_smf_session(sess);

    ogs_pool_free(&smf_n4_seid_pool, sess->smf_n4_seid_node);
    ogs_pool_id_free(&smf_sess_pool, sess);
}

void smf_sess_remove_all(smf_ue_t *smf_ue)
{
    smf_sess_t *sess = NULL, *next = NULL;;

    ogs_assert(smf_ue);

    ogs_list_for_each_safe(&smf_ue->sess_list, next, sess)
        smf_sess_remove(sess);
}

smf_sess_t *smf_sess_find_by_teid(uint32_t teid)
{
    return smf_sess_find_by_seid(teid);
}

smf_sess_t *smf_sess_find_by_seid(uint64_t seid)
{
    return ogs_hash_get(self.smf_n4_seid_hash, &seid, sizeof(seid));
}

smf_sess_t *smf_sess_find_by_apn(smf_ue_t *smf_ue, char *apn, uint8_t rat_type)
{
    smf_sess_t *sess = NULL;

    ogs_assert(smf_ue);
    ogs_assert(apn);

    ogs_list_reverse_for_each(&smf_ue->sess_list, sess) {
        if (ogs_strcasecmp(sess->session.name, apn) == 0 &&
            sess->gtp_rat_type == rat_type)
            return sess;
    }

    return NULL;
}

smf_sess_t *smf_sess_find_by_psi(smf_ue_t *smf_ue, uint8_t psi)
{
    smf_sess_t *sess = NULL;

    ogs_assert(smf_ue);
    ogs_assert(psi != OGS_NAS_PDU_SESSION_IDENTITY_UNASSIGNED);

    ogs_list_reverse_for_each(&smf_ue->sess_list, sess) {
        if (sess->psi == psi)
            return sess;
    }

    return NULL;
}

smf_sess_t *smf_sess_find(uint32_t index)
{
    return ogs_pool_find(&smf_sess_pool, index);
}

smf_sess_t *smf_sess_find_by_charging_id(uint32_t charging_id)
{
    ogs_assert(charging_id);
    return smf_sess_find(charging_id);
}

smf_sess_t *smf_sess_find_by_sm_context_ref(char *sm_context_ref)
{
    ogs_assert(sm_context_ref);
    return smf_sess_find(atoll(sm_context_ref));
}

smf_sess_t *smf_sess_find_by_pdu_session_ref(char *pdu_session_ref)
{
    ogs_assert(pdu_session_ref);
    return smf_sess_find(atoll(pdu_session_ref));
}

smf_sess_t *smf_sess_find_by_ipv4(uint32_t addr)
{
    ogs_assert(self.ipv4_hash);
    return (smf_sess_t *)ogs_hash_get(self.ipv4_hash, &addr, OGS_IPV4_LEN);
}

smf_sess_t *smf_sess_find_by_ipv6(uint32_t *addr6)
{
    smf_sess_t *sess = NULL;
    ogs_pfcp_subnet_t *subnet = NULL;
    uint8_t key[(OGS_IPV6_DEFAULT_PREFIX_LEN >> 3) + 1];

    ogs_assert(self.ipv6_hash);
    ogs_assert(addr6);

    sess = (smf_sess_t *)ogs_hash_get(
            self.ipv6_hash, addr6, OGS_IPV6_DEFAULT_PREFIX_LEN >> 3);
    if (sess)
        return sess;

    /* Not a link /64: the address may sit inside a delegated block. Only
     * the block lengths configured in some subnet can be in the hash. */
    ogs_list_for_each(&ogs_pfcp_self()->subnet_list, subnet) {
        if (subnet->family != AF_INET6 || !subnet->pd_prefixlen)
            continue;
        ipv6_pd_key(key, addr6, subnet->pd_prefixlen);
        sess = (smf_sess_t *)ogs_hash_get(self.ipv6_pd_hash, key, sizeof(key));
        if (sess)
            return sess;
    }

    return NULL;
}

smf_sess_t *smf_sess_find_by_paging_n1n2message_location(
        char *n1n2message_location)
{
    ogs_assert(self.n1n2message_hash);
    ogs_assert(n1n2message_location);
    return (smf_sess_t *)ogs_hash_get(self.n1n2message_hash,
            n1n2message_location, strlen(n1n2message_location));
}

ogs_pcc_rule_t *smf_pcc_rule_find_by_id(smf_sess_t *sess, char *pcc_rule_id)
{
    int i;

    ogs_assert(sess);
    ogs_assert(pcc_rule_id);

    for (i = 0; i < sess->policy.num_of_pcc_rule; i++) {
        ogs_pcc_rule_t *pcc_rule = &sess->policy.pcc_rule[i];
        if (pcc_rule->id && strcmp(pcc_rule->id, pcc_rule_id) == 0) {
            return pcc_rule;
        }
    }

    return NULL;
}

smf_bearer_t *smf_qos_flow_add(smf_sess_t *sess)
{
    smf_bearer_t *qos_flow = NULL;

    ogs_pfcp_pdr_t *dl_pdr = NULL;
    ogs_pfcp_pdr_t *ul_pdr = NULL;
    ogs_pfcp_far_t *dl_far = NULL;
    ogs_pfcp_far_t *ul_far = NULL;
    ogs_pfcp_urr_t *urr = NULL;
    ogs_pfcp_qer_t *qer = NULL;

    ogs_assert(sess);

    ogs_pool_id_calloc(&smf_bearer_pool, &qos_flow);
    ogs_assert(qos_flow);

    smf_pf_identifier_pool_init(qos_flow);

    ogs_list_init(&qos_flow->pf_list);

    /* PDR */
    dl_pdr = ogs_pfcp_pdr_add(&sess->pfcp);
    ogs_assert(dl_pdr);
    qos_flow->dl_pdr = dl_pdr;

    ogs_assert(sess->session.name);
    dl_pdr->apn = ogs_strdup(sess->session.name);
    ogs_assert(dl_pdr->apn);

    dl_pdr->src_if = OGS_PFCP_INTERFACE_CORE;

    dl_pdr->src_if_type_presence = true;
    dl_pdr->src_if_type = OGS_PFCP_3GPP_INTERFACE_TYPE_N6;

    ul_pdr = ogs_pfcp_pdr_add(&sess->pfcp);
    ogs_assert(ul_pdr);
    qos_flow->ul_pdr = ul_pdr;

    ogs_assert(sess->session.name);
    ul_pdr->apn = ogs_strdup(sess->session.name);
    ogs_assert(ul_pdr->apn);

    ul_pdr->src_if = OGS_PFCP_INTERFACE_ACCESS;

    ul_pdr->src_if_type_presence = true;
    if (HOME_ROUTED_ROAMING_IN_HSMF(sess))
        ul_pdr->src_if_type = OGS_PFCP_3GPP_INTERFACE_TYPE_N9_FOR_ROAMING;
    else
        ul_pdr->src_if_type = OGS_PFCP_3GPP_INTERFACE_TYPE_N3_3GPP_ACCESS;

    ul_pdr->outer_header_removal_len = 1;
    ul_pdr->outer_header_removal.description =
        OGS_PFCP_OUTER_HEADER_REMOVAL_GTPU_UDP_IP;

    /* FAR */
    dl_far = ogs_pfcp_far_add(&sess->pfcp);
    ogs_assert(dl_far);
    qos_flow->dl_far = dl_far;

    ogs_assert(sess->session.name);
    dl_far->apn = ogs_strdup(sess->session.name);
    ogs_assert(dl_far->apn);

    dl_far->dst_if = OGS_PFCP_INTERFACE_ACCESS;

    dl_far->dst_if_type_presence = true;
    if (HOME_ROUTED_ROAMING_IN_HSMF(sess))
        dl_far->dst_if_type = OGS_PFCP_3GPP_INTERFACE_TYPE_N9_FOR_ROAMING;
    else
        dl_far->dst_if_type = OGS_PFCP_3GPP_INTERFACE_TYPE_N3_3GPP_ACCESS;

    ogs_pfcp_pdr_associate_far(dl_pdr, dl_far);

    dl_far->apply_action =
        OGS_PFCP_APPLY_ACTION_BUFF| OGS_PFCP_APPLY_ACTION_NOCP;
    ogs_assert(sess->pfcp.bar);

    ul_far = ogs_pfcp_far_add(&sess->pfcp);
    ogs_assert(ul_far);
    qos_flow->ul_far = ul_far;

    ogs_assert(sess->session.name);
    ul_far->apn = ogs_strdup(sess->session.name);
    ogs_assert(ul_far->apn);

    ul_far->dst_if = OGS_PFCP_INTERFACE_CORE;

    ul_far->dst_if_type_presence = true;
    ul_far->dst_if_type = OGS_PFCP_3GPP_INTERFACE_TYPE_N6;

    ogs_pfcp_pdr_associate_far(ul_pdr, ul_far);

    ul_far->apply_action = OGS_PFCP_APPLY_ACTION_FORW;

    /* URR */
    urr = ogs_pfcp_urr_add(&sess->pfcp);
    ogs_assert(urr);
    qos_flow->urr = urr;

    urr->meas_method = OGS_PFCP_MEASUREMENT_METHOD_VOLUME;
    urr->rep_triggers.volume_threshold = 1;
    urr->vol_threshold.tovol = 1;
    urr->vol_threshold.total_volume = 1024*1024*100;

    ogs_pfcp_pdr_associate_urr(dl_pdr, urr);

    /* QER */
    qer = ogs_pfcp_qer_add(&sess->pfcp);
    ogs_assert(qer);
    qos_flow->qer = qer;

    ogs_pfcp_pdr_associate_qer(dl_pdr, qer);
    ogs_pfcp_pdr_associate_qer(ul_pdr, qer);

    /* Allocate QFI */
    ogs_pool_alloc(&sess->qfi_pool, &qos_flow->qfi_node);
    ogs_assert(qos_flow->qfi_node);

    qos_flow->qfi = ul_pdr->qfi = qer->qfi = *(qos_flow->qfi_node);

    qos_flow->sess_id = sess->id;

    ogs_list_add(&sess->bearer_list, qos_flow);
    smf_metrics_inst_by_5qi_add(&sess->serving_plmn_id, &sess->s_nssai,
            sess->session.qos.index, SMF_METR_GAUGE_SM_QOSFLOWNBR, 1);
    smf_metrics_inst_global_inc(SMF_METR_GLOB_GAUGE_BEARERS_ACTIVE);

    return qos_flow;
}

smf_bearer_t *smf_vcn_tunnel_add(smf_sess_t *sess)
{
    smf_bearer_t *qos_flow = NULL;

    ogs_pfcp_pdr_t *dl_pdr = NULL;
    ogs_pfcp_pdr_t *ul_pdr = NULL;
    ogs_pfcp_far_t *dl_far = NULL;
    ogs_pfcp_far_t *ul_far = NULL;

    ogs_assert(sess);

    ogs_pool_id_calloc(&smf_bearer_pool, &qos_flow);
    ogs_assert(qos_flow);

    /*
     * Since smf_pf_identifier_pool_final() is executed by smf_bearer_remove(),
     * so even if there is no PF Rule in vcnTunnel,
     * we at least need to initialize it using smf_pf_identifier_pool_init().
     */
    smf_pf_identifier_pool_init(qos_flow);

    ogs_list_init(&qos_flow->pf_list);

    /* PDR */
    dl_pdr = ogs_pfcp_pdr_add(&sess->pfcp);
    ogs_assert(dl_pdr);
    qos_flow->dl_pdr = dl_pdr;

    ogs_assert(sess->session.name);
    dl_pdr->apn = ogs_strdup(sess->session.name);
    ogs_assert(dl_pdr->apn);

    dl_pdr->src_if = OGS_PFCP_INTERFACE_CORE;

    dl_pdr->src_if_type_presence = true;
    dl_pdr->src_if_type = OGS_PFCP_3GPP_INTERFACE_TYPE_N9_FOR_ROAMING;

    ul_pdr = ogs_pfcp_pdr_add(&sess->pfcp);
    ogs_assert(ul_pdr);
    qos_flow->ul_pdr = ul_pdr;

    ogs_assert(sess->session.name);
    ul_pdr->apn = ogs_strdup(sess->session.name);
    ogs_assert(ul_pdr->apn);

    ul_pdr->src_if = OGS_PFCP_INTERFACE_ACCESS;

    ul_pdr->src_if_type_presence = true;
    ul_pdr->src_if_type = OGS_PFCP_3GPP_INTERFACE_TYPE_N3_3GPP_ACCESS;

    /* FAR */
    dl_far = ogs_pfcp_far_add(&sess->pfcp);
    ogs_assert(dl_far);
    qos_flow->dl_far = dl_far;

    ogs_assert(sess->session.name);
    dl_far->apn = ogs_strdup(sess->session.name);
    ogs_assert(dl_far->apn);

    dl_far->dst_if = OGS_PFCP_INTERFACE_ACCESS;

    dl_far->dst_if_type_presence = true;
    dl_far->dst_if_type = OGS_PFCP_3GPP_INTERFACE_TYPE_N3_3GPP_ACCESS;

    ogs_pfcp_pdr_associate_far(dl_pdr, dl_far);

    ogs_assert(sess->pfcp.bar);
    dl_far->apply_action =
        OGS_PFCP_APPLY_ACTION_BUFF| OGS_PFCP_APPLY_ACTION_NOCP;

    ul_far = ogs_pfcp_far_add(&sess->pfcp);
    ogs_assert(ul_far);
    qos_flow->ul_far = ul_far;

    ogs_assert(sess->session.name);
    ul_far->apn = ogs_strdup(sess->session.name);
    ogs_assert(ul_far->apn);

    ul_far->dst_if = OGS_PFCP_INTERFACE_CORE;

    ul_far->dst_if_type_presence = true;
    ul_far->dst_if_type = OGS_PFCP_3GPP_INTERFACE_TYPE_N9_FOR_ROAMING;

    ogs_pfcp_pdr_associate_far(ul_pdr, ul_far);

    ul_far->apply_action =
        OGS_PFCP_APPLY_ACTION_BUFF| OGS_PFCP_APPLY_ACTION_NOCP;

    /* URR --- SKIPPED */

    /* QER --- SKIPPED */

    qos_flow->sess_id = sess->id;

    ogs_list_add(&sess->bearer_list, qos_flow);

    return qos_flow;
}

void smf_sess_create_indirect_data_forwarding(smf_sess_t *sess)
{
    smf_bearer_t *qos_flow = NULL;

    ogs_assert(sess);

    ogs_list_for_each(&sess->bearer_list, qos_flow) {
        ogs_pfcp_pdr_t *pdr = NULL;
        ogs_pfcp_far_t *far = NULL;
        ogs_pfcp_qer_t *qer = NULL;

        ogs_assert(sess);

        pdr = ogs_pfcp_pdr_add(&sess->pfcp);
        ogs_assert(pdr);

        ogs_assert(sess->session.name);
        pdr->apn = ogs_strdup(sess->session.name);
        ogs_assert(pdr->apn);

        pdr->src_if = OGS_PFCP_INTERFACE_ACCESS;

        pdr->src_if_type_presence = true;
        pdr->src_if_type =
            OGS_PFCP_3GPP_INTERFACE_TYPE_SGW_UPF_GTP_U_FOR_UL_DATA_FORWARDING;

        pdr->outer_header_removal_len = 1;
        pdr->outer_header_removal.description =
            OGS_PFCP_OUTER_HEADER_REMOVAL_GTPU_UDP_IP;

        far = ogs_pfcp_far_add(&sess->pfcp);
        ogs_assert(far);

        ogs_assert(sess->session.name);
        far->apn = ogs_strdup(sess->session.name);
        ogs_assert(far->apn);

        far->dst_if = OGS_PFCP_INTERFACE_ACCESS;

        far->dst_if_type_presence = true;
        far->dst_if_type =
            OGS_PFCP_3GPP_INTERFACE_TYPE_SGW_UPF_GTP_U_FOR_DL_DATA_FORWARDING;

        ogs_pfcp_pdr_associate_far(pdr, far);

        far->apply_action = OGS_PFCP_APPLY_ACTION_FORW;

        qer = qos_flow->qer;
        if (qer) {
            ogs_pfcp_pdr_associate_qer(pdr, qer);

            pdr->qfi = qos_flow->qfi;
        }

        ogs_assert(sess->pfcp_node);
        if (sess->pfcp_node->up_function_features.ftup) {

           /* TS 129 244 V16.5.0 8.2.3
            *
            * At least one of the V4 and V6 flags shall be set to "1",
            * and both may be set to "1" for both scenarios:
            *
            * - when the CP function is providing F-TEID, i.e.
            *   both IPv4 address field and IPv6 address field may be present;
            *   or
            * - when the UP function is requested to allocate the F-TEID,
            *   i.e. when CHOOSE bit is set to "1",
            *   and the IPv4 address and IPv6 address fields are not present.
            */

            pdr->f_teid.ipv4 = 1;
            pdr->f_teid.ipv6 = 1;
            pdr->f_teid.ch = 1;
            pdr->f_teid.chid = 1;
            pdr->f_teid.choose_id = OGS_PFCP_INDIRECT_DATA_FORWARDING_CHOOSE_ID;
            pdr->f_teid_len = 2;
        } else {
            /*
             * CHOOSE_ID is set in INDIRECT so that all PDRs must be set
             * to the same TEID.
             *
             * If sess->handover.local_dl_teid is set in the PDR of
             * the first QoS flow, the PDRs of the remaining QoS flows use
             * the same TEID.
             */
            if (ogs_list_first(&sess->bearer_list) == qos_flow) {
                if (sess->handover.local_dl_addr)
                    ogs_freeaddrinfo(sess->handover.local_dl_addr);
                if (sess->handover.local_dl_addr6)
                    ogs_freeaddrinfo(sess->handover.local_dl_addr6);

                ogs_assert(sess->pfcp_node->addr_list);
                if (sess->pfcp_node->addr_list->ogs_sa_family == AF_INET)
                    ogs_assert(OGS_OK == ogs_copyaddrinfo(
                        &sess->handover.local_dl_addr,
                        sess->pfcp_node->addr_list));
                else if (sess->pfcp_node->addr_list->ogs_sa_family ==
                        AF_INET6)
                    ogs_assert(OGS_OK == ogs_copyaddrinfo(
                        &sess->handover.local_dl_addr6,
                        sess->pfcp_node->addr_list));
                else
                    ogs_assert_if_reached();

                sess->handover.local_dl_teid = pdr->teid;
            }

            ogs_assert(OGS_OK ==
                ogs_pfcp_sockaddr_to_f_teid(
                    sess->handover.local_dl_addr, sess->handover.local_dl_addr6,
                    &pdr->f_teid, &pdr->f_teid_len));
            pdr->f_teid.teid = sess->handover.local_dl_teid;
        }

        ogs_assert(OGS_OK ==
            ogs_pfcp_ip_to_outer_header_creation(
                    &sess->handover.remote_dl_ip,
                    &far->outer_header_creation,
                    &far->outer_header_creation_len));
        far->outer_header_creation.teid = sess->handover.remote_dl_teid;

        /* Indirect Data Forwarding PDRs is set to highest precedence
         * (lowest precedence value) */
        pdr->precedence = OGS_PFCP_INDIRECT_PDR_PRECEDENCE;
    }
}

bool smf_sess_have_indirect_data_forwarding(smf_sess_t *sess)
{
    ogs_pfcp_pdr_t *pdr = NULL;

    ogs_assert(sess);

    ogs_list_for_each(&sess->pfcp.pdr_list, pdr) {
        ogs_pfcp_far_t *far = pdr->far;

        ogs_assert(far);

        if ((pdr->src_if == OGS_PFCP_INTERFACE_ACCESS) &&
            (far->dst_if == OGS_PFCP_INTERFACE_ACCESS)) {
            return true;
        }
    }

    return false;
}

void smf_sess_delete_indirect_data_forwarding(smf_sess_t *sess)
{
    ogs_pfcp_pdr_t *pdr = NULL;

    ogs_assert(sess);

    /*
     * Indirect tunnel PDR/FARs are only identified by ACCESS -> ACCESS,
     * so this deletes whichever tunnel the session holds now.
     * A session holds one tunnel at a time.
     */
    ogs_list_for_each(&sess->pfcp.pdr_list, pdr) {
        ogs_pfcp_far_t *far = pdr->far;

        ogs_assert(far);

        if ((pdr->src_if == OGS_PFCP_INTERFACE_ACCESS) &&
            (far->dst_if == OGS_PFCP_INTERFACE_ACCESS)) {
            ogs_pfcp_pdr_remove(pdr);
            ogs_pfcp_far_remove(far);
        }
    }
}

void smf_sess_create_cp_up_data_forwarding(smf_sess_t *sess)
{
    smf_bearer_t *qos_flow = NULL;

    ogs_pfcp_pdr_t *cp2up_pdr = NULL;
    ogs_pfcp_pdr_t *up2cp_pdr = NULL;
    ogs_pfcp_far_t *cp2up_far = NULL;
    ogs_pfcp_far_t *up2cp_far = NULL;

    ogs_assert(sess);
    ogs_assert(sess->session.name);

    smf_sess_delete_cp_up_data_forwarding(sess);

    cp2up_pdr = ogs_pfcp_pdr_add(&sess->pfcp);
    ogs_assert(cp2up_pdr);
    sess->cp2up_pdr = cp2up_pdr;

    if (ogs_global_conf()->parameter.use_upg_vpp == true) {
        cp2up_pdr->apn = ogs_strdup(sess->session.name);
        ogs_assert(cp2up_pdr->apn);
    }

    cp2up_pdr->src_if = OGS_PFCP_INTERFACE_CP_FUNCTION;

    cp2up_pdr->outer_header_removal_len = 1;
    cp2up_pdr->outer_header_removal.description =
        OGS_PFCP_OUTER_HEADER_REMOVAL_GTPU_UDP_IP;

    up2cp_pdr = ogs_pfcp_pdr_add(&sess->pfcp);
    ogs_assert(up2cp_pdr);
    sess->up2cp_pdr = up2cp_pdr;

    up2cp_pdr->apn = ogs_strdup(sess->session.name);
    ogs_assert(up2cp_pdr->apn);

    up2cp_pdr->src_if = OGS_PFCP_INTERFACE_ACCESS;

    up2cp_pdr->src_if_type_presence = true;
    if (HOME_ROUTED_ROAMING_IN_HSMF(sess))
        up2cp_pdr->src_if_type = OGS_PFCP_3GPP_INTERFACE_TYPE_N9_FOR_ROAMING;
    else
        up2cp_pdr->src_if_type = OGS_PFCP_3GPP_INTERFACE_TYPE_N3_3GPP_ACCESS;

    up2cp_pdr->outer_header_removal_len = 1;
    up2cp_pdr->outer_header_removal.description =
        OGS_PFCP_OUTER_HEADER_REMOVAL_GTPU_UDP_IP;

    qos_flow = smf_default_bearer_in_sess(sess);
    ogs_assert(qos_flow);
    ogs_assert(ogs_list_next(qos_flow) == NULL);

    /* We'll use the DL-FAR for CP2UP-FAR */
    cp2up_far = qos_flow->dl_far;
    ogs_assert(cp2up_far);
    ogs_pfcp_pdr_associate_far(cp2up_pdr, cp2up_far);
    sess->cp2up_far = cp2up_far;

    up2cp_far = ogs_pfcp_far_add(&sess->pfcp);
    ogs_assert(up2cp_far);
    sess->up2cp_far = up2cp_far;

    if (ogs_global_conf()->parameter.use_upg_vpp == true) {
        up2cp_far->apn = ogs_strdup(sess->session.name);
        ogs_assert(up2cp_far->apn);
    }

    up2cp_far->dst_if = OGS_PFCP_INTERFACE_CP_FUNCTION;
    ogs_pfcp_pdr_associate_far(up2cp_pdr, up2cp_far);

    up2cp_far->apply_action = OGS_PFCP_APPLY_ACTION_FORW;

#if 0
    /*
     * MODIFIED the PDI matching for UP2CP
     * to not distinguish the QoS Flow Identifier.
     *
     * When omitted, the UPF was also adjusted to not compare the QFI.
     */
    if (qos_flow->qer && qos_flow->qfi) {
        /* To match the PDI of UP2CP_PDR(from ff02::2/128 to assigned)
         * Router-Solicitation has QFI in the Extended Header */
        up2cp_pdr->qfi = qos_flow->qfi;

        /* When UPF sends router advertisement to gNB,
         * it includes QFI in extension header */
        ogs_pfcp_pdr_associate_qer(cp2up_pdr, qos_flow->qer);
    }
#endif
}

void smf_sess_delete_cp_up_data_forwarding(smf_sess_t *sess)
{
    ogs_assert(sess);

    if (sess->cp2up_pdr)
        ogs_pfcp_pdr_remove(sess->cp2up_pdr);
    if (sess->up2cp_pdr)
        ogs_pfcp_pdr_remove(sess->up2cp_pdr);

    /* CP2UP-FAR == DL-FAR in Default QoS Flow
     * Should not remove CP2UP-FAR here */
    if (sess->up2cp_far)
        ogs_pfcp_far_remove(sess->up2cp_far);
}

smf_bearer_t *smf_qos_flow_find_by_qfi(smf_sess_t *sess, uint8_t qfi)
{
    smf_bearer_t *qos_flow = NULL;

    ogs_assert(sess);
    ogs_list_for_each(&sess->bearer_list, qos_flow) {
        if (qos_flow->qfi == qfi)
            return qos_flow;
    }

    return qos_flow;
}

smf_bearer_t *smf_qos_flow_find_by_pcc_rule_id(
        smf_sess_t *sess, char *pcc_rule_id)
{
    smf_bearer_t *qos_flow = NULL;

    ogs_assert(sess);
    ogs_assert(pcc_rule_id);

    ogs_list_for_each(&sess->bearer_list, qos_flow) {
        if (qos_flow->pcc_rule.id &&
            strcmp(qos_flow->pcc_rule.id, pcc_rule_id) == 0)
            return qos_flow;
    }

    return NULL;
}

smf_bearer_t *smf_bearer_add(smf_sess_t *sess)
{
    smf_bearer_t *bearer = NULL;

    ogs_pfcp_pdr_t *dl_pdr = NULL;
    ogs_pfcp_pdr_t *ul_pdr = NULL;
    ogs_pfcp_far_t *dl_far = NULL;
    ogs_pfcp_far_t *ul_far = NULL;

    ogs_assert(sess);

    ogs_pool_id_calloc(&smf_bearer_pool, &bearer);
    ogs_assert(bearer);

    smf_pf_identifier_pool_init(bearer);

    ogs_list_init(&bearer->pf_list);

    /* PDR */
    dl_pdr = ogs_pfcp_pdr_add(&sess->pfcp);
    ogs_assert(dl_pdr);
    bearer->dl_pdr = dl_pdr;

    ogs_assert(sess->session.name);
    dl_pdr->apn = ogs_strdup(sess->session.name);
    ogs_assert(dl_pdr->apn);

    dl_pdr->src_if = OGS_PFCP_INTERFACE_CORE;

    dl_pdr->src_if_type_presence = true;
    dl_pdr->src_if_type = OGS_PFCP_3GPP_INTERFACE_TYPE_N6;

    ul_pdr = ogs_pfcp_pdr_add(&sess->pfcp);
    ogs_assert(ul_pdr);
    bearer->ul_pdr = ul_pdr;

    ogs_assert(sess->session.name);
    ul_pdr->apn = ogs_strdup(sess->session.name);
    ogs_assert(ul_pdr->apn);

    ul_pdr->src_if = OGS_PFCP_INTERFACE_ACCESS;

    ul_pdr->src_if_type_presence = true;
    ul_pdr->src_if_type = OGS_PFCP_3GPP_INTERFACE_TYPE_N3_3GPP_ACCESS;

    ul_pdr->outer_header_removal_len = 1;
    ul_pdr->outer_header_removal.description =
        OGS_PFCP_OUTER_HEADER_REMOVAL_GTPU_UDP_IP;

    /* FAR */
    dl_far = ogs_pfcp_far_add(&sess->pfcp);
    ogs_assert(dl_far);
    bearer->dl_far = dl_far;

    ogs_assert(sess->session.name);
    dl_far->apn = ogs_strdup(sess->session.name);
    ogs_assert(dl_far->apn);

    dl_far->dst_if = OGS_PFCP_INTERFACE_ACCESS;

    dl_far->dst_if_type_presence = true;
    dl_far->dst_if_type = OGS_PFCP_3GPP_INTERFACE_TYPE_N3_3GPP_ACCESS;

    ogs_pfcp_pdr_associate_far(dl_pdr, dl_far);

    dl_far->apply_action =
        OGS_PFCP_APPLY_ACTION_BUFF| OGS_PFCP_APPLY_ACTION_NOCP;
    ogs_assert(sess->pfcp.bar);

    ul_far = ogs_pfcp_far_add(&sess->pfcp);
    ogs_assert(ul_far);
    bearer->ul_far = ul_far;

    ogs_assert(sess->session.name);
    ul_far->apn = ogs_strdup(sess->session.name);
    ogs_assert(ul_far->apn);

    ul_far->dst_if = OGS_PFCP_INTERFACE_CORE;

    ul_far->dst_if_type_presence = true;
    ul_far->dst_if_type = OGS_PFCP_3GPP_INTERFACE_TYPE_N6;

    ogs_pfcp_pdr_associate_far(ul_pdr, ul_far);

    ul_far->apply_action = OGS_PFCP_APPLY_ACTION_FORW;

    bearer->sess_id = sess->id;

    ogs_list_add(&sess->bearer_list, bearer);

    smf_metrics_inst_global_inc(SMF_METR_GLOB_GAUGE_BEARERS_ACTIVE);
    return bearer;
}

int smf_bearer_remove(smf_bearer_t *bearer)
{
    smf_sess_t *sess = NULL;
    ogs_assert(bearer);
    sess = smf_sess_find_by_id(bearer->sess_id);
    ogs_assert(sess);

    ogs_list_remove(&sess->bearer_list, bearer);

    ogs_assert(bearer->dl_pdr);
    ogs_pfcp_pdr_remove(bearer->dl_pdr);
    ogs_assert(bearer->ul_pdr);
    ogs_pfcp_pdr_remove(bearer->ul_pdr);
    ogs_assert(bearer->dl_far);
    ogs_pfcp_far_remove(bearer->dl_far);
    ogs_assert(bearer->ul_far);
    ogs_pfcp_far_remove(bearer->ul_far);
    if (bearer->urr)
        ogs_pfcp_urr_remove(bearer->urr);
    if (bearer->qer)
        ogs_pfcp_qer_remove(bearer->qer);

    if (bearer->pcc_rule.name)
        ogs_free(bearer->pcc_rule.name);
    if (bearer->pcc_rule.id)
        ogs_free(bearer->pcc_rule.id);
    if (bearer->pgw_s5u_addr)
        ogs_freeaddrinfo(bearer->pgw_s5u_addr);
    if (bearer->pgw_s5u_addr6)
        ogs_freeaddrinfo(bearer->pgw_s5u_addr6);

    smf_pf_remove_all(bearer);

    smf_pf_identifier_pool_final(bearer);

    if (SMF_IS_QOF_FLOW(bearer))
        ogs_pool_free(&sess->qfi_pool, bearer->qfi_node);

    ogs_pool_id_free(&smf_bearer_pool, bearer);

    smf_metrics_inst_global_dec(SMF_METR_GLOB_GAUGE_BEARERS_ACTIVE);
    return OGS_OK;
}

void smf_bearer_remove_all(smf_sess_t *sess)
{
    smf_bearer_t *bearer = NULL, *next_bearer = NULL;

    ogs_assert(sess);
    ogs_list_for_each_safe(&sess->bearer_list, next_bearer, bearer)
        smf_bearer_remove(bearer);
}

smf_bearer_t *smf_bearer_find_by_pgw_s5u_teid(
        smf_sess_t *sess, uint32_t pgw_s5u_teid)
{
    smf_bearer_t *bearer = NULL;

    ogs_assert(sess);

    ogs_list_for_each(&sess->bearer_list, bearer) {
        if (bearer->pgw_s5u_teid == pgw_s5u_teid)
            return bearer;
    }

    return NULL;
}

smf_bearer_t *smf_bearer_find_by_ebi(smf_sess_t *sess, uint8_t ebi)
{
    smf_bearer_t *bearer = NULL;

    ogs_assert(sess);

    ogs_list_for_each(&sess->bearer_list, bearer) {
        if (bearer->ebi == ebi)
            return bearer;
    }

    return NULL;
}

smf_bearer_t *smf_bearer_find_by_pcc_rule_name(
        smf_sess_t *sess, char *pcc_rule_name)
{
    smf_bearer_t *bearer = NULL;

    ogs_assert(sess);
    ogs_assert(pcc_rule_name);

    ogs_list_for_each(&sess->bearer_list, bearer) {
        if (bearer->pcc_rule.name &&
            strcmp(bearer->pcc_rule.name, pcc_rule_name) == 0)
            return bearer;
    }

    return NULL;
}

smf_bearer_t *smf_bearer_find_by_pdr_id(
        smf_sess_t *sess, ogs_pfcp_pdr_id_t pdr_id)
{
    smf_bearer_t *bearer = NULL;

    ogs_assert(sess);

    ogs_list_for_each(&sess->bearer_list, bearer) {
        ogs_pfcp_pdr_t *dl_pdr = NULL;
        ogs_pfcp_pdr_t *ul_pdr = NULL;

        dl_pdr = bearer->dl_pdr;
        ogs_assert(dl_pdr);
        ul_pdr = bearer->ul_pdr;
        ogs_assert(ul_pdr);

        if (dl_pdr->id == pdr_id || ul_pdr->id == pdr_id)
            return bearer;
    }

    return NULL;
}

void smf_bearer_tft_update(smf_bearer_t *bearer)
{
    smf_pf_t *pf = NULL;
    ogs_pfcp_pdr_t *dl_pdr = NULL, *ul_pdr = NULL;

    ogs_assert(bearer);

    dl_pdr = bearer->dl_pdr;
    ogs_assert(dl_pdr);
    ul_pdr = bearer->ul_pdr;
    ogs_assert(ul_pdr);

    dl_pdr->num_of_flow = 0;
    ul_pdr->num_of_flow = 0;

    ogs_list_for_each(&bearer->pf_list, pf) {
        if (pf->direction == OGS_FLOW_DOWNLINK_ONLY) {
            dl_pdr->flow[dl_pdr->num_of_flow].fd = 1;
            dl_pdr->flow[dl_pdr->num_of_flow].description =
                pf->flow_description;
            dl_pdr->num_of_flow++;
        } else if (pf->direction == OGS_FLOW_UPLINK_ONLY) {
            ul_pdr->flow[ul_pdr->num_of_flow].fd = 1;
            ul_pdr->flow[ul_pdr->num_of_flow].description =
                pf->flow_description;
            ul_pdr->num_of_flow++;
        } else if (pf->direction == OGS_FLOW_BIDIRECTIONAL) {
            dl_pdr->flow[dl_pdr->num_of_flow].fd = 1;
            dl_pdr->flow[dl_pdr->num_of_flow].description =
                pf->flow_description;
            dl_pdr->flow[dl_pdr->num_of_flow].bid = 1;
            dl_pdr->flow[dl_pdr->num_of_flow].sdf_filter_id = pf->sdf_filter_id;
            dl_pdr->num_of_flow++;
            ul_pdr->flow[ul_pdr->num_of_flow].bid = 1;
            ul_pdr->flow[ul_pdr->num_of_flow].sdf_filter_id = pf->sdf_filter_id;
            ul_pdr->num_of_flow++;
        } else {
            ogs_fatal("Unsupported direction [%d]", pf->direction);
            ogs_assert_if_reached();
        }
    }
}

void smf_bearer_qos_update(smf_bearer_t *bearer)
{
    smf_sess_t *sess = NULL;

    ogs_pfcp_pdr_t *dl_pdr = NULL, *ul_pdr = NULL;
    ogs_pfcp_qer_t *qer = NULL;

    ogs_assert(bearer);
    sess = smf_sess_find_by_id(bearer->sess_id);
    ogs_assert(sess);

    dl_pdr = bearer->dl_pdr;
    ogs_assert(dl_pdr);
    ul_pdr = bearer->ul_pdr;
    ogs_assert(ul_pdr);

    qer = bearer->qer;
    if (!qer) {
        qer = ogs_pfcp_qer_add(&sess->pfcp);
        ogs_assert(qer);
        bearer->qer = qer;
    }

    ogs_pfcp_pdr_associate_qer(dl_pdr, qer);
    ogs_pfcp_pdr_associate_qer(ul_pdr, qer);

    qer->mbr.uplink = bearer->qos.mbr.uplink;
    qer->mbr.downlink = bearer->qos.mbr.downlink;
    qer->gbr.uplink = bearer->qos.gbr.uplink;
    qer->gbr.downlink = bearer->qos.gbr.downlink;
}

smf_bearer_t *smf_default_bearer_in_sess(smf_sess_t *sess)
{
    ogs_assert(sess);
    return ogs_list_first(&sess->bearer_list);
}

smf_ue_t *smf_ue_find_by_id(ogs_pool_id_t id)
{
    return ogs_pool_find_by_id(&smf_ue_pool, id);
}

smf_sess_t *smf_sess_find_by_id(ogs_pool_id_t id)
{
    return ogs_pool_find_by_id(&smf_sess_pool, id);
}

smf_bearer_t *smf_bearer_find_by_id(ogs_pool_id_t id)
{
    return ogs_pool_find_by_id(&smf_bearer_pool, id);
}

smf_bearer_t *smf_qos_flow_find_by_id(ogs_pool_id_t id)
{
    return ogs_pool_find_by_id(&smf_bearer_pool, id);
}

smf_pf_t *smf_pf_find_by_id(ogs_pool_id_t id)
{
    return ogs_pool_find_by_id(&smf_pf_pool, id);
}

smf_pf_t *smf_pf_add(smf_bearer_t *bearer)
{
    smf_sess_t *sess = NULL;
    smf_pf_t *pf = NULL;

    ogs_assert(bearer);
    sess = smf_sess_find_by_id(bearer->sess_id);
    ogs_assert(sess);

    ogs_pool_id_calloc(&smf_pf_pool, &pf);
    ogs_assert(pf);

    ogs_pool_alloc(&bearer->pf_identifier_pool, &pf->identifier_node);
    if (!pf->identifier_node) {
        ogs_error("smf_pf_add: Expectation `pf->identifier_node' failed");
        ogs_pool_id_free(&smf_pf_pool, pf);
        return NULL;
    }

    pf->identifier = *(pf->identifier_node);
    ogs_assert(pf->identifier > 0 && pf->identifier <=
            OGS_MAX_NUM_OF_FLOW_IN_BEARER);

    ogs_pool_alloc(&sess->pf_precedence_pool, &pf->precedence_node);
    if (!pf->precedence_node) {
        ogs_error("smf_pf_add: Expectation `pf->precedence_node' failed");
        ogs_pool_free(&bearer->pf_identifier_pool, pf->identifier_node);
        ogs_pool_id_free(&smf_pf_pool, pf);
        return NULL;
    }

    pf->precedence = *(pf->precedence_node);
    ogs_assert(pf->precedence > 0 && pf->precedence <=
            (OGS_MAX_NUM_OF_BEARER * OGS_MAX_NUM_OF_FLOW_IN_BEARER));

    /* Re-use 'pf_precedence_pool' to generate SDF Filter ID */
    pf->sdf_filter_id = *(pf->precedence_node);

    pf->bearer_id = bearer->id;

    ogs_list_add(&bearer->pf_list, pf);

    return pf;
}

int smf_pf_remove(smf_pf_t *pf)
{
    smf_sess_t *sess = NULL;
    smf_bearer_t *bearer = NULL;

    ogs_assert(pf);
    bearer = smf_bearer_find_by_id(pf->bearer_id);
    ogs_assert(bearer);
    sess = smf_sess_find_by_id(bearer->sess_id);
    ogs_assert(sess);

    ogs_list_remove(&bearer->pf_list, pf);
    if (pf->flow_description)
        ogs_free(pf->flow_description);

    if (pf->identifier_node)
        ogs_pool_free(&bearer->pf_identifier_pool, pf->identifier_node);
    if (pf->precedence_node)
        ogs_pool_free(
                &sess->pf_precedence_pool, pf->precedence_node);

    ogs_pool_id_free(&smf_pf_pool, pf);

    return OGS_OK;
}

void smf_pf_remove_all(smf_bearer_t *bearer)
{
    smf_pf_t *pf = NULL, *next_pf = NULL;

    ogs_assert(bearer);
    ogs_list_for_each_safe(&bearer->pf_list, next_pf, pf)
        smf_pf_remove(pf);
}

smf_pf_t *smf_pf_find_by_identifier(
        smf_bearer_t *bearer, uint8_t identifier)
{
    smf_pf_t *pf = NULL;

    ogs_list_for_each(&bearer->pf_list, pf) {
        if (pf->identifier == identifier) return pf;
    }

    return NULL;
}

smf_pf_t *smf_pf_find_by_flow(
    smf_bearer_t *bearer, uint8_t direction, char *flow_description)
{
    smf_pf_t *pf = NULL;

    ogs_list_for_each(&bearer->pf_list, pf) {
        if ((pf->direction == direction) &&
            (!strcmp(pf->flow_description, flow_description))) {
            return pf;
        }
    }

    return NULL;
}

smf_pf_t *smf_pf_first(smf_bearer_t *bearer)
{
    return ogs_list_first(&bearer->pf_list);
}

smf_pf_t *smf_pf_next(smf_pf_t *pf)
{
    return ogs_list_next(pf);
}

/*
 * The following code is stolen from osmo-ggsn.
 * https://github.com/osmocom/osmo-ggsn/blob/master/ggsn/pco.c#L26-L43
 */

/* determine if IPCP contains given option */
static const uint8_t *ipcp_contains_option(
    const ogs_pco_ipcp_t *ipcp, size_t ipcp_len,
    enum ogs_pco_ipcp_options opt, size_t opt_minlen)
{
    const uint8_t *cur_opt = (const uint8_t *)ipcp->options;

    /* iterate over Options and check if protocol contained */
    while (cur_opt + sizeof(struct ogs_pco_ipcp_options_s) <=
            (uint8_t*)ipcp + ipcp_len) {
        const struct ogs_pco_ipcp_options_s *cur_opt_hdr =
            (const struct ogs_pco_ipcp_options_s *)cur_opt;
        /* length value includes 2 bytes type/length */
        if (cur_opt_hdr->len < 2)
            return NULL;
        if (cur_opt_hdr->type == opt &&
            cur_opt_hdr->len >= 2 + opt_minlen)
            return cur_opt;
        cur_opt += cur_opt_hdr->len;
    }
    return NULL;
}

#include "../version.h"
static const char *pap_welcome = "Welcome to open5gs-smfd " OPEN5GS_VERSION;

int smf_pco_build(uint8_t *pco_buf, uint8_t *buffer, int length)
{
    int rv;
    ogs_pco_t ue, smf;
    ogs_pco_pap_t pco_pap;
    ogs_pco_chap_t pco_chap;
#define OGS_PCO_MAX_NUM_OF_IPCP 4
    ogs_pco_ipcp_t pco_ipcp[OGS_PCO_MAX_NUM_OF_IPCP];
    int num_of_ipcp;
    int pco_size = 0;
    ogs_ipsubnet_t dns_primary, dns_secondary, dns6_primary, dns6_secondary;
    ogs_ipsubnet_t p_cscf, p_cscf6;
    int size = 0;
    int i = 0;
    uint16_t mtu = 0;

    ogs_assert(pco_buf);
    ogs_assert(buffer);
    ogs_assert(length);

    num_of_ipcp = 0;
    memset(&pco_ipcp, 0, sizeof(pco_ipcp));

    size = ogs_pco_parse(&ue, buffer, length);
    if (size != length) {
        ogs_error("ogs_pco_parse() failed [size:%d != length:%d]",
                size, length);
        return 0;
    }

    memset(&smf, 0, sizeof(ogs_pco_t));
    smf.ext = ue.ext;
    smf.configuration_protocol = ue.configuration_protocol;

    for (i = 0; i < ue.num_of_id; i++) {
        uint8_t *data = ue.ids[i].data;
        switch(ue.ids[i].id) {
        case OGS_PCO_ID_PASSWORD_AUTHENTICATION_PROTOCOL:
            if (data[0] == 1) { /* Code : Authenticate-Request */
                memset(&pco_pap, 0, sizeof(ogs_pco_pap_t));

                pco_pap.welcome_len = strlen(pap_welcome);
                memcpy(pco_pap.welcome, pap_welcome, pco_pap.welcome_len);

                pco_size =
                    4 + /* sizeof(code+identifier+len) */
                    1 + /* sizeof(welcome_len) */
                    pco_pap.welcome_len;

                pco_pap.code = 2; /* Code : Authenticate-Ack */
                pco_pap.identifier = data[1]; /* Identifier */
                pco_pap.len = htobe16(pco_size);

                smf.ids[smf.num_of_id].id = ue.ids[i].id;
                smf.ids[smf.num_of_id].len = pco_size;
                smf.ids[smf.num_of_id].data = (uint8_t *)&pco_pap;
                smf.num_of_id++;
            }
            break;
        case OGS_PCO_ID_CHALLENGE_HANDSHAKE_AUTHENTICATION_PROTOCOL:
            if (data[0] == 2) { /* Code : Response */
                memset(&pco_chap, 0, sizeof(ogs_pco_chap_t));
                pco_size = 4; /* sizeof(code+identifier+len) */

                pco_chap.code = 3; /* Code : Success */
                pco_chap.identifier = data[1]; /* Identifier */
                pco_chap.len = htobe16(pco_size);

                smf.ids[smf.num_of_id].id = ue.ids[i].id;
                smf.ids[smf.num_of_id].len = pco_size;
                smf.ids[smf.num_of_id].data = (uint8_t *)&pco_chap;
                smf.num_of_id++;
            }
            break;
        case OGS_PCO_ID_INTERNET_PROTOCOL_CONTROL_PROTOCOL:
            if (data[0] == 1) { /* Code : Configuration Request */
                ogs_pco_ipcp_t *ipcp = (ogs_pco_ipcp_t *)data;
                uint16_t in_len = 0;
                uint16_t out_len = 0;
                int num_of_option = 0;

                ogs_assert(smf_self()->dns[0] || smf_self()->dns[1]);

                ogs_assert(ipcp);
                in_len = be16toh(ipcp->len);

                ogs_assert(num_of_ipcp <= OGS_PCO_MAX_NUM_OF_IPCP);
                pco_ipcp[num_of_ipcp].code = 2; /* Code : Configuration Ack */
                pco_ipcp[num_of_ipcp].identifier = ipcp->identifier; /* ID: Needs to match request */

                out_len = 4;
                /* Primary DNS Server IP Address */
                if (smf_self()->dns[0] &&
                    ipcp_contains_option(ipcp, in_len,
                        OGS_IPCP_OPT_PRIMARY_DNS, 4)) {
                    rv = ogs_ipsubnet(
                            &dns_primary, smf_self()->dns[0], NULL);
                    ogs_assert(rv == OGS_OK);
                    ogs_assert(
                            num_of_option <= OGS_PCO_MAX_NUM_OF_IPCP_OPTIONS);
                    pco_ipcp[num_of_ipcp].options[num_of_option].type =
                        OGS_IPCP_OPT_PRIMARY_DNS;
                    pco_ipcp[num_of_ipcp].options[num_of_option].len = 6;
                    pco_ipcp[num_of_ipcp].options[num_of_option].addr =
                        dns_primary.sub[0];
                    num_of_option++;

                    out_len += 6;
                }

                /* Secondary DNS Server IP Address */
                if (smf_self()->dns[1] &&
                    ipcp_contains_option(ipcp, in_len,
                        OGS_IPCP_OPT_SECONDARY_DNS, 4)) {
                    rv = ogs_ipsubnet(
                            &dns_secondary, smf_self()->dns[1], NULL);
                    ogs_assert(rv == OGS_OK);
                    ogs_assert(
                            num_of_option <= OGS_PCO_MAX_NUM_OF_IPCP_OPTIONS);
                    pco_ipcp[num_of_ipcp].options[num_of_option].type =
                        OGS_IPCP_OPT_SECONDARY_DNS;
                    pco_ipcp[num_of_ipcp].options[num_of_option].len = 6;
                    pco_ipcp[num_of_ipcp].options[num_of_option].addr =
                        dns_secondary.sub[0];
                    num_of_option++;

                    out_len += 6;
                }

                pco_ipcp[num_of_ipcp].len = htobe16(out_len);

                smf.ids[smf.num_of_id].id = ue.ids[i].id;
                smf.ids[smf.num_of_id].len = out_len;
                smf.ids[smf.num_of_id].data = (uint8_t *)&pco_ipcp[num_of_ipcp];

                num_of_ipcp++;

                smf.num_of_id++;
            }
            break;
        case OGS_PCO_ID_DNS_SERVER_IPV4_ADDRESS_REQUEST:
            if (smf_self()->dns[0]) {
                rv = ogs_ipsubnet(
                        &dns_primary, smf_self()->dns[0], NULL);
                ogs_assert(rv == OGS_OK);
                smf.ids[smf.num_of_id].id = ue.ids[i].id;
                smf.ids[smf.num_of_id].len = OGS_IPV4_LEN;
                smf.ids[smf.num_of_id].data = dns_primary.sub;
                smf.num_of_id++;
            }

            if (smf_self()->dns[1]) {
                rv = ogs_ipsubnet(
                        &dns_secondary, smf_self()->dns[1], NULL);
                ogs_assert(rv == OGS_OK);
                smf.ids[smf.num_of_id].id = ue.ids[i].id;
                smf.ids[smf.num_of_id].len = OGS_IPV4_LEN;
                smf.ids[smf.num_of_id].data = dns_secondary.sub;
                smf.num_of_id++;
            }
            break;
        case OGS_PCO_ID_DNS_SERVER_IPV6_ADDRESS_REQUEST:
            if (smf_self()->dns6[0]) {
                rv = ogs_ipsubnet(
                        &dns6_primary, smf_self()->dns6[0], NULL);
                ogs_assert(rv == OGS_OK);
                smf.ids[smf.num_of_id].id = ue.ids[i].id;
                smf.ids[smf.num_of_id].len = OGS_IPV6_LEN;
                smf.ids[smf.num_of_id].data = dns6_primary.sub;
                smf.num_of_id++;
            }

            if (smf_self()->dns6[1]) {
                rv = ogs_ipsubnet(
                        &dns6_secondary, smf_self()->dns6[1], NULL);
                ogs_assert(rv == OGS_OK);
                smf.ids[smf.num_of_id].id = ue.ids[i].id;
                smf.ids[smf.num_of_id].len = OGS_IPV6_LEN;
                smf.ids[smf.num_of_id].data = dns6_secondary.sub;
                smf.num_of_id++;
            }
            break;
        case OGS_PCO_ID_P_CSCF_IPV4_ADDRESS_REQUEST:
            if (smf_self()->num_of_p_cscf) {
                rv = ogs_ipsubnet(&p_cscf,
                    smf_self()->p_cscf[smf_self()->p_cscf_index], NULL);
                ogs_assert(rv == OGS_OK);
                smf.ids[smf.num_of_id].id = ue.ids[i].id;
                smf.ids[smf.num_of_id].len = OGS_IPV4_LEN;
                smf.ids[smf.num_of_id].data = p_cscf.sub;
                smf.num_of_id++;

                smf_self()->p_cscf_index++;
                smf_self()->p_cscf_index %= smf_self()->num_of_p_cscf;
            }
            break;
        case OGS_PCO_ID_P_CSCF_IPV6_ADDRESS_REQUEST:
            if (smf_self()->num_of_p_cscf6) {
                rv = ogs_ipsubnet(&p_cscf6,
                    smf_self()->p_cscf6[smf_self()->p_cscf6_index], NULL);
                ogs_assert(rv == OGS_OK);
                smf.ids[smf.num_of_id].id = ue.ids[i].id;
                smf.ids[smf.num_of_id].len = OGS_IPV6_LEN;
                smf.ids[smf.num_of_id].data = p_cscf6.sub;
                smf.num_of_id++;

                smf_self()->p_cscf6_index++;
                smf_self()->p_cscf6_index %= smf_self()->num_of_p_cscf6;
            }
            break;
        case OGS_PCO_ID_IPV4_LINK_MTU_REQUEST:
            if (smf_self()->mtu) {
                mtu = htobe16(smf_self()->mtu);
                smf.ids[smf.num_of_id].id = ue.ids[i].id;
                smf.ids[smf.num_of_id].len = sizeof(uint16_t);
                smf.ids[smf.num_of_id].data = &mtu;
                smf.num_of_id++;
            }
            break;
        case OGS_PCO_ID_IP_ADDRESS_ALLOCATION_VIA_NAS_SIGNALLING:
            /* TODO */
            break;
        case OGS_PCO_ID_MS_SUPPORTS_BCM:
            /* TODO */
            break;
        case OGS_PCO_ID_MS_SUPPORT_LOCAL_ADDR_TFT_INDICATOR:
            smf.ids[smf.num_of_id].id = ue.ids[i].id;
            smf.ids[smf.num_of_id].len = 0;
            smf.ids[smf.num_of_id].data = 0;
            smf.num_of_id++;
            break;
        case OGS_PCO_ID_P_CSCF_RE_SELECTION_SUPPORT:
            /* TODO */
            break;
        default:
            ogs_warn("Unknown PCO ID:(0x%x)", ue.ids[i].id);
        }
    }

    size = ogs_pco_build(pco_buf, OGS_MAX_PCO_LEN, &smf);
    ogs_expect(size > 0);
    return size;
}

void smf_qfi_pool_init(smf_sess_t *sess)
{
    ogs_assert(sess);

    ogs_pool_create(&sess->qfi_pool, OGS_MAX_QOS_FLOW_ID);
    ogs_pool_sequence_id_generate(&sess->qfi_pool);
}

void smf_qfi_pool_final(smf_sess_t *sess)
{
    ogs_assert(sess);

    ogs_pool_destroy(&sess->qfi_pool);
}

void smf_pf_identifier_pool_init(smf_bearer_t *bearer)
{
    ogs_assert(bearer);

    ogs_pool_create(&bearer->pf_identifier_pool, OGS_MAX_NUM_OF_FLOW_IN_BEARER);
    ogs_pool_sequence_id_generate(&bearer->pf_identifier_pool);
}

void smf_pf_identifier_pool_final(smf_bearer_t *bearer)
{
    ogs_assert(bearer);

    ogs_pool_destroy(&bearer->pf_identifier_pool);
}

void smf_pf_precedence_pool_init(smf_sess_t *sess)
{
    ogs_assert(sess);

    ogs_pool_create(&sess->pf_precedence_pool,
            OGS_MAX_NUM_OF_BEARER * OGS_MAX_NUM_OF_FLOW_IN_BEARER);
    ogs_pool_sequence_id_generate(&sess->pf_precedence_pool);
}

void smf_pf_precedence_pool_final(smf_sess_t *sess)
{
    ogs_assert(sess);

    ogs_pool_destroy(&sess->pf_precedence_pool);
}

static void stats_add_smf_session(void)
{
    num_of_smf_sess = num_of_smf_sess + 1;
    ogs_info("[Added] Number of SMF-Sessions is now %d", num_of_smf_sess);
}

static void stats_remove_smf_session(smf_sess_t *sess)
{
    ogs_assert(sess);

    num_of_smf_sess = num_of_smf_sess - 1;
    ogs_info("[Removed] Number of SMF-Sessions is now %d", num_of_smf_sess);
}

int smf_instance_get_load(void)
{
    return (((ogs_pool_size(&smf_sess_pool) -
            ogs_pool_avail(&smf_sess_pool)) * 100) /
            ogs_pool_size(&smf_sess_pool));
}

int smf_integrity_protection_indication_value2enum(const char *value)
{
    ogs_assert(value);
    if (!strcmp(value, "required"))
        return NGAP_IntegrityProtectionIndication_required;
    else if (!strcmp(value, "preferred"))
        return NGAP_IntegrityProtectionIndication_preferred;
    else if (!strcmp(value, "not-needed"))
        return NGAP_IntegrityProtectionIndication_not_needed;
    else {
        ogs_error("Invalid value[%s]", value);
        return -1;
    }
}
int smf_confidentiality_protection_indication_value2enum(const char *value)
{
    ogs_assert(value);
    return smf_integrity_protection_indication_value2enum(value);
}
int smf_maximum_integrity_protected_data_rate_uplink_value2enum(
        const char *value)
{
    ogs_assert(value);
    if (!strcmp(value, "bitrate64kbs"))
        return NGAP_MaximumIntegrityProtectedDataRate_bitrate64kbs;
    else if (!strcmp(value, "maximum-UE-rate"))
        return NGAP_MaximumIntegrityProtectedDataRate_maximum_UE_rate;
    else {
        ogs_error("Invalid value[%s]", value);
        return -1;
    }
}
int smf_maximum_integrity_protected_data_rate_downlink_value2enum(
        const char *value)
{
    ogs_assert(value);
    return smf_maximum_integrity_protected_data_rate_uplink_value2enum(value);
}
