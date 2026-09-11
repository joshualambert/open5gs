/*
 * Copyright (C) 2026 by Josh Lambert <josh.lambert@alabamalightwave.com>
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

#include "pd-scenario.h"

#define EPC_MSIN_1      "3746000006"
#define EPC_MSIN_2      "3746000007"

typedef struct epc_enb_s {
    ogs_socknode_t *s1ap;
    ogs_socknode_t *gtpu;
} epc_enb_t;

/* Reads one S1AP message within PD_SIGNALLING_TIMEOUT and dispatches it */
static bool recv_s1ap(abts_case *tc, epc_enb_t *enb, test_ue_t *test_ue)
{
    ogs_pkbuf_t *recvbuf = NULL;

    recvbuf = testenb_s1ap_read_timeout(enb->s1ap, PD_SIGNALLING_TIMEOUT);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    if (!recvbuf)
        return false;

    tests1ap_recv(test_ue, recvbuf);
    return true;
}

static bool send_s1ap(abts_case *tc, epc_enb_t *enb, ogs_pkbuf_t *sendbuf)
{
    int rv;

    ABTS_PTR_NOTNULL(tc, sendbuf);
    if (!sendbuf)
        return false;

    rv = testenb_s1ap_send(enb->s1ap, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);
    return rv == OGS_OK;
}

/* eNB connects to MME/SGW and completes S1 Setup */
static void enb_setup(abts_case *tc, epc_enb_t *enb)
{
    memset(enb, 0, sizeof *enb);

    enb->s1ap = tests1ap_client(AF_INET);
    ABTS_PTR_NOTNULL(tc, enb->s1ap);

    enb->gtpu = test_gtpu_server(1, AF_INET);
    ABTS_PTR_NOTNULL(tc, enb->gtpu);

    if (!send_s1ap(tc, enb, test_s1ap_build_s1_setup_request(
                    S1AP_ENB_ID_PR_macroENB_ID, 0x54f64)))
        return;
    recv_s1ap(tc, enb, NULL);
}

static void enb_close(epc_enb_t *enb)
{
    testenb_s1ap_close(enb->s1ap);
    test_gtpu_close(enb->gtpu);
}

/* id_base seeds the eNB-UE-S1AP-ID so that concurrent UEs do not collide */
static test_ue_t *ue_new(const char *msin, uint32_t id_base)
{
    ogs_nas_5gs_mobile_identity_suci_t mobile_identity_suci;
    test_ue_t *test_ue = NULL;

    memset(&mobile_identity_suci, 0, sizeof(mobile_identity_suci));
    mobile_identity_suci.h.supi_format = OGS_NAS_5GS_SUPI_FORMAT_IMSI;
    mobile_identity_suci.h.type = OGS_NAS_5GS_MOBILE_IDENTITY_SUCI;
    mobile_identity_suci.routing_indicator1 = 0;
    mobile_identity_suci.routing_indicator2 = 0xf;
    mobile_identity_suci.routing_indicator3 = 0xf;
    mobile_identity_suci.routing_indicator4 = 0xf;
    mobile_identity_suci.protection_scheme_id = OGS_PROTECTION_SCHEME_NULL;
    mobile_identity_suci.home_network_pki_value = 0;

    test_ue = test_ue_add_by_suci(&mobile_identity_suci, msin);
    ogs_assert(test_ue);

    test_ue->enb_ue_s1ap_id = id_base;
    test_ue->e_cgi.cell_id = 0x1079baf0;
    test_ue->nas.ksi = OGS_NAS_KSI_NO_KEY_IS_AVAILABLE;
    test_ue->nas.value = OGS_NAS_ATTACH_TYPE_COMBINED_EPS_IMSI_ATTACH;

    test_ue->k_string = "465b5ce8b199b49faa5f0a2ee238a6bc";
    test_ue->opc_string = "e8ed289deba952e4283b54e88e6183ca";

    return test_ue;
}

/* Removes the subscriber and frees the test UE */
static void ue_cleanup(abts_case *tc, test_ue_t *test_ue)
{
    ABTS_INT_EQUAL(tc, OGS_OK, test_db_remove_ue(test_ue));
    test_ue_remove(test_ue);
}

/*
 * Provisions the subscriber and attaches up to (and including) the MME's
 * answer to the ESM Information Response: Initial Context Setup Request
 * with Attach Accept, or Attach Reject.  test_ue/sess are always created.
 */
static bool attach_epc_begin(abts_case *tc, epc_enb_t *enb,
        const char *msin, uint32_t id_base,
        int session_type, const char *static_ipv6,
        test_ue_t **test_ue_out, test_sess_t **sess_out)
{
    ogs_pkbuf_t *emmbuf = NULL;
    ogs_pkbuf_t *esmbuf = NULL;
    test_ue_t *test_ue = NULL;
    test_sess_t *sess = NULL;
    bson_t *doc = NULL;
    uint8_t pdn_type;

    switch (session_type) {
    case OGS_PDU_SESSION_TYPE_IPV6:
        pdn_type = OGS_NAS_EPS_PDN_TYPE_IPV6;
        break;
    case OGS_PDU_SESSION_TYPE_IPV4V6:
        pdn_type = OGS_NAS_EPS_PDN_TYPE_IPV4V6;
        break;
    default:
        ogs_assert_if_reached();
        return false;
    }

    test_ue = ue_new(msin, id_base);
    sess = test_sess_add_by_apn(test_ue, "internet", OGS_GTP2_RAT_TYPE_EUTRAN);
    ogs_assert(sess);
    *test_ue_out = test_ue;
    *sess_out = sess;

    /********** Insert Subscriber in Database */
    if (static_ipv6)
        doc = test_db_new_static_ipv6(test_ue, session_type, static_ipv6);
    else
        doc = test_db_new_session_type(test_ue, session_type);
    ABTS_PTR_NOTNULL(tc, doc);
    ABTS_INT_EQUAL(tc, OGS_OK, test_db_insert_ue(test_ue, doc));

    /* Send Attach Request */
    memset(&sess->pdn_connectivity_param,
            0, sizeof(sess->pdn_connectivity_param));
    sess->pdn_connectivity_param.eit = 1;
    sess->pdn_connectivity_param.request_type =
        OGS_NAS_EPS_REQUEST_TYPE_INITIAL;
    esmbuf = testesm_build_pdn_connectivity_request(sess, false, pdn_type);
    ABTS_PTR_NOTNULL(tc, esmbuf);

    memset(&test_ue->attach_request_param,
            0, sizeof(test_ue->attach_request_param));
    test_ue->attach_request_param.drx_parameter = 1;
    test_ue->attach_request_param.ms_network_capability = 1;
    test_ue->attach_request_param.tmsi_status = 1;
    test_ue->attach_request_param.mobile_station_classmark_2 = 1;
    test_ue->attach_request_param.ue_usage_setting = 1;
    emmbuf = testemm_build_attach_request(test_ue, esmbuf, true, false);
    ABTS_PTR_NOTNULL(tc, emmbuf);

    memset(&test_ue->initial_ue_param, 0, sizeof(test_ue->initial_ue_param));
    if (!send_s1ap(tc, enb, test_s1ap_build_initial_ue_message(
            test_ue, emmbuf, S1AP_RRC_Establishment_Cause_mo_Signalling, false)))
        return false;

    /* Receive Authentication Request */
    if (!recv_s1ap(tc, enb, test_ue))
        return false;

    /* Send Authentication response */
    emmbuf = testemm_build_authentication_response(test_ue);
    ABTS_PTR_NOTNULL(tc, emmbuf);
    if (!send_s1ap(tc, enb,
                test_s1ap_build_uplink_nas_transport(test_ue, emmbuf)))
        return false;

    /* Receive Security mode Command */
    if (!recv_s1ap(tc, enb, test_ue))
        return false;

    /* Send Security mode complete */
    test_ue->mobile_identity_imeisv_presence = true;
    emmbuf = testemm_build_security_mode_complete(test_ue);
    ABTS_PTR_NOTNULL(tc, emmbuf);
    if (!send_s1ap(tc, enb,
                test_s1ap_build_uplink_nas_transport(test_ue, emmbuf)))
        return false;

    /* Receive ESM Information Request */
    if (!recv_s1ap(tc, enb, test_ue))
        return false;

    /* Send ESM Information Response */
    sess->esm_information_param.epco = 1;
    esmbuf = testesm_build_esm_information_response(sess);
    ABTS_PTR_NOTNULL(tc, esmbuf);
    if (!send_s1ap(tc, enb,
                test_s1ap_build_uplink_nas_transport(test_ue, esmbuf)))
        return false;

    /* Receive Initial Context Setup Request +
     * Attach Accept +
     * Activate Default Bearer Context Request
     * (or Attach Reject when the SMF refused the session) */
    return recv_s1ap(tc, enb, test_ue);
}

/*
 * Completes an accepted attach: Initial Context Setup Response, Attach
 * Complete, EMM Information.  Fills ctx (bearer may stay NULL on failure).
 */
static bool attach_epc_finish(abts_case *tc, epc_enb_t *enb,
        test_ue_t *test_ue, test_sess_t *sess, int session_type,
        pd_ctx_t *ctx)
{
    ogs_pkbuf_t *emmbuf = NULL;
    ogs_pkbuf_t *esmbuf = NULL;
    test_bearer_t *bearer = NULL;

    ABTS_INT_EQUAL(tc, S1AP_ProcedureCode_id_InitialContextSetup,
            test_ue->s1ap_procedure_code);
    ABTS_INT_EQUAL(tc, OGS_NAS_EPS_ATTACH_ACCEPT, test_ue->emm_message_type);

    bearer = test_bearer_find_by_ue_ebi(test_ue, 5);
    pd_ctx_init(ctx, tc, enb->gtpu, test_ue, sess, bearer);
    ABTS_PTR_NOTNULL(tc, bearer);
    if (!bearer)
        return false;

    /* Send UE Capability Info Indication */
    if (!send_s1ap(tc, enb,
                tests1ap_build_ue_radio_capability_info_indication(test_ue)))
        return false;

    /* Send Initial Context Setup Response */
    if (!send_s1ap(tc, enb,
                test_s1ap_build_initial_context_setup_response(test_ue)))
        return false;

    /* Send Attach Complete + Activate default EPS bearer cotext accept */
    test_ue->nr_cgi.cell_id = 0x1234502;
    esmbuf = testesm_build_activate_default_eps_bearer_context_accept(
            bearer, false);
    ABTS_PTR_NOTNULL(tc, esmbuf);
    emmbuf = testemm_build_attach_complete(test_ue, esmbuf);
    ABTS_PTR_NOTNULL(tc, emmbuf);
    if (!send_s1ap(tc, enb,
                test_s1ap_build_uplink_nas_transport(test_ue, emmbuf)))
        return false;

    /* Receive EMM information */
    if (!recv_s1ap(tc, enb, test_ue))
        return false;

    /* PDN type as requested */
    ABTS_TRUE(tc, sess->ue_ip.ipv6);
    ABTS_INT_EQUAL(tc, session_type == OGS_PDU_SESSION_TYPE_IPV4V6,
            sess->ue_ip.ipv4);

    return sess->ue_ip.ipv6;
}

/*
 * Provisions the subscriber, attaches with the given PDN type and runs
 * router discovery.  Returns true when the UE is ready for DHCPv6; ctx is
 * always initialised so that detach_epc() can clean up.
 */
static bool attach_epc(abts_case *tc, epc_enb_t *enb,
        const char *msin, uint32_t id_base,
        int session_type, const char *static_ipv6, pd_ctx_t *ctx)
{
    test_ue_t *test_ue = NULL;
    test_sess_t *sess = NULL;

    if (!attach_epc_begin(tc, enb, msin, id_base,
                session_type, static_ipv6, &test_ue, &sess)) {
        pd_ctx_init(ctx, tc, enb->gtpu, test_ue, sess, NULL);
        return false;
    }

    if (!attach_epc_finish(tc, enb, test_ue, sess, session_type, ctx))
        return false;

    /* Send Router Solicitation, receive Router Advertisement */
    return pd_router_discovery(ctx);
}

/* Detaches, removes the subscriber and frees the test UE */
static void detach_epc(abts_case *tc, epc_enb_t *enb, pd_ctx_t *ctx)
{
    ogs_pkbuf_t *emmbuf = NULL;
    test_ue_t *test_ue = ctx->test_ue;
    uint32_t enb_ue_s1ap_id;

    if (!test_ue)
        return;

    /* Send Detach Request */
    emmbuf = testemm_build_detach_request(test_ue, 1, true, false);
    ABTS_PTR_NOTNULL(tc, emmbuf);
    if (!send_s1ap(tc, enb, test_s1ap_build_initial_ue_message(
            test_ue, emmbuf, S1AP_RRC_Establishment_Cause_mo_Signalling, true)))
        goto cleanup;

    /* Receive OLD UE Context Release Command */
    enb_ue_s1ap_id = test_ue->enb_ue_s1ap_id;

    if (!recv_s1ap(tc, enb, test_ue))
        goto cleanup;

    /* Send OLD UE Context Release Complete */
    if (!send_s1ap(tc, enb,
                test_s1ap_build_ue_context_release_complete(test_ue)))
        goto cleanup;

    test_ue->enb_ue_s1ap_id = enb_ue_s1ap_id;

    /* Receive UE Context Release Command */
    if (!recv_s1ap(tc, enb, test_ue))
        goto cleanup;

    /* Send UE Context Release Complete */
    send_s1ap(tc, enb, test_s1ap_build_ue_context_release_complete(test_ue));

cleanup:
    ogs_msleep(300);

    ue_cleanup(tc, test_ue);
    ctx->test_ue = NULL;
}

/*
 * DESIGN 5.3: a static UE IPv6 address outside every subnet of the APN is
 * refused by the SMF (Create Session Response with a failure cause); the
 * MME turns that into Attach Reject (EMM cause #17 network failure) and
 * releases the S1 context.  If the attach is accepted instead, the test
 * fails but still tears the session down.
 *
 * PDN type IPv6 is requested on purpose: for IPv4v6 the SMF's historical
 * family fallback downgrades the session to IPv4-only ("No IPv6 subnet ...
 * only IPv4 assigned") before the containment check can reject it.
 */
static void attach_epc_expect_reject(abts_case *tc, epc_enb_t *enb,
        const char *msin, uint32_t id_base, const char *static_ipv6)
{
    test_ue_t *test_ue = NULL;
    test_sess_t *sess = NULL;
    pd_ctx_t ctx;

    if (!attach_epc_begin(tc, enb, msin, id_base,
                OGS_PDU_SESSION_TYPE_IPV6, static_ipv6, &test_ue, &sess)) {
        ue_cleanup(tc, test_ue);
        return;
    }

    if (test_ue->s1ap_procedure_code ==
            S1AP_ProcedureCode_id_downlinkNASTransport &&
        test_ue->emm_message_type == OGS_NAS_EPS_ATTACH_REJECT) {

        ABTS_INT_EQUAL(tc,
                OGS_NAS_EMM_CAUSE_NETWORK_FAILURE, test_ue->emm_cause);

        /* Receive UE Context Release Command */
        if (recv_s1ap(tc, enb, test_ue)) {
            ABTS_INT_EQUAL(tc, S1AP_ProcedureCode_id_UEContextRelease,
                    test_ue->s1ap_procedure_code);
            /* Send UE Context Release Complete */
            send_s1ap(tc, enb,
                    test_s1ap_build_ue_context_release_complete(test_ue));
        }

        ogs_msleep(300);
        ue_cleanup(tc, test_ue);
        return;
    }

    ogs_error("Static UE IPv6 %s outside every subnet: expected Attach "
            "Reject, got S1AP procedure[%d] EMM message[%d]", static_ipv6,
            (int)test_ue->s1ap_procedure_code, test_ue->emm_message_type);
    ABTS_FAIL(tc, "Attach with an orphan static address was accepted");

    /* Complete the attach so that the session can be torn down cleanly */
    pd_ctx_init(&ctx, tc, enb->gtpu, test_ue, sess, NULL);
    if (test_ue->s1ap_procedure_code == S1AP_ProcedureCode_id_InitialContextSetup)
        attach_epc_finish(tc, enb, test_ue, sess,
                OGS_PDU_SESSION_TYPE_IPV6, &ctx);
    detach_epc(tc, enb, &ctx);
}

/*
 * Test cases
 */

static void run_scenario(abts_case *tc, int session_type,
        void (*scenario)(pd_ctx_t *ctx))
{
    epc_enb_t enb;
    pd_ctx_t ctx;

    enb_setup(tc, &enb);

    if (attach_epc(tc, &enb, EPC_MSIN_1, 0, session_type, NULL, &ctx))
        scenario(&ctx);
    detach_epc(tc, &enb, &ctx);

    enb_close(&enb);
}

static void ipv4v6_basic(abts_case *tc, void *data)
{
    run_scenario(tc, OGS_PDU_SESSION_TYPE_IPV4V6, pd_scenario_basic);
}

static void ipv4v6_lifecycle(abts_case *tc, void *data)
{
    run_scenario(tc, OGS_PDU_SESSION_TYPE_IPV4V6, pd_scenario_lifecycle);
}

static void ipv4v6_no_exclude(abts_case *tc, void *data)
{
    run_scenario(tc, OGS_PDU_SESSION_TYPE_IPV4V6, pd_scenario_no_exclude);
}

static void ipv4v6_rapid_commit(abts_case *tc, void *data)
{
    run_scenario(tc, OGS_PDU_SESSION_TYPE_IPV4V6, pd_scenario_rapid_commit);
}

static void ipv4v6_negative(abts_case *tc, void *data)
{
    run_scenario(tc, OGS_PDU_SESSION_TYPE_IPV4V6, pd_scenario_negative);
}

static void ipv6_basic(abts_case *tc, void *data)
{
    run_scenario(tc, OGS_PDU_SESSION_TYPE_IPV6, pd_scenario_basic);
}

static void ipv6_lifecycle(abts_case *tc, void *data)
{
    run_scenario(tc, OGS_PDU_SESSION_TYPE_IPV6, pd_scenario_lifecycle);
}

static void ipv6_no_exclude(abts_case *tc, void *data)
{
    run_scenario(tc, OGS_PDU_SESSION_TYPE_IPV6, pd_scenario_no_exclude);
}

static void ipv6_rapid_commit(abts_case *tc, void *data)
{
    run_scenario(tc, OGS_PDU_SESSION_TYPE_IPV6, pd_scenario_rapid_commit);
}

static void ipv6_negative(abts_case *tc, void *data)
{
    run_scenario(tc, OGS_PDU_SESSION_TYPE_IPV6, pd_scenario_negative);
}

/* Two UEs attached at the same time get distinct blocks */
static void two_ues(abts_case *tc, void *data)
{
    epc_enb_t enb;
    pd_ctx_t ctx1, ctx2;
    bool ok1, ok2;

    enb_setup(tc, &enb);

    ok1 = attach_epc(tc, &enb, EPC_MSIN_1, 0,
            OGS_PDU_SESSION_TYPE_IPV4V6, NULL, &ctx1);
    ok2 = attach_epc(tc, &enb, EPC_MSIN_2, 100,
            OGS_PDU_SESSION_TYPE_IPV6, NULL, &ctx2);

    if (ok1)
        ok1 = pd_solicit_request(&ctx1, true);
    if (ok2)
        ok2 = pd_solicit_request(&ctx2, true);
    if (ok1 && ok2)
        pd_check_distinct_blocks(&ctx1, &ctx2);

    detach_epc(tc, &enb, &ctx2);
    detach_epc(tc, &enb, &ctx1);

    enb_close(&enb);
}

/* Attach/detach cycles: blocks and bindings must return to the pool */
static void reattach(abts_case *tc, void *data)
{
    epc_enb_t enb;
    pd_ctx_t ctx;
    int i;

    enb_setup(tc, &enb);

    for (i = 0; i < 3; i++) {
        if (attach_epc(tc, &enb, EPC_MSIN_1, 0,
                    OGS_PDU_SESSION_TYPE_IPV4V6, NULL, &ctx))
            pd_scenario_basic(&ctx);
        detach_epc(tc, &enb, &ctx);
    }

    enb_close(&enb);
}

/* Static UE IPv6 address inside the dynamic cafe subnet (outside its
 * range): fixed /64 and /56, identical on re-attach */
static void static_pd(abts_case *tc, void *data)
{
    epc_enb_t enb;
    pd_ctx_t ctx;
    uint8_t link[OGS_IPV6_LEN], block[OGS_IPV6_LEN];
    bool ok;

    enb_setup(tc, &enb);

    ok = attach_epc(tc, &enb, EPC_MSIN_1, 0,
            OGS_PDU_SESSION_TYPE_IPV4V6, PD_STATIC_UE_IPV6, &ctx);
    if (ok)
        pd_scenario_static(&ctx, true);
    memcpy(link, ctx.link, OGS_IPV6_LEN);
    memcpy(block, ctx.block, OGS_IPV6_LEN);
    detach_epc(tc, &enb, &ctx);

    if (attach_epc(tc, &enb, EPC_MSIN_1, 0,
                OGS_PDU_SESSION_TYPE_IPV6, PD_STATIC_UE_IPV6, &ctx)) {
        pd_scenario_static(&ctx, false);
        if (ok)
            pd_check_same_prefixes(&ctx, link, block);
    }
    detach_epc(tc, &enb, &ctx);

    enb_close(&enb);
}

/* 5.1/5.6: RA with SLLA and the documented defaults, NS/NA for the gateway */
static void neighbour_discovery(abts_case *tc, void *data)
{
    run_scenario(tc, OGS_PDU_SESSION_TYPE_IPV4V6,
            pd_scenario_neighbour_discovery);
}

/* 5.7: RS from :: gets an RA to ff02::1 */
static void rs_unspecified(abts_case *tc, void *data)
{
    run_scenario(tc, OGS_PDU_SESSION_TYPE_IPV6, pd_scenario_rs_unspecified);
}

/* 5.2 (UPF): leaked link-local LAN traffic is dropped, NFs stay alive */
static void leaky_cpe(abts_case *tc, void *data)
{
    run_scenario(tc, OGS_PDU_SESSION_TYPE_IPV4V6, pd_scenario_leaky_cpe);
}

/* 5.2 (SMF): a second DUID cannot steal a live binding */
static void sticky_binding(abts_case *tc, void *data)
{
    run_scenario(tc, OGS_PDU_SESSION_TYPE_IPV4V6, pd_scenario_sticky_binding);
}

/* 5.8: TP-Link HX220 fixtures */
static void hx220(abts_case *tc, void *data)
{
    run_scenario(tc, OGS_PDU_SESSION_TYPE_IPV4V6, pd_scenario_hx220);
}

/* 5.3/5.5: static address in the static-only subnet; the UPF routes the
 * block while the session exists and removes the route afterwards */
static void static_only(abts_case *tc, void *data)
{
    epc_enb_t enb;
    pd_ctx_t ctx;
    uint8_t link[OGS_IPV6_LEN], block[OGS_IPV6_LEN];
    bool ok;

    enb_setup(tc, &enb);

    ok = attach_epc(tc, &enb, EPC_MSIN_1, 0,
            OGS_PDU_SESSION_TYPE_IPV4V6, PD_STATIC_ONLY_UE_IPV6, &ctx);
    if (ok)
        pd_scenario_static_only(&ctx, true);
    memcpy(link, ctx.link, OGS_IPV6_LEN);
    memcpy(block, ctx.block, OGS_IPV6_LEN);
    detach_epc(tc, &enb, &ctx);
    pd_check_kernel_route(tc, PD_STATIC_ONLY_ROUTE, false);

    if (attach_epc(tc, &enb, EPC_MSIN_1, 0,
                OGS_PDU_SESSION_TYPE_IPV6, PD_STATIC_ONLY_UE_IPV6, &ctx)) {
        pd_scenario_static_only(&ctx, false);
        if (ok)
            pd_check_same_prefixes(&ctx, link, block);
    }
    detach_epc(tc, &enb, &ctx);
    pd_check_kernel_route(tc, PD_STATIC_ONLY_ROUTE, false);

    enb_close(&enb);
}

/* 5.3: static address outside every subnet -> Attach Reject */
static void static_orphan(abts_case *tc, void *data)
{
    epc_enb_t enb;

    enb_setup(tc, &enb);
    attach_epc_expect_reject(tc, &enb, EPC_MSIN_1, 0,
            PD_STATIC_ORPHAN_UE_IPV6);
    enb_close(&enb);
}

/* 5.4: pool 1 holds one block; UE1 gets it, UE2 spills into pool 2, and
 * after both detach the next UE lands in pool 1 again */
static void multi_pool(abts_case *tc, void *data)
{
    epc_enb_t enb;
    pd_ctx_t ctx1, ctx2;
    bool ok1, ok2;

    enb_setup(tc, &enb);

    ok1 = attach_epc(tc, &enb, EPC_MSIN_1, 0,
            OGS_PDU_SESSION_TYPE_IPV4V6, NULL, &ctx1);
    ok2 = attach_epc(tc, &enb, EPC_MSIN_2, 100,
            OGS_PDU_SESSION_TYPE_IPV6, NULL, &ctx2);

    if (ok1)
        pd_scenario_in_pool(&ctx1, PD_POOL1);
    if (ok2)
        pd_scenario_in_pool(&ctx2, PD_POOL2);
    if (ok1 && ok2)
        pd_check_distinct_blocks(&ctx1, &ctx2);

    detach_epc(tc, &enb, &ctx2);
    detach_epc(tc, &enb, &ctx1);

    if (attach_epc(tc, &enb, EPC_MSIN_2, 200,
                OGS_PDU_SESSION_TYPE_IPV4V6, NULL, &ctx1))
        pd_scenario_in_pool(&ctx1, PD_POOL1);
    detach_epc(tc, &enb, &ctx1);

    enb_close(&enb);
}

abts_suite *test_epc(abts_suite *suite)
{
    suite = ADD_SUITE(suite)

    abts_run_test(suite, ipv4v6_basic, NULL);
    abts_run_test(suite, ipv4v6_lifecycle, NULL);
    abts_run_test(suite, ipv4v6_no_exclude, NULL);
    abts_run_test(suite, ipv4v6_rapid_commit, NULL);
    abts_run_test(suite, ipv4v6_negative, NULL);
    abts_run_test(suite, ipv6_basic, NULL);
    abts_run_test(suite, ipv6_lifecycle, NULL);
    abts_run_test(suite, ipv6_no_exclude, NULL);
    abts_run_test(suite, ipv6_rapid_commit, NULL);
    abts_run_test(suite, ipv6_negative, NULL);
    abts_run_test(suite, two_ues, NULL);
    abts_run_test(suite, reattach, NULL);
    abts_run_test(suite, static_pd, NULL);

    abts_run_test(suite, neighbour_discovery, NULL);
    abts_run_test(suite, rs_unspecified, NULL);
    abts_run_test(suite, leaky_cpe, NULL);
    abts_run_test(suite, sticky_binding, NULL);
    abts_run_test(suite, hx220, NULL);
    abts_run_test(suite, static_only, NULL);
    abts_run_test(suite, static_orphan, NULL);
    abts_run_test(suite, multi_pool, NULL);

    return suite;
}
