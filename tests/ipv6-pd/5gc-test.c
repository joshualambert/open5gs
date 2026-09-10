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

#define FGC_MSIN_1      "0000203190"
#define FGC_MSIN_2      "0000203191"

typedef struct fgc_gnb_s {
    ogs_socknode_t *ngap;
    ogs_socknode_t *gtpu;
} fgc_gnb_t;

static test_ue_t *ue_new(const char *msin, uint32_t id_base);

/* gNB connects to AMF/UPF and completes NG Setup */
static void gnb_setup(abts_case *tc, fgc_gnb_t *gnb)
{
    int rv;
    ogs_pkbuf_t *sendbuf = NULL;
    ogs_pkbuf_t *recvbuf = NULL;
    test_ue_t *test_ue = NULL;

    memset(gnb, 0, sizeof *gnb);

    gnb->ngap = testngap_client(1, AF_INET);
    ABTS_PTR_NOTNULL(tc, gnb->ngap);

    gnb->gtpu = test_gtpu_server(1, AF_INET);
    ABTS_PTR_NOTNULL(tc, gnb->gtpu);

    sendbuf = testngap_build_ng_setup_request(0x4000, 22);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(gnb->ngap, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    /* testngap_recv() needs a UE context even for the NG Setup Response */
    test_ue = ue_new(FGC_MSIN_1, 0);
    recvbuf = testgnb_ngap_read(gnb->ngap);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    testngap_recv(test_ue, recvbuf);
    test_ue_remove(test_ue);
}

static void gnb_close(fgc_gnb_t *gnb)
{
    testgnb_gtpu_close(gnb->gtpu);
    testgnb_ngap_close(gnb->ngap);
}

/* id_base seeds the RAN-UE-NGAP-ID so that concurrent UEs do not collide */
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

    test_ue->ran_ue_ngap_id = id_base;
    test_ue->nr_cgi.cell_id = 0x40001;

    test_ue->nas.registration.tsc = 0;
    test_ue->nas.registration.ksi = OGS_NAS_KSI_NO_KEY_IS_AVAILABLE;
    test_ue->nas.registration.follow_on_request = 1;
    test_ue->nas.registration.value = OGS_NAS_5GS_REGISTRATION_TYPE_INITIAL;

    test_ue->k_string = "465b5ce8b199b49faa5f0a2ee238a6bc";
    test_ue->opc_string = "e8ed289deba952e4283b54e88e6183ca";

    return test_ue;
}

/*
 * Provisions the subscriber, registers, establishes a PDU session of the
 * given type and runs router discovery.  Returns true when the UE is
 * ready for DHCPv6.
 */
static bool attach_5gc(abts_case *tc, fgc_gnb_t *gnb,
        const char *msin, uint32_t id_base,
        int session_type, const char *static_ipv6, pd_ctx_t *ctx)
{
    int rv;
    ogs_pkbuf_t *gmmbuf = NULL;
    ogs_pkbuf_t *gsmbuf = NULL;
    ogs_pkbuf_t *nasbuf = NULL;
    ogs_pkbuf_t *sendbuf = NULL;
    ogs_pkbuf_t *recvbuf = NULL;
    ogs_socknode_t *ngap = gnb->ngap;

    test_ue_t *test_ue = NULL;
    test_sess_t *sess = NULL;
    test_bearer_t *qos_flow = NULL;
    bson_t *doc = NULL;

    ogs_assert(session_type == OGS_PDU_SESSION_TYPE_IPV6 ||
            session_type == OGS_PDU_SESSION_TYPE_IPV4V6);

    test_ue = ue_new(msin, id_base);

    /********** Insert Subscriber in Database */
    if (static_ipv6)
        doc = test_db_new_static_ipv6(test_ue, session_type, static_ipv6);
    else
        doc = test_db_new_session_type(test_ue, session_type);
    ABTS_PTR_NOTNULL(tc, doc);
    ABTS_INT_EQUAL(tc, OGS_OK, test_db_insert_ue(test_ue, doc));

    /* Send Registration request */
    test_ue->registration_request_param.guti = 1;
    gmmbuf = testgmm_build_registration_request(test_ue, NULL, false, false);
    ABTS_PTR_NOTNULL(tc, gmmbuf);

    test_ue->registration_request_param.gmm_capability = 1;
    test_ue->registration_request_param.s1_ue_network_capability = 1;
    test_ue->registration_request_param.requested_nssai = 1;
    test_ue->registration_request_param.last_visited_registered_tai = 1;
    test_ue->registration_request_param.ue_usage_setting = 1;
    nasbuf = testgmm_build_registration_request(test_ue, NULL, false, false);
    ABTS_PTR_NOTNULL(tc, nasbuf);

    sendbuf = testngap_build_initial_ue_message(test_ue, gmmbuf,
                NGAP_RRCEstablishmentCause_mo_Signalling, false, true);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    /* Receive Identity request */
    recvbuf = testgnb_ngap_read(ngap);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    testngap_recv(test_ue, recvbuf);

    /* Send Identity response */
    gmmbuf = testgmm_build_identity_response(test_ue);
    ABTS_PTR_NOTNULL(tc, gmmbuf);
    sendbuf = testngap_build_uplink_nas_transport(test_ue, gmmbuf);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    /* Receive Authentication request */
    recvbuf = testgnb_ngap_read(ngap);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    testngap_recv(test_ue, recvbuf);

    /* Send Authentication response */
    gmmbuf = testgmm_build_authentication_response(test_ue);
    ABTS_PTR_NOTNULL(tc, gmmbuf);
    sendbuf = testngap_build_uplink_nas_transport(test_ue, gmmbuf);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    /* Receive Security mode command */
    recvbuf = testgnb_ngap_read(ngap);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    testngap_recv(test_ue, recvbuf);

    /* Send Security mode complete */
    gmmbuf = testgmm_build_security_mode_complete(test_ue, nasbuf);
    ABTS_PTR_NOTNULL(tc, gmmbuf);
    sendbuf = testngap_build_uplink_nas_transport(test_ue, gmmbuf);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    /* Receive InitialContextSetupRequest +
     * Registration accept */
    recvbuf = testgnb_ngap_read(ngap);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    testngap_recv(test_ue, recvbuf);
    ABTS_INT_EQUAL(tc,
            NGAP_ProcedureCode_id_InitialContextSetup,
            test_ue->ngap_procedure_code);

    /* Send UERadioCapabilityInfoIndication */
    sendbuf = testngap_build_ue_radio_capability_info_indication(test_ue);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    /* Send InitialContextSetupResponse */
    sendbuf = testngap_build_initial_context_setup_response(test_ue, false);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    /* Send Registration complete */
    gmmbuf = testgmm_build_registration_complete(test_ue);
    ABTS_PTR_NOTNULL(tc, gmmbuf);
    sendbuf = testngap_build_uplink_nas_transport(test_ue, gmmbuf);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    /* Receive Configuration update command */
    recvbuf = testgnb_ngap_read(ngap);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    testngap_recv(test_ue, recvbuf);

    /* Send PDU session establishment request */
    sess = test_sess_add_by_dnn_and_psi(test_ue, "internet", 5);
    ogs_assert(sess);
    sess->pdu_session_type = session_type;

    sess->ul_nas_transport_param.request_type =
        OGS_NAS_5GS_REQUEST_TYPE_INITIAL;
    sess->ul_nas_transport_param.dnn = 1;
    sess->ul_nas_transport_param.s_nssai = 0;

    sess->pdu_session_establishment_param.ssc_mode = 1;
    sess->pdu_session_establishment_param.epco = 1;

    gsmbuf = testgsm_build_pdu_session_establishment_request(sess);
    ABTS_PTR_NOTNULL(tc, gsmbuf);
    gmmbuf = testgmm_build_ul_nas_transport(sess,
            OGS_NAS_PAYLOAD_CONTAINER_N1_SM_INFORMATION, gsmbuf);
    ABTS_PTR_NOTNULL(tc, gmmbuf);
    sendbuf = testngap_build_uplink_nas_transport(test_ue, gmmbuf);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    /* Receive PDUSessionResourceSetupRequest +
     * DL NAS transport +
     * PDU session establishment accept */
    recvbuf = testgnb_ngap_read(ngap);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    testngap_recv(test_ue, recvbuf);
    ABTS_INT_EQUAL(tc,
            NGAP_ProcedureCode_id_PDUSessionResourceSetup,
            test_ue->ngap_procedure_code);

    /* Send PDUSessionResourceSetupResponse */
    sendbuf = testngap_sess_build_pdu_session_resource_setup_response(sess);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    qos_flow = test_qos_flow_find_by_qfi(sess, 1);
    ogs_assert(qos_flow);

    /* PDU session type as requested */
    ABTS_TRUE(tc, sess->ue_ip.ipv6);
    ABTS_INT_EQUAL(tc, session_type == OGS_PDU_SESSION_TYPE_IPV4V6,
            sess->ue_ip.ipv4);

    pd_ctx_init(ctx, tc, gnb->gtpu, test_ue, sess, qos_flow);
    if (!sess->ue_ip.ipv6)
        return false;

    /* Send Router Solicitation, receive Router Advertisement
     * (buffered by the UPF until the N3 downlink tunnel is known) */
    return pd_router_discovery(ctx);
}

/* Releases the UE context, de-registers, removes the subscriber */
static void detach_5gc(abts_case *tc, fgc_gnb_t *gnb, pd_ctx_t *ctx)
{
    int rv;
    ogs_pkbuf_t *gmmbuf = NULL;
    ogs_pkbuf_t *sendbuf = NULL;
    ogs_pkbuf_t *recvbuf = NULL;
    ogs_socknode_t *ngap = gnb->ngap;
    test_ue_t *test_ue = ctx->test_ue;

    /* Send UEContextReleaseRequest */
    sendbuf = testngap_build_ue_context_release_request(test_ue,
            NGAP_Cause_PR_radioNetwork, NGAP_CauseRadioNetwork_user_inactivity,
            true);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    /* Receive UEContextReleaseCommand */
    recvbuf = testgnb_ngap_read(ngap);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    testngap_recv(test_ue, recvbuf);
    ABTS_INT_EQUAL(tc,
            NGAP_ProcedureCode_id_UEContextRelease,
            test_ue->ngap_procedure_code);

    /* Send UEContextReleaseComplete */
    sendbuf = testngap_build_ue_context_release_complete(test_ue);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    /* Send De-registration request */
    gmmbuf = testgmm_build_de_registration_request(test_ue, 1, true, false);
    ABTS_PTR_NOTNULL(tc, gmmbuf);
    sendbuf = testngap_build_initial_ue_message(test_ue, gmmbuf,
                NGAP_RRCEstablishmentCause_mo_Signalling, true, false);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    /* Receive UEContextReleaseCommand */
    recvbuf = testgnb_ngap_read(ngap);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    testngap_recv(test_ue, recvbuf);
    ABTS_INT_EQUAL(tc,
            NGAP_ProcedureCode_id_UEContextRelease,
            test_ue->ngap_procedure_code);

    /* Send UEContextReleaseComplete */
    sendbuf = testngap_build_ue_context_release_complete(test_ue);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    ogs_msleep(300);

    /********** Remove Subscriber in Database */
    ABTS_INT_EQUAL(tc, OGS_OK, test_db_remove_ue(test_ue));

    test_ue_remove(test_ue);
    ctx->test_ue = NULL;
}

/*
 * Test cases
 */

static void run_scenario(abts_case *tc, int session_type,
        void (*scenario)(pd_ctx_t *ctx))
{
    fgc_gnb_t gnb;
    pd_ctx_t ctx;

    gnb_setup(tc, &gnb);

    if (attach_5gc(tc, &gnb, FGC_MSIN_1, 0, session_type, NULL, &ctx))
        scenario(&ctx);
    detach_5gc(tc, &gnb, &ctx);

    gnb_close(&gnb);
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

/* Two UEs registered at the same time get distinct blocks */
static void two_ues(abts_case *tc, void *data)
{
    fgc_gnb_t gnb;
    pd_ctx_t ctx1, ctx2;
    bool ok1, ok2;

    gnb_setup(tc, &gnb);

    ok1 = attach_5gc(tc, &gnb, FGC_MSIN_1, 0,
            OGS_PDU_SESSION_TYPE_IPV4V6, NULL, &ctx1);
    ok2 = attach_5gc(tc, &gnb, FGC_MSIN_2, 100,
            OGS_PDU_SESSION_TYPE_IPV6, NULL, &ctx2);

    if (ok1)
        ok1 = pd_solicit_request(&ctx1, true);
    if (ok2)
        ok2 = pd_solicit_request(&ctx2, true);
    if (ok1 && ok2)
        pd_check_distinct_blocks(&ctx1, &ctx2);

    detach_5gc(tc, &gnb, &ctx2);
    detach_5gc(tc, &gnb, &ctx1);

    gnb_close(&gnb);
}

/* Register/de-register cycles: blocks and bindings return to the pool */
static void reattach(abts_case *tc, void *data)
{
    fgc_gnb_t gnb;
    pd_ctx_t ctx;
    int i;

    gnb_setup(tc, &gnb);

    for (i = 0; i < 3; i++) {
        if (attach_5gc(tc, &gnb, FGC_MSIN_1, 0,
                    OGS_PDU_SESSION_TYPE_IPV4V6, NULL, &ctx))
            pd_scenario_basic(&ctx);
        detach_5gc(tc, &gnb, &ctx);
    }

    gnb_close(&gnb);
}

/* Static UE IPv6 address: fixed /64 and /56, identical on re-attach */
static void static_pd(abts_case *tc, void *data)
{
    fgc_gnb_t gnb;
    pd_ctx_t ctx;
    uint8_t link[OGS_IPV6_LEN], block[OGS_IPV6_LEN];
    bool ok;

    gnb_setup(tc, &gnb);

    ok = attach_5gc(tc, &gnb, FGC_MSIN_1, 0,
            OGS_PDU_SESSION_TYPE_IPV4V6, PD_STATIC_UE_IPV6, &ctx);
    if (ok)
        pd_scenario_static(&ctx, true);
    memcpy(link, ctx.link, OGS_IPV6_LEN);
    memcpy(block, ctx.block, OGS_IPV6_LEN);
    detach_5gc(tc, &gnb, &ctx);

    if (attach_5gc(tc, &gnb, FGC_MSIN_1, 0,
                OGS_PDU_SESSION_TYPE_IPV6, PD_STATIC_UE_IPV6, &ctx)) {
        pd_scenario_static(&ctx, false);
        if (ok)
            pd_check_same_prefixes(&ctx, link, block);
    }
    detach_5gc(tc, &gnb, &ctx);

    gnb_close(&gnb);
}

abts_suite *test_5gc(abts_suite *suite)
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

    return suite;
}
