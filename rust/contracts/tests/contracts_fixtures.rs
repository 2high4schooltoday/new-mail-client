use contracts::pam::{validate_request, Request, Response};
use contracts::updater::{ApplyRequest, ApplyStatus, APPLY_STATE_IN_PROGRESS};
use contracts::{
    mailsec, mailsec::Request as MailsecRequest, mailsec::Response as MailsecResponse,
};

#[test]
fn pam_fixture_request_and_response_are_stable() {
    let req_raw = include_str!("fixtures/pam/request_ok.json");
    let resp_raw = include_str!("fixtures/pam/response_ok.json");

    let req: Request = serde_json::from_str(req_raw).expect("parse request fixture");
    validate_request(&req).expect("request fixture should be valid");

    let resp: Response = serde_json::from_str(resp_raw).expect("parse response fixture");
    assert!(resp.ok);
    assert_eq!(resp.code, "ok");
    assert_eq!(resp.request_id, req.request_id);
}

#[test]
fn updater_fixture_schema_is_stable() {
    let req_raw = include_str!("fixtures/updater/request.json");
    let status_raw = include_str!("fixtures/updater/status_in_progress.json");

    let req: ApplyRequest = serde_json::from_str(req_raw).expect("parse updater request fixture");
    let status: ApplyStatus =
        serde_json::from_str(status_raw).expect("parse updater status fixture");

    assert_eq!(status.state, APPLY_STATE_IN_PROGRESS);
    assert_eq!(status.request_id, req.request_id);
    assert_eq!(status.target_version, req.target_version);
}

#[test]
fn mailsec_fixture_schema_is_stable() {
    let req_raw = include_str!("fixtures/mailsec/request_parse.json");
    let resp_raw = include_str!("fixtures/mailsec/response_ok.json");

    let req: MailsecRequest = serde_json::from_str(req_raw).expect("parse mailsec request fixture");
    mailsec::validate_request(&req).expect("mailsec request fixture should be valid");

    let resp: MailsecResponse =
        serde_json::from_str(resp_raw).expect("parse mailsec response fixture");
    assert!(resp.ok);
    assert_eq!(resp.code, "ok");
    assert_eq!(resp.request_id, req.request_id);
}

#[test]
fn mailsec_crypto_fixture_schema_is_stable() {
    let req_raw = include_str!("fixtures/mailsec/request_crypto_pgp_sign.json");
    let resp_raw = include_str!("fixtures/mailsec/response_crypto_pgp_sign_ok.json");

    let req: MailsecRequest = serde_json::from_str(req_raw).expect("parse mailsec crypto request");
    mailsec::validate_request(&req).expect("mailsec crypto request fixture should be valid");
    assert_eq!(req.op, "crypto.pgp.sign");

    let resp: MailsecResponse =
        serde_json::from_str(resp_raw).expect("parse mailsec crypto response");
    assert!(resp.ok);
    assert_eq!(resp.code, "ok");
    assert_eq!(resp.request_id, req.request_id);
}
