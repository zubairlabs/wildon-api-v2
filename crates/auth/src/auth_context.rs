use crate::claims::Claims;
use contracts::wildon::{
    auth_context::v1::AuthContext as ProtoAuthContext,
    common::v1::{Audience, Realm},
};

pub type AuthContext = ProtoAuthContext;

pub fn from_claims(claims: Claims, request_id: String) -> AuthContext {
    AuthContext {
        sub: claims.sub,
        subject_type: "user".to_string(),
        cid: claims.cid,
        aud: audience_to_proto(&claims.aud) as i32,
        realm: realm_to_proto(&claims.realm) as i32,
        sv: i64::from(claims.sv),
        perm_rev: claims.perm_rev,
        jti: claims.jti,
        exp: claims.exp,
        iat: claims.iat,
        sid: claims.sid.unwrap_or_default(),
        amr: claims.amr,
        device_id: claims.device_id.unwrap_or_default(),
        roles: claims.roles,
        scopes: claims.scopes,
        request_id,
        trace_id: String::new(),
    }
}

fn audience_to_proto(audience: &str) -> Audience {
    match audience {
        "public" => Audience::Public,
        "platform" => Audience::Platform,
        "control" => Audience::Control,
        _ => Audience::Unspecified,
    }
}

fn realm_to_proto(realm: &str) -> Realm {
    match realm {
        "public" => Realm::WildonPublic,
        "platform" => Realm::WildonPlatform,
        "control" => Realm::WildonControl,
        _ => Realm::Unspecified,
    }
}
