use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use serde_json::Value;
use serde::{Serialize, Deserialize};
use webauthn_rs::prelude::*;
use std::sync::OnceLock;
use url::Url;
use uuid::Uuid;

#[derive(Serialize)]
struct RegistrationOutput {
    challenge: CreationChallengeResponse,
    registration: PasskeyRegistration,
    uuid: Uuid,
}

static WEBAUTHN: OnceLock<Webauthn> = OnceLock::new();

fn get_webauthn() -> &'static Webauthn {
    WEBAUTHN.get_or_init(|| {
        let rp_id = "example.com";
        let rp_origin = Url::parse("https://example.com").unwrap();

        println!("RP ID: {}", rp_id);
        println!("RP Origin: {}", rp_origin);

        WebauthnBuilder::new(rp_id, &rp_origin)
            .expect("Failed to create WebauthnBuilder")
            .rp_name("Example Corp")
            .build()
            .expect("Failed to build Webauthn instance")
    })
}

#[no_mangle]
pub extern "C" fn rust_json_api(input: *const c_char) -> *mut c_char {
    let c_str = unsafe {
        if input.is_null() {
            return std::ptr::null_mut();
        }
        CStr::from_ptr(input)
    };

    let input_str = match c_str.to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };

    println!("{}", input_str);

    let output_str = match handle_json(input_str) {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };

    CString::new(output_str).unwrap().into_raw()
}

#[no_mangle]
pub extern "C" fn free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        unsafe { let _ = CString::from_raw(ptr); };
    }
}

fn handle_json(input: &str) -> Result<String, ()> {
    let v: Value = serde_json::from_str(input).map_err(|_| ())?;
    let op = v.get("op").and_then(|v| v.as_str()).ok_or(())?;

    let result = match op {
        "register_begin" => handle_register_begin(&v),
        "register_finish" => handle_register_finish(&v),
        "login_begin" => handle_login_begin(&v),
        "login_finish" => handle_login_finish(&v),
        _ => Err(()),
    }?;

    Ok(serde_json::to_string(&result).unwrap())
}

fn handle_register_begin(_v: &Value) -> Result<Value, ()> {
    Ok(serde_json::to_value(start_registration("testuser", "Test User")).unwrap())
}

fn handle_register_finish(_v: &Value) -> Result<Value, ()> {
    Ok(serde_json::json!({ "ok": true }))
}

fn handle_login_begin(_v: &Value) -> Result<Value, ()> {
    Ok(serde_json::json!({ "challenge": "def456" }))
}

fn handle_login_finish(_v: &Value) -> Result<Value, ()> {
    Ok(serde_json::json!({ "ok": true }))
}

fn start_registration(user_id: &str, user_name: &str) -> RegistrationOutput {
    let webauthn = get_webauthn();
    let uuid = Uuid::new_v4();
    let (challenge, registration) = webauthn
        .start_passkey_registration(
            uuid,  // Generate a new UUID for the registration request
            user_id,         // The unique user ID
            user_name,       // The user's name
            None,            // No user icon for now
        )
        .expect("Failed to start registration");

    RegistrationOutput {
        challenge,
        registration,
        uuid,
    }
}