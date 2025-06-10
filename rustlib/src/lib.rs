use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use serde_json::Value;
use serde::Serialize;
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

#[derive(Serialize)]
struct AuthenticationOutput {
    challenge: RequestChallengeResponse,
    auth_state: PasskeyAuthentication,
}

static WEBAUTHN: OnceLock<Webauthn> = OnceLock::new();

fn get_webauthn() -> &'static Webauthn {
    println!("Initializing Webauthn instance");
    WEBAUTHN.get_or_init(|| {
        let rp_id = "example.com";
        let rp_origin = Url::parse("https://example.com").unwrap();

        println!("RP ID: {}", rp_id);
        println!("RP Origin: {}", rp_origin);

        let builder = WebauthnBuilder::new(rp_id, &rp_origin)
            .expect("Failed to create WebauthnBuilder");
        println!("Created WebauthnBuilder");

        let webauthn = builder
            .rp_name("Example Corp")
            .build()
            .expect("Failed to build Webauthn instance");
        println!("Built Webauthn instance");

        webauthn
    })
}

#[no_mangle]
pub extern "C" fn rust_json_api(input: *const c_char) -> *mut c_char {
    println!("rust_json_api called");
    
    let c_str = unsafe {
        if input.is_null() {
            println!("Input is null");
            return std::ptr::null_mut();
        }
        CStr::from_ptr(input)
    };

    let input_str = match c_str.to_str() {
        Ok(s) => s,
        Err(e) => {
            println!("Failed to convert input to string: {}", e);
            return std::ptr::null_mut();
        }
    };

    println!("Received input: {}", input_str);

    let output_str = match handle_json(input_str) {
        Ok(s) => s,
        Err(e) => {
            println!("Error handling JSON: {:?}", e);
            return std::ptr::null_mut();
        }
    };

    println!("Sending response: {}", output_str);

    match CString::new(output_str) {
        Ok(s) => s.into_raw(),
        Err(e) => {
            println!("Failed to create CString: {}", e);
            std::ptr::null_mut()
        }
    }
}

#[no_mangle]
pub extern "C" fn free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        unsafe { let _ = CString::from_raw(ptr); };
    }
}

fn handle_json(input: &str) -> Result<String, ()> {
    println!("Parsing JSON input");
    let v: Value = serde_json::from_str(input).map_err(|e| {
        println!("Failed to parse JSON: {}", e);
        ()
    })?;
    
    let op = v.get("op").and_then(|v| v.as_str()).ok_or_else(|| {
        println!("Missing or invalid 'op' field");
        ()
    })?;

    println!("Operation: {}", op);

    let result = match op {
        "register_begin" => handle_register_begin(&v),
        "register_finish" => handle_register_finish(&v),
        "login_begin" => handle_login_begin(&v),
        "login_finish" => handle_login_finish(v),
        _ => {
            println!("Unknown operation: {}", op);
            Err(())
        }
    }?;

    println!("Operation completed successfully");
    Ok(serde_json::to_string(&result).unwrap())
}

fn handle_register_begin(v: &Value) -> Result<Value, ()> {
    println!("Handling register_begin");
    let user_id = v.get("user_id").and_then(|v| v.as_str()).ok_or_else(|| {
        println!("Missing user_id");
        ()
    })?;
    let user_name = v.get("user_name").and_then(|v| v.as_str()).ok_or_else(|| {
        println!("Missing user_name");
        ()
    })?;
    
    println!("Starting registration for user: {} ({})", user_name, user_id);
    let result = start_registration(user_id, user_name);
    println!("Registration started successfully");
    
    Ok(serde_json::to_value(result).unwrap())
}

fn handle_register_finish(v: &Value) -> Result<Value, ()> {
    println!("Handling register_finish request");
    
    let registration = v.get("registration").ok_or_else(|| {
        println!("Missing registration data");
        ()
    })?;
    
    let client_data = v.get("client_data").and_then(|v| v.as_str()).ok_or_else(|| {
        println!("Missing client_data");
        ()
    })?;

    println!("Received data - client_data: {}", client_data);

    let webauthn = get_webauthn();
    
    // Parse the registration state
    let registration: PasskeyRegistration = serde_json::from_value(registration.clone()).map_err(|e| {
        println!("Failed to parse registration data: {}", e);
        ()
    })?;

    // Parse the credential from the JSON data
    let credential: RegisterPublicKeyCredential = serde_json::from_str(client_data).map_err(|e| {
        println!("Failed to parse credential: {}", e);
        ()
    })?;

    println!("Attempting to finish registration");
    
    let result = webauthn
        .finish_passkey_registration(&credential, &registration)
        .map_err(|e| {
            println!("Failed to finish registration: {}", e);
            ()
        })?;
    
    println!("Registration completed successfully");
    
    Ok(serde_json::to_value(result).unwrap())
}

fn handle_login_begin(v: &Value) -> Result<Value, ()> {
    let _user_id = v.get("user_id").and_then(|v| v.as_str()).ok_or(())?;
    let passkeys = v.get("passkeys")
        .and_then(|v| v.as_array())
        .ok_or(())?
        .iter()
        .filter_map(|v| serde_json::from_value::<Passkey>(v.clone()).ok())
        .collect::<Vec<_>>();

    if passkeys.is_empty() {
        return Err(());
    }

    let webauthn = get_webauthn();
    let (challenge, auth_state) = webauthn
        .start_passkey_authentication(&passkeys)
        .map_err(|_| ())?;

    let output = AuthenticationOutput {
        challenge,
        auth_state,
    };

    Ok(serde_json::to_value(output).unwrap())
}

pub fn handle_login_finish(v: Value) -> Result<Value, ()> {
    let auth_state = v.get("auth_state").ok_or(())?;
    let client_data = v.get("client_data").and_then(|v| v.as_str()).ok_or(())?;
    
    let webauthn = get_webauthn();
    let auth_state: PasskeyAuthentication = serde_json::from_value(auth_state.clone()).map_err(|_| ())?;
    let credential: PublicKeyCredential = serde_json::from_str(client_data).map_err(|_| ())?;
    
    let result = webauthn
        .finish_passkey_authentication(&credential, &auth_state)
        .map_err(|_| ())?;
    
    Ok(serde_json::to_value(result).unwrap())
}

fn start_registration(user_id: &str, user_name: &str) -> RegistrationOutput {
    let webauthn = get_webauthn();
    let uuid = Uuid::new_v4();
    let (challenge, registration) = webauthn
        .start_passkey_registration(
            uuid,
            user_id,
            user_name,
            None,
        )
        .expect("Failed to start registration");

    RegistrationOutput {
        challenge,
        registration,
        uuid,
    }
}