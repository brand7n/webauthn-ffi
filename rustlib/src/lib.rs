use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use serde_json::Value;
use serde::Serialize;
use serde_json::json;                                                      
use webauthn_rs::prelude::*;
use std::sync::OnceLock;
use url::Url;
use uuid::Uuid;
use base64::Engine;
use std::fs::OpenOptions;
use std::io::Write;
use std::sync::Mutex;
use chrono::Local;
use serde_cbor;

#[derive(Serialize)]
struct RegistrationOutput {
    challenge: CreationChallengeResponse,
    registration: Value,
    uuid: Uuid,
}

#[derive(Serialize)]
struct AuthenticationOutput {
    challenge: RequestChallengeResponse,
    auth_state: Value,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
    details: Option<String>,
}

static WEBAUTHN: OnceLock<Webauthn> = OnceLock::new();
static LOG_FILE: OnceLock<Mutex<std::fs::File>> = OnceLock::new();

fn init_logger() {
    LOG_FILE.get_or_init(|| {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open("/tmp/webauthn_ffi.log")
            .expect("Failed to open log file");
        Mutex::new(file)
    });
}

fn log(message: &str) {
    if let Some(file) = LOG_FILE.get() {
        if let Ok(mut file) = file.lock() {
            let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S%.3f");
            let _ = writeln!(file, "[{}] {}", timestamp, message);
            let _ = file.flush();
        }
    }
}

fn get_webauthn(rp_id: &str, rp_origin: &str) -> Result<&'static Webauthn, String> {
    log(&format!("Getting Webauthn instance for RP ID: {}, Origin: {}", rp_id, rp_origin));
    
    WEBAUTHN.get_or_init(|| {
        log("Initializing new Webauthn instance");
        let rp_origin = Url::parse(rp_origin).expect("Failed to parse RP origin URL");
        log(&format!("Parsed RP origin URL: {}", rp_origin));
        
        let builder = WebauthnBuilder::new(rp_id, &rp_origin).expect("Failed to create WebauthnBuilder");
        log("Created WebauthnBuilder");
        
        // let webauthn = builder.rp_name("Example Corp").build().expect("Failed to build Webauthn instance");
        
        builder.build().expect("Failed to build Webauthn instance")
    });
    
    Ok(WEBAUTHN.get().expect("Webauthn instance should be initialized"))
}

fn error_log(message: &str) {
    // Write to stderr which PHP will capture
    eprintln!("[WebAuthn] {}", message);
}

#[no_mangle]
pub extern "C" fn rust_json_api(input: *const c_char) -> *mut c_char {
    init_logger();
    log("rust_json_api called");
    
    let c_str = unsafe {
        if input.is_null() {
            log("Input is null");
            return create_error_response("Input is null", None);
        }
        CStr::from_ptr(input)
    };

    let input_str = match c_str.to_str() {
        Ok(s) => s,
        Err(e) => {
            log(&format!("Failed to convert input to string: {}", e));
            return create_error_response("Failed to convert input to string", Some(e.to_string()));
        }
    };

    log(&format!("Received input: {}", input_str));

    let output_str = match handle_json(input_str) {
        Ok(s) => s,
        Err(e) => {
            log(&format!("Error handling JSON: {}", e));
            return create_error_response("Error handling JSON", Some(e));
        }
    };

    log(&format!("Sending response: {}", output_str));

    match CString::new(output_str) {
        Ok(s) => s.into_raw(),
        Err(e) => {
            log(&format!("Failed to create CString: {}", e));
            create_error_response("Failed to create CString", Some(e.to_string()))
        }
    }
}

#[no_mangle]
pub extern "C" fn free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        unsafe {
            // Convert the raw pointer back to a CString and let it drop
            let _ = CString::from_raw(ptr);
        }
    }
}

fn create_error_response(message: &str, details: Option<String>) -> *mut c_char {
    let error = ErrorResponse {
        error: message.to_string(),
        details,
    };
    
    match serde_json::to_string(&error) {
        Ok(s) => match CString::new(s) {
            Ok(s) => s.into_raw(),
            Err(_) => std::ptr::null_mut(),
        },
        Err(_) => std::ptr::null_mut(),
    }
}

fn handle_json(input: &str) -> Result<String, String> {
    log("Parsing JSON input");
    let v: Value = serde_json::from_str(input).map_err(|e| {
        log(&format!("Failed to parse JSON: {}", e));
        format!("Failed to parse JSON: {}", e)
    })?;
    
    let op = v.get("op").and_then(|v| v.as_str()).ok_or_else(|| {
        log("Missing or invalid 'op' field");
        "Missing or invalid 'op' field".to_string()
    })?;

    log(&format!("Operation: {}", op));

    let result = match op {
        "register_begin" => {
            log("Handling register_begin");
            handle_register_begin(&v)
        },
        "register_finish" => {
            log("Handling register_finish");
            handle_register_finish(&v)
        },
        // "login_begin" => {
        //     log("Handling login_begin");
        //     handle_login_begin(&v)
        // },
        // "login_finish" => {
        //     log("Handling login_finish");
        //     handle_login_finish(v)
        // },
        _ => {
            log(&format!("Unknown operation: {}", op));
            Err(format!("Unknown operation: {}", op))
        }
    }?;

    log("Operation completed successfully");
    Ok(serde_json::to_string(&result).unwrap())
}

fn handle_register_begin(v: &Value) -> Result<Value, String> {
    let user_id = v.get("user_id").and_then(|v| v.as_str()).ok_or_else(|| {
        "Missing user_id".to_string()
    })?;
    let user_name = v.get("user_name").and_then(|v| v.as_str()).ok_or_else(|| {
        "Missing user_name".to_string()
    })?;
    let rp_id = v.get("rp_id").and_then(|v| v.as_str()).ok_or_else(|| {
        "Missing rp_id".to_string()
    })?;
    let rp_origin = v.get("rp_origin").and_then(|v| v.as_str()).ok_or_else(|| {
        "Missing rp_origin".to_string()
    })?;
    
    log(&format!("Starting registration with RP ID: {}, Origin: {}", rp_id, rp_origin));
    
    let webauthn = get_webauthn(rp_id, rp_origin)?;
    let result = start_registration(webauthn, user_id, user_name);
    Ok(serde_json::to_value(result).unwrap())
}

fn handle_register_finish(v: &Value) -> Result<Value, String> {
    let registration = v.get("registration").ok_or_else(|| {
        "Missing registration data".to_string()
    })?;
    
    let client_data = v.get("client_data").and_then(|v| v.as_str()).ok_or_else(|| {
        "Missing client_data".to_string()
    })?;

    let rp_id = v.get("rp_id").and_then(|v| v.as_str()).ok_or_else(|| {
        "Missing rp_id".to_string()
    })?;
    let rp_origin = v.get("rp_origin").and_then(|v| v.as_str()).ok_or_else(|| {
        "Missing rp_origin".to_string()
    })?;

    log(&format!("Finishing registration with RP ID: {}, Origin: {}", rp_id, rp_origin));
    
    let webauthn = get_webauthn(rp_id, rp_origin)?;
    
    // Parse the registration state
    let registration: PasskeyRegistration = serde_json::from_value(registration.clone()).map_err(|e| {
        format!("Failed to parse registration data: {}", e)
    })?;

    // Parse the credential from the JSON data
    let credential: RegisterPublicKeyCredential = serde_json::from_str(client_data).map_err(|e| {
        format!("Failed to parse credential: {}", e)
    })?;
    
    log(&format!("Parsed credential data: {:?}", credential));
    
    let result = webauthn
        .finish_passkey_registration(&credential, &registration)
        .map_err(|e| {
            format!("Failed to finish registration: {}", e)
        })?;
    
    // Format the result to match the expected structure
    let formatted_result = json!({
        "credential": {
            "id": base64::engine::general_purpose::STANDARD.encode(result.cred_id().as_ref()),
            "counter": 0, // Initial counter value
            "public_key": base64::engine::general_purpose::STANDARD.encode(serde_cbor::to_vec(result.get_public_key()).unwrap()),
        }
    });
    
    Ok(formatted_result)
}

fn start_registration(webauthn: &Webauthn, user_id: &str, user_name: &str) -> RegistrationOutput {
    let uuid = Uuid::new_v4();
    let (challenge, registration) = webauthn
        .start_passkey_registration(
            uuid,
            user_id,
            user_name,
            None,
        )
        .expect("Failed to start registration");

    log(&format!("Generated registration challenge: {:?}", challenge));

    // Store the complete registration state
    let registration_json = serde_json::to_value(registration).expect("Failed to serialize registration state");

    RegistrationOutput {
        challenge,
        registration: registration_json,
        uuid,
    }
}