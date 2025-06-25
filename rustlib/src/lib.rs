use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use serde_json::Value;
use serde::Serialize;
use webauthn_rs::prelude::*;
use std::sync::OnceLock;
use url::Url;
use uuid::Uuid;
use base64::Engine;

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

fn get_webauthn(rp_id: &str, rp_origin: &str) -> Result<&'static Webauthn, String> {
    //log(&format!("Getting Webauthn instance for RP ID: {}, Origin: {}", rp_id, rp_origin));
    
    WEBAUTHN.get_or_init(|| {
        //log("Initializing new Webauthn instance");
        let rp_origin = Url::parse(rp_origin).expect("Failed to parse RP origin URL");
        //log(&format!("Parsed RP origin URL: {}", rp_origin));
        
        let builder = WebauthnBuilder::new(rp_id, &rp_origin).expect("Failed to create WebauthnBuilder");
        //log("Created WebauthnBuilder");
                
        builder.build().expect("Failed to build Webauthn instance")
    });
    
    Ok(WEBAUTHN.get().expect("Webauthn instance should be initialized"))
}

#[no_mangle]
pub extern "C" fn rust_json_api(input: *const c_char) -> *mut c_char {
    //log("rust_json_api called");
    
    let c_str = unsafe {
        if input.is_null() {
            //log("Input is null");
            return create_error_response("Input is null", None);
        }
        CStr::from_ptr(input)
    };

    let input_str = match c_str.to_str() {
        Ok(s) => s,
        Err(e) => {
            //log(&format!("Failed to convert input to string: {}", e));
            return create_error_response("Failed to convert input to string", Some(e.to_string()));
        }
    };

    //log(&format!("Received input: {}", input_str));

    let output_str = match handle_json(input_str) {
        Ok(s) => s,
        Err(e) => {
            //log(&format!("Error handling JSON: {}", e));
            return create_error_response("Error handling JSON", Some(e));
        }
    };

    //log(&format!("Sending response: {}", output_str));

    match CString::new(output_str) {
        Ok(s) => s.into_raw(),
        Err(e) => {
            //log(&format!("Failed to create CString: {}", e));
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
    //log("Parsing JSON input");
    let v: Value = serde_json::from_str(input).map_err(|e| {
        //log(&format!("Failed to parse JSON: {}", e));
        format!("Failed to parse JSON: {}", e)
    })?;
    
    let op = v.get("op").and_then(|v| v.as_str()).ok_or_else(|| {
        //log("Missing or invalid 'op' field");
        "Missing or invalid 'op' field".to_string()
    })?;

    //log(&format!("Operation: {}", op));

    let result = match op {
        "register_begin" => {
            //log("Handling register_begin");
            handle_register_begin(&v)
        },
        "register_finish" => {
            //log("Handling register_finish");
            handle_register_finish(&v)
        },
        "login_begin" => {
            //log("Handling login_begin");
            handle_login_begin(&v)
        },
        "login_finish" => {
            //log("Handling login_finish");
            handle_login_finish(&v)
        },
        _ => {
            //log(&format!("Unknown operation: {}", op));
            Err(format!("Unknown operation: {}", op))
        }
    }?;

    //log("Operation completed successfully");
    Ok(serde_json::to_string(&result).unwrap())
}

fn handle_register_begin(v: &Value) -> Result<Value, String> {
    #[derive(serde::Deserialize)]
    struct RegisterBeginRequest {
        user_id: String,
        user_name: String,
        rp_id: String,
        rp_origin: String,
    }
    
    let req: RegisterBeginRequest = serde_json::from_value(v.clone()).map_err(|e| {
        format!("Failed to parse register_begin request: {}", e)
    })?;
    
    //log(&format!("Starting registration with RP ID: {}, Origin: {}", req.rp_id, req.rp_origin));
    
    let webauthn = get_webauthn(&req.rp_id, &req.rp_origin)?;
    let result = start_registration(webauthn, &req.user_id, &req.user_name);
    Ok(serde_json::to_value(result).unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_handle_register_begin_success() {
        let input = json!({
            "op": "register_begin",
            "user_id": "test_user_123",
            "user_name": "Test User",
            "rp_id": "example.com",
            "rp_origin": "https://example.com"
        });

        let result = handle_register_begin(&input);
        assert!(result.is_ok(), "Registration should succeed with valid input");

        let result_value = result.unwrap();
        
        // Verify the response structure
        assert!(result_value.get("challenge").is_some(), "Response should contain challenge");
        assert!(result_value.get("registration").is_some(), "Response should contain registration");
        assert!(result_value.get("uuid").is_some(), "Response should contain uuid");

        // Verify challenge structure
        let challenge = result_value.get("challenge").unwrap();
        assert!(challenge.get("publicKey").is_some(), "Challenge should contain publicKey");
        
        let public_key = challenge.get("publicKey").unwrap();
        assert!(public_key.get("challenge").is_some(), "publicKey should contain challenge");
        assert!(public_key.get("rp").is_some(), "publicKey should contain rp");
        assert!(public_key.get("user").is_some(), "publicKey should contain user");
        assert!(public_key.get("pubKeyCredParams").is_some(), "publicKey should contain pubKeyCredParams");
        assert!(public_key.get("timeout").is_some(), "publicKey should contain timeout");
        assert!(public_key.get("attestation").is_some(), "publicKey should contain attestation");

        // Verify user info in challenge - user.id is base64 encoded
        let user = public_key.get("user").unwrap();
        // The user.id is base64 encoded, so we can't directly compare the string
        assert!(user.get("id").is_some(), "User should have an id field");
        // The WebAuthn library sets user.name to user_id
        assert_eq!(user.get("name").unwrap().as_str().unwrap(), "test_user_123");
        // displayName might be the same as user_name or user_id
        assert!(user.get("displayName").is_some(), "User should have displayName field");

        // Verify RP info in challenge
        let rp = public_key.get("rp").unwrap();
        assert_eq!(rp.get("id").unwrap().as_str().unwrap(), "example.com");
        // The WebAuthn library sets rp.name to rp_id
        assert_eq!(rp.get("name").unwrap().as_str().unwrap(), "example.com");
    }

    #[test]
    fn test_handle_register_begin_missing_user_id() {
        let input = json!({
            "op": "register_begin",
            "user_name": "Test User",
            "rp_id": "example.com",
            "rp_origin": "https://example.com"
        });

        let result = handle_register_begin(&input);
        assert!(result.is_err(), "Should fail when user_id is missing");
        assert!(result.unwrap_err().contains("Failed to parse register_begin request"));
    }

    #[test]
    fn test_handle_register_begin_missing_user_name() {
        let input = json!({
            "op": "register_begin",
            "user_id": "test_user_123",
            "rp_id": "example.com",
            "rp_origin": "https://example.com"
        });

        let result = handle_register_begin(&input);
        assert!(result.is_err(), "Should fail when user_name is missing");
        assert!(result.unwrap_err().contains("Failed to parse register_begin request"));
    }

    #[test]
    fn test_handle_register_begin_missing_rp_id() {
        let input = json!({
            "op": "register_begin",
            "user_id": "test_user_123",
            "user_name": "Test User",
            "rp_origin": "https://example.com"
        });

        let result = handle_register_begin(&input);
        assert!(result.is_err(), "Should fail when rp_id is missing");
        assert!(result.unwrap_err().contains("Failed to parse register_begin request"));
    }

    #[test]
    fn test_handle_register_begin_missing_rp_origin() {
        let input = json!({
            "op": "register_begin",
            "user_id": "test_user_123",
            "user_name": "Test User",
            "rp_id": "example.com"
        });

        let result = handle_register_begin(&input);
        assert!(result.is_err(), "Should fail when rp_origin is missing");
        assert!(result.unwrap_err().contains("Failed to parse register_begin request"));
    }

    #[test]
    fn test_handle_register_begin_special_characters_in_names() {
        let input = json!({
            "op": "register_begin",
            "user_id": "user_with_special_chars_123",
            "user_name": "Test User with Special Characters: !@#$%^&*()",
            "rp_id": "example.com",
            "rp_origin": "https://example.com"
        });

        let result = handle_register_begin(&input);
        assert!(result.is_ok(), "Should handle special characters in user names");

        let result_value = result.unwrap();
        let challenge = result_value.get("challenge").unwrap();
        let public_key = challenge.get("publicKey").unwrap();
        let user = public_key.get("user").unwrap();
        
        // The WebAuthn library sets user.name to user_id
        assert_eq!(user.get("name").unwrap().as_str().unwrap(), "user_with_special_chars_123");
        // displayName might be the same as user_name or user_id
        assert!(user.get("displayName").is_some(), "User should have displayName field");
    }

    #[test]
    fn test_handle_register_begin_invalid_json() {
        // Test with malformed JSON structure
        let input = json!({
            "op": "register_begin",
            "user_id": 123, // Should be string
            "user_name": "Test User",
            "rp_id": "example.com",
            "rp_origin": "https://example.com"
        });

        let result = handle_register_begin(&input);
        assert!(result.is_err(), "Should fail with invalid JSON types");
        assert!(result.unwrap_err().contains("Failed to parse register_begin request"));
    }

    #[test]
    fn test_handle_register_begin_extra_fields() {
        let input = json!({
            "op": "register_begin",
            "user_id": "test_user_123",
            "user_name": "Test User",
            "rp_id": "example.com",
            "rp_origin": "https://example.com",
            "extra_field": "should_be_ignored"
        });

        let result = handle_register_begin(&input);
        assert!(result.is_ok(), "Should succeed with extra fields (they should be ignored)");
    }
}

fn handle_register_finish(v: &Value) -> Result<Value, String> {
    #[derive(serde::Deserialize)]
    struct RegisterFinishRequest {
        registration: PasskeyRegistration,
        client_data: RegisterPublicKeyCredential,
        rp_id: String,
        rp_origin: String,
    }
    
    let req: RegisterFinishRequest = serde_json::from_value(v.clone()).map_err(|e| {
        format!("Failed to parse register_finish request: {}", e)
    })?;

    //log(&format!("Finishing registration with RP ID: {}, Origin: {}", req.rp_id, req.rp_origin));
    
    let webauthn = get_webauthn(&req.rp_id, &req.rp_origin)?;
    
    //log(&format!("Parsed credential data: {:?}", req.client_data));
    
    let result = webauthn
        .finish_passkey_registration(&req.client_data, &req.registration)
        .map_err(|e| {
            format!("Failed to finish registration: {}", e)
        })?;

    Ok(serde_json::to_value(result).unwrap())
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

    //log(&format!("Generated registration challenge: {:?}", challenge));

    // Store the complete registration state
    let registration_json = serde_json::to_value(registration).expect("Failed to serialize registration state");

    RegistrationOutput {
        challenge,
        registration: registration_json,
        uuid,
    }
}

fn handle_login_begin(v: &Value) -> Result<Value, String> {
    #[derive(serde::Deserialize)]
    struct LoginBeginRequest {
        _user_id: String,
        passkeys: Vec<Passkey>,
        rp_id: String,
        rp_origin: String,
    }
    
    let req: LoginBeginRequest = serde_json::from_value(v.clone()).map_err(|e| {
        format!("Failed to parse login_begin request: {}", e)
    })?;
    
    //log(&format!("Starting login with RP ID: {}, Origin: {}", req.rp_id, req.rp_origin));
    
    let webauthn = get_webauthn(&req.rp_id, &req.rp_origin)?;
    
    // Start the authentication process with the provided passkeys
    let (challenge, auth_state) = webauthn
        .start_passkey_authentication(&req.passkeys)
        .map_err(|e| {
            format!("Failed to start authentication: {}", e)
        })?;
    
    //log(&format!("Generated authentication challenge: {:?}", challenge));
    
    // Store the complete authentication state
    let auth_state_json = serde_json::to_value(auth_state).expect("Failed to serialize auth state");
    
    let output = AuthenticationOutput {
        challenge,
        auth_state: auth_state_json,
    };
    
    Ok(serde_json::to_value(output).unwrap())
}

fn handle_login_finish(v: &Value) -> Result<Value, String> {
    #[derive(serde::Deserialize)]
    struct LoginFinishRequest {
        auth_state: PasskeyAuthentication,
        client_data: PublicKeyCredential,
        rp_id: String,
        rp_origin: String,
    }
    
    let req: LoginFinishRequest = serde_json::from_value(v.clone()).map_err(|e| {
        format!("Failed to parse login_finish request: {}", e)
    })?;

    //log(&format!("Finishing login with RP ID: {}, Origin: {}", req.rp_id, req.rp_origin));
    
    let webauthn = get_webauthn(&req.rp_id, &req.rp_origin)?;
    
    //log(&format!("Parsed credential data: {:?}", req.client_data));
    
    let result = webauthn
        .finish_passkey_authentication(&req.client_data, &req.auth_state)
        .map_err(|e| {
            // indicates authentication failed
            format!("Failed to finish authentication: {}", e)
        })?;
    
    #[derive(serde::Serialize)]
    struct LoginFinishResponse {
        credential_id: String,
        counter: u32,
        needs_update: bool,
    }

    // Format the result to match the expected structure
    let formatted_result = LoginFinishResponse {
        credential_id: base64::engine::general_purpose::STANDARD.encode(result.cred_id().as_ref()),
        counter: result.counter(),
        needs_update: result.needs_update(),
    };
    
    Ok(serde_json::to_value(formatted_result).unwrap())
}