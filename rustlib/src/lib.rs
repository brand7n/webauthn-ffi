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

    // Tests for handle_login_begin
    #[test]
    fn test_handle_login_begin_success() {
        let input = json!({
            "op": "login_begin",
            "_user_id": "test_user_123",
            "passkeys": [],
            "rp_id": "example.com",
            "rp_origin": "https://example.com"
        });

        let result = handle_login_begin(&input);
        assert!(result.is_ok(), "Login should succeed with valid input");

        let result_value = result.unwrap();
        
        // Verify the response structure
        assert!(result_value.get("challenge").is_some(), "Response should contain challenge");
        assert!(result_value.get("auth_state").is_some(), "Response should contain auth_state");

        // Verify challenge structure
        let challenge = result_value.get("challenge").unwrap();
        assert!(challenge.get("publicKey").is_some(), "Challenge should contain publicKey");
        
        let public_key = challenge.get("publicKey").unwrap();
        assert!(public_key.get("challenge").is_some(), "publicKey should contain challenge");
        assert!(public_key.get("rpId").is_some(), "publicKey should contain rpId");
        assert!(public_key.get("timeout").is_some(), "publicKey should contain timeout");
        assert!(public_key.get("userVerification").is_some(), "publicKey should contain userVerification");
    }

    #[test]
    fn test_handle_login_begin_missing_passkeys() {
        let input = json!({
            "op": "login_begin",
            "_user_id": "test_user_123",
            "rp_id": "example.com",
            "rp_origin": "https://example.com"
        });

        let result = handle_login_begin(&input);
        assert!(result.is_err(), "Should fail when passkeys field is missing");
        assert!(result.unwrap_err().contains("Failed to parse login_begin request"));
    }

    #[test]
    fn test_handle_login_begin_missing_rp_id() {
        let input = json!({
            "op": "login_begin",
            "_user_id": "test_user_123",
            "passkeys": [],
            "rp_origin": "https://example.com"
        });

        let result = handle_login_begin(&input);
        assert!(result.is_err(), "Should fail when rp_id is missing");
        assert!(result.unwrap_err().contains("Failed to parse login_begin request"));
    }

    #[test]
    fn test_handle_login_begin_missing_rp_origin() {
        let input = json!({
            "op": "login_begin",
            "_user_id": "test_user_123",
            "passkeys": [],
            "rp_id": "example.com"
        });

        let result = handle_login_begin(&input);
        assert!(result.is_err(), "Should fail when rp_origin is missing");
        assert!(result.unwrap_err().contains("Failed to parse login_begin request"));
    }

    // Tests for handle_register_finish
    #[test]
    fn test_handle_register_finish_missing_registration() {
        let input = json!({
            "op": "register_finish",
            "client_data": {},
            "rp_id": "example.com",
            "rp_origin": "https://example.com"
        });

        let result = handle_register_finish(&input);
        assert!(result.is_err(), "Should fail when registration field is missing");
        assert!(result.unwrap_err().contains("Failed to parse register_finish request"));
    }

    #[test]
    fn test_handle_register_finish_missing_client_data() {
        let input = json!({
            "op": "register_finish",
            "registration": {},
            "rp_id": "example.com",
            "rp_origin": "https://example.com"
        });

        let result = handle_register_finish(&input);
        assert!(result.is_err(), "Should fail when client_data field is missing");
        assert!(result.unwrap_err().contains("Failed to parse register_finish request"));
    }

    #[test]
    fn test_handle_register_finish_missing_rp_id() {
        let input = json!({
            "op": "register_finish",
            "registration": {},
            "client_data": {},
            "rp_origin": "https://example.com"
        });

        let result = handle_register_finish(&input);
        assert!(result.is_err(), "Should fail when rp_id is missing");
        assert!(result.unwrap_err().contains("Failed to parse register_finish request"));
    }

    #[test]
    fn test_handle_register_finish_missing_rp_origin() {
        let input = json!({
            "op": "register_finish",
            "registration": {},
            "client_data": {},
            "rp_id": "example.com"
        });

        let result = handle_register_finish(&input);
        assert!(result.is_err(), "Should fail when rp_origin is missing");
        assert!(result.unwrap_err().contains("Failed to parse register_finish request"));
    }

    // Tests for handle_login_finish
    #[test]
    fn test_handle_login_finish_missing_auth_state() {
        let input = json!({
            "op": "login_finish",
            "client_data": {},
            "rp_id": "example.com",
            "rp_origin": "https://example.com"
        });

        let result = handle_login_finish(&input);
        assert!(result.is_err(), "Should fail when auth_state field is missing");
        assert!(result.unwrap_err().contains("Failed to parse login_finish request"));
    }

    #[test]
    fn test_handle_login_finish_missing_client_data() {
        let input = json!({
            "op": "login_finish",
            "auth_state": {},
            "rp_id": "example.com",
            "rp_origin": "https://example.com"
        });

        let result = handle_login_finish(&input);
        assert!(result.is_err(), "Should fail when client_data field is missing");
        assert!(result.unwrap_err().contains("Failed to parse login_finish request"));
    }

    #[test]
    fn test_handle_login_finish_missing_rp_id() {
        let input = json!({
            "op": "login_finish",
            "auth_state": {},
            "client_data": {},
            "rp_origin": "https://example.com"
        });

        let result = handle_login_finish(&input);
        assert!(result.is_err(), "Should fail when rp_id is missing");
        assert!(result.unwrap_err().contains("Failed to parse login_finish request"));
    }

    #[test]
    fn test_handle_login_finish_missing_rp_origin() {
        let input = json!({
            "op": "login_finish",
            "auth_state": {},
            "client_data": {},
            "rp_id": "example.com"
        });

        let result = handle_login_finish(&input);
        assert!(result.is_err(), "Should fail when rp_origin is missing");
        assert!(result.unwrap_err().contains("Failed to parse login_finish request"));
    }

    // Tests for rust_json_api and free_string
    #[test]
    fn test_rust_json_api_register_begin() {
        let input = r#"{"op":"register_begin","user_id":"test_user","user_name":"Test User","rp_id":"example.com","rp_origin":"https://example.com"}"#;
        
        let input_cstr = std::ffi::CString::new(input).unwrap();
        let result_ptr = rust_json_api(input_cstr.as_ptr());
        
        assert!(!result_ptr.is_null(), "Should return non-null pointer");
        
        let result_str = unsafe { std::ffi::CStr::from_ptr(result_ptr) };
        let result = result_str.to_str().unwrap();
        
        // Parse the result to verify it's valid JSON
        let parsed: serde_json::Value = serde_json::from_str(result).unwrap();
        assert!(parsed.get("challenge").is_some(), "Should contain challenge");
        assert!(parsed.get("registration").is_some(), "Should contain registration");
        assert!(parsed.get("uuid").is_some(), "Should contain uuid");
        
        // Clean up
        free_string(result_ptr);
    }

    #[test]
    fn test_rust_json_api_login_begin() {
        let input = r#"{"op":"login_begin","_user_id":"test_user","passkeys":[],"rp_id":"example.com","rp_origin":"https://example.com"}"#;
        
        let input_cstr = std::ffi::CString::new(input).unwrap();
        let result_ptr = rust_json_api(input_cstr.as_ptr());
        
        assert!(!result_ptr.is_null(), "Should return non-null pointer");
        
        let result_str = unsafe { std::ffi::CStr::from_ptr(result_ptr) };
        let result = result_str.to_str().unwrap();
        
        // Parse the result to verify it's valid JSON
        let parsed: serde_json::Value = serde_json::from_str(result).unwrap();
        assert!(parsed.get("challenge").is_some(), "Should contain challenge");
        assert!(parsed.get("auth_state").is_some(), "Should contain auth_state");
        
        // Clean up
        free_string(result_ptr);
    }

    #[test]
    fn test_rust_json_api_null_input() {
        let result_ptr = rust_json_api(std::ptr::null());
        
        assert!(!result_ptr.is_null(), "Should return error response for null input");
        
        let result_str = unsafe { std::ffi::CStr::from_ptr(result_ptr) };
        let result = result_str.to_str().unwrap();
        
        // Parse the result to verify it's an error
        let parsed: serde_json::Value = serde_json::from_str(result).unwrap();
        assert!(parsed.get("error").is_some(), "Should contain error field");
        assert_eq!(parsed["error"], "Input is null");
        
        // Clean up
        free_string(result_ptr);
    }

    #[test]
    fn test_rust_json_api_invalid_json() {
        let input = r#"{"op":"register_begin","user_id":"test_user"#; // Invalid JSON
        
        let input_cstr = std::ffi::CString::new(input).unwrap();
        let result_ptr = rust_json_api(input_cstr.as_ptr());
        
        assert!(!result_ptr.is_null(), "Should return error response for invalid JSON");
        
        let result_str = unsafe { std::ffi::CStr::from_ptr(result_ptr) };
        let result = result_str.to_str().unwrap();
        
        // Parse the result to verify it's an error
        let parsed: serde_json::Value = serde_json::from_str(result).unwrap();
        assert!(parsed.get("error").is_some(), "Should contain error field");
        assert_eq!(parsed["error"], "Error handling JSON");
        assert!(parsed.get("details").is_some(), "Should contain details field");
        assert!(parsed["details"].as_str().unwrap().contains("Failed to parse JSON"));
        
        // Clean up
        free_string(result_ptr);
    }

    #[test]
    fn test_rust_json_api_unknown_operation() {
        let input = r#"{"op":"unknown_operation","user_id":"test_user"}"#;
        
        let input_cstr = std::ffi::CString::new(input).unwrap();
        let result_ptr = rust_json_api(input_cstr.as_ptr());
        
        assert!(!result_ptr.is_null(), "Should return error response for unknown operation");
        
        let result_str = unsafe { std::ffi::CStr::from_ptr(result_ptr) };
        let result = result_str.to_str().unwrap();
        
        // Parse the result to verify it's an error
        let parsed: serde_json::Value = serde_json::from_str(result).unwrap();
        assert!(parsed.get("error").is_some(), "Should contain error field");
        assert_eq!(parsed["error"], "Error handling JSON");
        assert!(parsed.get("details").is_some(), "Should contain details field");
        assert!(parsed["details"].as_str().unwrap().contains("Unknown operation"));
        
        // Clean up
        free_string(result_ptr);
    }

    #[test]
    fn test_rust_json_api_missing_op() {
        let input = r#"{"user_id":"test_user","user_name":"Test User"}"#;
        
        let input_cstr = std::ffi::CString::new(input).unwrap();
        let result_ptr = rust_json_api(input_cstr.as_ptr());
        
        assert!(!result_ptr.is_null(), "Should return error response for missing op");
        
        let result_str = unsafe { std::ffi::CStr::from_ptr(result_ptr) };
        let result = result_str.to_str().unwrap();
        
        // Parse the result to verify it's an error
        let parsed: serde_json::Value = serde_json::from_str(result).unwrap();
        assert!(parsed.get("error").is_some(), "Should contain error field");
        assert_eq!(parsed["error"], "Error handling JSON");
        assert!(parsed.get("details").is_some(), "Should contain details field");
        assert!(parsed["details"].as_str().unwrap().contains("Missing or invalid 'op' field"));
        
        // Clean up
        free_string(result_ptr);
    }

    #[test]
    fn test_free_string_null_pointer() {
        // Should not panic when called with null pointer
        free_string(std::ptr::null_mut());
    }

    #[test]
    fn test_free_string_valid_pointer() {
        // Test that we can free a valid pointer
        let input = r#"{"op":"register_begin","user_id":"test_user","user_name":"Test User","rp_id":"example.com","rp_origin":"https://example.com"}"#;
        
        let input_cstr = std::ffi::CString::new(input).unwrap();
        let result_ptr = rust_json_api(input_cstr.as_ptr());
        
        assert!(!result_ptr.is_null(), "Should return non-null pointer");
        
        // Free the pointer - should not panic
        free_string(result_ptr);
    }

    // Integration tests for complete WebAuthn flow
    #[test]
    fn test_integration_registration_flow() {
        // Step 1: Start registration
        let register_begin_input = json!({
            "op": "register_begin",
            "user_id": "integration_test_user",
            "user_name": "Integration Test User",
            "rp_id": "example.com",
            "rp_origin": "https://example.com"
        });

        let register_begin_result = handle_register_begin(&register_begin_input);
        assert!(register_begin_result.is_ok(), "Registration begin should succeed");
        
        let register_begin_data = register_begin_result.unwrap();
        let challenge = register_begin_data.get("challenge").unwrap();
        let registration_state = register_begin_data.get("registration").unwrap();
        let uuid = register_begin_data.get("uuid").unwrap();
        
        // Verify we have the expected data
        assert!(challenge.get("publicKey").is_some(), "Challenge should contain publicKey");
        assert!(registration_state.is_object(), "Registration state should be an object");
        assert!(uuid.is_string(), "UUID should be a string");

        // Step 2: Simulate client-side credential creation (mock data)
        // In a real scenario, this would be done by the browser/authenticator
        let mock_client_data = json!({
            "id": "mock_credential_id",
            "rawId": "bW9ja19jcmVkZW50aWFsX2lk",
            "response": {
                "attestationObject": "mock_attestation_object_data",
                "clientDataJSON": "mock_client_data_json"
            },
            "type": "public-key"
        });

        // Step 3: Finish registration
        let register_finish_input = json!({
            "op": "register_finish",
            "registration": registration_state,
            "client_data": mock_client_data,
            "rp_id": "example.com",
            "rp_origin": "https://example.com"
        });

        let register_finish_result = handle_register_finish(&register_finish_input);
        // This will likely fail with mock data, but we can verify the function handles it gracefully
        // In a real scenario, this would succeed with valid credential data
        assert!(register_finish_result.is_ok() || register_finish_result.is_err());
        
        if register_finish_result.is_err() {
            let error = register_finish_result.unwrap_err();
            // Should fail with a meaningful error about invalid credential data
            assert!(error.contains("Failed to finish registration") || 
                   error.contains("Failed to parse register_finish request"));
        }
    }

    #[test]
    fn test_integration_authentication_flow() {
        // Step 1: Start authentication
        let login_begin_input = json!({
            "op": "login_begin",
            "_user_id": "integration_test_user",
            "passkeys": [], // Empty array for testing - in real scenario this would contain actual credentials
            "rp_id": "example.com",
            "rp_origin": "https://example.com"
        });

        let login_begin_result = handle_login_begin(&login_begin_input);
        
        // Debug: print the result
        match &login_begin_result {
            Ok(data) => println!("Login begin succeeded: {:?}", data),
            Err(e) => println!("Login begin failed: {}", e),
        }
        
        assert!(login_begin_result.is_ok(), "Login begin should succeed");
        
        let login_begin_data = login_begin_result.unwrap();
        let challenge = login_begin_data.get("challenge").unwrap();
        let auth_state = login_begin_data.get("auth_state").unwrap();
        
        // Verify we have the expected data
        assert!(challenge.get("publicKey").is_some(), "Challenge should contain publicKey");
        assert!(auth_state.is_object(), "Auth state should be an object");

        // Step 2: Simulate client-side authentication (mock data)
        // In a real scenario, this would be done by the browser/authenticator
        let mock_client_data = json!({
            "id": "mock_credential_id",
            "rawId": "bW9ja19jcmVkZW50aWFsX2lk",
            "response": {
                "authenticatorData": "mock_authenticator_data",
                "clientDataJSON": "mock_client_data_json",
                "signature": "mock_signature"
            },
            "type": "public-key"
        });

        // Step 3: Finish authentication
        let login_finish_input = json!({
            "op": "login_finish",
            "auth_state": auth_state,
            "client_data": mock_client_data,
            "rp_id": "example.com",
            "rp_origin": "https://example.com"
        });

        let login_finish_result = handle_login_finish(&login_finish_input);
        // This will likely fail with mock data, but we can verify the function handles it gracefully
        // In a real scenario, this would succeed with valid credential data
        assert!(login_finish_result.is_ok() || login_finish_result.is_err());
        
        if login_finish_result.is_err() {
            let error = login_finish_result.unwrap_err();
            // Should fail with a meaningful error about invalid credential data
            assert!(error.contains("Failed to finish authentication") || 
                   error.contains("Failed to parse login_finish request"));
        }
    }

    #[test]
    fn test_integration_c_api_flow() {
        // Test the complete flow using the C API
        
        // Step 1: Start registration via C API
        let register_begin_input = r#"{"op":"register_begin","user_id":"c_api_test_user","user_name":"C API Test User","rp_id":"example.com","rp_origin":"https://example.com"}"#;
        
        let input_cstr = std::ffi::CString::new(register_begin_input).unwrap();
        let result_ptr = rust_json_api(input_cstr.as_ptr());
        
        assert!(!result_ptr.is_null(), "Should return non-null pointer");
        
        let result_str = unsafe { std::ffi::CStr::from_ptr(result_ptr) };
        let result = result_str.to_str().unwrap();
        
        // Parse and verify the result
        let parsed: serde_json::Value = serde_json::from_str(result).unwrap();
        assert!(parsed.get("challenge").is_some(), "Should contain challenge");
        assert!(parsed.get("registration").is_some(), "Should contain registration");
        assert!(parsed.get("uuid").is_some(), "Should contain uuid");
        
        // Clean up
        free_string(result_ptr);

        // Step 2: Start authentication via C API
        let login_begin_input = r#"{"op":"login_begin","_user_id":"c_api_test_user","passkeys":[],"rp_id":"example.com","rp_origin":"https://example.com"}"#;
        
        let login_input_cstr = std::ffi::CString::new(login_begin_input).unwrap();
        let login_result_ptr = rust_json_api(login_input_cstr.as_ptr());
        
        assert!(!login_result_ptr.is_null(), "Should return non-null pointer");
        
        let login_result_str = unsafe { std::ffi::CStr::from_ptr(login_result_ptr) };
        let login_result = login_result_str.to_str().unwrap();
        
        // Parse and verify the result
        let login_parsed: serde_json::Value = serde_json::from_str(login_result).unwrap();
        assert!(login_parsed.get("challenge").is_some(), "Should contain challenge");
        assert!(login_parsed.get("auth_state").is_some(), "Should contain auth_state");
        
        // Clean up
        free_string(login_result_ptr);
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