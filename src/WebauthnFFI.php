<?php

namespace Remodulate;

class WebauthnFFI
{
    private \FFI $ffi;
    private const HEADER_PATH = __DIR__ . '/../ffi/webauthn.h';

    public function __construct()
    {
        try {
            $this->checkFFIExtension();
            $this->checkLibraryFile();
            
            $this->initializeFFI();
        } catch (\Throwable $e) {
            error_log("Error in WebauthnFFI constructor: " . $e->getMessage() . "\n" . $e->getTraceAsString());
            throw $e;
        }
    }

    private function checkFFIExtension(): void
    {
        if (!extension_loaded('ffi')) {
            throw new \RuntimeException('FFI extension is not loaded. Please install and enable the FFI extension.');
        }

        if (!ini_get('ffi.enable')) {
            if (!ini_set('ffi.enable', true)) {
                throw new \RuntimeException('FFI is not enabled and cannot be enabled at runtime. Please enable it in your PHP configuration.');
            }
        }

        error_log("FFI extension is loaded and enabled");
    }

    private function checkLibraryFile(): void
    {
        $libPath = $this->resolveLibraryPath();
        error_log("Checking library file: " . $libPath);

        if (!file_exists($libPath)) {
            throw new \RuntimeException("FFI library not found at: $libPath");
        }

        if (!is_readable($libPath)) {
            throw new \RuntimeException("FFI library is not readable: $libPath");
        }

        // Check file permissions
        $perms = fileperms($libPath);
        error_log("Library file permissions: " . decoct($perms & 0777));

        // Check file size
        $size = filesize($libPath);
        error_log("Library file size: " . $size . " bytes");

        // Try to get file type
        $type = mime_content_type($libPath);
        error_log("Library file type: " . $type);

        error_log("Library file checks passed");
    }

    private function initializeFFI(): void
    {
        try {
            $libPath = $this->resolveLibraryPath();
            error_log("Attempting to load FFI library from: " . $libPath);
            
            if (!file_exists(self::HEADER_PATH)) {
                throw new \RuntimeException("FFI header not found at: " . self::HEADER_PATH);
            }

            $header = file_get_contents(self::HEADER_PATH);
            if ($header === false) {
                throw new \RuntimeException("Could not read FFI header");
            }

            error_log("FFI header content: " . $header);

            try {
                $this->ffi = \FFI::cdef($header, $libPath);
                error_log("FFI initialized successfully");
            } catch (\FFI\Exception $e) {
                error_log("FFI initialization failed: " . $e->getMessage());
                throw new \RuntimeException("Failed to initialize FFI: " . $e->getMessage());
            }
        } catch (\Throwable $e) {
            error_log("Error during FFI initialization: " . $e->getMessage() . "\n" . $e->getTraceAsString());
            throw new \RuntimeException("FFI initialization failed: " . $e->getMessage());
        }
    }

    private function getRpInfo(): array
    {
        $rp_id = parse_url(config('app.url'), PHP_URL_HOST);
        if (!$rp_id) {
            throw new \RuntimeException("Could not determine RP ID from app.url configuration");
        }
        
        $rp_origin = rtrim(config('app.url'), '/');
        error_log("Using RP ID: {$rp_id}, Origin: {$rp_origin}");
        
        return [
            'rp_id' => $rp_id,
            'rp_origin' => $rp_origin
        ];
    }

    public function registerBegin(array $params): array
    {
        // Add RP information to the request
        $params = array_merge($params, $this->getRpInfo());
        error_log("Register begin params: " . json_encode($params));
        
        return $this->callFFI('register_begin', $params);
    }

    public function registerFinish(array $params): array
    {
        // Add RP information to the request
        $params = array_merge($params, $this->getRpInfo());
        error_log("Register finish params: " . json_encode($params));
        
        return $this->callFFI('register_finish', $params);
    }

    public function authenticateBegin(array $params): array
    {
        // Add RP information to the request
        $params = array_merge($params, $this->getRpInfo());
        error_log("Authenticate begin params: " . json_encode($params));
        
        return $this->callFFI('login_begin', $params);
    }

    public function authenticateFinish(array $params): array
    {
        // Add RP information to the request
        $params = array_merge($params, $this->getRpInfo());
        error_log("Authenticate finish params: " . json_encode($params));
        
        return $this->callFFI('login_finish', $params);
    }

    private function callFFI(string $operation, array $params): array
    {
        $request = [
            'op' => $operation,
            ...$params
        ];

        error_log("Preparing FFI call for operation: " . $operation);
        error_log("Request parameters: " . json_encode($params));

        $json = $this->serializeJson($request);
        error_log("Serialized request: " . $json);
        
        try {
            $result = $this->rust_json_api($json);
            
            if ($result === null) {
                error_log("FFI call returned null for operation: " . $operation);
                throw new \RuntimeException("FFI call failed for operation: $operation");
            }

            error_log("FFI call successful, deserializing result");
            $data = $this->deserializeJson($result);
            error_log("Deserialized result: " . json_encode($data));
            
            if (isset($data['error'])) {
                error_log("FFI returned error: " . json_encode($data));
                throw new \RuntimeException($data['error'] . (isset($data['details']) ? ': ' . $data['details'] : ''));
            }
            
            return $data;
        } catch (\Throwable $e) {
            error_log("FFI call failed: " . $e->getMessage() . "\n" . $e->getTraceAsString());
            throw $e;
        }
    }

    private function serializeJson($data): string
    {
        $json = json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        if ($json === false) {
            $error = json_last_error_msg();
            error_log("JSON encoding failed: " . $error);
            throw new \RuntimeException("JSON encoding failed: " . $error);
        }
        return $json;
    }

    private function deserializeJson(string $json): array
    {
        $data = json_decode($json, true);
        if ($data === null) {
            $error = json_last_error_msg();
            error_log("JSON decoding failed: " . $error . " for JSON: " . $json);
            throw new \RuntimeException("JSON decoding failed: " . $error);
        }
        return $data;
    }

    private function rust_json_api(string $json): ?string
    {
        try {
            error_log("FFI call with input: " . $json);
            
            if (!isset($this->ffi)) {
                error_log("FFI not initialized");
                throw new \RuntimeException("FFI not initialized");
            }
            
            // Convert PHP string to C string
            $cString = \FFI::new("char[" . (strlen($json) + 1) . "]");
            \FFI::memcpy($cString, $json, strlen($json));
            $cString[strlen($json)] = "\0";

            error_log("Calling rust_json_api function");
            
            // Call the FFI function
            $resultPtr = $this->ffi->rust_json_api($cString);
            
            if ($resultPtr === null) {
                error_log("FFI returned null for input: " . $json);
                throw new \RuntimeException("FFI returned null");
            }
            
            if (!($resultPtr instanceof \FFI\CData)) {
                error_log("FFI returned invalid type: " . gettype($resultPtr));
                throw new \RuntimeException("FFI returned invalid type: " . gettype($resultPtr));
            }

            error_log("Converting result to string");
            $result = \FFI::string($resultPtr);
            
            error_log("Freeing result pointer");
            $this->ffi->free_string($resultPtr);
            
            error_log("FFI call result: " . $result);
            return $result;
        } catch (\Throwable $e) {
            error_log("FFI error: " . $e->getMessage() . "\n" . $e->getTraceAsString());
            throw $e;
        }
    }

    private function resolveLibraryPath(): string
    {
        $base = __DIR__ . '/../bin/';
        $ext = match (PHP_OS_FAMILY) {
            'Windows' => '.dll',
            'Darwin'  => '.dylib',
            default   => '.so',
        };

        $libName = 'libwebauthn_ffi' . $ext;
        $path = $base . $libName;
        error_log("Resolved library path: " . $path);
        return $path;
    }
}
