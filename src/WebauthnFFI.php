<?php

namespace Remodulate;

class WebauthnFFI
{
    private \FFI $ffi;
    private const HEADER_PATH = __DIR__ . '/../ffi/webauthn.h';
    private const LOG_FILE = '/tmp/webauthn_ffi_php.log';

    private string $rp_id;
    private string $rp_origin;

    private function log(string $message): void
    {
        $timestamp = date('Y-m-d H:i:s.v');
        $logMessage = "[{$timestamp}] {$message}\n";
        file_put_contents(self::LOG_FILE, $logMessage, FILE_APPEND);
    }

    public function __construct(string $rp_id, string $rp_origin)
    {
        $this->rp_id = $rp_id;
        $this->rp_origin = $rp_origin;

        try {
            $this->checkFFIExtension();
            $this->checkLibraryFile();
            
            $this->initializeFFI();
        } catch (\Throwable $e) {
            $this->log("Error in WebauthnFFI constructor: " . $e->getMessage() . "\n" . $e->getTraceAsString());
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

        $this->log("FFI extension is loaded and enabled");
    }

    private function checkLibraryFile(): void
    {
        $libPath = $this->resolveLibraryPath();
        $this->log("Checking library file: " . $libPath);

        if (!file_exists($libPath)) {
            throw new \RuntimeException("FFI library not found at: $libPath");
        }

        if (!is_readable($libPath)) {
            throw new \RuntimeException("FFI library is not readable: $libPath");
        }

        // Check file permissions
        $perms = fileperms($libPath);
        $this->log("Library file permissions: " . decoct($perms & 0777));

        // Check file size
        $size = filesize($libPath);
        $this->log("Library file size: " . $size . " bytes");

        // Try to get file type
        $type = mime_content_type($libPath);
        $this->log("Library file type: " . $type);

        $this->log("Library file checks passed");
    }

    private function initializeFFI(): void
    {
        try {
            $libPath = $this->resolveLibraryPath();
            $this->log("Attempting to load FFI library from: " . $libPath);
            
            if (!file_exists(self::HEADER_PATH)) {
                throw new \RuntimeException("FFI header not found at: " . self::HEADER_PATH);
            }

            $header = file_get_contents(self::HEADER_PATH);
            if ($header === false) {
                throw new \RuntimeException("Could not read FFI header");
            }

            $this->log("FFI header content: " . $header);

            try {
                $this->ffi = \FFI::cdef($header, $libPath);
                $this->log("FFI initialized successfully");
            } catch (\FFI\Exception $e) {
                $this->log("FFI initialization failed: " . $e->getMessage());
                throw new \RuntimeException("Failed to initialize FFI: " . $e->getMessage());
            }
        } catch (\Throwable $e) {
            $this->log("Error during FFI initialization: " . $e->getMessage() . "\n" . $e->getTraceAsString());
            throw new \RuntimeException("FFI initialization failed: " . $e->getMessage());
        }
    }

    private function getRpInfo(): array
    {   
        return [
            'rp_id' => $this->rp_id,
            'rp_origin' => $this->rp_origin
        ];
    }

    public function registerBegin(array $params): array
    {
        // Add RP information to the request
        $params = array_merge($params, $this->getRpInfo());
        $this->log("Register begin params: " . json_encode($params));
        
        return $this->callFFI('register_begin', $params);
    }

    public function registerFinish(array $params): array
    {
        // Add RP information to the request
        $params = array_merge($params, $this->getRpInfo());
        $this->log("Register finish params: " . json_encode($params));
        
        return $this->callFFI('register_finish', $params);
    }

    public function authenticateBegin(array $params): array
    {
        // Add RP information to the request
        $params = array_merge($params, $this->getRpInfo());
        $this->log("Authenticate begin params: " . json_encode($params));
        
        return $this->callFFI('login_begin', $params);
    }

    public function authenticateFinish(array $params): array
    {
        // Add RP information to the request
        $params = array_merge($params, $this->getRpInfo());
        $this->log("Authenticate finish params: " . json_encode($params));
        
        return $this->callFFI('login_finish', $params);
    }

    private function callFFI(string $operation, array $params): array
    {
        $request = [
            'op' => $operation,
            ...$params
        ];

        $this->log("Preparing FFI call for operation: " . $operation);
        $this->log("Request parameters: " . json_encode($params));

        $json = $this->serializeJson($request);
        $this->log("Serialized request: " . $json);
        
        try {
            $result = $this->rust_json_api($json);
            
            if ($result === null) {
                $this->log("FFI call returned null for operation: " . $operation);
                throw new \RuntimeException("FFI call failed for operation: $operation");
            }

            $this->log("FFI call successful, deserializing result");
            $data = $this->deserializeJson($result);
            $this->log("Deserialized result: " . json_encode($data));
            
            if (isset($data['error'])) {
                $this->log("FFI returned error: " . json_encode($data));
                throw new \RuntimeException($data['error'] . (isset($data['details']) ? ': ' . $data['details'] : ''));
            }
            
            return $data;
        } catch (\Throwable $e) {
            $this->log("FFI call failed: " . $e->getMessage() . "\n" . $e->getTraceAsString());
            throw $e;
        }
    }

    private function serializeJson($data): string
    {
        $json = json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        if ($json === false) {
            $error = json_last_error_msg();
            $this->log("JSON encoding failed: " . $error);
            throw new \RuntimeException("JSON encoding failed: " . $error);
        }
        return $json;
    }

    private function deserializeJson(string $json): array
    {
        $data = json_decode($json, true);
        if ($data === null) {
            $error = json_last_error_msg();
            $this->log("JSON decoding failed: " . $error . " for JSON: " . $json);
            throw new \RuntimeException("JSON decoding failed: " . $error);
        }
        return $data;
    }

    private function rust_json_api(string $json): ?string
    {
        try {
            $this->log("FFI call with input: " . $json);
            
            if (!isset($this->ffi)) {
                $this->log("FFI not initialized");
                throw new \RuntimeException("FFI not initialized");
            }
            
            // Convert PHP string to C string
            $cString = \FFI::new("char[" . (strlen($json) + 1) . "]");
            \FFI::memcpy($cString, $json, strlen($json));
            $cString[strlen($json)] = "\0";

            $this->log("Calling rust_json_api function");
            
            // Call the FFI function
            $resultPtr = $this->ffi->rust_json_api($cString);
            
            if ($resultPtr === null) {
                $this->log("FFI returned null for input: " . $json);
                throw new \RuntimeException("FFI returned null");
            }
            
            if (!($resultPtr instanceof \FFI\CData)) {
                $this->log("FFI returned invalid type: " . gettype($resultPtr));
                throw new \RuntimeException("FFI returned invalid type: " . gettype($resultPtr));
            }

            $this->log("Converting result to string");
            $result = \FFI::string($resultPtr);
            
            $this->log("Freeing result pointer");
            $this->ffi->free_string($resultPtr);
            
            $this->log("FFI call result: " . $result);
            return $result;
        } catch (\Throwable $e) {
            $this->log("FFI error: " . $e->getMessage() . "\n" . $e->getTraceAsString());
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
        $this->log("Resolved library path: " . $path);
        return $path;
    }
}
