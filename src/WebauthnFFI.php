<?php

namespace Remodulate;

class WebauthnFFI
{
    private \FFI $ffi;
    private const HEADER_PATH = __DIR__ . '/../ffi/webauthn.h';

    public function __construct()
    {
        $this->checkFFIExtension();
        $this->checkLibraryFile();
        $this->initializeFFI();
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
            error_log("Error during FFI initialization: " . $e->getMessage());
            throw new \RuntimeException("FFI initialization failed: " . $e->getMessage());
        }
    }

    public function registerBegin(array $params): array
    {
        return $this->callFFI('register_begin', $params);
    }

    public function registerFinish(array $params): array
    {
        return $this->callFFI('register_finish', $params);
    }

    public function authenticateBegin(array $params): array
    {
        return $this->callFFI('login_begin', $params);
    }

    public function authenticateFinish(array $params): array
    {
        return $this->callFFI('login_finish', $params);
    }

    private function callFFI(string $operation, array $params): array
    {
        $request = [
            'op' => $operation,
            ...$params
        ];

        $json = $this->serializeJson($request);
        $result = $this->rust_json_api($json);
        
        if ($result === null) {
            throw new \RuntimeException("FFI call failed for operation: $operation");
        }

        return $this->deserializeJson($result);
    }

    private function serializeJson($data): string
    {
        $json = json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        if ($json === false) {
            throw new \RuntimeException("JSON encoding failed: " . json_last_error_msg());
        }
        return $json;
    }

    private function deserializeJson(string $json): array
    {
        $data = json_decode($json, true);
        if ($data === null) {
            throw new \RuntimeException("JSON decoding failed: " . json_last_error_msg());
        }
        return $data;
    }

    private function rust_json_api(string $json): ?string
    {
        try {
            // Convert PHP string to C string
            $cString = \FFI::new("char[" . (strlen($json) + 1) . "]");
            \FFI::memcpy($cString, $json, strlen($json));
            $cString[strlen($json)] = "\0";

            // Call the FFI function
            $resultPtr = $this->ffi->rust_json_api($cString);
            
            if ($resultPtr === null) {
                error_log("FFI returned null for input: " . $json);
                return null;
            }
            
            if (!($resultPtr instanceof \FFI\CData)) {
                error_log("FFI returned invalid type: " . gettype($resultPtr));
                return null;
            }

            $result = \FFI::string($resultPtr);
            $this->ffi->free_string($resultPtr);
            return $result;
        } catch (\Throwable $e) {
            error_log("FFI error: " . $e->getMessage() . " for input: " . $json);
            return null;
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

$w = new WebauthnFFI(); 
var_dump($w->registerBegin(['user_id' => '9', 'user_name' => 'brandin'   ]));
