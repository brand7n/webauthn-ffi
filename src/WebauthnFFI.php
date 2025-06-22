<?php

namespace Remodulate;

use Psr\Log\LoggerInterface;

class WebauthnFFI
{
    private \FFI $ffi;
    private const HEADER_PATH = __DIR__ . '/../ffi/webauthn.h';
    private LoggerInterface $logger;
    private string $rp_id;
    private string $rp_origin;

    public function __construct(LoggerInterface $logger, string $rp_id, string $rp_origin)
    {
        $this->logger = $logger;
        $this->rp_id = $rp_id;
        $this->rp_origin = $rp_origin;

        try {
            $this->logger->debug("Starting WebauthnFFI constructor");
            $this->checkFFIExtension();
            $this->checkLibraryFile();
            
            $this->logger->debug("Initializing FFI");
            $this->initializeFFI();
            $this->logger->debug("FFI initialized successfully");
        } catch (\Throwable $e) {
            $this->logger->error("Error in WebauthnFFI constructor: " . $e->getMessage() . "\n" . $e->getTraceAsString());
            throw $e;
        }
    }

    private function checkFFIExtension(): void
    {
        if (!extension_loaded('ffi')) {
            $this->logger->error("FFI extension is not loaded");
            throw new \RuntimeException("FFI extension is not loaded");
        }
        $this->logger->debug("FFI extension is loaded");
    }

    private function checkLibraryFile(): void
    {
        $libPath = $this->resolveLibraryPath();
        if (!file_exists($libPath)) {
            $this->logger->error("FFI library not found at: " . $libPath);
            throw new \RuntimeException("FFI library not found at: " . $libPath);
        }
        $this->logger->debug("FFI library found at: " . $libPath);
    }

    private function initializeFFI(): void
    {
        try {
            $libPath = $this->resolveLibraryPath();
            $this->logger->debug("Attempting to load FFI library from: " . $libPath);
            
            if (!file_exists(self::HEADER_PATH)) {
                throw new \RuntimeException("FFI header not found at: " . self::HEADER_PATH);
            }

            $header = file_get_contents(self::HEADER_PATH);
            if ($header === false) {
                throw new \RuntimeException("Could not read FFI header");
            }

            $this->logger->debug("FFI header content: " . $header);

            try {
                $this->ffi = \FFI::cdef($header, $libPath);
                $this->logger->debug("FFI initialized successfully");
            } catch (\FFI\Exception $e) {
                $this->logger->error("FFI initialization failed: " . $e->getMessage());
                throw new \RuntimeException("Failed to initialize FFI: " . $e->getMessage());
            }
        } catch (\Throwable $e) {
            $this->logger->error("Error during FFI initialization: " . $e->getMessage() . "\n" . $e->getTraceAsString());
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
        $this->logger->debug("Register begin params: " . json_encode($params));
        
        return $this->callFFI('register_begin', $params);
    }

    public function registerFinish(array $params): array
    {
        // Add RP information to the request
        $params = array_merge($params, $this->getRpInfo());
        $this->logger->debug("Register finish params: " . json_encode($params));
        
        return $this->callFFI('register_finish', $params);
    }

    public function authenticateBegin(array $params): array
    {
        try {
            $this->logger->debug("Getting authentication options", ['params' => $params]);
            
            // Add RP information to the request
            $params = array_merge($params, $this->getRpInfo());
            $this->logger->debug("Authenticate begin params: " . json_encode($params));
            
            return $this->callFFI('login_begin', $params);
        } catch (\Throwable $e) {
            $this->logger->error("Error in authenticateBegin: " . $e->getMessage() . "\n" . $e->getTraceAsString());
            throw new \RuntimeException("Failed to get authentication options: " . $e->getMessage());
        }
    }

    public function authenticateFinish(array $params): array
    {
        // Add RP information to the request
        $params = array_merge($params, $this->getRpInfo());
        $this->logger->debug("Authenticate finish params: " . json_encode($params));
        
        // TODO: validate returned credential_id against the user's credentials
        // TODO: handle exception if authentication fails?
        return $this->callFFI('login_finish', $params);
    }

    private function callFFI(string $operation, array $params): array
    {
        $request = [
            'op' => $operation,
            ...$params
        ];

        $this->logger->debug("Preparing FFI call for operation: " . $operation);
        $this->logger->debug("Request parameters: " . json_encode($params, JSON_PRETTY_PRINT));

        $json = $this->serializeJson($request);
        $this->logger->debug("Serialized request: " . $json);
        
        try {
            $result = $this->rust_json_api($json);
            
            if ($result === null) {
                $this->logger->error("FFI call returned null for operation: " . $operation);
                throw new \RuntimeException("FFI call failed for operation: $operation");
            }

            $this->logger->debug("FFI call successful, deserializing result");
            $data = $this->deserializeJson($result);
            $this->logger->debug("Deserialized result: " . json_encode($data, JSON_PRETTY_PRINT));
            
            if (isset($data['error'])) {
                $this->logger->error("FFI returned error: " . json_encode($data));
                throw new \RuntimeException($data['error'] . (isset($data['details']) ? ': ' . $data['details'] : ''));
            }
            
            return $data;
        } catch (\Throwable $e) {
            $this->logger->error("FFI call failed: " . $e->getMessage() . "\n" . $e->getTraceAsString());
            throw $e;
        }
    }

    private function serializeJson($data): string
    {
        $json = json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        if ($json === false) {
            $error = json_last_error_msg();
            $this->logger->error("JSON encoding failed: " . $error);
            throw new \RuntimeException("JSON encoding failed: " . $error);
        }
        return $json;
    }

    private function deserializeJson(string $json): array
    {
        $data = json_decode($json, true);
        if ($data === null) {
            $error = json_last_error_msg();
            $this->logger->error("JSON decoding failed: " . $error . " for JSON: " . $json);
            throw new \RuntimeException("JSON decoding failed: " . $error);
        }
        return $data;
    }

    private function rust_json_api(string $json): ?string
    {
        try {
            $this->logger->debug("FFI call with input: " . $json);
            
            if (!isset($this->ffi)) {
                $this->logger->error("FFI not initialized");
                throw new \RuntimeException("FFI not initialized");
            }
            
            // Convert PHP string to C string
            $cString = \FFI::new("char[" . (strlen($json) + 1) . "]");
            \FFI::memcpy($cString, $json, strlen($json));
            $cString[strlen($json)] = "\0";

            $this->logger->debug("Calling rust_json_api function");
            
            // Call the FFI function
            $resultPtr = $this->ffi->rust_json_api($cString);
            
            if ($resultPtr === null) {
                $this->logger->error("FFI returned null for input: " . $json);
                throw new \RuntimeException("FFI returned null");
            }
            
            if (!($resultPtr instanceof \FFI\CData)) {
                $this->logger->error("FFI returned invalid type: " . gettype($resultPtr));
                throw new \RuntimeException("FFI returned invalid type: " . gettype($resultPtr));
            }

            $this->logger->debug("Converting result to string");
            $result = \FFI::string($resultPtr);
            
            $this->logger->debug("Freeing result pointer");
            $this->ffi->free_string($resultPtr);
            
            $this->logger->debug("FFI call result: " . $result);
            return $result;
        } catch (\Throwable $e) {
            $this->logger->error("FFI error: " . $e->getMessage() . "\n" . $e->getTraceAsString());
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
        $this->logger->debug("Resolved library path: " . $path);
        return $path;
    }
}
