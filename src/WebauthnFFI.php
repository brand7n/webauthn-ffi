<?php

namespace Remodulate;

class WebauthnFFI
{
    private \FFI $ffi;

    public function __construct()
    {
        $libPath = $this->resolveLibraryPath();
        $headerPath = __DIR__ . '/../ffi/yourlib.h';

        if (!file_exists($libPath)) {
            throw new \RuntimeException("FFI library not found: $libPath");
        }

        $this->ffi = \FFI::cdef(file_get_contents($headerPath), $libPath);
    }

    public function ffiTest(): void
    {
        $json = json_encode(['op' => 'register_begin']);
        $resultPtr = $this->ffi->rust_json_api($json);
        $result = \FFI::string($resultPtr);
        $this->ffi->free_string($resultPtr);

        echo $result . PHP_EOL;
    }

    private function resolveLibraryPath(): string
    {
        $base = __DIR__ . '/../bin/';
        $ext = match (PHP_OS_FAMILY) {
            'Windows' => '.dll',
            'Darwin'  => '.dylib',
            default   => '.so',
        };

        $libName = 'libyourlib' . $ext;
        return $base . $libName;
    }
}