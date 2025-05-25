<?php

namespace YourNamespace;

class YourModule
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

    public function doSomething(int $x): int
    {
        return $this->ffi->your_function($x);
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

$a = new \YourNamespace\YourModule();
echo($a->doSomething(5).PHP_EOL);
