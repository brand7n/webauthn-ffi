<?php

namespace Remodulate;

class Installer
{
    public static function installBinary()
    {
        echo "🔧 Building Rust FFI library...\n";

        $rustDir = __DIR__ . '/../rustlib';
        $release = true;
        $target = $release ? 'release' : 'debug';
        $cmd = $release ? 'cargo build --release' : 'cargo build';

        $descriptors = [
            1 => ['pipe', 'w'],
            2 => ['pipe', 'w'],
        ];

        $proc = proc_open($cmd, $descriptors, $pipes, $rustDir);

        if (!is_resource($proc)) {
            throw new \RuntimeException("Failed to start cargo build process.");
        }

        echo stream_get_contents($pipes[1]);
        $stderr = stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        $exitCode = proc_close($proc);

        if ($exitCode !== 0) {
            throw new \RuntimeException("Rust build failed:\n" . $stderr);
        }

        $ext = match(PHP_OS_FAMILY) {
            'Darwin' => '.dylib',
            'Windows' => '.dll',
            default => '.so',
        };

        $pattern = $rustDir . "/target/{$target}/lib*{$ext}";
        $binaries = glob($pattern);

        if (!$binaries) {
            throw new \RuntimeException("No compiled library found in target/$target.");
        }

        $binary = $binaries[0];
        $dest = __DIR__ . '/../bin/libyourlib' . $ext;
        @mkdir(dirname($dest), 0777, true);
        copy($binary, $dest);

        echo "✅ Built and installed binary to: $dest\n";
    }
}
