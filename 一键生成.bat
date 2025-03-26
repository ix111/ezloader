@echo off
:: 编译 Rust 项目
cargo build -r

:: 允许 PowerShell 脚本执行
powershell -ep bypass -File "%~dp0\script.ps1"
