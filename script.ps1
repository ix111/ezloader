# 进入 metatwin 目录
Set-Location -Path .\metatwin

# 导入 metatwin.ps1 模块
Import-Module .\metatwin.ps1

# 运行 Invoke-MetaTwin
Invoke-MetaTwin -Source ../TranslucentTB.exe -Target ../target/release/ezloader.exe -Sign
