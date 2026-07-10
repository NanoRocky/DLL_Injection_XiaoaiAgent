# 编译小爱同学资源文件
windres -c 65001 resources/XiaoaiAgent.rc -O coff -o XiaoaiAgent_res.o
Write-Host "[+] XiaoaiAgent.rc 编译完成" -ForegroundColor Green

# 编译 小爱同学 注入器
g++ src/XiaoaiAgentInjector.cpp -I include XiaoaiAgent_res.o -o XiaoaiAgentInjector.exe -static -static-libgcc -static-libstdc++ -luser32 -lshell32 -ladvapi32 -mwindows -finput-charset=UTF-8 -fexec-charset=GBK
if ($?) { Write-Host "[+] XiaoaiAgentInjector.exe 编译成功" -ForegroundColor Green } else { Write-Host "[-] XiaoaiAgentInjector.exe 编译失败" -ForegroundColor Red }

# 编译小米AI创作资源文件
windres -c 65001 resources/XiaomiAICreatorClient.rc -O coff -o XiaomiAICreatorClient_res.o
Write-Host "[+] XiaomiAICreatorClient.rc 编译完成" -ForegroundColor Green

# 编译 小米AI创作 注入器
g++ src/XiaomiAICreatorInjector.cpp -I include XiaomiAICreatorClient_res.o -o XiaomiAICreatorInjector.exe -static -static-libgcc -static-libstdc++ -luser32 -lshell32 -ladvapi32 -mwindows -finput-charset=UTF-8 -fexec-charset=GBK
if ($?) { Write-Host "[+] XiaomiAICreatorInjector.exe 编译成功" -ForegroundColor Green } else { Write-Host "[-] XiaomiAICreatorInjector.exe 编译失败" -ForegroundColor Red }

# 编译小米电脑管家资源文件
windres -c 65001 resources/XiaomiPcManager.rc -O coff -o XiaomiPcManager_res.o
Write-Host "[+] XiaomiPcManager.rc 编译完成" -ForegroundColor Green

# 编译 小米电脑管家 注入器
g++ src/XiaomiPcManagerInjector.cpp -I include XiaomiPcManager_res.o -o XiaomiPcManagerInjector.exe -static -static-libgcc -static-libstdc++ -luser32 -lshell32 -ladvapi32 -mwindows -finput-charset=UTF-8 -fexec-charset=GBK
if ($?) { Write-Host "[+] XiaomiPcManagerInjector.exe 编译成功" -ForegroundColor Green } else { Write-Host "[-] XiaomiPcManagerInjector.exe 编译失败" -ForegroundColor Red }

# 清理生成的对象文件
Remove-Item XiaoaiAgent_res.o, XiaomiAICreatorClient_res.o, XiaomiPcManager_res.o -ErrorAction SilentlyContinue
Write-Host "[*] 清理临时文件完成" -ForegroundColor Yellow
