#include "../include/InjectorCore.h"

int main() {
    return RunInjector(
        "XiaomiPcManager Injector",
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\XiaomiPcManager.exe",
        "XiaomiPcManager.exe",
        "错误：未能从小米电脑管家注册表获取安装路径，请检查程序是否安装！"
    );
}
