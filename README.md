# HHI

在 QA 电脑上把 DEV HAP 下载、校验后，用工具自带的 HDC 安装到鸿蒙真机。安装失败不会回传或改变打包平台上的构建任务。

macOS Apple 芯片安装包：[HHI_0.1.0_aarch64.dmg](https://github.com/LiangYaJie00/harmony-hap-installer/releases/download/v0.1.0/HHI_0.1.0_aarch64.dmg)

当前安装包内置的是 macOS Apple 芯片上的 `hdc` 3.2.0d。Windows 的 `hdc.exe` 还没有放进 `vendor/hdc/windows-x64/`，所以还不能打出可用的 Windows 包。

首页的高级设置默认关闭。关闭时不限制下载域名、包名和证书指纹，选中的 HAP 可以安装。开启后，这三项名单必须都填写，否则拒绝安装。名单保存在工具自己的数据目录 `identity-policy.json`，不写进安装包。

确认页始终显示下载域名、包名和证书指纹。文件必须是 HAP，多台设备要手动选择，更高版本不会被降级覆盖，签名冲突时不会自动卸载。没有平台 manifest 时，只能证明本机文件没有被改过，不能证明它就是平台原始产物。

命令行入口是 `installer doctor`、`installer resolve`、`installer devices`、`installer install` 和 `installer verify-installed`。桌面窗口提供同样的流程，QA 不需要自己拼 HDC 命令。

未签名的 macOS 安装包第一次打开时，系统会提示来自未识别的开发者。Windows 安装包在补齐 `hdc.exe` 后才能构建；没有代码签名证书时，SmartScreen 也会拦截。

## 真机检查

这些场景需要连上鸿蒙真机，自动化测试用假 HDC 覆盖了对应的分支：

- 首次安装后，设备上的 bundleName、versionName、versionCode 与 HAP 一致
- 同签名升级可以覆盖安装
- 同版本需要在确认页再次确认后才覆盖
- 更高版本会被阻断，不会降级
- 不同签名只提示人工处理，不会卸载应用
- 没有设备、未授权、多台设备时，不会自动装到第一台以外的设备
- 安装超时后先查询设备上的实际版本，再决定记成功、允许用同一个 HAP 重试，或标成结果未知
