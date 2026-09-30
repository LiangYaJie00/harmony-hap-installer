# HHI

鸿蒙 HAP 包安装平台。在 QA 电脑上把 DEV HAP 下载、校验后，用工具自带的 HDC 安装到鸿蒙真机。安装失败不会回传或改变打包平台上的构建任务。

## 下载

macOS 安装包，Apple 芯片和 Intel 芯片都可以使用：

[HHI_0.1.0_macos.dmg](https://github.com/LiangYaJie00/harmony-hap-installer/releases/download/v0.1.0/HHI_0.1.0_macos.dmg)

安装包内置 HDC 3.2.0d。不需要事先安装 HDC，也不需要安装 DevEco。Windows 的 `hdc.exe` 还没有放进 `vendor/hdc/windows-x64/`，目前不能打出可用的 Windows 包。

## 安装注意事项

从浏览器下载后，第一次打开可能会被 macOS 拦住。这是因为安装包还没有 Apple 开发者签名和公证。

如果系统提示无法验证开发者，请打开「系统设置 → 隐私与安全性」，选择仍要打开。确认一次之后，以后可以直接打开。

## 使用

桌面窗口和命令行走同一套流程。QA 不需要自己拼 HDC 命令。

1. 粘贴下载链接，或选择本机 HAP、二维码。链接如果打开的是网页，会转到浏览器。
2. 确认包名、版本、大小、下载域名和证书指纹。
3. 选择一台已授权的在线设备。多台设备必须手动选择。
4. 安装完成后，工具会在 10 秒内核对设备上的包名、版本名和版本号。核对一致才算安装成功。

命令行入口：

- `installer doctor`
- `installer resolve`
- `installer devices`
- `installer install`
- `installer verify-installed`

## 安装规则

这些检查始终生效：

- 文件必须是 HAP
- 安装前需要确认
- 多台设备必须手动选择
- 不会把设备上的更高版本降级覆盖
- 签名冲突时只提示人工处理，不会自动卸载
- 下载只接受 HTTPS，且链接里不能带账号密码

没有平台 manifest 时，只能证明本机文件没有被改过，不能证明它就是平台原始产物。

首页的高级设置默认关闭。关闭时不限制下载域名、包名和证书指纹，选中的 HAP 可以安装。开启后，这三项名单必须都填写，否则拒绝安装。名单保存在工具数据目录的 `identity-policy.json`，不写进安装包。

macOS 数据目录：`~/Library/Application Support/HarmonyHapInstaller/`

## 真机行为

这些场景需要连上鸿蒙真机。自动化测试用假 HDC 覆盖了对应分支：

- 首次安装后，设备上的 bundleName、versionName、versionCode 与 HAP 一致
- 同签名升级可以覆盖安装
- 同版本需要在确认页再次确认后才覆盖
- 更高版本会被阻断，不会降级
- 不同签名只提示人工处理，不会卸载应用
- 没有设备、未授权或多台设备时，不会自动装到未选中的设备
- 安装超时后先查询设备上的实际版本，再决定记成功、允许用同一个 HAP 重试，或标成结果未知
