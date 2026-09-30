use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ErrorCode {
    SourceInvalid,
    DomainNotAllowed,
    LinkExpired,
    DownloadFailed,
    SizeMismatch,
    HashMismatch,
    SignatureInvalid,
    HdcNotFound,
    HdcVersionUnsupported,
    HdcConflict,
    NoDevice,
    DeviceUnauthorized,
    MultipleDevices,
    DeviceOffline,
    SdkIncompatible,
    InsufficientStorage,
    SignatureConflict,
    InstallTimeout,
    InstallFailed,
    VerifyFailed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InstallError {
    pub code: ErrorCode,
    pub message: String,
    pub suggestion: String,
    pub diagnostic: String,
}

impl InstallError {
    pub fn new(code: ErrorCode, detail: impl Into<String>) -> Self {
        let detail = detail.into();
        let (message, suggestion) = code.copy();
        let message = if detail.is_empty() {
            message.to_string()
        } else {
            format!("{message}：{detail}")
        };
        Self {
            code,
            message,
            suggestion: suggestion.to_string(),
            diagnostic: String::new(),
        }
    }

    pub fn with_diagnostic(mut self, diagnostic: impl Into<String>) -> Self {
        self.diagnostic = diagnostic.into();
        self
    }
}

impl std::fmt::Display for InstallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}\n{}", self.message, self.suggestion)
    }
}

impl ErrorCode {
    fn copy(self) -> (&'static str, &'static str) {
        match self {
            Self::SourceInvalid => ("无法解析安装包来源", "请重新复制下载链接，或改用选择本地 HAP"),
            Self::DomainNotAllowed => ("下载域名不在允许列表中", "请确认链接来自打包平台，不要下载其他地址"),
            Self::LinkExpired => ("下载链接已过期", "请回到打包平台重新获取链接"),
            Self::DownloadFailed => ("下载失败", "请检查网络后重试；如果页面需要登录，请在浏览器下载后选择本地 HAP"),
            Self::SizeMismatch => ("文件大小和平台记录不一致", "工具会删除临时文件并重新下载一次"),
            Self::HashMismatch => ("文件校验失败", "请不要安装该文件，重新从平台获取产物"),
            Self::SignatureInvalid => ("HAP 签名无法通过允许的证书校验", "请确认这是受控的 DEV 签名包"),
            Self::HdcNotFound => ("安装包里没有当前系统可用的 HDC", "请使用包含对应系统 HDC 的安装包"),
            Self::HdcVersionUnsupported => ("内置 HDC 版本和策略不一致", "请重新安装工具，不要手动替换 HDC"),
            Self::HdcConflict => ("HDC 客户端和后台服务版本冲突", "请先关闭冲突的 HDC 或 DevEco Studio 后再试，工具不会强制结束这些进程"),
            Self::NoDevice => ("没有发现鸿蒙设备", "请打开开发者模式，并用 USB 或无线调试连接手机"),
            Self::DeviceUnauthorized => ("设备尚未授权", "请在手机上确认 USB 调试授权"),
            Self::MultipleDevices => ("连接了多台设备", "请明确选择一台目标设备"),
            Self::DeviceOffline => ("设备已离线", "请重新连接后再试"),
            Self::SdkIncompatible => ("设备系统版本不兼容这个 HAP", "请更换满足版本要求的测试机"),
            Self::InsufficientStorage => ("设备剩余空间不足", "请在手机上释放空间后再试"),
            Self::SignatureConflict => ("设备上已有不同签名的同名应用", "工具不会自动卸载。请人工确认后再处理，以免清除测试数据"),
            Self::InstallTimeout => ("安装超时", "工具会先查询设备上的实际版本，再决定能否用同一个 HAP 重试"),
            Self::InstallFailed => ("安装失败", "请根据诊断信息处理后再试"),
            Self::VerifyFailed => ("安装后版本核对失败", "不能把这次操作记为成功。结果不明确时不要立刻再次安装"),
        }
    }
}
