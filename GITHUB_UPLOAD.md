# GitHub 更新与 v1.4.0 下载

仓库：[Cedar-Xs/mail-forward-topsec](https://github.com/Cedar-Xs/mail-forward-topsec)。

Windows 使用者可从 [Releases](https://github.com/Cedar-Xs/mail-forward-topsec/releases) 下载 `MailForwarderClient-v1.4.0-Windows.zip`，解压后运行 `MailForwarderClient.exe`。已有账号、加密凭据、历史邮件基线和投递记录继续使用本机原数据目录；多账号继续使用包内同名的 A/B 启动脚本。

开发更新使用独立分支和 Pull Request。完成修改及版本说明后，通过 Windows Python 3.11 / 3.12 完整测试、源码窗口检查和打包 EXE 窗口检查；合并后确认最终 main 提交的 CI 通过，再为同一提交创建一个 annotated tag 和 GitHub Release，附上对应已验证的 Windows ZIP。

源码运行和本地打包方法见 README。发布包只包含程序和启动脚本，私有账号、密码、Webhook、配置、日志及数据库不随包分发。
