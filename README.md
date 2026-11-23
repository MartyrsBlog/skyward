# Skyward for diting

Skyward 的 diting（Redmi K50 Ultra，`22081212C`）适配，基于 [kirklin/skyward](https://github.com/kirklin/skyward)。

## 状态

触摸、`/data` 解密、WLAN、备份与恢复、文件管理、终端、adb 与 MTP 可用。

安装 OTA 包没有测过：这台机器跑的是移植系统，官方包会覆盖 `boot`。双系统不支持，diting 没有 `init_boot` 分区。

## 构建

需要 Rust、`cargo-ndk`、NDK r28+ 和系统里的 `lz4`。

```sh
cargo build --release -p skyward-pack

export ANDROID_NDK_HOME=/path/to/ndk
cargo ndk -t arm64-v8a --platform 30 build --release -p skyward
RUSTFLAGS="-C target-feature=+crt-static" \
  cargo ndk -t arm64-v8a --platform 30 build --release \
  -p skyward-system-init --target-dir target/system-init
```

打包用 `skyward-pack recovery`，以官方 recovery 为基底。除常规参数外，还要用 `--extra` 把
`companion/a<sdk>/` 里的 `servicemanager`、`hwservicemanager` 和依赖库放进 `/skyward/hidl/a<sdk>/`；
`<sdk>` 由打包器从基底镜像的 `prop.default` 读出，配置里的 `{sdk}` 会被替换成同一个值。

## 刷入

```sh
fastboot flash recovery_a skyward-diting.img
fastboot reboot recovery
```

刷 recovery 不动 `boot`，KernelSU 不受影响。要回滚，把原来的 recovery 刷回去即可。

## 说明

diting 的 vendor 固定在 Android 12（SDK 31），换系统不会变。vendor 的 HIDL 服务只跟同代的
`hwservicemanager` 注册，跨代会失败，所以镜像里带的是 SDK 31 那一套，运行时按
`/vendor/build.prop` 的 `ro.vendor.build.version.sdk` 选择。

## 许可

GPL-3.0
