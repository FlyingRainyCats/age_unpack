# AEG 电子书解包

## 快速使用

### 前置条件

1. 安装使用 rust 编写的 [uv]
2. 执行 uv 来初始化环境：

   ```shell
   uv sync
   ```

[uv]: https://docs.astral.sh/uv/getting-started/installation/

### 解包

参考下方示例，执行解包命令：

```shell
python unpack.py -o out/ ebook.exe
```

其中：

- `-o out/` 指定输出目录
- `ebook.exe` 指定要解包的文件

## 授权协议

本项目使用 [MIT 许可证](LICENSE)，请遵循相关条款。

## 测试档案

以下样本测试通过：

- [求助关于雅致Flash播放器(AGE FlashPacker)的数据解密问题][ref1]

[ref1]: https://www.52pojie.cn/thread-2030470-1-1.html
