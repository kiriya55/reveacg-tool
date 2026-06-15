# ReveACG 资源解密脚本

**ReveAVG织梦者**旗下的乙游《晨曦列车》和《梦浮灯》的图片资源解密脚本。

加密通过XOR进行，格式是：

```c
// encrypted file
// [0] = 0x32
// [1] = 0x67
// [2] = 0x98
// [3] = xor_key
// [4..end] = real_file_bytes ^ xor_key

if (buf[0] == 0x32 && buf[1] == 0x67 && buf[2] == 0x98) {
    key = buf[3];
    for (i = 4; i < len; i++) {
        buf[i] ^= key;
    }
    data = buf + 4;
    len -= 4;
}
```

key为`0xD8`

IDA对应：

```plain
libcocos2djs.so
cocos2d::Image::initWithImageData  VA 0xF9FB74
检测 magic:                         0xF9FC10 - 0xF9FC3C
XOR 循环:                           0xF9FC64 - 0xF9FCBC
跳过前 4 字节:                      0xF9FCC4 - 0xF9FCC8
```

Cocos用的XXTEA加密，对应的key和sign分别是：`trainjs` 和`zaq8jfokp1j4`

相关APK资源请自搜，这里不做过多解释

## 用法

配置好python环境以后：

运行：

```bash
python decrypt_reveacg_res.py `
  "path\\to\\assets\\res" `
  "output\\res_dec"
```

类似的，对于jsc脚本（目前只找了晨曦列车的，梦浮灯的懒得搞了有兴趣IDA稍微折腾一下的可以开pull request）：

运行：

```bash
python decrypt_revetrain_jsc.py `
  "path\\to\\assets\\script" `
  "output\\script_dec"
```

这个不在资源的apk包里面，而是在`com.revetrain.game\assets\script`目录下

# Some results

晨曦列车：

https://photo.baidu.com/photo/wap/albumShare/invite/jxDtTLFOGt?from=webcreate

梦浮灯：

https://photo.baidu.com/photo/wap/albumShare/invite/zhBmnNbkDS?from=webcreate
