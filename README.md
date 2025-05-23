# ZZUtil

## build & install

```sh
# build depends
mkdir -p depends/build
(cd depends/build && cmake .. && cmake --build .)
# build zzutil
mkdir -p build
(cd build && cmake .. && cmake --build . --target install)
```

## 网络接口

### 计划

#### 平台无关界面

主要解决跨平台 socket 接口不一致的问题（Linux、Windows）。

要能够以统一的形式收发 UDP 包。

参见头文件：[zzmessage.h](include/zzutil/zzmessage.h)。

#### 数据包缓存

引入缓存的根据：

1. 数据包的接收要快，不能阻塞图形界面线程，也不能被阻塞。
2. 分离对 Qt 网络接口的依赖。

能够以键值对的形式存储数据包，以便图形程序查询。它需要实现以下几个方面的功能:

1. 存储：根据键，将数据存储。
2. 查询：根据键，查询存储的数据。
3. 舍弃：及时清理过时的数据。

它将包含以下数据结构：

1. 固定大小的缓存
2. 以队列的形式写缓存，以便覆盖旧数据
3. 存储数据的时间戳，以便清理过时数据
4. 以键值对的形式存储到队列数据的索引，以便查询

参见头文件：[zzcache.h](include/zzutil/zzcache.h)。

### Skf 加密解密封装

对 Skf 的加密解密接口进行封装，方面使用。

-[x] SM2 加密解密
-[x] SM4 加密解密
-[ ] 验证: 指纹, Pin 码

参见头文件：[zzcrypt.h](include/zzutil/zzcrypt.h)。
