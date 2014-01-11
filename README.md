Ubuntu One command line
==================

##setup

脚本依赖`oauth2`, ubuntu 下可以 `sudo apt-get install python-oauth2` 安装

```sh
git clone https://github.com/likebeta/ubuntuone_uploader.git
cd ubuntuone_uploader
chmod +x ubuntuone_uploader.py
```

使用`-h`查看命令参数：

```sh
./ubuntuone_uploader.py -h
```

参看子命令`upload`使用方法：

```sh
./ubuntuone_uploader.py upload -h
```

##auth

使用任何功能前先进行授权，授权后的token存在脚本所在目录的.ubuntuone中：

```sh
./ubuntuone_uploader.py auth
```

##quota

查看空间容量信息：

```sh
./ubuntuone_uploader.py quota
```

##list

查看目录中的文件，不指定目录时默认查询根目录，目录从根目录`/`写起，`---`代表的是目录：

```sh
./ubuntuone_uploader.py list                #查看根目录
./ubuntuone_uploader.py list -d /path       #查看path目录
```

##download

下载文件默认输出到屏幕，需要保存可以使用重定向：

```sh
./ubuntuone_uploader.py download /2000.png > 2000.png
```

##upload

上传文件时不指定目标路径时默认上传到根目录。目标路径从根目录`/`写起，文件名不能省略，如果指定的是存在的目录名，Ubuntu One的API会将目录删除，然后创建一个同名文件(与删除的目录)，所以上传的时候要注意。

上传时先试图通过sha1来进行秒传，如果失败才会进行实际上传：

```sh
./ubuntuone_uploader.py upload Chesszip                         #上传到根目录
./ubuntuone_uploader.py upload Chess.zip -r /ysl/cs.zip         #上传到/ysl，名称为cs.zip
```

##delete

删除文件或者目录，删除路径从根目录`/`写起：

```sh
./ubuntuone_uploader.py delete /ysl
```

##mkdir

创建目录，创建路径从根目录`/`写起，可以递归创建：

```sh
./ubuntuone_uploader.py mkdir /fuck/me      #递归创建
```

##move

移动文件或者目录，路径从根目录`/`写起，目标路径需要包含文件名或者目录名，否则会删除目录或者文件名，并创建同名文件或者路径(与删除目录同名)，类似upload；

```sh
./ubuntuone_uploader.py move /2000.png /ysl/2000.png    #移动文件
./ubuntuone_uploader.py move /fuck /ysl/fuck            #移动目录
```

##copy

没有相关api，有个变通的方法：如果Ubuntu One已经有该文件，你可以使用upload的秒传功能来实现copy功能。

##share

分享文件，目前没有分享目录的API：

```sh
./ubuntuone_uploader.py share -l                #查看所有的分享文件
./ubuntuone_uploader.py share -s /be.jpg        #分享
./ubuntuone_uploader.py share -c /be.jpg        #取消分享
```
