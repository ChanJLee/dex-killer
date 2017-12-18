# dex killer

dex killer is a tools for dumping dex file from memory, so make sure your device has root.

--------------------

## Directory

- 360 

  contains test apk
- art
  
  contains screenshot

## MAKE

1. clone repo

```shell
git clone https://github.com/ChanJLee/dex_killer.git
```

2. make

```shell
cd dex_killer
make
```

3. push file to your android device

```shell
make install
```

4. run on your device, Specify the pkg(the app's pkg what you want to dump). 
```shell
adb shell
su
/data/local/tmp/dex_killer {pkg}
```
