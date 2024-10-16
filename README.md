# B61Decoder
Experimental project for ARIB STD-B61<br/>
検証・研究目的としてB61Decoder.exe(C#)のソースコードをC++向けに移植しDLL化したものです。<br/>
I/Fは実質IB25Decoder相当のみ対応となっています。

# Libraries

以下のライブラリが必要です。

- **OpenSSL**

# How to build

VS2022/17にて、以下の設定を変更しbuildしてください。

- C/C++ > 追加のインクルードディレクトリ 
  -  OpenSSL Includeパスを変更
- リンカー > 追加のライブラリディレクトリ 
  - OpenSSL Libパスを変更

# INI File

実行時はモジュールと同名のiniファイルを同一フォルダに配置し、ダミー値を変更して利用してください。
