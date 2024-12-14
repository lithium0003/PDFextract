# PDFextract
extract jpeg from pdf file(NDL Digital Collection)

## Compile
```
make
```

## Run
```
./pdfextract digidepo_00000000_0001.pdf
./pdfextract digidepo_00000000_0002.pdf 100
```
extract jpeg files to current folder.

2nd argument is start page number when pdf continues filename number.


# PDFextract
https://dl.ndl.go.jp/
国会図書館デジタルコレクション

から印刷したpdfを連番のjpgに展開します。

第2引数に続きからのページ番号を指定することができます。

## Limitation
やっつけ仕事なので、pdfファイル構造が決め打ちです。
他のものに使いたいときは、改造して使ってください。
