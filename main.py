from CFGRecovery import CFGRecovery
from CFGBlocks import CFGBlocks
from dot import dotExport

if __name__ == "__main__":
    start = 0x14001B2B4
    rec = CFGRecovery(start)
    rec.recmain() # вызываем главную функцию обработки кода и формирования блоков
    cfg = CFGBlocks(rec) # передаем заполненный словарь с заполненным блоками для прорисовки графа
    cfg.Show() # рисуем граф
    #dotExport(rec) #расскоментить, если рендерим через graphviz
   
'''   
Как запускать:
скачать отсюда установщик https://graphviz.org/download/, установить
открыть терминал, сделать pip install graphviz
запустить скрипт этот
в терминале ввести: dot -Tsvg C:\users\admin\desktop\cfg.dot -o C:\users\admin\desktop\cfg.svg
открыть svg файл на рабочем столе

Что реализовать:
1. понять почему коряво выводит ломанный код через встроенный GraphViewer
2. сделать цветной рендер
'''