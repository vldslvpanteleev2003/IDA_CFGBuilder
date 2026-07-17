from collections import deque
import ida_bytes
import ida_ua
import idautils
import idc
import constants
import CFGBlocks
import ida_allins


'''
Общая суть данного кода в том, чтобы пройтись по всему коду, до которого процессор может дойти,
добавить каждый блок в словарь, заполнить для блока инструкции и узлы
Используется метод поиска в ширину (BFS)
'''
class CFGRecovery:
    def __init__(self, start):
        self.start_block = start # начальный адрес каждого блока
        self.ea = start # указывает на текущий адрес выполнения в программе
        self.insn = None # указывает на текущий тип инструкции, через него сравниваем с типами инструкций в constants.py
        self.size = 0 # указывает не текущий размер декодированной инструкции
        self.visited = set() # множество для обработанных блоков
        self.queue = deque([start]) # список тех узлов (адресов), которые необходимо пройти
        self.blocks = {} # здесь в ключе instructions храним инструкции в текстовом формате, в ключе edges храним список узлов (адресов), на которые программа прыгает после выполнения текущего блока
        
    def addblock(self):
        '''
        суть данной функции в том, чтобы окончательно формировать блоки, для этого вычисляются узлы (адреса переходов)
        для текущего блока и далее формируется единный словарь, куда добавляются инструкции и узлы для каждого блока
        '''
        # проверяем тип инструкции, находится ли инструкция в RET_INSNS из constants.py и проверяем размер
        # инструкции на 0 как одно из условий завершения обработки блока, когда код нетипичный
        if (self.insn.itype in constants.RET_INSNS) or (self.size <= 0):  
            self.blocks[self.start_block] = {
            "instructions": self.blockinstructions,
            "edges": []}
            return
        
        edges = []
        truebranch = idc.get_operand_value(self.ea, 0) # вовзращает значение первого операнда, короче говоря дает начальный адрес следующего блока, если сравнение успешно
        falsebranch = self.ea + self.size # если сравнение неуспешно, то сохраняем адрес следующей инструкции после сравнения
        
        if self.insn.itype in constants.COND_JUMPS: #проверяем тип инструкции, находится ли инструкция в COND_JUMPS из constants.py
            if (truebranch not in self.visited) and (truebranch not in self.queue):
                self.queue.append(truebranch)
            edges.append(truebranch)
            if (falsebranch not in self.visited) and (falsebranch not in self.queue): 
                self.queue.append(falsebranch)
            edges.append(falsebranch)
        
        if self.insn.itype == ida_allins.NN_jmp:   #проверяем тип инструкции на jmp
            if (truebranch not in self.visited) and (truebranch not in self.queue):
                self.queue.appendleft(truebranch)
            edges.append(truebranch)
        
        self.blocks[self.start_block] = {
                    "instructions": self.blockinstructions,
                    "edges": edges}
        return
        
    def makeinstr(self):
        '''
        главная функция обработки блоков, обрабатывает по одному блоку, сохраняет все инструкции текущего блока, далее
        вызывает addblock где инструкции уже добавляются в словарь, вычисляются узлы для каждого блока и также добавляются в словарь
        '''
        self.blockinstructions = "" # здесь храним инструкции для каждого блока
        self.ea = self.start_block # 
        while (True):
            self.insn = ida_ua.insn_t() # создаем пустой обьект инструкции    
            self.size = ida_ua.decode_insn(self.insn, self.ea) # декодируем инструкцию, заполняем обьект инструкции и сразу же получам размер инструкции в байтах
            if self.size <= 0: # если по каким то причинам не удается декодировать инструкцию, то завершаем функцию, добавляем во множество уже посещенных
                self.visited.add(self.start_block) 
                self.addblock() 
                return
            ida_bytes.del_items(self.ea, ida_bytes.DELIT_SIMPLE, self.size) # удаляем видимый код в ida в обычные байты
            ida_ua.create_insn(self.ea) #создаем видимый код в ida
            
            asminstr = idc.generate_disasm_line(self.ea, 0) #сохраняем текущий дизасемблированный код из textview в словарь blocks с ключом instructions
            self.blockinstructions += asminstr + "\n" #"\\l" - ставить, если рендерим с помощью graphviz, "\n" - если используем встроенный в IDA GraphViewer
            print(asminstr)
            
            if self.insn.itype in constants.COND_JUMPS: #добавляем начальный адрес блока в посещенные, если текущая инструкция из COND_JUMPS
                self.visited.add(self.start_block)
                self.addblock()
                return
                
            elif self.insn.itype == ida_allins.NN_jmp: #добавляем начальный адрес блока в посещенные, если текущая инструкция jmp
                self.visited.add(self.start_block)
                self.addblock()
                return
                
            elif self.insn.itype in constants.RET_INSNS: #добавляем начальный адрес блока в посещенные, если текущая инструкция из RET_INSNS
                self.visited.add(self.start_block)
                self.addblock()
                return
                
            self.ea += self.size # меняем текущий адрес инструкции на следующий
            
    def recmain(self):
        '''
        данная функция поочередено вытаскивает начальный адрес каждого блока, проверяет адрес во множестве посещенных,
        если блок не обработан, то вызывает makeinstr 
        '''
        while(self.queue): # пока существуют переходы создаем графы и узлы
            self.start_block = self.queue.popleft() # вытаскиваем начальный адрес при запуске скрипта
            if self.start_block in self.visited: # если начальный адрес следующего блока уже есть во множестве, то пропускаем данный блок
                continue
            self.makeinstr()
            
if __name__ == '__main__':
    raise RuntimeError(
        "This module is not intended to be run directly"
    )
    
    
'''
Проблемы:
1) Нет обработки нетипичных случаев в коде, когда к примеру встречаются COND_JUMPS инструкции, которые указывают на несуществующие адреса,
в таком случае добавляются пустые блоки и далее поведение программы уже неизвестно
'''