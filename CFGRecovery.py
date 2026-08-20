from collections import deque
import ida_bytes
import ida_ua
import idautils
import idc
import Constants
import CFGRender
import ida_allins
import ida_lines
import Models

'''
Общая суть данного кода в том, чтобы пройтись по всему коду, до которого процессор может дойти,
добавить каждый блок в словарь blocks, заполнить для блока инструкции, узлы и другие данные
Используется метод поиска в ширину (BFS)
'''
class CFGRecovery:
    def __init__(self, start):
        self.start_block = start # начальный адрес каждого блока
        self.ea = start # указывает на текущий адрес выполнения в программе
        self.insn = None # указывает на текущий тип инструкции, через него сравниваем с типами инструкций в Constants.py
        self.size = 0 # указывает не текущий размер декодированной инструкции
        self.visited = set() # множество для обработанных блоков
        self.queue = deque([start]) # список тех узлов (адресов), которые необходимо пройти
        self.blocks : dict[int, BlockInfo] = {} # хранит всю информацию о блоках, здесь в int - адрес начала блока, BlockInfo - обьект класса BlockInfo
        
    def addblock(self, block):
        '''
        суть данной функции в том, чтобы окончательно формировать блоки, для этого вычисляются узлы (адреса переходов)
        для текущего блока и далее формируется единный словарь, куда добавляет обект блока класса BlockInfo
        '''
        # проверяем тип инструкции, является ли инструкция терминатором (BLOCK_END_UNKNOWN_TARGET) с неизвестными узлами из Constants.py и проверяем размер
        # инструкции на 0 как одно из условий завершения обработки блока, когда код не сдекодировался
        if self.insn.itype in Constants.BLOCK_END_UNKNOWN_TARGET or self.size <= 0:  
            block.edges = []
        
        elif self.insn.itype in Constants.COND_JUMPS: #проверяем тип инструкции, является ли терминатором для блока с двойными узлами (COND_JUMPS) из Constants.py
            truebranch = idc.get_operand_value(self.ea, 0) # вовзращает значение первого операнда, короче говоря дает начальный адрес следующего блока, если сравнение успешно
            falsebranch = self.ea + self.size # если сравнение неуспешно, то сохраняем адрес следующей инструкции после сравнения
            if (truebranch not in self.visited) and (truebranch not in self.queue): # проверяем target узел в посещенных и в очереди, дабы не плодить очередь
                self.queue.append(truebranch)
            block.edges.append((truebranch, "GREEN"))
            if (falsebranch not in self.visited) and (falsebranch not in self.queue): # проверяем fall-through узел в посещенных и в очереди, дабы не плодить очередь
                self.queue.append(falsebranch)
            block.edges.append((falsebranch, "RED"))
        
        elif self.insn.itype in Constants.UNCOND_JUMPS:  #проверяем тип инструкции на jmp (UNCOND_JUMPS), который указывает на один узел
            operand = self.insn.ops[0]
            if operand.type in {ida_ua.o_near, ida_ua.o_far}: # проверяем тип target (target узел может быть определен заранее, к примеру jmp sub_1400, а может и нет, к примеру jmp rax). Если вдруг инструкция типа indirect (jmp rax и т.д.), то переходим к else
                truebranch = idc.get_operand_value(self.ea, 0) # вовзращает значение первого операнда, короче говоря дает начальный адрес следующего блока, если сравнение успешно
                if (truebranch not in self.visited) and (truebranch not in self.queue):
                    self.queue.appendleft(truebranch)
                block.edges.append((truebranch, "BLUE"))
            else:
                pass
                    
        self.blocks[self.start_block] = block
        return
        
    def makeinstr(self):
        '''
        главная функция обработки блоков, при вызове обрабатывает один блок, сохраняет все инструкции текущего блока, далее
        вызывает addblock где инструкции уже добавляются в словарь
        '''
        #инициализируем обьект одного блока класса BlockInfo
        block = Models.BlockInfo(self.start_block)
        self.blocks[self.start_block] = block
        self.ea = self.start_block
        
        while (True):
            #инициализируем обьект класса InstructionInfo для одной строки инструкции
            instruction = Models.InstructionInfo(self.start_block)
            block.instructions.append(instruction)
            
            self.insn = ida_ua.insn_t() # создаем пустой обьект инструкции    
            self.size = ida_ua.decode_insn(self.insn, self.ea) # декодируем инструкцию, заполняем обьект инструкции и сразу же получам размер инструкции в байтах
            if self.size <= 0: # если по каким то причинам не удается декодировать инструкцию, то завершаем функцию, добавляем во множество уже посещенных
                self.visited.add(self.start_block)
                instruction.plain_text = "UNDECODABLE".center(20)
                self.addblock(block) 
                return
            ida_bytes.del_items(self.ea, ida_bytes.DELIT_SIMPLE, self.size) # удаляем видимый код в ida в обычные байты
            ida_ua.create_insn(self.ea) #создаем видимый код в ida
            
            asminstr = idc.generate_disasm_line(self.ea, 0) #сохраняем текущий дизасемблированный код из textview в словарь blocks с ключом instructions
            clean_instr = ida_lines.tag_remove(asminstr) # удаляем на всякий случай тэги
            instruction.address = self.ea
            instruction.plain_text = f"{self.ea:#x}\t{clean_instr}" #"\\l" - ставить, если рендерим с помощью graphviz, "\n" - если используем встроенный в IDA GraphViewer
            
            instruction.address_range = (instruction.plain_text.find(str(hex(instruction.address))), instruction.plain_text.find(str(instruction.address)) + len(str(instruction.address))) # рассчитываем диапазон адреса инструкции, нужен для прыжков
            instruction.ida_instruction_object = self.insn # сохраняем в обьекте класса InstructionInfo внутренний обьект инструкции из ida, нигде не используется
            
            if self.insn.itype in Constants.BASIC_BLOCK_END_INSNS: #добавляем начальный адрес блока в посещенные, если текущая инструкция является терминатором любого типа
                self.visited.add(self.start_block)
                self.addblock(block)
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


