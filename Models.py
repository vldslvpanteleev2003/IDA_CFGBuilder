from dataclasses import dataclass, field
import ida_ua

"""
Класс который описывает операнды одной строки инструкции. Является атрибутом класса InstructionInfo. Создавался для того, чтобы в будущем, если будет не лень, реализовать переход на textview с графа при кликании на операнды.
Нигде пока что не реализуется
"""    
@dataclass
class OperandInfo:
    text: str
    text_range: tuple[int, int]


"""
Класс который описывает одну конкретную строку инструкции. Является атрибутом класса BlockInfo. Создавался для:
1) реализации прыжков с графа на textview на точные адреса, а не начало блоков, а для этого требуется создать дополнительные атрибуты для каждой строки инструкции с расположениями слов
2) визуального представления данных
3) для возможных будущих улучшений
"""    
@dataclass
class InstructionInfo:
    address: int | None #адрес строки инструкции
    plain_text: str = field(init=False) # текст одной сттроки инструкции
    address_range: tuple[int, int] | None = field(init=False) # диапазон текста адреса в блоке, нужен для реализации прыжков
    operands: list[OperandInfo] | None = field(init=False, default_factory=list) # список операндо, не используется
    ida_instruction_object : ida_ua.insn_t | None = None # обьект инструкции в ida, нигде не используется, добавил на всякий
    
    def address_contains(self, column: int) -> bool: # используется в CFGHooks.py, сделал, чтобы быстрее проверять расположение курсора при двойных кликах. Если двойной клик был в диапазоне адреса, то делаем переход
        start, end = self.address_range
        return start <= column < end
        

"""
Класс который описывает один блок с инструкциями и узлами. Используется в словаре в CFGRecovery.py, сделал для удобства, чтобы через адрес сразу обращаться к нужному блоку. 
"""    
@dataclass
class BlockInfo:
    start_address : int # адрес начала блока
    instructions : list[InstructionInfo] = field(default_factory=list) # список обьектов класса InstructionInfo
    edges: list[(int, str)] = field(default_factory=list) # узлы блока, хранит список адресов узла и цвет соединения с текущим блоком
    
    def instruction_at_line(self, line: int) -> InstructionInfo | None: # используется в CFGHooks, возвращает конкретный обьект InstructionInfo. Нужен для определения конкретной строки в блоке, куда мы нажали
        if not 0 <= line < len(self.instructions):
            return None

        return self.instructions[line]
        
        
