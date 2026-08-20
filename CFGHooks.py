import ida_kernwin


class CFGViewHooks(ida_kernwin.View_Hooks):

    def __init__(self, renderer):
        super().__init__()
        self.renderer = renderer

    '''
    Callback срабатывает при двойном клике мышью.

    event.renderer_pos:
        node - node_id блока
        cy   - номер строки внутри блока
        cx   - номер символа внутри строки
    '''
    def view_dblclick(self, view, event):

        # View_Hooks получает события от всех окон IDA
        # Обрабатываем только наш CFG
        if view != self.renderer.GetWidget():
            return

        position = event.renderer_pos

        node_id = position.node
        line = position.cy
        column = position.cx

        # Получаем адрес начала блока по node_id
        block_address = self.renderer.node_to_addr.get(node_id)

        if block_address is None:
            return

        # Получаем объект BlockInfo
        block = self.renderer.blocks.get(block_address)

        if block is None:
            return

        # cy напрямую соответствует индексу инструкции внутри block.instructions
        instruction = block.instruction_at_line(line)

        if instruction is None:
            return

        # Например UNDECODABLE может не иметь нормального адреса/range
        if instruction.address is None:
            return

        if instruction.address_range is None:
            return

        # Прыгаем только если пользователь нажал именно на диапазон символов адреса
        if instruction.address_contains(column):
            ida_kernwin.jumpto(instruction.address)

    '''
    Callback вызывается при закрытии view.
    Снимаем глобальный View_Hooks.
    '''
    def view_close(self, view):
        if view == self.renderer.GetWidget():
            self.unhook()