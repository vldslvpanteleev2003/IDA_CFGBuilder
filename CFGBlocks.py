import ida_graph
#from graphviz import Digraph #расскоментить, если рендерим с помощью graphviz

class CFGBlocks(ida_graph.GraphViewer):
    def __init__(self, rec): 
        # вызываем инициализацию родительского класса для переопределения функций OnRefresh и OnGetText. "CFG" - заголовок графа
        super().__init__("CFG") 
        self.blocks = rec.blocks # забираем готовый заполненный словарь 
        self.node_to_text = {}
        self.addr_to_node = {}

    '''переопределенная callback функция, которая рефрешит графы, когда вызывается cfg.show()'''
    def OnRefresh(self):
        self.Clear() # очистка графа

        self.node_to_text = {} # дополнительно очищаем словари
        self.addr_to_node = {} # дополнительно очищаем словари

        '''
        node_id = self.AddNode(startblock) - тут AddNode принимает начальный адрес блока и дает node_id. 
        self.addr_to_node[startblock] = node_id - добавляет для каждого адреса начала блока его node_id
        self.node_to_text[node_id] = block["instructions"] - для каждого node_id добавляет текст инструкций всего блока
        '''
        for startblock, block in self.blocks.items():
            node_id = self.AddNode(startblock)
            self.addr_to_node[startblock] = node_id
            self.node_to_text[node_id] = block["instructions"]

        '''
        Суть данных циклов в том, чтобы соединить блоки по их node_id. Тут AddEdge принимает два node_id:
            self.addr_to_node[startblock]
            self.addr_to_node[edge]
        и соединяет их
        '''
        for startblock, block in self.blocks.items():
            for edge in block["edges"]:
                self.AddEdge(
                    self.addr_to_node[startblock],
                    self.addr_to_node[edge]
                )
    
        return True
        
    '''
    переопределенная callback функция, которая присваивает каждому ноду свой текст или "" 
    '''
    def OnGetText(self, node_id):
        return self.node_to_text.get(node_id, "")
        
if __name__ == '__main__':
    raise RuntimeError(
        "This module is not intended to be run directly"
    )