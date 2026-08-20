import ida_graph
import time
import ida_kernwin
import Constants
import CFGHooks

class CFGRender(ida_graph.GraphViewer):
    
    '''
    БЛОК CALLBACK функций
    '''
    def __init__(self, rec): 
        # вызываем инициализацию родительского класса для переопределения функции OnRefresh и инициализации кучи параметров. "CFG" - заголовок графа
        super().__init__(f"CFG {time.time_ns()}") # коряво рисует графы, если граф постоянно инициализируется с одним и тем же названием, поэтому генерим название графа
        self.blocks = rec.blocks # забираем готовый заполненный словарь 
        self.node_to_text = {}
        self.addr_to_node = {}
        self.node_to_addr = {}
        
        self.view_hooks = CFGHooks.CFGViewHooks(self)

        self.direct_graph = None # Нужно сохранить ссылку на обьект типа interactive_graph_t, чтобы SWIG/Python не уничтожил объект.
    
    """
    Переопределенная callback функция, которая рефрешит графы, когда вызывается cfg.show()
    
    Переведенная информация из документации:
        Событие, вызываемое при обновлении или первом создании графа.
        На основе этого события вы должны создать узлы и рёбра.
        Этот обратный вызов является обязательным.
        ПРИМЕЧАНИЕ: ***Важно очистить предыдущие узлы перед добавлением новых.***
        :returns: Если вернуть True, средство просмотра графа будет использовать эти элементы. В противном случае будут использоваться старые элементы.
    """
    def OnRefresh(self):
        return False
      
    def OnGetText(self, node_id): # переопределенная callback функция, которая присваивает каждому ноду свой текст или "" 
        return self.node_to_text.get(node_id, "")
    '''
    БЛОК CALLBACK функций
    '''  
        
        
        
    '''
    КАСТОМНЫЙ БЛОК ФУНКЦИЙ
    '''
    '''
    В данной функции функции вытаскиваем обьект класса TWidget и из него сразу получаем обьект класса graph_viewer_t
    '''
    def _get_native_viewer(self):
        widget = None

        try:
            widget = self.GetWidget()
        except Exception as error:
            print("[!] GetWidget failed:", error)
            widget = None

        if widget is None:
            widget = ida_kernwin.find_widget(self._title)

        if widget is None:
            print("[!] Widget not found")
            return None

        viewer = ida_graph.get_graph_viewer(widget)

        if viewer is None:
            print("[!] get_graph_viewer returned None")
            return None   
        
        return viewer
  
    '''
    ставит функцию в очередь на выполнение в главном UI-потоке IDA, в качестве аргумента ожидается кортеж функций, в данном случае функция одна
    '''
    def _start_graph_build(self):
        ida_kernwin.execute_ui_requests((self._install_direct_graph,))
    '''
    КАСТОМНЫЙ БЛОК ФУНКЦИЙ
    '''
    
    def _install_direct_graph(self):
        '''
        очищаем словари 
        '''
        self.node_to_text.clear() 
        self.addr_to_node.clear() 
        self.node_to_addr.clear() 
        
        viewer = self._get_native_viewer()
        
        if viewer is None:
            return False
        
        graph_id = int(time.time_ns() & 0x7FFFFFFF) # уникальный ID внутреннего графа.

        graph = ida_graph.create_interactive_graph(graph_id) # создаем новый пустой график с заданным идентификатором
        
        ida_graph.set_viewer_graph(viewer, graph) # Подменяем внутренний граф текущего viewer.

        if graph is None:
            print("[!] create_interactive_graph returned None")
            return False

        for startblock, block in self.blocks.items():
            rect = ida_graph.rect_t() # создаем объект прямоугольника
            node_id = graph.add_node(rect) # добавляем блок
            self.addr_to_node[startblock] = node_id # добавляет для каждого адреса начала блока его node_id
            self.node_to_addr[node_id] = startblock # для функции OnDblClick дабы кликать по блокам и переходить в textivew
            self.node_to_text[node_id] = "\n".join([instruction.plain_text for instruction in block.instructions]) # для каждого node_id добавляет текст инструкций всего блока    
                      
        for startblock, block in self.blocks.items():
            for edge, color  in block.edges:
                true_edge = ida_graph.edge_info_t() # создаем обьект линии между блоками
                true_edge.color = Constants.COLORS[color] # вытаскиваем цвет и меняем атрибут
                true_edge.width = 1 # задаем толщину линии
                graph.add_edge(self.addr_to_node[startblock], self.addr_to_node[edge], true_edge) # Тут add_edge принимает два node_id и обьект линии между блоками и соединяет блоки
        
        for node_id, text in self.node_to_text.items():
            node_info = ida_graph.node_info_t() # создаем обьект блока
            node_info.text = text # присваиваем атрибуту обьекта текст блока
        
            ida_graph.viewer_set_node_info(viewer, node_id, node_info, ida_graph.NIF_TEXT) # сохраняем свойства блока, аналог данной функции - set_node_info (работает через обьект класса interactive_graph_t)
        
        graph.create_digraph_layout() # Строим layout уже для полностью готового графа.
        
        self.direct_graph = graph # Сохраняем ссылку на объект.

        ida_graph.refresh_viewer(viewer)
        ida_graph.viewer_fit_window(viewer)

        self.view_hooks.hook()
        
        return False # специально ставим false, чтобы execute_ui_requests() не ставила данную функцию в цикл, потому что execute_ui_requests() считывает вывод функций


if __name__ == '__main__':
    raise RuntimeError(
        "This module is not intended to be run directly"
    )
    
    
'''
widget - обьект класса TWidget, окно в интерфейсе IDA, используем только для получения обьекта graph_viewer_t, в остальном не нужен
viewer - обьект класса graph_viewer_t, графический просмотрщик внутри этого окна, почти не используем, но можно в том числе и через данный обьект обращаться к узлам как и через обьект interactive_graph_t
graph - обьект класса interactive_graph_t, данные графа: узлы, рёбра, layout, используем чаще всего, именно через него рисуем все узлы и графы
'''