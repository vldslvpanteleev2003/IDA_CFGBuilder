import idaapi
import ida_graph
import ida_kernwin

# IDA colors are usually 0xBBGGRR:
RED   = 0x0000FF
GREEN = 0x00FF00
BLUE  = 0xFF0000

class DataGraph(idaapi.GraphViewer):
    TITLE = "Data blocks graph"

    def __init__(self):
        super().__init__(self.TITLE, True)
        self.edge_colors = {}

    def OnRefresh(self):
        self.Clear()

        n0 = self.AddNode("DATA[0]\n.rdata: strings")
        n1 = self.AddNode("DATA[1]\nconfig blob")
        n2 = self.AddNode("DATA[2]\nkey material")

        self.AddEdge(n0, n1)
        self.AddEdge(n0, n2)

        self.edge_colors = {
            (n0, n1): RED,
            (n0, n2): GREEN,
        }

        return True

    def OnGetText(self, node_id):
        return str(self[node_id])

    def get_graph_viewer_93_safe(self):
        # Do NOT use self.GetWidgetAsGraphViewer() in IDA 9.3 here.
        widget = None

        try:
            widget = self.GetWidget()
        except Exception as e:
            print("[!] GetWidget() failed:", e)

        if widget is None:
            widget = ida_kernwin.find_widget(self.TITLE)

        if widget is None:
            print("[!] widget not found")
            return None

        gv = ida_graph.get_graph_viewer(widget)
        if gv is None:
            print("[!] ida_graph.get_graph_viewer() returned None")
            return None

        return gv

    def apply_edge_colors(self):
        gv = self.get_graph_viewer_93_safe()
        if gv is None:
            return False

        g = ida_graph.get_viewer_graph(gv)
        if g is None:
            print("[!] ida_graph.get_viewer_graph() returned None")
            return False

        for (src, dst), color in self.edge_colors.items():
            ei = ida_graph.edge_info_t()
            ei.color = color
            ei.width = 2

            # GraphViewer.AddEdge() creates plain edges.
            # Recreate them with edge_info_t.
            deleted = g.del_edge(src, dst)
            added = g.add_edge(src, dst, ei)

            print("[edge]", src, "->", dst,
                  "deleted =", deleted,
                  "added =", added,
                  "color =", hex(color))

        g.create_digraph_layout()
        ida_graph.refresh_viewer(gv)
        return False


dg = DataGraph()
dg.Show()

ida_kernwin.execute_ui_requests((dg.apply_edge_colors,))