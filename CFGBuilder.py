from collections import deque
import ida_bytes
import ida_ua
import idautils
import ida_idp
import idc
import ida_gdl
import ida_graph

COND_JUMPS = {
    ida_allins.NN_ja,
    ida_allins.NN_jae,
    ida_allins.NN_jb,
    ida_allins.NN_jbe,
    ida_allins.NN_jc,
    ida_allins.NN_je,
    ida_allins.NN_jg,
    ida_allins.NN_jge,
    ida_allins.NN_jl,
    ida_allins.NN_jle,
    ida_allins.NN_jne,
    ida_allins.NN_jno,
    ida_allins.NN_jnp,
    ida_allins.NN_jns,
    ida_allins.NN_jo,
    ida_allins.NN_jp,
    ida_allins.NN_js,
    ida_allins.NN_jz,
    ida_allins.NN_jnz,
}

RET_INSNS = {
    ida_allins.NN_retn,
    ida_allins.NN_retf,
}

class CFGRecovery:
    def __init__(self, start):
        self.start_block = start
        self.ea = start
        self.insn = None
        self.size = 0
        self.visited = set()
        self.queue = deque([start])
        self.blocks = {}
        
    def addblock(self):
        
        if (self.insn.itype in RET_INSNS) or (if self.size <= 0):  :   # chechking for ret instruictions or zero size instruction
            self.blocks[self.start_block] = {
                    "instructions": self.blockinstructions,
                    "edges": [],
                }
            return

        edges = []
        truebranch = idc.get_operand_value(self.ea, 0)
        falsebranch = self.ea + self.size
        
        if self.insn.itype in COND_JUMPS:       #checking for COND_JUMPS instructions
            if (truebranch not in self.visited) and (truebranch not in self.queue):
                self.queue.append(truebranch)
            edges.append(truebranch)
            if (falsebranch not in self.visited) and (falsebranch not in self.queue): 
                self.queue.append(falsebranch)
            edges.append(falsebranch)
        
        if self.insn.itype == ida_allins.NN_jmp:   #chechking for jmp instruction
            if (truebranch not in self.visited) and (truebranch not in self.queue):
                self.queue.appendleft(truebranch)
            edges.append(truebranch)
        
        self.blocks[self.start_block] = {
                    "instructions": self.blockinstructions,
                    "edges": edges,
                }
        return
        
    def makeinstr(self):
        self.blockinstructions = ""
        self.ea = self.start_block
        while (True):
            self.insn = ida_ua.insn_t()        
            self.size = ida_ua.decode_insn(self.insn, self.ea)
            if self.size <= 0:
                self.visited.add(self.start_block)
                self.addblock()
                return
            ida_bytes.del_items(self.ea, ida_bytes.DELIT_SIMPLE, self.size)
            ida_ua.create_insn(self.ea)
            
            asminstr = idc.generate_disasm_line(self.ea, 0)
            self.blockinstructions += asminstr + "\n"
            print(asminstr)
            
            if self.insn.itype in COND_JUMPS:
                self.visited.add(self.start_block)
                self.addblock()
                return
                
            elif self.insn.itype == ida_allins.NN_jmp:
                self.visited.add(self.start_block)
                self.addblock()
                return
                
            elif self.insn.itype in RET_INSNS:
                self.visited.add(self.start_block)
                self.addblock()
                return
                
            self.ea += self.size
            
    def recmain(self):
        while(self.queue):
            self.start_block = self.queue.popleft()
            if self.start_block in self.visited:
                continue
            self.makeinstr()
        
class CFG(ida_graph.GraphViewer):
    def __init__(self, rec):
        super().__init__("CFG")
        self.blocks = rec.blocks
        self.node_to_text = {}
        self.addr_to_node = {}

    def OnRefresh(self):
        self.Clear()

        self.node_to_text = {}
        self.addr_to_node = {}

        for startblock, block in self.blocks.items():
            node_id = self.AddNode(startblock)
            self.addr_to_node[startblock] = node_id
            self.node_to_text[node_id] = block["instructions"]

        for startblock, block in self.blocks.items():
            for edge in block["edges"]:
                self.AddEdge(
                    self.addr_to_node[startblock],
                    self.addr_to_node[edge]
                )

        return True

    def OnGetText(self, node_id):
        return self.node_to_text.get(node_id, "")

if __name__ == "__main__":
    start = 0x000000014001B2B4
    rec = CFGRecovery(start)
    rec.recmain()
    cfg = CFG(rec)
    cfg.Show()
    
# План:
# понять в каких случаях нам останавливать скрипт (отсутствие кода, недоступная память к примеру)
# важное отличие от предыдущего скрипта (надо запомнить): мы не декодим всю память,
# что не очень полезно, мы декодим только код по условным переходам
# 
