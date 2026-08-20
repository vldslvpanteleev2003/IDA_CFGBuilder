import ida_idaapi

# require используется для того чтобы при изменении модулей ida обновляла скрипт полностью, нужен для отладки
ida_idaapi.require("Constants")
ida_idaapi.require("CFGRecovery")
ida_idaapi.require("CFGRender")
ida_idaapi.require("CFGHooks")
ida_idaapi.require("Models")
ida_idaapi.require("runner")

import CFGRecovery
import CFGRender
import ida_kernwin

if __name__ == "__main__":
    start = ida_kernwin.get_screen_ea() # получаем адрес курсора
    recovery = CFGRecovery.CFGRecovery(start)
    recovery.recmain()
    cfg_render = CFGRender.CFGRender(recovery)
    cfg_render._start_graph_build() if cfg_render.Show() else print("[!] Show() failed") # если граф инициализировался нормально, то продолжаем строить граф

    