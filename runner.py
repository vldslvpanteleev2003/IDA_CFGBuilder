import ida_kernwin

ACTION_NAME = "cfg:run"

class RunCFGAction(ida_kernwin.action_handler_t):
    def activate(self, ctx):
        exec(
            compile(
                open(
                    r"C:\Users\admin\Desktop\Nextcloud\CFGBuilder\main.py",
                    encoding="utf-8",
                ).read(),
                r"C:\Users\admin\Desktop\Nextcloud\CFGBuilder\main.py",
                "exec",
            ),
            globals(),
        )
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS
        
ida_kernwin.register_action(
    ida_kernwin.action_desc_t(
        ACTION_NAME,
        "Run CFG",
        RunCFGAction(),
        "Ctrl+Shift+R",
        "Run CFG script"
    )
)