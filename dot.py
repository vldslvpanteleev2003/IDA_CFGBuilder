def dotExport(rec):
    with open(r"C:\users\admin\desktop\cfg.dot", "w", encoding="utf-8") as f:

            f.write("digraph CFG {\n")
            f.write("graph [rankdir=TB];\n")
            f.write("node [shape=box];\n")
        
            for start, block in rec.blocks.items():
        
                label = block["instructions"]
                label = label.replace("\\", "\\\\")
                label = label.replace('"', '\\"')
        
                f.write(
                    f'"{start:x}" [label="{label}"];\n'
                )
        
            for start, block in rec.blocks.items():
        
                for edge in block["edges"]:
        
                    f.write(
                        f'"{start:x}" -> "{edge:x}";\n'
                    )
        
            f.write("}\n")
            
if __name__ == '__main__':
    raise RuntimeError(
        "This module is not intended to be run directly"
    )