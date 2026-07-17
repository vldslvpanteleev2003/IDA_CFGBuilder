import ida_allins

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