import ida_allins

# цвета для рендера стрелок между блоками
COLORS = {
"RED": 0x0000FF,
"GREEN": 0x006900,
"BLUE": 0xFF0000,
}

# ниже множества из инструкций, которые так или иначе влияют на control flow graph
COND_JUMPS = {
    ida_allins.NN_ja,
    ida_allins.NN_jae,
    ida_allins.NN_jb,
    ida_allins.NN_jbe,
    ida_allins.NN_jc,
    ida_allins.NN_jcxz,
    ida_allins.NN_jecxz,
    ida_allins.NN_jrcxz,
    ida_allins.NN_je,
    ida_allins.NN_jg,
    ida_allins.NN_jge,
    ida_allins.NN_jl,
    ida_allins.NN_jle,
    ida_allins.NN_jna,
    ida_allins.NN_jnae,
    ida_allins.NN_jnb,
    ida_allins.NN_jnbe,
    ida_allins.NN_jnc,
    ida_allins.NN_jne,
    ida_allins.NN_jng,
    ida_allins.NN_jnge,
    ida_allins.NN_jnl,
    ida_allins.NN_jnle,
    ida_allins.NN_jno,
    ida_allins.NN_jnp,
    ida_allins.NN_jns,
    ida_allins.NN_jnz,
    ida_allins.NN_jo,
    ida_allins.NN_jp,
    ida_allins.NN_jpe,
    ida_allins.NN_jpo,
    ida_allins.NN_js,
    ida_allins.NN_jz,

    ida_allins.NN_loopw,
    ida_allins.NN_loop,
    ida_allins.NN_loopd,
    ida_allins.NN_loopq,

    ida_allins.NN_loopwe,
    ida_allins.NN_loope,
    ida_allins.NN_loopde,
    ida_allins.NN_loopqe,

    ida_allins.NN_loopwne,
    ida_allins.NN_loopne,
    ida_allins.NN_loopdne,
    ida_allins.NN_loopqne,
    
    ida_allins.NN_xbegin,
}


UNCOND_JUMPS = {
    ida_allins.NN_jmp,
    ida_allins.NN_jmpfi,
    ida_allins.NN_jmpni,
    ida_allins.NN_jmpshort,
}


NEAR_RET_INSNS = {
    ida_allins.NN_retn,
    ida_allins.NN_retnw,
    ida_allins.NN_retnd,
    ida_allins.NN_retnq,
}

FAR_RET_INSNS = {
    ida_allins.NN_retf,
    ida_allins.NN_retfw,
    ida_allins.NN_retfd,
    ida_allins.NN_retfq,
}

INTERRUPT_RET_INSNS = {
    ida_allins.NN_iretw,
    ida_allins.NN_iret,
    ida_allins.NN_iretd,
    ida_allins.NN_iretq,
    ida_allins.NN_uiret,
}


# Инструкции, после которых нет обычного локального fall-through.
NO_FALLTHROUGH_INSNS = {
    ida_allins.NN_ud0,
    ida_allins.NN_ud1,
    ida_allins.NN_ud2,

    ida_allins.NN_rsm,
    ida_allins.NN_sysenter,
    ida_allins.NN_sysexit,
    ida_allins.NN_sysret,
    ida_allins.NN_vmexit,
}


# Передают управление обработчику исключения/прерывания.
# Потенциальное продолжение зависит от внешнего состояния.
EXCEPTION_CONTROL_FLOW = {
    ida_allins.NN_int,
    ida_allins.NN_into,
    ida_allins.NN_int3,
    ida_allins.NN_icebp,
}

TRANSACTION_ABORT_INSNS = {
    ida_allins.NN_xabort,
}


SPECIAL_VM_CONTROL_FLOW = {
    ida_allins.NN_vmhlt,
    ida_allins.NN_vmiretd,
}

# ENCLU может изменять или не изменять ход выполнения программы в зависимости от значения EAX (листовая функция)
# Пока что это рассматривается как обычная инструкция
DYNAMIC_CONTROL_FLOW = {
    ida_allins.NN_enclu,
}

ENVIRONMENT_DEPENDENT_FALLTHROUGH = {
    ida_allins.NN_hlt,
}

ENVIRONMENT_DEPENDENT_CONTROL_FLOW = {
    ida_allins.NN_loadall,
}

RET_INSNS = (
    NEAR_RET_INSNS
    | FAR_RET_INSNS
    | INTERRUPT_RET_INSNS
)

# список всех инструкций терминаторов, у которых узлы неизвестны. Используется в CFGRecovery, чтобы сразу определять, что у обьекта класса BlockInfo нет узлов
BLOCK_END_UNKNOWN_TARGET = (
    RET_INSNS
    | NO_FALLTHROUGH_INSNS
    | EXCEPTION_CONTROL_FLOW
    | TRANSACTION_ABORT_INSNS
    | SPECIAL_VM_CONTROL_FLOW
    | ENVIRONMENT_DEPENDENT_CONTROL_FLOW
)

# общий список всех инструкций терминаторов, на которых блок заканчивается. Используется в CFGRecovery.py, чтобы сразу сразу определять вообще заканичвается ли блок
BASIC_BLOCK_END_INSNS = (
    COND_JUMPS
    | UNCOND_JUMPS
    | BLOCK_END_UNKNOWN_TARGET
)

'''
Обьединил TRANSACTION_BRANCHES с COND_JUMPS, потому что логика такая же:
'''