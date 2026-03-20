#!/usr/bin/env python3
import struct, os

def box(t, p=b''):
    return struct.pack('>I4s', 8 + len(p), t.encode()) + p

def fb(t, p=b'', ver=0, flags=0):
    return box(t, bytes([ver]) + struct.pack('>I', flags)[1:] + p)

def ftyp(major, compat):
    return box('ftyp', major.encode() + b'\x00'*4 + b''.join(b.encode() for b in compat))

def hdlr():
    return fb('hdlr', b'\x00'*4 + b'pict' + b'\x00'*13)

def pitm(i):    return fb('pitm', struct.pack('>H', i))
def iinf(es):   return fb('iinf', struct.pack('>H', len(es)) + b''.join(es))
def infe(i, t): return fb('infe', struct.pack('>HH', i, 0) + t.encode() + b'\x00', ver=2)

def iloc(items):
    p = b'\x44\x00' + struct.pack('>H', len(items))
    for item_id, extents in items:
        p += struct.pack('>HHH', item_id, 0, len(extents))
        for off, ln in extents:
            p += struct.pack('>II', off, ln)
    return fb('iloc', p)

def ispe(w, h):  return fb('ispe', struct.pack('>II', w, h))
def pixi(chs):   return fb('pixi', bytes([len(chs)] + chs))
def colr_nclx(): return box('colr', b'nclx' + struct.pack('>HHHb', 1, 13, 6, 0))

def ipma(assocs):
    p = struct.pack('>I', len(assocs))
    for item_id, props in assocs:
        p += struct.pack('>HB', item_id, len(props))
        for idx, essential in props:
            p += struct.pack('>H', idx | (0x8000 if essential else 0))
    return fb('ipma', p)

def iprp(props, assocs):
    return box('iprp', box('ipco', b''.join(props)) + ipma(assocs))

def iref_thmb(from_id, to_id):
    return box('thmb', struct.pack('>HHH', from_id, 1, to_id))

def meta(*children):
    return fb('meta', b''.join(children))

PAD = box('free', b'\x00' * 16)

seeds = {
    '1_minimal_meta.heic': (
        ftyp('heic', ['heic', 'mif1'])
        + meta(hdlr(), pitm(1), iinf([]), iloc([]))
        + PAD
    ),
    '2_single_hvc1_item.heic': (
        ftyp('heic', ['heic', 'mif1'])
        + meta(hdlr(), pitm(1), iinf([infe(1, 'hvc1')]), iloc([(1, [(0, 0)])]))
        + PAD
    ),
    '3_image_properties.heic': (
        ftyp('heic', ['heic', 'mif1'])
        + meta(
            hdlr(), pitm(1),
            iinf([infe(1, 'hvc1')]),
            iloc([(1, [(0, 0)])]),
            iprp([ispe(64, 64), pixi([8, 8, 8]), colr_nclx()],
                 [(1, [(1, True), (2, False), (3, False)])]),
        )
        + PAD
    ),
    '4_multi_item_with_iref.heic': (
        ftyp('heic', ['heic', 'mif1'])
        + meta(
            hdlr(), pitm(1),
            iinf([infe(1, 'hvc1'), infe(2, 'hvc1')]),
            iloc([(1, [(0, 0)]), (2, [(0, 0)])]),
            iprp([ispe(64, 64), ispe(16, 16)],
                 [(1, [(1, True)]), (2, [(2, True)])]),
            fb('iref', iref_thmb(2, 1)),
        )
        + PAD
    ),
    '5_avif_av01.heic': (
        ftyp('avif', ['avif', 'mif1', 'miaf'])
        + meta(hdlr(), pitm(1), iinf([infe(1, 'av01')]), iloc([(1, [(0, 0)])]))
        + PAD
    ),
    '6_grid_derived_image.heic': (
        ftyp('heic', ['heic', 'mif1'])
        + meta(
            hdlr(), pitm(1),
            iinf([infe(1, 'grid'), infe(2, 'hvc1'), infe(3, 'hvc1')]),
            iloc([(1, [(0, 8)]), (2, [(8, 0)]), (3, [(8, 0)])]),
            iprp([ispe(64, 32), ispe(32, 32)],
                 [(1, [(1, True)]), (2, [(2, True)]), (3, [(2, True)])]),
            fb('iref', box('dimg', struct.pack('>HHHH', 1, 2, 2, 3))),
        )
        + bytes([0, 0, 0, 1, 64, 0, 0, 32])   # grid payload: 1x2 grid, 64x32
        + PAD
    ),
}

out_dir = os.path.join(os.path.dirname(__file__), 'seeds')
os.makedirs(out_dir, exist_ok=True)
for name, data in seeds.items():
    with open(os.path.join(out_dir, name), 'wb') as f:
        f.write(data)
    print(f"{name}  {len(data)} bytes")
