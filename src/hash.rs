use bincode::Error;

use crate::blocks::UnhashedBlock;

const BYTES_PER_BLOCK: usize = 512 / 8;
const INPUT_PAD: u8 = 0b1000_0000;

type MessageSchedule = [u32; 64];

#[derive(Debug)]
struct HKState {
    a: u32,
    b: u32,
    c: u32,
    d: u32,
    e: u32,
    f: u32,
    g: u32,
    h: u32,
}

struct HKTempState {
    temp1: u32,
    temp2: u32
}

impl Default for HKState {
    fn default() -> Self {
        HKState { a: H[0], b: H[1], c: H[2], d: H[3], e: H[4], f: H[5], g: H[6], h: H[7] }
    }
}

const H: [u32; 8] = [
    0b01101010000010011110011001100111,
    0b10111011011001111010111010000101,
    0b00111100011011101111001101110010,
    0b10100101010011111111010100111010,
    0b01010001000011100101001001111111,
    0b10011011000001010110100010001100,
    0b00011111100000111101100110101011,
    0b01011011111000001100110100011001
];

const K: [u32; 64] = [
    0b01000010100010100010111110011000,
    0b01110001001101110100010010010001,
    0b10110101110000001111101111001111,
    0b11101001101101011101101110100101,
    0b00111001010101101100001001011011,
    0b01011001111100010001000111110001,
    0b10010010001111111000001010100100,
    0b10101011000111000101111011010101,
    0b11011000000001111010101010011000,
    0b00010010100000110101101100000001,
    0b00100100001100011000010110111110,
    0b01010101000011000111110111000011,
    0b01110010101111100101110101110100,
    0b10000000110111101011000111111110,
    0b10011011110111000000011010100111,
    0b11000001100110111111000101110100,
    0b11100100100110110110100111000001,
    0b11101111101111100100011110000110,
    0b00001111110000011001110111000110,
    0b00100100000011001010000111001100,
    0b00101101111010010010110001101111,
    0b01001010011101001000010010101010,
    0b01011100101100001010100111011100,
    0b01110110111110011000100011011010,
    0b10011000001111100101000101010010,
    0b10101000001100011100011001101101,
    0b10110000000000110010011111001000,
    0b10111111010110010111111111000111,
    0b11000110111000000000101111110011,
    0b11010101101001111001000101000111,
    0b00000110110010100110001101010001,
    0b00010100001010010010100101100111,
    0b00100111101101110000101010000101,
    0b00101110000110110010000100111000,
    0b01001101001011000110110111111100,
    0b01010011001110000000110100010011,
    0b01100101000010100111001101010100,
    0b01110110011010100000101010111011,
    0b10000001110000101100100100101110,
    0b10010010011100100010110010000101,
    0b10100010101111111110100010100001,
    0b10101000000110100110011001001011,
    0b11000010010010111000101101110000,
    0b11000111011011000101000110100011,
    0b11010001100100101110100000011001,
    0b11010110100110010000011000100100,
    0b11110100000011100011010110000101,
    0b00010000011010101010000001110000,
    0b00011001101001001100000100010110,
    0b00011110001101110110110000001000,
    0b00100111010010000111011101001100,
    0b00110100101100001011110010110101,
    0b00111001000111000000110010110011,
    0b01001110110110001010101001001010,
    0b01011011100111001100101001001111,
    0b01101000001011100110111111110011,
    0b01110100100011111000001011101110,
    0b01111000101001010110001101101111,
    0b10000100110010000111100000010100,
    0b10001100110001110000001000001000,
    0b10010000101111101111111111111010,
    0b10100100010100000110110011101011,
    0b10111110111110011010001111110111,
    0b11000110011100010111100011110010,
];

fn make_temp_state(schedule: &MessageSchedule, idx: usize, state: HKState) -> HKTempState {
    let HKState { a, b, c, e, f, g, h, .. } = state;
    let majority = (a & b) ^ (a & c) ^ (b & c);
    let e0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
    let choice = (e & f) ^ ((!e) & g);
    let e1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
    let temp2 = e0.wrapping_add(majority);
    let temp1 = h.wrapping_add(e1).wrapping_add(choice).wrapping_add(K[idx]).wrapping_add(schedule[idx]);

    HKTempState { temp1, temp2 }
}

fn make_next_state(schedule: &MessageSchedule, idx: usize, state: HKState) -> HKState {
    let HKState { a, b, c, d, e, f, g, .. } = state;
    let HKTempState { temp1, temp2, .. } = make_temp_state(schedule, idx, state);

    HKState{a: temp1.wrapping_add(temp2), b: a, c: b, d: c, e: d.wrapping_add(temp1), f: e, g: f, h: g}
}

fn split(a: u64) -> [u8; 8] {
    let b1 = ((a & 0xFF00_0000_0000_0000) >> 56) as u8;
    let b2 = ((a & 0x00FF_0000_0000_0000) >> 48) as u8;
    let b3 = ((a & 0x0000_FF00_0000_0000) >> 40) as u8;
    let b4 = ((a & 0x0000_00FF_0000_0000) >> 32) as u8;
    let b5 = ((a & 0x0000_0000_FF00_0000) >> 24) as u8;
    let b6 = ((a & 0x0000_0000_00FF_0000) >> 16) as u8;
    let b7 = ((a & 0x0000_0000_0000_FF00) >> 8) as u8;
    let b8 = (a & 0x0000_0000_0000_00FF) as u8;

    [b1, b2, b3, b4, b5, b6, b7, b8]
}

fn make_message_block(input: &[u8]) -> (Vec<u8>, usize) {
    let num_chunks = ((input.len() + 8) / 64) + 1;
    let bit_length = split((input.len() * 8) as u64);
    let block_length = num_chunks * BYTES_PER_BLOCK;
    let mut v = vec![0 as u8; block_length];

    v[0..input.len()].copy_from_slice(input);
    v[input.len()] = INPUT_PAD;
    v[(block_length - 8)..block_length].copy_from_slice(&bit_length);
    
    (v, num_chunks)
}

fn copy_chunk_to_schedule(chunks: &[u8], chunk_num: usize, schedule: &mut MessageSchedule) {
    let chunk = &chunks[(BYTES_PER_BLOCK * chunk_num)..(BYTES_PER_BLOCK * (chunk_num + 1))];
    for i in 0..16 {
        let idx = i * 4;
        let b1 = chunk[idx];
        let b2 = chunk[idx + 1];
        let b3 = chunk[idx + 2];
        let b4 = chunk[idx + 3];
        let elem = ((b1 as u32) << 24) | ((b2 as u32) << 16) | ((b3 as u32) << 8) | (b4 as u32); 
        schedule[i] = elem;
    }
}

fn calc_schedule_entry(schedule: &MessageSchedule, offset: usize) -> u32 {
    let w0 = schedule[offset];
    let w9 = schedule[offset + 9];
    let w1 = schedule[offset + 1];
    let s0 = w1.rotate_right(7) ^ w1.rotate_right(18) ^ (w1 >> 3);
    let w14 = schedule[offset + 14];
    let s1 = w14.rotate_right(17) ^ w14.rotate_right(19) ^ (w14 >> 10);

    w0.wrapping_add(s0).wrapping_add(w9).wrapping_add(s1)
}

pub fn hash_block(block: &UnhashedBlock) -> Result<[u32; 8], Error> {
    let bytes = bincode::serialize(&block)?;

    Ok(hash_sha256(&bytes))
}

/**
 * CPU implementation of sha256 hashing
 */
pub fn hash_sha256(input: &[u8]) -> [u32; 8] {
    let (block, num_chunks) = make_message_block(input);
    let mut schedule: MessageSchedule = [0; 64];
    let mut state = HKState::default();
    let mut hash = [0 as u32; 8];
    hash.copy_from_slice(&H);

    for i in 0..num_chunks {
        state.a = hash[0];
        state.b = hash[1];
        state.c = hash[2];
        state.d = hash[3];
        state.e = hash[4];
        state.f = hash[5];
        state.g = hash[6];
        state.h = hash[7];

        copy_chunk_to_schedule(block.as_slice(), i, &mut schedule);
        
        for j in 0..48 {
            schedule[j + 16] = calc_schedule_entry(&schedule, j);
        }

        for j in 0..64 {
            state = make_next_state(&schedule, j, state);
        }

        let HKState { a, b, c, d, e, f, g, h } = state;

        hash[0] = hash[0].wrapping_add(a);
        hash[1] = hash[1].wrapping_add(b);
        hash[2] = hash[2].wrapping_add(c);
        hash[3] = hash[3].wrapping_add(d);
        hash[4] = hash[4].wrapping_add(e);
        hash[5] = hash[5].wrapping_add(f);
        hash[6] = hash[6].wrapping_add(g);
        hash[7] = hash[7].wrapping_add(h);
    }

    hash
}
