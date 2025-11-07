//==============================================================================
// File: aes256_key_expansion_comb.v
// Description: COMBINATIONAL Key Expansion for AES-256
// - Fully combinational - generates all round keys in 0 cycles!
// - Trade-off: More LUTs but zero latency
//==============================================================================

module aes256_key_expansion_comb (
    input  wire [255:0] key_i,          // Master key (256-bit)
    output wire [127:0] round_keys_o [0:14]  // 15 round keys (128-bit each)
);

    //==========================================================================
    // RCON (Round Constants)
    //==========================================================================
    wire [7:0] rcon [0:6];
    assign rcon[0] = 8'h01;
    assign rcon[1] = 8'h02;
    assign rcon[2] = 8'h04;
    assign rcon[3] = 8'h08;
    assign rcon[4] = 8'h10;
    assign rcon[5] = 8'h20;
    assign rcon[6] = 8'h40;

    //==========================================================================
    // S-BOX (for SubWord operation)
    //==========================================================================
    function [7:0] sbox;
        input [7:0] in;
        case (in)
            8'h00: sbox = 8'h63; 8'h01: sbox = 8'h7C; 8'h02: sbox = 8'h77; 8'h03: sbox = 8'h7B;
            8'h04: sbox = 8'hF2; 8'h05: sbox = 8'h6B; 8'h06: sbox = 8'h6F; 8'h07: sbox = 8'hC5;
            8'h08: sbox = 8'h30; 8'h09: sbox = 8'h01; 8'h0A: sbox = 8'h67; 8'h0B: sbox = 8'h2B;
            8'h0C: sbox = 8'hFE; 8'h0D: sbox = 8'hD7; 8'h0E: sbox = 8'hAB; 8'h0F: sbox = 8'h76;
            8'h10: sbox = 8'hCA; 8'h11: sbox = 8'h82; 8'h12: sbox = 8'hC9; 8'h13: sbox = 8'h7D;
            8'h14: sbox = 8'hFA; 8'h15: sbox = 8'h59; 8'h16: sbox = 8'h47; 8'h17: sbox = 8'hF0;
            8'h18: sbox = 8'hAD; 8'h19: sbox = 8'hD4; 8'h1A: sbox = 8'hA2; 8'h1B: sbox = 8'hAF;
            8'h1C: sbox = 8'h9C; 8'h1D: sbox = 8'hA4; 8'h1E: sbox = 8'h72; 8'h1F: sbox = 8'hC0;
            8'h20: sbox = 8'hB7; 8'h21: sbox = 8'hFD; 8'h22: sbox = 8'h93; 8'h23: sbox = 8'h26;
            8'h24: sbox = 8'h36; 8'h25: sbox = 8'h3F; 8'h26: sbox = 8'hF7; 8'h27: sbox = 8'hCC;
            8'h28: sbox = 8'h34; 8'h29: sbox = 8'hA5; 8'h2A: sbox = 8'hE5; 8'h2B: sbox = 8'hF1;
            8'h2C: sbox = 8'h71; 8'h2D: sbox = 8'hD8; 8'h2E: sbox = 8'h31; 8'h2F: sbox = 8'h15;
            8'h30: sbox = 8'h04; 8'h31: sbox = 8'hC7; 8'h32: sbox = 8'h23; 8'h33: sbox = 8'hC3;
            8'h34: sbox = 8'h18; 8'h35: sbox = 8'h96; 8'h36: sbox = 8'h05; 8'h37: sbox = 8'h9A;
            8'h38: sbox = 8'h07; 8'h39: sbox = 8'h12; 8'h3A: sbox = 8'h80; 8'h3B: sbox = 8'hE2;
            8'h3C: sbox = 8'hEB; 8'h3D: sbox = 8'h27; 8'h3E: sbox = 8'hB2; 8'h3F: sbox = 8'h75;
            8'h40: sbox = 8'h09; 8'h41: sbox = 8'h83; 8'h42: sbox = 8'h2C; 8'h43: sbox = 8'h1A;
            8'h44: sbox = 8'h1B; 8'h45: sbox = 8'h6E; 8'h46: sbox = 8'h5A; 8'h47: sbox = 8'hA0;
            8'h48: sbox = 8'h52; 8'h49: sbox = 8'h3B; 8'h4A: sbox = 8'hD6; 8'h4B: sbox = 8'hB3;
            8'h4C: sbox = 8'h29; 8'h4D: sbox = 8'hE3; 8'h4E: sbox = 8'h2F; 8'h4F: sbox = 8'h84;
            8'h50: sbox = 8'h53; 8'h51: sbox = 8'hD1; 8'h52: sbox = 8'h00; 8'h53: sbox = 8'hED;
            8'h54: sbox = 8'h20; 8'h55: sbox = 8'hFC; 8'h56: sbox = 8'hB1; 8'h57: sbox = 8'h5B;
            8'h58: sbox = 8'h6A; 8'h59: sbox = 8'hCB; 8'h5A: sbox = 8'hBE; 8'h5B: sbox = 8'h39;
            8'h5C: sbox = 8'h4A; 8'h5D: sbox = 8'h4C; 8'h5E: sbox = 8'h58; 8'h5F: sbox = 8'hCF;
            8'h60: sbox = 8'hD0; 8'h61: sbox = 8'hEF; 8'h62: sbox = 8'hAA; 8'h63: sbox = 8'hFB;
            8'h64: sbox = 8'h43; 8'h65: sbox = 8'h4D; 8'h66: sbox = 8'h33; 8'h67: sbox = 8'h85;
            8'h68: sbox = 8'h45; 8'h69: sbox = 8'hF9; 8'h6A: sbox = 8'h02; 8'h6B: sbox = 8'h7F;
            8'h6C: sbox = 8'h50; 8'h6D: sbox = 8'h3C; 8'h6E: sbox = 8'h9F; 8'h6F: sbox = 8'hA8;
            8'h70: sbox = 8'h51; 8'h71: sbox = 8'hA3; 8'h72: sbox = 8'h40; 8'h73: sbox = 8'h8F;
            8'h74: sbox = 8'h92; 8'h75: sbox = 8'h9D; 8'h76: sbox = 8'h38; 8'h77: sbox = 8'hF5;
            8'h78: sbox = 8'hBC; 8'h79: sbox = 8'hB6; 8'h7A: sbox = 8'hDA; 8'h7B: sbox = 8'h21;
            8'h7C: sbox = 8'h10; 8'h7D: sbox = 8'hFF; 8'h7E: sbox = 8'hF3; 8'h7F: sbox = 8'hD2;
            8'h80: sbox = 8'hCD; 8'h81: sbox = 8'h0C; 8'h82: sbox = 8'h13; 8'h83: sbox = 8'hEC;
            8'h84: sbox = 8'h5F; 8'h85: sbox = 8'h97; 8'h86: sbox = 8'h44; 8'h87: sbox = 8'h17;
            8'h88: sbox = 8'hC4; 8'h89: sbox = 8'hA7; 8'h8A: sbox = 8'h7E; 8'h8B: sbox = 8'h3D;
            8'h8C: sbox = 8'h64; 8'h8D: sbox = 8'h5D; 8'h8E: sbox = 8'h19; 8'h8F: sbox = 8'h73;
            8'h90: sbox = 8'h60; 8'h91: sbox = 8'h81; 8'h92: sbox = 8'h4F; 8'h93: sbox = 8'hDC;
            8'h94: sbox = 8'h22; 8'h95: sbox = 8'h2A; 8'h96: sbox = 8'h90; 8'h97: sbox = 8'h88;
            8'h98: sbox = 8'h46; 8'h99: sbox = 8'hEE; 8'h9A: sbox = 8'hB8; 8'h9B: sbox = 8'h14;
            8'h9C: sbox = 8'hDE; 8'h9D: sbox = 8'h5E; 8'h9E: sbox = 8'h0B; 8'h9F: sbox = 8'hDB;
            8'hA0: sbox = 8'hE0; 8'hA1: sbox = 8'h32; 8'hA2: sbox = 8'h3A; 8'hA3: sbox = 8'h0A;
            8'hA4: sbox = 8'h49; 8'hA5: sbox = 8'h06; 8'hA6: sbox = 8'h24; 8'hA7: sbox = 8'h5C;
            8'hA8: sbox = 8'hC2; 8'hA9: sbox = 8'hD3; 8'hAA: sbox = 8'hAC; 8'hAB: sbox = 8'h62;
            8'hAC: sbox = 8'h91; 8'hAD: sbox = 8'h95; 8'hAE: sbox = 8'hE4; 8'hAF: sbox = 8'h79;
            8'hB0: sbox = 8'hE7; 8'hB1: sbox = 8'hC8; 8'hB2: sbox = 8'h37; 8'hB3: sbox = 8'h6D;
            8'hB4: sbox = 8'h8D; 8'hB5: sbox = 8'hD5; 8'hB6: sbox = 8'h4E; 8'hB7: sbox = 8'hA9;
            8'hB8: sbox = 8'h6C; 8'hB9: sbox = 8'h56; 8'hBA: sbox = 8'hF4; 8'hBB: sbox = 8'hEA;
            8'hBC: sbox = 8'h65; 8'hBD: sbox = 8'h7A; 8'hBE: sbox = 8'hAE; 8'hBF: sbox = 8'h08;
            8'hC0: sbox = 8'hBA; 8'hC1: sbox = 8'h78; 8'hC2: sbox = 8'h25; 8'hC3: sbox = 8'h2E;
            8'hC4: sbox = 8'h1C; 8'hC5: sbox = 8'hA6; 8'hC6: sbox = 8'hB4; 8'hC7: sbox = 8'hC6;
            8'hC8: sbox = 8'hE8; 8'hC9: sbox = 8'hDD; 8'hCA: sbox = 8'h74; 8'hCB: sbox = 8'h1F;
            8'hCC: sbox = 8'h4B; 8'hCD: sbox = 8'hBD; 8'hCE: sbox = 8'h8B; 8'hCF: sbox = 8'h8A;
            8'hD0: sbox = 8'h70; 8'hD1: sbox = 8'h3E; 8'hD2: sbox = 8'hB5; 8'hD3: sbox = 8'h66;
            8'hD4: sbox = 8'h48; 8'hD5: sbox = 8'h03; 8'hD6: sbox = 8'hF6; 8'hD7: sbox = 8'h0E;
            8'hD8: sbox = 8'h61; 8'hD9: sbox = 8'h35; 8'hDA: sbox = 8'h57; 8'hDB: sbox = 8'hB9;
            8'hDC: sbox = 8'h86; 8'hDD: sbox = 8'hC1; 8'hDE: sbox = 8'h1D; 8'hDF: sbox = 8'h9E;
            8'hE0: sbox = 8'hE1; 8'hE1: sbox = 8'hF8; 8'hE2: sbox = 8'h98; 8'hE3: sbox = 8'h11;
            8'hE4: sbox = 8'h69; 8'hE5: sbox = 8'hD9; 8'hE6: sbox = 8'h8E; 8'hE7: sbox = 8'h94;
            8'hE8: sbox = 8'h9B; 8'hE9: sbox = 8'h1E; 8'hEA: sbox = 8'h87; 8'hEB: sbox = 8'hE9;
            8'hEC: sbox = 8'hCE; 8'hED: sbox = 8'h55; 8'hEE: sbox = 8'h28; 8'hEF: sbox = 8'hDF;
            8'hF0: sbox = 8'h8C; 8'hF1: sbox = 8'hA1; 8'hF2: sbox = 8'h89; 8'hF3: sbox = 8'h0D;
            8'hF4: sbox = 8'hBF; 8'hF5: sbox = 8'hE6; 8'hF6: sbox = 8'h42; 8'hF7: sbox = 8'h68;
            8'hF8: sbox = 8'h41; 8'hF9: sbox = 8'h99; 8'hFA: sbox = 8'h2D; 8'hFB: sbox = 8'h0F;
            8'hFC: sbox = 8'hB0; 8'hFD: sbox = 8'h54; 8'hFE: sbox = 8'hBB; 8'hFF: sbox = 8'h16;
        endcase
    endfunction

    //==========================================================================
    // HELPER FUNCTIONS
    //==========================================================================
    
    // RotWord: Rotate word left by 1 byte
    function [31:0] rot_word;
        input [31:0] word_in;
        begin
            rot_word = {word_in[23:0], word_in[31:24]};
        end
    endfunction

    // SubWord: Apply S-box to each byte of word
    function [31:0] sub_word;
        input [31:0] word_in;
        begin
            sub_word = {sbox(word_in[31:24]), sbox(word_in[23:16]), 
                       sbox(word_in[15:8]), sbox(word_in[7:0])};
        end
    endfunction

    //==========================================================================
    // COMBINATIONAL KEY EXPANSION
    // Generate all 60 words combinationally
    //==========================================================================
    wire [31:0] w [0:59];
    
    // Initialize first 8 words from master key
    assign w[0] = key_i[255:224];
    assign w[1] = key_i[223:192];
    assign w[2] = key_i[191:160];
    assign w[3] = key_i[159:128];
    assign w[4] = key_i[127:96];
    assign w[5] = key_i[95:64];
    assign w[6] = key_i[63:32];
    assign w[7] = key_i[31:0];
    
    // Generate remaining words combinationally
    // w[8]
    assign w[8] = w[0] ^ sub_word(rot_word(w[7])) ^ {rcon[0], 24'h000000};
    assign w[9] = w[1] ^ w[8];
    assign w[10] = w[2] ^ w[9];
    assign w[11] = w[3] ^ w[10];
    assign w[12] = w[4] ^ sub_word(w[11]);  // AES-256 special case
    assign w[13] = w[5] ^ w[12];
    assign w[14] = w[6] ^ w[13];
    assign w[15] = w[7] ^ w[14];
    
    // w[16]
    assign w[16] = w[8] ^ sub_word(rot_word(w[15])) ^ {rcon[1], 24'h000000};
    assign w[17] = w[9] ^ w[16];
    assign w[18] = w[10] ^ w[17];
    assign w[19] = w[11] ^ w[18];
    assign w[20] = w[12] ^ sub_word(w[19]);
    assign w[21] = w[13] ^ w[20];
    assign w[22] = w[14] ^ w[21];
    assign w[23] = w[15] ^ w[22];
    
    // w[24]
    assign w[24] = w[16] ^ sub_word(rot_word(w[23])) ^ {rcon[2], 24'h000000};
    assign w[25] = w[17] ^ w[24];
    assign w[26] = w[18] ^ w[25];
    assign w[27] = w[19] ^ w[26];
    assign w[28] = w[20] ^ sub_word(w[27]);
    assign w[29] = w[21] ^ w[28];
    assign w[30] = w[22] ^ w[29];
    assign w[31] = w[23] ^ w[30];
    
    // w[32]
    assign w[32] = w[24] ^ sub_word(rot_word(w[31])) ^ {rcon[3], 24'h000000};
    assign w[33] = w[25] ^ w[32];
    assign w[34] = w[26] ^ w[33];
    assign w[35] = w[27] ^ w[34];
    assign w[36] = w[28] ^ sub_word(w[35]);
    assign w[37] = w[29] ^ w[36];
    assign w[38] = w[30] ^ w[37];
    assign w[39] = w[31] ^ w[38];
    
    // w[40]
    assign w[40] = w[32] ^ sub_word(rot_word(w[39])) ^ {rcon[4], 24'h000000};
    assign w[41] = w[33] ^ w[40];
    assign w[42] = w[34] ^ w[41];
    assign w[43] = w[35] ^ w[42];
    assign w[44] = w[36] ^ sub_word(w[43]);
    assign w[45] = w[37] ^ w[44];
    assign w[46] = w[38] ^ w[45];
    assign w[47] = w[39] ^ w[46];
    
    // w[48]
    assign w[48] = w[40] ^ sub_word(rot_word(w[47])) ^ {rcon[5], 24'h000000};
    assign w[49] = w[41] ^ w[48];
    assign w[50] = w[42] ^ w[49];
    assign w[51] = w[43] ^ w[50];
    assign w[52] = w[44] ^ sub_word(w[51]);
    assign w[53] = w[45] ^ w[52];
    assign w[54] = w[46] ^ w[53];
    assign w[55] = w[47] ^ w[54];
    
    // w[56]
    assign w[56] = w[48] ^ sub_word(rot_word(w[55])) ^ {rcon[6], 24'h000000};
    assign w[57] = w[49] ^ w[56];
    assign w[58] = w[50] ^ w[57];
    assign w[59] = w[51] ^ w[58];
    
    //==========================================================================
    // PACK WORDS INTO ROUND KEYS
    //==========================================================================
    genvar i;
    generate
        for (i = 0; i < 15; i = i + 1) begin : pack_round_keys
            assign round_keys_o[i] = {w[i*4], w[i*4 + 1], w[i*4 + 2], w[i*4 + 3]};
        end
    endgenerate

endmodule
