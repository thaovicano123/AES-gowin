//==============================================================================
// File: tb_aes256_subbytes.v
// Description: Comprehensive Testbench for aes256_subbytes.v
// 
// Test Coverage:
// 1. S-box lookup for encryption (mode=0)
// 2. Inverse S-box lookup for decryption (mode=1)
// 3. Inverse property: InvSubBytes(SubBytes(state)) = state
// 4. FIPS-197 test vectors
// 5. All 256 possible byte values
// 6. Edge cases (0x00, 0xFF)
//==============================================================================

`timescale 1ns / 1ps

module tb_aes256_subbytes;

    //==========================================================================
    // Test Signals
    //==========================================================================
    reg         mode;           // 0=Encrypt, 1=Decrypt
    reg  [127:0] state_in;      // Input state (16 bytes)
    wire [127:0] state_out;     // Output state (16 bytes)
    
    // Error tracking
    integer errors;
    integer test_count;
    
    //==========================================================================
    // Reference S-box and Inverse S-box Tables (for verification)
    //==========================================================================
    reg [7:0] ref_sbox [0:255];
    reg [7:0] ref_inv_sbox [0:255];
    
    initial begin
        // Reference S-box (same as in aes256_subbytes.v)
        ref_sbox[  0] = 8'h63; ref_sbox[  1] = 8'h7C; ref_sbox[  2] = 8'h77; ref_sbox[  3] = 8'h7B;
        ref_sbox[  4] = 8'hF2; ref_sbox[  5] = 8'h6B; ref_sbox[  6] = 8'h6F; ref_sbox[  7] = 8'hC5;
        ref_sbox[  8] = 8'h30; ref_sbox[  9] = 8'h01; ref_sbox[ 10] = 8'h67; ref_sbox[ 11] = 8'h2B;
        ref_sbox[ 12] = 8'hFE; ref_sbox[ 13] = 8'hD7; ref_sbox[ 14] = 8'hAB; ref_sbox[ 15] = 8'h76;
        ref_sbox[ 16] = 8'hCA; ref_sbox[ 17] = 8'h82; ref_sbox[ 18] = 8'hC9; ref_sbox[ 19] = 8'h7D;
        ref_sbox[ 20] = 8'hFA; ref_sbox[ 21] = 8'h59; ref_sbox[ 22] = 8'h47; ref_sbox[ 23] = 8'hF0;
        ref_sbox[ 24] = 8'hAD; ref_sbox[ 25] = 8'hD4; ref_sbox[ 26] = 8'hA2; ref_sbox[ 27] = 8'hAF;
        ref_sbox[ 28] = 8'h9C; ref_sbox[ 29] = 8'hA4; ref_sbox[ 30] = 8'h72; ref_sbox[ 31] = 8'hC0;
        ref_sbox[ 32] = 8'hB7; ref_sbox[ 33] = 8'hFD; ref_sbox[ 34] = 8'h93; ref_sbox[ 35] = 8'h26;
        ref_sbox[ 36] = 8'h36; ref_sbox[ 37] = 8'h3F; ref_sbox[ 38] = 8'hF7; ref_sbox[ 39] = 8'hCC;
        ref_sbox[ 40] = 8'h34; ref_sbox[ 41] = 8'hA5; ref_sbox[ 42] = 8'hE5; ref_sbox[ 43] = 8'hF1;
        ref_sbox[ 44] = 8'h71; ref_sbox[ 45] = 8'hD8; ref_sbox[ 46] = 8'h31; ref_sbox[ 47] = 8'h15;
        ref_sbox[ 48] = 8'h04; ref_sbox[ 49] = 8'hC7; ref_sbox[ 50] = 8'h23; ref_sbox[ 51] = 8'hC3;
        ref_sbox[ 52] = 8'h18; ref_sbox[ 53] = 8'h96; ref_sbox[ 54] = 8'h05; ref_sbox[ 55] = 8'h9A;
        ref_sbox[ 56] = 8'h07; ref_sbox[ 57] = 8'h12; ref_sbox[ 58] = 8'h80; ref_sbox[ 59] = 8'hE2;
        ref_sbox[ 60] = 8'hEB; ref_sbox[ 61] = 8'h27; ref_sbox[ 62] = 8'hB2; ref_sbox[ 63] = 8'h75;
        ref_sbox[ 64] = 8'h09; ref_sbox[ 65] = 8'h83; ref_sbox[ 66] = 8'h2C; ref_sbox[ 67] = 8'h1A;
        ref_sbox[ 68] = 8'h1B; ref_sbox[ 69] = 8'h6E; ref_sbox[ 70] = 8'h5A; ref_sbox[ 71] = 8'hA0;
        ref_sbox[ 72] = 8'h52; ref_sbox[ 73] = 8'h3B; ref_sbox[ 74] = 8'hD6; ref_sbox[ 75] = 8'hB3;
        ref_sbox[ 76] = 8'h29; ref_sbox[ 77] = 8'hE3; ref_sbox[ 78] = 8'h2F; ref_sbox[ 79] = 8'h84;
        ref_sbox[ 80] = 8'h53; ref_sbox[ 81] = 8'hD1; ref_sbox[ 82] = 8'h00; ref_sbox[ 83] = 8'hED;
        ref_sbox[ 84] = 8'h20; ref_sbox[ 85] = 8'hFC; ref_sbox[ 86] = 8'hB1; ref_sbox[ 87] = 8'h5B;
        ref_sbox[ 88] = 8'h6A; ref_sbox[ 89] = 8'hCB; ref_sbox[ 90] = 8'hBE; ref_sbox[ 91] = 8'h39;
        ref_sbox[ 92] = 8'h4A; ref_sbox[ 93] = 8'h4C; ref_sbox[ 94] = 8'h58; ref_sbox[ 95] = 8'hCF;
        ref_sbox[ 96] = 8'hD0; ref_sbox[ 97] = 8'hEF; ref_sbox[ 98] = 8'hAA; ref_sbox[ 99] = 8'hFB;
        ref_sbox[100] = 8'h43; ref_sbox[101] = 8'h4D; ref_sbox[102] = 8'h33; ref_sbox[103] = 8'h85;
        ref_sbox[104] = 8'h45; ref_sbox[105] = 8'hF9; ref_sbox[106] = 8'h02; ref_sbox[107] = 8'h7F;
        ref_sbox[108] = 8'h50; ref_sbox[109] = 8'h3C; ref_sbox[110] = 8'h9F; ref_sbox[111] = 8'hA8;
        ref_sbox[112] = 8'h51; ref_sbox[113] = 8'hA3; ref_sbox[114] = 8'h40; ref_sbox[115] = 8'h8F;
        ref_sbox[116] = 8'h92; ref_sbox[117] = 8'h9D; ref_sbox[118] = 8'h38; ref_sbox[119] = 8'hF5;
        ref_sbox[120] = 8'hBC; ref_sbox[121] = 8'hB6; ref_sbox[122] = 8'hDA; ref_sbox[123] = 8'h21;
        ref_sbox[124] = 8'h10; ref_sbox[125] = 8'hFF; ref_sbox[126] = 8'hF3; ref_sbox[127] = 8'hD2;
        ref_sbox[128] = 8'hCD; ref_sbox[129] = 8'h0C; ref_sbox[130] = 8'h13; ref_sbox[131] = 8'hEC;
        ref_sbox[132] = 8'h5F; ref_sbox[133] = 8'h97; ref_sbox[134] = 8'h44; ref_sbox[135] = 8'h17;
        ref_sbox[136] = 8'hC4; ref_sbox[137] = 8'hA7; ref_sbox[138] = 8'h7E; ref_sbox[139] = 8'h3D;
        ref_sbox[140] = 8'h64; ref_sbox[141] = 8'h5D; ref_sbox[142] = 8'h19; ref_sbox[143] = 8'h73;
        ref_sbox[144] = 8'h60; ref_sbox[145] = 8'h81; ref_sbox[146] = 8'h4F; ref_sbox[147] = 8'hDC;
        ref_sbox[148] = 8'h22; ref_sbox[149] = 8'h2A; ref_sbox[150] = 8'h90; ref_sbox[151] = 8'h88;
        ref_sbox[152] = 8'h46; ref_sbox[153] = 8'hEE; ref_sbox[154] = 8'hB8; ref_sbox[155] = 8'h14;
        ref_sbox[156] = 8'hDE; ref_sbox[157] = 8'h5E; ref_sbox[158] = 8'h0B; ref_sbox[159] = 8'hDB;
        ref_sbox[160] = 8'hE0; ref_sbox[161] = 8'h32; ref_sbox[162] = 8'h3A; ref_sbox[163] = 8'h0A;
        ref_sbox[164] = 8'h49; ref_sbox[165] = 8'h06; ref_sbox[166] = 8'h24; ref_sbox[167] = 8'h5C;
        ref_sbox[168] = 8'hC2; ref_sbox[169] = 8'hD3; ref_sbox[170] = 8'hAC; ref_sbox[171] = 8'h62;
        ref_sbox[172] = 8'h91; ref_sbox[173] = 8'h95; ref_sbox[174] = 8'hE4; ref_sbox[175] = 8'h79;
        ref_sbox[176] = 8'hE7; ref_sbox[177] = 8'hC8; ref_sbox[178] = 8'h37; ref_sbox[179] = 8'h6D;
        ref_sbox[180] = 8'h8D; ref_sbox[181] = 8'hD5; ref_sbox[182] = 8'h4E; ref_sbox[183] = 8'hA9;
        ref_sbox[184] = 8'h6C; ref_sbox[185] = 8'h56; ref_sbox[186] = 8'hF4; ref_sbox[187] = 8'hEA;
        ref_sbox[188] = 8'h65; ref_sbox[189] = 8'h7A; ref_sbox[190] = 8'hAE; ref_sbox[191] = 8'h08;
        ref_sbox[192] = 8'hBA; ref_sbox[193] = 8'h78; ref_sbox[194] = 8'h25; ref_sbox[195] = 8'h2E;
        ref_sbox[196] = 8'h1C; ref_sbox[197] = 8'hA6; ref_sbox[198] = 8'hB4; ref_sbox[199] = 8'hC6;
        ref_sbox[200] = 8'hE8; ref_sbox[201] = 8'hDD; ref_sbox[202] = 8'h74; ref_sbox[203] = 8'h1F;
        ref_sbox[204] = 8'h4B; ref_sbox[205] = 8'hBD; ref_sbox[206] = 8'h8B; ref_sbox[207] = 8'h8A;
        ref_sbox[208] = 8'h70; ref_sbox[209] = 8'h3E; ref_sbox[210] = 8'hB5; ref_sbox[211] = 8'h66;
        ref_sbox[212] = 8'h48; ref_sbox[213] = 8'h03; ref_sbox[214] = 8'hF6; ref_sbox[215] = 8'h0E;
        ref_sbox[216] = 8'h61; ref_sbox[217] = 8'h35; ref_sbox[218] = 8'h57; ref_sbox[219] = 8'hB9;
        ref_sbox[220] = 8'h86; ref_sbox[221] = 8'hC1; ref_sbox[222] = 8'h1D; ref_sbox[223] = 8'h9E;
        ref_sbox[224] = 8'hE1; ref_sbox[225] = 8'hF8; ref_sbox[226] = 8'h98; ref_sbox[227] = 8'h11;
        ref_sbox[228] = 8'h69; ref_sbox[229] = 8'hD9; ref_sbox[230] = 8'h8E; ref_sbox[231] = 8'h94;
        ref_sbox[232] = 8'h9B; ref_sbox[233] = 8'h1E; ref_sbox[234] = 8'h87; ref_sbox[235] = 8'hE9;
        ref_sbox[236] = 8'hCE; ref_sbox[237] = 8'h55; ref_sbox[238] = 8'h28; ref_sbox[239] = 8'hDF;
        ref_sbox[240] = 8'h8C; ref_sbox[241] = 8'hA1; ref_sbox[242] = 8'h89; ref_sbox[243] = 8'h0D;
        ref_sbox[244] = 8'hBF; ref_sbox[245] = 8'hE6; ref_sbox[246] = 8'h42; ref_sbox[247] = 8'h68;
        ref_sbox[248] = 8'h41; ref_sbox[249] = 8'h99; ref_sbox[250] = 8'h2D; ref_sbox[251] = 8'h0F;
        ref_sbox[252] = 8'hB0; ref_sbox[253] = 8'h54; ref_sbox[254] = 8'hBB; ref_sbox[255] = 8'h16;
        
        // Reference Inverse S-box (same as in aes256_subbytes.v)
        ref_inv_sbox[  0] = 8'h52; ref_inv_sbox[  1] = 8'h09; ref_inv_sbox[  2] = 8'h6A; ref_inv_sbox[  3] = 8'hD5;
        ref_inv_sbox[  4] = 8'h30; ref_inv_sbox[  5] = 8'h36; ref_inv_sbox[  6] = 8'hA5; ref_inv_sbox[  7] = 8'h38;
        ref_inv_sbox[  8] = 8'hBF; ref_inv_sbox[  9] = 8'h40; ref_inv_sbox[ 10] = 8'hA3; ref_inv_sbox[ 11] = 8'h9E;
        ref_inv_sbox[ 12] = 8'h81; ref_inv_sbox[ 13] = 8'hF3; ref_inv_sbox[ 14] = 8'hD7; ref_inv_sbox[ 15] = 8'hFB;
        ref_inv_sbox[ 16] = 8'h7C; ref_inv_sbox[ 17] = 8'hE3; ref_inv_sbox[ 18] = 8'h39; ref_inv_sbox[ 19] = 8'h82;
        ref_inv_sbox[ 20] = 8'h9B; ref_inv_sbox[ 21] = 8'h2F; ref_inv_sbox[ 22] = 8'hFF; ref_inv_sbox[ 23] = 8'h87;
        ref_inv_sbox[ 24] = 8'h34; ref_inv_sbox[ 25] = 8'h8E; ref_inv_sbox[ 26] = 8'h43; ref_inv_sbox[ 27] = 8'h44;
        ref_inv_sbox[ 28] = 8'hC4; ref_inv_sbox[ 29] = 8'hDE; ref_inv_sbox[ 30] = 8'hE9; ref_inv_sbox[ 31] = 8'hCB;
        ref_inv_sbox[ 32] = 8'h54; ref_inv_sbox[ 33] = 8'h7B; ref_inv_sbox[ 34] = 8'h94; ref_inv_sbox[ 35] = 8'h32;
        ref_inv_sbox[ 36] = 8'hA6; ref_inv_sbox[ 37] = 8'hC2; ref_inv_sbox[ 38] = 8'h23; ref_inv_sbox[ 39] = 8'h3D;
        ref_inv_sbox[ 40] = 8'hEE; ref_inv_sbox[ 41] = 8'h4C; ref_inv_sbox[ 42] = 8'h95; ref_inv_sbox[ 43] = 8'h0B;
        ref_inv_sbox[ 44] = 8'h42; ref_inv_sbox[ 45] = 8'hFA; ref_inv_sbox[ 46] = 8'hC3; ref_inv_sbox[ 47] = 8'h4E;
        ref_inv_sbox[ 48] = 8'h08; ref_inv_sbox[ 49] = 8'h2E; ref_inv_sbox[ 50] = 8'hA1; ref_inv_sbox[ 51] = 8'h66;
        ref_inv_sbox[ 52] = 8'h28; ref_inv_sbox[ 53] = 8'hD9; ref_inv_sbox[ 54] = 8'h24; ref_inv_sbox[ 55] = 8'hB2;
        ref_inv_sbox[ 56] = 8'h76; ref_inv_sbox[ 57] = 8'h5B; ref_inv_sbox[ 58] = 8'hA2; ref_inv_sbox[ 59] = 8'h49;
        ref_inv_sbox[ 60] = 8'h6D; ref_inv_sbox[ 61] = 8'h8B; ref_inv_sbox[ 62] = 8'hD1; ref_inv_sbox[ 63] = 8'h25;
        ref_inv_sbox[ 64] = 8'h72; ref_inv_sbox[ 65] = 8'hF8; ref_inv_sbox[ 66] = 8'hF6; ref_inv_sbox[ 67] = 8'h64;
        ref_inv_sbox[ 68] = 8'h86; ref_inv_sbox[ 69] = 8'h68; ref_inv_sbox[ 70] = 8'h98; ref_inv_sbox[ 71] = 8'h16;
        ref_inv_sbox[ 72] = 8'hD4; ref_inv_sbox[ 73] = 8'hA4; ref_inv_sbox[ 74] = 8'h5C; ref_inv_sbox[ 75] = 8'hCC;
        ref_inv_sbox[ 76] = 8'h5D; ref_inv_sbox[ 77] = 8'h65; ref_inv_sbox[ 78] = 8'hB6; ref_inv_sbox[ 79] = 8'h92;
        ref_inv_sbox[ 80] = 8'h6C; ref_inv_sbox[ 81] = 8'h70; ref_inv_sbox[ 82] = 8'h48; ref_inv_sbox[ 83] = 8'h50;
        ref_inv_sbox[ 84] = 8'hFD; ref_inv_sbox[ 85] = 8'hED; ref_inv_sbox[ 86] = 8'hB9; ref_inv_sbox[ 87] = 8'hDA;
        ref_inv_sbox[ 88] = 8'h5E; ref_inv_sbox[ 89] = 8'h15; ref_inv_sbox[ 90] = 8'h46; ref_inv_sbox[ 91] = 8'h57;
        ref_inv_sbox[ 92] = 8'hA7; ref_inv_sbox[ 93] = 8'h8D; ref_inv_sbox[ 94] = 8'h9D; ref_inv_sbox[ 95] = 8'h84;
        ref_inv_sbox[ 96] = 8'h90; ref_inv_sbox[ 97] = 8'hD8; ref_inv_sbox[ 98] = 8'hAB; ref_inv_sbox[ 99] = 8'h00;
        ref_inv_sbox[100] = 8'h8C; ref_inv_sbox[101] = 8'hBC; ref_inv_sbox[102] = 8'hD3; ref_inv_sbox[103] = 8'h0A;
        ref_inv_sbox[104] = 8'hF7; ref_inv_sbox[105] = 8'hE4; ref_inv_sbox[106] = 8'h58; ref_inv_sbox[107] = 8'h05;
        ref_inv_sbox[108] = 8'hB8; ref_inv_sbox[109] = 8'hB3; ref_inv_sbox[110] = 8'h45; ref_inv_sbox[111] = 8'h06;
        ref_inv_sbox[112] = 8'hD0; ref_inv_sbox[113] = 8'h2C; ref_inv_sbox[114] = 8'h1E; ref_inv_sbox[115] = 8'h8F;
        ref_inv_sbox[116] = 8'hCA; ref_inv_sbox[117] = 8'h3F; ref_inv_sbox[118] = 8'h0F; ref_inv_sbox[119] = 8'h02;
        ref_inv_sbox[120] = 8'hC1; ref_inv_sbox[121] = 8'hAF; ref_inv_sbox[122] = 8'hBD; ref_inv_sbox[123] = 8'h03;
        ref_inv_sbox[124] = 8'h01; ref_inv_sbox[125] = 8'h13; ref_inv_sbox[126] = 8'h8A; ref_inv_sbox[127] = 8'h6B;
        ref_inv_sbox[128] = 8'h3A; ref_inv_sbox[129] = 8'h91; ref_inv_sbox[130] = 8'h11; ref_inv_sbox[131] = 8'h41;
        ref_inv_sbox[132] = 8'h4F; ref_inv_sbox[133] = 8'h67; ref_inv_sbox[134] = 8'hDC; ref_inv_sbox[135] = 8'hEA;
        ref_inv_sbox[136] = 8'h97; ref_inv_sbox[137] = 8'hF2; ref_inv_sbox[138] = 8'hCF; ref_inv_sbox[139] = 8'hCE;
        ref_inv_sbox[140] = 8'hF0; ref_inv_sbox[141] = 8'hB4; ref_inv_sbox[142] = 8'hE6; ref_inv_sbox[143] = 8'h73;
        ref_inv_sbox[144] = 8'h96; ref_inv_sbox[145] = 8'hAC; ref_inv_sbox[146] = 8'h74; ref_inv_sbox[147] = 8'h22;
        ref_inv_sbox[148] = 8'hE7; ref_inv_sbox[149] = 8'hAD; ref_inv_sbox[150] = 8'h35; ref_inv_sbox[151] = 8'h85;
        ref_inv_sbox[152] = 8'hE2; ref_inv_sbox[153] = 8'hF9; ref_inv_sbox[154] = 8'h37; ref_inv_sbox[155] = 8'hE8;
        ref_inv_sbox[156] = 8'h1C; ref_inv_sbox[157] = 8'h75; ref_inv_sbox[158] = 8'hDF; ref_inv_sbox[159] = 8'h6E;
        ref_inv_sbox[160] = 8'h47; ref_inv_sbox[161] = 8'hF1; ref_inv_sbox[162] = 8'h1A; ref_inv_sbox[163] = 8'h71;
        ref_inv_sbox[164] = 8'h1D; ref_inv_sbox[165] = 8'h29; ref_inv_sbox[166] = 8'hC5; ref_inv_sbox[167] = 8'h89;
        ref_inv_sbox[168] = 8'h6F; ref_inv_sbox[169] = 8'hB7; ref_inv_sbox[170] = 8'h62; ref_inv_sbox[171] = 8'h0E;
        ref_inv_sbox[172] = 8'hAA; ref_inv_sbox[173] = 8'h18; ref_inv_sbox[174] = 8'hBE; ref_inv_sbox[175] = 8'h1B;
        ref_inv_sbox[176] = 8'hFC; ref_inv_sbox[177] = 8'h56; ref_inv_sbox[178] = 8'h3E; ref_inv_sbox[179] = 8'h4B;
        ref_inv_sbox[180] = 8'hC6; ref_inv_sbox[181] = 8'hD2; ref_inv_sbox[182] = 8'h79; ref_inv_sbox[183] = 8'h20;
        ref_inv_sbox[184] = 8'h9A; ref_inv_sbox[185] = 8'hDB; ref_inv_sbox[186] = 8'hC0; ref_inv_sbox[187] = 8'hFE;
        ref_inv_sbox[188] = 8'h78; ref_inv_sbox[189] = 8'hCD; ref_inv_sbox[190] = 8'h5A; ref_inv_sbox[191] = 8'hF4;
        ref_inv_sbox[192] = 8'h1F; ref_inv_sbox[193] = 8'hDD; ref_inv_sbox[194] = 8'hA8; ref_inv_sbox[195] = 8'h33;
        ref_inv_sbox[196] = 8'h88; ref_inv_sbox[197] = 8'h07; ref_inv_sbox[198] = 8'hC7; ref_inv_sbox[199] = 8'h31;
        ref_inv_sbox[200] = 8'hB1; ref_inv_sbox[201] = 8'h12; ref_inv_sbox[202] = 8'h10; ref_inv_sbox[203] = 8'h59;
        ref_inv_sbox[204] = 8'h27; ref_inv_sbox[205] = 8'h80; ref_inv_sbox[206] = 8'hEC; ref_inv_sbox[207] = 8'h5F;
        ref_inv_sbox[208] = 8'h60; ref_inv_sbox[209] = 8'h51; ref_inv_sbox[210] = 8'h7F; ref_inv_sbox[211] = 8'hA9;
        ref_inv_sbox[212] = 8'h19; ref_inv_sbox[213] = 8'hB5; ref_inv_sbox[214] = 8'h4A; ref_inv_sbox[215] = 8'h0D;
        ref_inv_sbox[216] = 8'h2D; ref_inv_sbox[217] = 8'hE5; ref_inv_sbox[218] = 8'h7A; ref_inv_sbox[219] = 8'h9F;
        ref_inv_sbox[220] = 8'h93; ref_inv_sbox[221] = 8'hC9; ref_inv_sbox[222] = 8'h9C; ref_inv_sbox[223] = 8'hEF;
        ref_inv_sbox[224] = 8'hA0; ref_inv_sbox[225] = 8'hE0; ref_inv_sbox[226] = 8'h3B; ref_inv_sbox[227] = 8'h4D;
        ref_inv_sbox[228] = 8'hAE; ref_inv_sbox[229] = 8'h2A; ref_inv_sbox[230] = 8'hF5; ref_inv_sbox[231] = 8'hB0;
        ref_inv_sbox[232] = 8'hC8; ref_inv_sbox[233] = 8'hEB; ref_inv_sbox[234] = 8'hBB; ref_inv_sbox[235] = 8'h3C;
        ref_inv_sbox[236] = 8'h83; ref_inv_sbox[237] = 8'h53; ref_inv_sbox[238] = 8'h99; ref_inv_sbox[239] = 8'h61;
        ref_inv_sbox[240] = 8'h17; ref_inv_sbox[241] = 8'h2B; ref_inv_sbox[242] = 8'h04; ref_inv_sbox[243] = 8'h7E;
        ref_inv_sbox[244] = 8'hBA; ref_inv_sbox[245] = 8'h77; ref_inv_sbox[246] = 8'hD6; ref_inv_sbox[247] = 8'h26;
        ref_inv_sbox[248] = 8'hE1; ref_inv_sbox[249] = 8'h69; ref_inv_sbox[250] = 8'h14; ref_inv_sbox[251] = 8'h63;
        ref_inv_sbox[252] = 8'h55; ref_inv_sbox[253] = 8'h21; ref_inv_sbox[254] = 8'h0C; ref_inv_sbox[255] = 8'h7D;
    end
    
    //==========================================================================
    // DUT Instantiation
    //==========================================================================
    aes256_subbytes dut (
        .mode_i(mode),
        .state_i(state_in),
        .state_o(state_out)
    );
    
    //==========================================================================
    // Helper Task: Check Single State Transformation
    //==========================================================================
    task check_subbytes;
        input [127:0] test_state;
        input test_mode;  // 0=encrypt, 1=decrypt
        input [255:0] test_name;
        reg [127:0] expected;
        integer i;
        integer byte_errors;
    begin
        byte_errors = 0;
        
        // Apply inputs
        mode = test_mode;
        state_in = test_state;
        #10;  // Wait for combinational logic
        
        // Calculate expected output
        for (i = 0; i < 16; i = i + 1) begin
            if (test_mode == 0) begin
                // Encryption: use S-box
                expected[i*8 +: 8] = ref_sbox[test_state[i*8 +: 8]];
            end else begin
                // Decryption: use Inverse S-box
                expected[i*8 +: 8] = ref_inv_sbox[test_state[i*8 +: 8]];
            end
        end
        
        // Check output
        test_count = test_count + 1;
        if (state_out !== expected) begin
            errors = errors + 1;
            $display("ERROR [Test %0d]: %s", test_count, test_name);
            $display("  Mode: %s", test_mode ? "DECRYPT" : "ENCRYPT");
            $display("  Input:    %032h", test_state);
            $display("  Expected: %032h", expected);
            $display("  Got:      %032h", state_out);
            
            // Show which bytes are wrong
            for (i = 0; i < 16; i = i + 1) begin
                if (state_out[i*8 +: 8] !== expected[i*8 +: 8]) begin
                    byte_errors = byte_errors + 1;
                    $display("  Byte[%2d]: Expected %02h, Got %02h", 
                             i, expected[i*8 +: 8], state_out[i*8 +: 8]);
                end
            end
        end else begin
            $display("PASS [Test %0d]: %s", test_count, test_name);
        end
    end
    endtask
    
    //==========================================================================
    // Helper Task: Check Inverse Property
    //==========================================================================
    task check_inverse_property;
        input [127:0] original_state;
        input [255:0] test_name;
        reg [127:0] encrypted;
        reg [127:0] decrypted;
    begin
        // Encrypt
        mode = 0;
        state_in = original_state;
        #10;
        encrypted = state_out;
        
        // Decrypt
        mode = 1;
        state_in = encrypted;
        #10;
        decrypted = state_out;
        
        // Check if we got back the original
        test_count = test_count + 1;
        if (decrypted !== original_state) begin
            errors = errors + 1;
            $display("ERROR [Test %0d]: Inverse Property - %s", test_count, test_name);
            $display("  Original:  %032h", original_state);
            $display("  Encrypted: %032h", encrypted);
            $display("  Decrypted: %032h", decrypted);
        end else begin
            $display("PASS [Test %0d]: Inverse Property - %s", test_count, test_name);
        end
    end
    endtask
    
    //==========================================================================
    // Main Test Sequence
    //==========================================================================
    initial begin
        // Initialize
        errors = 0;
        test_count = 0;
        mode = 0;
        state_in = 128'h0;
        
        $display("================================================================================");
        $display("AES-256 SubBytes Module Testbench");
        $display("================================================================================");
        $display("");
        
        //======================================================================
        // Test 1: Edge Cases
        //======================================================================
        $display("--- Test Section 1: Edge Cases ---");
        check_subbytes(128'h00000000000000000000000000000000, 0, "All zeros - Encrypt");
        check_subbytes(128'h00000000000000000000000000000000, 1, "All zeros - Decrypt");
        check_subbytes(128'hFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF, 0, "All ones - Encrypt");
        check_subbytes(128'hFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF, 1, "All ones - Decrypt");
        $display("");
        
        //======================================================================
        // Test 2: FIPS-197 Test Vectors (Appendix B)
        //======================================================================
        $display("--- Test Section 2: FIPS-197 Test Vectors ---");
        
        // FIPS-197 Appendix B - Start of Round (before SubBytes)
        check_subbytes(
            128'h193de3bea0f4e22b9ac68d2ae9f84808,
            0,
            "FIPS-197 Start of Round - Encrypt"
        );
        
        // FIPS-197 Appendix B - After SubBytes (should produce this when encrypted)
        // Input: d4bf5d30e0b452aeb84111f11e2798e5 (after SubBytes in spec)
        // We reverse: apply InvSubBytes to get original
        check_subbytes(
            128'hd4bf5d30e0b452aeb84111f11e2798e5,
            1,
            "FIPS-197 After SubBytes - Decrypt"
        );
        
        // Additional FIPS-197 states
        check_subbytes(
            128'h00112233445566778899aabbccddeeff,
            0,
            "FIPS-197 Sequential Pattern - Encrypt"
        );
        $display("");
        
        //======================================================================
        // Test 3: Known S-box Lookups
        //======================================================================
        $display("--- Test Section 3: Known S-box Values ---");
        
        // Test specific S-box entries
        // S-box[0x00] = 0x63
        check_subbytes(128'h00000000000000000000000000000000, 0, "S-box[0x00] = 0x63");
        
        // S-box[0x53] = 0xED (from FIPS-197 example)
        state_in = 128'h0;
        state_in[7:0] = 8'h53;
        check_subbytes(state_in, 0, "S-box[0x53] = 0xED");
        
        // InvS-box[0x63] = 0x00
        state_in = 128'h0;
        state_in[7:0] = 8'h63;
        check_subbytes(state_in, 1, "InvS-box[0x63] = 0x00");
        $display("");
        
        //======================================================================
        // Test 4: Inverse Property Tests
        //======================================================================
        $display("--- Test Section 4: Inverse Property (InvSubBytes(SubBytes(x)) = x) ---");
        
        check_inverse_property(128'h00000000000000000000000000000000, "All zeros");
        check_inverse_property(128'hFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF, "All ones");
        check_inverse_property(128'h193de3bea0f4e22b9ac68d2ae9f84808, "FIPS-197 state");
        check_inverse_property(128'h00112233445566778899aabbccddeeff, "Sequential pattern");
        check_inverse_property(128'hfedcba9876543210fedcba9876543210, "Descending pattern");
        check_inverse_property(128'ha5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5, "Alternating bits 1");
        check_inverse_property(128'h5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a, "Alternating bits 2");
        $display("");
        
        //======================================================================
        // Test 5: All 256 Byte Values (Exhaustive S-box Test)
        //======================================================================
        $display("--- Test Section 5: Exhaustive S-box Test (all 256 byte values) ---");
        
        begin : exhaustive_test
            integer byte_val;
            integer sbox_errors;
            integer inv_sbox_errors;
            
            sbox_errors = 0;
            inv_sbox_errors = 0;
            
            for (byte_val = 0; byte_val < 256; byte_val = byte_val + 1) begin
                // Test S-box
                state_in = 128'h0;
                state_in[7:0] = byte_val;
                mode = 0;
                #10;
                
                if (state_out[7:0] !== ref_sbox[byte_val]) begin
                    sbox_errors = sbox_errors + 1;
                    $display("  S-box ERROR: Input=0x%02h, Expected=0x%02h, Got=0x%02h",
                             byte_val, ref_sbox[byte_val], state_out[7:0]);
                end
                
                // Test Inverse S-box
                mode = 1;
                #10;
                
                if (state_out[7:0] !== ref_inv_sbox[byte_val]) begin
                    inv_sbox_errors = inv_sbox_errors + 1;
                    $display("  InvS-box ERROR: Input=0x%02h, Expected=0x%02h, Got=0x%02h",
                             byte_val, ref_inv_sbox[byte_val], state_out[7:0]);
                end
            end
            
            test_count = test_count + 2;
            if (sbox_errors == 0) begin
                $display("PASS [Test %0d]: All 256 S-box entries correct", test_count - 1);
            end else begin
                errors = errors + 1;
                $display("ERROR [Test %0d]: %0d S-box entries incorrect", test_count - 1, sbox_errors);
            end
            
            if (inv_sbox_errors == 0) begin
                $display("PASS [Test %0d]: All 256 Inverse S-box entries correct", test_count);
            end else begin
                errors = errors + 1;
                $display("ERROR [Test %0d]: %0d Inverse S-box entries incorrect", test_count, inv_sbox_errors);
            end
        end
        $display("");
        
        //======================================================================
        // Test 6: Random States
        //======================================================================
        $display("--- Test Section 6: Random State Patterns ---");
        
        check_subbytes(128'h3243f6a8885a308d313198a2e0370734, 0, "Random state 1 - Encrypt");
        check_subbytes(128'h3243f6a8885a308d313198a2e0370734, 1, "Random state 1 - Decrypt");
        check_inverse_property(128'h3243f6a8885a308d313198a2e0370734, "Random state 1");
        
        check_subbytes(128'hb7e151628aed2a6abf7158809cf4f3c7, 0, "Random state 2 - Encrypt");
        check_subbytes(128'hb7e151628aed2a6abf7158809cf4f3c7, 1, "Random state 2 - Decrypt");
        check_inverse_property(128'hb7e151628aed2a6abf7158809cf4f3c7, "Random state 2");
        $display("");
        
        //======================================================================
        // Final Results
        //======================================================================
        $display("================================================================================");
        $display("Test Summary:");
        $display("  Total Tests: %0d", test_count);
        $display("  Errors:      %0d", errors);
        if (errors == 0) begin
            $display("  Status:      ALL TESTS PASSED ✓");
        end else begin
            $display("  Status:      TESTS FAILED ✗");
        end
        $display("================================================================================");
        
        // Generate VCD for waveform viewing
        $dumpfile("tb_aes256_subbytes.vcd");
        $dumpvars(0, tb_aes256_subbytes);
        
        #100;
        $finish;
    end

endmodule
